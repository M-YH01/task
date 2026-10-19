#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
로컬 패스키(WebAuthn) 서버 — 카드 2(등록) + 카드 3(로그인·세션).
표준 라이브러리만 사용합니다 (설치 필요 없음). 실행: python server.py
접속: http://localhost:8787  (localhost는 WebAuthn이 "안전한 컨텍스트"로 인정)

[카드 2] 등록
  POST /api/challenge       등록용 challenge 발급·보관
  POST /api/register        attestationObject에서 공개키만 추출해 credentials.json에 저장
  GET  /api/credentials     저장된 패스키(공개키) 목록

[카드 3] 로그인
  POST /api/login/challenge 로그인용 challenge를 "매번 새로" 발급, 서버에 보관(120초, 1회용)
  POST /api/login/verify    서명을 저장해 둔 공개키로 직접 검증. 통과해야만 세션 토큰 발급
  GET  /api/private         비공개 자리. 세션 토큰이 없거나 틀리면 401
  POST /api/logout          서버 쪽 세션을 지움 -> 같은 토큰으로 다시 요청하면 401

서명 검증(ES256 = ECDSA P-256 + SHA-256)은 외부 라이브러리 없이 이 파일 안에서
직접 합니다. 검증 결과가 거짓이면 로그인은 거절됩니다.

세션 방식: 로그인에 성공하면 서버가 32바이트 난수 "불투명 세션 토큰"을 만들어 줍니다.
서버에는 토큰의 SHA-256 해시만 sessions.json에 저장하므로(원문 없음), 파일이 새어도
그대로는 쓸 수 없습니다. 브라우저는 이 토큰을 Authorization: Bearer 헤더로 보냅니다.
로그에 남는 토큰 값은 앞 4글자만 보이고 나머지는 가려집니다.

저장 파일(모두 이 스크립트가 있는 폴더, 평문 JSON):
  challenges.json   발급된 challenge, 용도(register/login), 사용 여부
  credentials.json  등록된 패스키(공개키 등)
  sessions.json     세션(토큰 해시, 만료시각)
  request_log.jsonl 요청 기록 (토큰은 가려서 기록)
"""

import base64
import hashlib
import json
import os
import secrets
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8787
RP_ID = "localhost"
LOGIN_CHALLENGE_TTL = 120      # 초
SESSION_TTL = 30 * 60          # 초

HERE = os.path.dirname(os.path.abspath(__file__))
CHALLENGES_PATH = os.path.join(HERE, "challenges.json")
CREDENTIALS_PATH = os.path.join(HERE, "credentials.json")
SESSIONS_PATH = os.path.join(HERE, "sessions.json")
LOG_PATH = os.path.join(HERE, "request_log.jsonl")

LOCK = threading.Lock()

# 비공개 자리의 내용(예시 문구). 이 값은 /api/private가 세션을 확인한 뒤에만 내보냅니다.
# index.html(공개 페이지)에는 들어 있지 않습니다.
PRIVATE_ITEMS = [
    {"title": "진행 중인 프로젝트 메모", "body": "(예시) 사이드 프로젝트 A - 다음 주까지 로그인 붙이기"},
    {"title": "지원하려는 곳 목록", "body": "(예시) 회사 A, 회사 B - 지원 마감일 확인 필요"},
    {"title": "스스로 쓰는 회고", "body": "(예시) 이번 주 잘한 점 / 고칠 점 메모"},
]


# ---------------------------------------------------------------------------
# 작은 JSON "파일 DB" 헬퍼
# ---------------------------------------------------------------------------
def _load(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()
        if not content:
            return default
        return json.loads(content)


def _save(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def mask_token(tok):
    """로그용: 토큰 앞 4글자만 보이고 나머지는 가림."""
    if not tok:
        return None
    return tok[:4] + "…(가림, 총 %d자)" % len(tok)


def append_log(entry):
    entry = dict(entry)
    entry["loggedAt"] = now_iso()
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


# ---------------------------------------------------------------------------
# 최소 CBOR 디코더 (attestationObject 파싱용)
# ---------------------------------------------------------------------------
class CborDecoder:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _byte(self):
        b = self.data[self.pos]
        self.pos += 1
        return b

    def _read_uint(self, info):
        if info < 24:
            return info
        extra_len = {24: 1, 25: 2, 26: 4, 27: 8}[info]
        n = int.from_bytes(self.data[self.pos:self.pos + extra_len], "big")
        self.pos += extra_len
        return n

    def decode(self):
        b0 = self._byte()
        major = b0 >> 5
        info = b0 & 0x1F

        if major == 0:
            return self._read_uint(info)
        if major == 1:
            return -1 - self._read_uint(info)
        if major == 2:
            length = self._read_uint(info)
            val = self.data[self.pos:self.pos + length]
            self.pos += length
            return bytes(val)
        if major == 3:
            length = self._read_uint(info)
            val = self.data[self.pos:self.pos + length]
            self.pos += length
            return val.decode("utf-8")
        if major == 4:
            length = self._read_uint(info)
            return [self.decode() for _ in range(length)]
        if major == 5:
            length = self._read_uint(info)
            result = {}
            for _ in range(length):
                k = self.decode()
                v = self.decode()
                result[k] = v
            return result
        if major == 6:
            self._read_uint(info)
            return self.decode()
        if major == 7:
            if info == 20:
                return False
            if info == 21:
                return True
            if info == 22:
                return None
            if info == 25:
                raw = self.data[self.pos:self.pos + 2]
                self.pos += 2
                return struct.unpack(">e", raw)[0]
            if info == 26:
                raw = self.data[self.pos:self.pos + 4]
                self.pos += 4
                return struct.unpack(">f", raw)[0]
            if info == 27:
                raw = self.data[self.pos:self.pos + 8]
                self.pos += 8
                return struct.unpack(">d", raw)[0]
            raise ValueError("unsupported simple value: %d" % info)
        raise ValueError("unsupported CBOR major type: %d" % major)


def cbor_decode(data: bytes):
    return CborDecoder(data).decode()


def parse_auth_data(auth_data: bytes):
    rp_id_hash = auth_data[0:32]
    flags = auth_data[32]
    counter = int.from_bytes(auth_data[33:37], "big")
    pos = 37

    at_present = bool(flags & 0x40)
    result = {
        "rpIdHash": rp_id_hash,
        "rpIdHashB64": b64url_encode(rp_id_hash),
        "flags": flags,
        "signCount": counter,
        "credentialId": None,
        "cosePublicKey": None,
    }
    if not at_present:
        return result

    aaguid = auth_data[pos:pos + 16]
    pos += 16
    cred_id_len = int.from_bytes(auth_data[pos:pos + 2], "big")
    pos += 2
    credential_id = auth_data[pos:pos + cred_id_len]
    pos += cred_id_len

    decoder = CborDecoder(auth_data[pos:])
    cose_key = decoder.decode()

    result["credentialId"] = credential_id
    result["cosePublicKey"] = cose_key
    result["aaguidB64"] = b64url_encode(aaguid)
    return result


COSE_ALG_NAMES = {-7: "ES256", -257: "RS256", -8: "EdDSA"}
COSE_CRV_NAMES = {1: "P-256", 2: "P-384", 3: "P-521"}


def describe_cose_key(cose_key: dict):
    kty = cose_key.get(1)
    alg = cose_key.get(3)
    out = {"kty": kty, "alg": alg, "algName": COSE_ALG_NAMES.get(alg, str(alg))}
    if kty == 2:
        crv = cose_key.get(-1)
        x = cose_key.get(-2)
        y = cose_key.get(-3)
        out["crv"] = COSE_CRV_NAMES.get(crv, str(crv))
        out["xB64"] = b64url_encode(x) if isinstance(x, bytes) else None
        out["yB64"] = b64url_encode(y) if isinstance(y, bytes) else None
    elif kty == 3:
        n = cose_key.get(-1)
        e = cose_key.get(-2)
        out["nB64"] = b64url_encode(n) if isinstance(n, bytes) else None
        out["eB64"] = b64url_encode(e) if isinstance(e, bytes) else None
    return out


# ---------------------------------------------------------------------------
# ES256(ECDSA P-256, SHA-256) 서명 검증 — 외부 라이브러리 없이 직접 구현
# ---------------------------------------------------------------------------
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G = (GX, GY)


def _inv(x, m):
    return pow(x, -1, m)


def _on_curve(pt):
    if pt is None:
        return True
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _scalar_mult(k, pt):
    result = None
    addend = pt
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def parse_der_signature(sig: bytes):
    """ECDSA DER 서명(SEQUENCE{INTEGER r, INTEGER s}) -> (r, s)"""
    if len(sig) < 8 or sig[0] != 0x30:
        raise ValueError("not a DER sequence")
    seq_len = sig[1]
    if seq_len >= 0x80 or seq_len != len(sig) - 2:
        raise ValueError("bad DER length")
    pos = 2
    if sig[pos] != 0x02:
        raise ValueError("expected INTEGER for r")
    rl = sig[pos + 1]
    r = int.from_bytes(sig[pos + 2:pos + 2 + rl], "big")
    pos += 2 + rl
    if sig[pos] != 0x02:
        raise ValueError("expected INTEGER for s")
    sl = sig[pos + 1]
    s = int.from_bytes(sig[pos + 2:pos + 2 + sl], "big")
    if pos + 2 + sl != len(sig):
        raise ValueError("trailing bytes in signature")
    return r, s


def ecdsa_p256_verify(pub_x: int, pub_y: int, message: bytes, der_signature: bytes) -> bool:
    """message를 SHA-256으로 해시해 서명을 공개키로 확인. 맞으면 True."""
    try:
        r, s = parse_der_signature(der_signature)
    except Exception:
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    q = (pub_x, pub_y)
    if not _on_curve(q) or q is None:
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = _inv(s, N)
    u1 = e * w % N
    u2 = r * w % N
    pt = _point_add(_scalar_mult(u1, G), _scalar_mult(u2, q))
    if pt is None:
        return False
    return pt[0] % N == r


# ---------------------------------------------------------------------------
# challenge / session 보관소
# ---------------------------------------------------------------------------
def issue_challenge(purpose):
    challenge_b64 = b64url_encode(secrets.token_bytes(32))
    store = _load(CHALLENGES_PATH, [])
    store.append({
        "challenge": challenge_b64,
        "purpose": purpose,
        "createdAt": now_iso(),
        "createdEpoch": time.time(),
        "used": False,
    })
    _save(CHALLENGES_PATH, store[-200:])
    return challenge_b64


def find_challenge(store, challenge_b64):
    for e in store:
        if e["challenge"] == challenge_b64:
            return e
    return None


def new_session(credential_id, label):
    token = b64url_encode(secrets.token_bytes(32))
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    sessions = _load(SESSIONS_PATH, [])
    sessions = [s for s in sessions if s["expiresEpoch"] > time.time()]
    sessions.append({
        "tokenSha256": token_hash,
        "credentialId": credential_id,
        "label": label,
        "createdAt": now_iso(),
        "expiresEpoch": time.time() + SESSION_TTL,
        "expiresAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + SESSION_TTL)),
    })
    _save(SESSIONS_PATH, sessions)
    return token, sessions[-1]["expiresAt"]


def lookup_session(token):
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("ascii", "ignore")).hexdigest()
    for s in _load(SESSIONS_PATH, []):
        if s["tokenSha256"] == token_hash and s["expiresEpoch"] > time.time():
            return s
    return None


def delete_session(token):
    token_hash = hashlib.sha256(token.encode("ascii", "ignore")).hexdigest()
    sessions = _load(SESSIONS_PATH, [])
    kept = [s for s in sessions if s["tokenSha256"] != token_hash]
    _save(SESSIONS_PATH, kept)
    return len(kept) != len(sessions)


def bearer_token(headers):
    h = headers.get("Authorization", "")
    if h.startswith("Bearer "):
        return h[7:].strip()
    return None


# ---------------------------------------------------------------------------
# HTTP 핸들러
# ---------------------------------------------------------------------------
INDEX_HTML = None


def json_response(handler, status, body):
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8")), raw.decode("utf-8")

    # ---------------- GET ----------------
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/api/credentials":
            with LOCK:
                creds = _load(CREDENTIALS_PATH, [])
            json_response(self, 200, {"credentials": creds})
            return

        if self.path == "/api/events":
            events = []
            with LOCK:
                if os.path.exists(LOG_PATH):
                    with open(LOG_PATH, "r", encoding="utf-8") as f:
                        lines = f.readlines()[-40:]
                    for line in lines:
                        line = line.strip()
                        if line:
                            events.append(json.loads(line))
            events.reverse()
            json_response(self, 200, {"events": events})
            return

        if self.path == "/api/private":
            token = bearer_token(self.headers)
            with LOCK:
                session = lookup_session(token)
                append_log({
                    "type": "private_access",
                    "authorization": ("Bearer " + mask_token(token)) if token else "(없음)",
                    "result": "allowed" if session else "denied_401",
                })
            if not session:
                json_response(self, 401, {"error": "unauthorized",
                                          "message": "유효한 세션 토큰이 없습니다. 패스키로 로그인하세요."})
                return
            json_response(self, 200, {"items": PRIVATE_ITEMS, "passkeyLabel": session["label"]})
            return

        self.send_response(404)
        self.end_headers()

    # ---------------- POST ----------------
    def do_POST(self):
        with LOCK:
            self._do_post_locked()

    def _reject_login(self, reason, extra=None, challenge=None):
        entry = {"type": "login_rejected", "reason": reason, "challenge": challenge}
        if extra:
            entry.update(extra)
        append_log(entry)
        body = {"error": reason}
        if extra:
            body.update(extra)
        json_response(self, 401, body)

    def _do_post_locked(self):
        # ----- 등록용 challenge -----
        if self.path == "/api/challenge":
            challenge_b64 = issue_challenge("register")
            append_log({"type": "challenge_issued", "purpose": "register", "challenge": challenge_b64})
            json_response(self, 200, {"challenge": challenge_b64})
            return

        # ----- 등록 -----
        if self.path == "/api/register":
            body, raw_text = self._read_json_body()
            append_log({"type": "register_request_received", "requestBody": body})

            challenge_b64 = body.get("challenge")
            label = (body.get("label") or "").strip()
            client_data_json_b64 = body.get("clientDataJSON")
            attestation_object_b64 = body.get("attestationObject")
            credential_id_b64 = body.get("credentialId")

            store = _load(CHALLENGES_PATH, [])
            match = find_challenge(store, challenge_b64)
            if match is None:
                json_response(self, 400, {"error": "unknown_challenge"})
                return
            if match.get("purpose", "register") != "register":
                json_response(self, 400, {"error": "wrong_challenge_purpose"})
                return
            if match.get("used"):
                json_response(self, 400, {"error": "challenge_already_used"})
                return

            try:
                client_data = json.loads(b64url_decode(client_data_json_b64).decode("utf-8"))
            except Exception as e:
                json_response(self, 400, {"error": "bad_client_data", "detail": str(e)})
                return

            if client_data.get("type") != "webauthn.create":
                json_response(self, 400, {"error": "wrong_type"})
                return
            if client_data.get("challenge") != challenge_b64:
                json_response(self, 400, {"error": "challenge_mismatch"})
                return
            origin = client_data.get("origin", "")
            if not (origin.startswith("http://localhost:") or origin.startswith("http://127.0.0.1:")):
                json_response(self, 400, {"error": "bad_origin", "origin": origin})
                return

            try:
                attestation = cbor_decode(b64url_decode(attestation_object_b64))
                parsed = parse_auth_data(attestation.get("authData"))
                cose_key = parsed["cosePublicKey"]
                key_desc = describe_cose_key(cose_key) if cose_key else None
            except Exception as e:
                json_response(self, 400, {"error": "attestation_parse_failed", "detail": str(e)})
                return

            if not label:
                json_response(self, 400, {"error": "missing_label"})
                return

            creds = _load(CREDENTIALS_PATH, [])
            for c in creds:
                if c["credentialId"] == credential_id_b64:
                    json_response(self, 400, {"error": "credential_already_registered"})
                    return

            record = {
                "credentialId": credential_id_b64,
                "label": label,
                "algorithm": key_desc.get("algName") if key_desc else None,
                "publicKey": key_desc,
                "signCount": parsed["signCount"],
                "createdAt": now_iso(),
                "fmt": attestation.get("fmt"),
            }
            creds.append(record)
            _save(CREDENTIALS_PATH, creds)

            for e in store:
                if e["challenge"] == challenge_b64:
                    e["used"] = True
                    e["usedAt"] = now_iso()
            _save(CHALLENGES_PATH, store)

            append_log({"type": "registered", "challenge": challenge_b64, "stored": record})
            json_response(self, 200, {"ok": True, "credential": record})
            return

        # ----- 로그인용 challenge (매번 새로) -----
        if self.path == "/api/login/challenge":
            creds = _load(CREDENTIALS_PATH, [])
            if not creds:
                json_response(self, 400, {"error": "no_credentials_registered"})
                return
            challenge_b64 = issue_challenge("login")
            append_log({"type": "login_challenge_issued", "purpose": "login", "challenge": challenge_b64,
                        "ttlSeconds": LOGIN_CHALLENGE_TTL})
            json_response(self, 200, {
                "challenge": challenge_b64,
                "ttlSeconds": LOGIN_CHALLENGE_TTL,
                "allowCredentials": [c["credentialId"] for c in creds],
            })
            return

        # ----- 로그인 검증 -----
        if self.path == "/api/login/verify":
            body, _raw = self._read_json_body()
            append_log({"type": "login_request_received", "requestBody": body})

            challenge_b64 = body.get("challenge")
            credential_id_b64 = body.get("credentialId")

            # 1) challenge: 서버가 보관 중인 로그인용 값인가 / 만료 / 이미 사용
            store = _load(CHALLENGES_PATH, [])
            match = find_challenge(store, challenge_b64)
            if match is None:
                self._reject_login("unknown_challenge", challenge=challenge_b64)
                return
            if match.get("purpose") != "login":
                self._reject_login("wrong_challenge_purpose", challenge=challenge_b64)
                return
            if match.get("used"):
                self._reject_login("challenge_already_used",
                                   {"message": "이미 한 번 쓴 질문입니다. 새 질문으로 다시 시도하세요."},
                                   challenge=challenge_b64)
                return

            # 이 시점에 곧바로 "사용됨" 처리: 서명이 틀려도 같은 질문으로 다시 시도할 수 없다.
            match["used"] = True
            match["usedAt"] = now_iso()
            _save(CHALLENGES_PATH, store)

            if time.time() - match.get("createdEpoch", 0) > LOGIN_CHALLENGE_TTL:
                self._reject_login("challenge_expired", challenge=challenge_b64)
                return

            # 2) 등록된 패스키인가
            creds = _load(CREDENTIALS_PATH, [])
            cred = None
            for c in creds:
                if c["credentialId"] == credential_id_b64:
                    cred = c
                    break
            if cred is None:
                self._reject_login("unknown_credential", challenge=challenge_b64)
                return
            pk = cred.get("publicKey") or {}
            if pk.get("kty") != 2 or pk.get("alg") != -7 or pk.get("crv") != "P-256":
                self._reject_login("unsupported_key_type", {"message": "이 서버는 ES256(P-256)만 검증합니다."},
                                   challenge=challenge_b64)
                return

            # 3) clientDataJSON / authenticatorData 확인
            try:
                client_data_raw = b64url_decode(body.get("clientDataJSON"))
                client_data = json.loads(client_data_raw.decode("utf-8"))
                auth_data = b64url_decode(body.get("authenticatorData"))
                signature = b64url_decode(body.get("signature"))
            except Exception as e:
                self._reject_login("malformed_request", {"detail": str(e)}, challenge=challenge_b64)
                return

            if client_data.get("type") != "webauthn.get":
                self._reject_login("wrong_type", challenge=challenge_b64)
                return
            if client_data.get("challenge") != challenge_b64:
                self._reject_login("challenge_mismatch", challenge=challenge_b64)
                return
            origin = client_data.get("origin", "")
            if not (origin.startswith("http://localhost:") or origin.startswith("http://127.0.0.1:")):
                self._reject_login("bad_origin", {"origin": origin}, challenge=challenge_b64)
                return
            if len(auth_data) < 37:
                self._reject_login("malformed_authenticator_data", challenge=challenge_b64)
                return
            if auth_data[0:32] != hashlib.sha256(RP_ID.encode("ascii")).digest():
                self._reject_login("rp_id_hash_mismatch", challenge=challenge_b64)
                return
            flags = auth_data[32]
            if not (flags & 0x01):
                self._reject_login("user_presence_missing", challenge=challenge_b64)
                return
            new_count = int.from_bytes(auth_data[33:37], "big")
            old_count = cred.get("signCount", 0)
            if (new_count != 0 or old_count != 0) and new_count <= old_count:
                self._reject_login("sign_count_not_increasing",
                                   {"stored": old_count, "received": new_count}, challenge=challenge_b64)
                return

            # 4) 서명 검증: 저장해 둔 공개키로 (authenticatorData || SHA256(clientDataJSON)) 확인
            signed_message = auth_data + hashlib.sha256(client_data_raw).digest()
            px = int.from_bytes(b64url_decode(pk["xB64"]), "big")
            py = int.from_bytes(b64url_decode(pk["yB64"]), "big")
            ok = ecdsa_p256_verify(px, py, signed_message, signature)
            if not ok:
                self._reject_login("bad_signature",
                                   {"message": "저장된 공개키로 서명을 확인할 수 없습니다."},
                                   challenge=challenge_b64)
                return

            # 5) 통과 -> signCount 갱신, 세션 발급
            cred["signCount"] = new_count
            cred["lastLoginAt"] = now_iso()
            _save(CREDENTIALS_PATH, creds)

            token, expires_at = new_session(cred["credentialId"], cred["label"])
            append_log({"type": "login_success", "challenge": challenge_b64,
                        "credentialId": cred["credentialId"], "label": cred["label"],
                        "sessionToken": mask_token(token), "expiresAt": expires_at})
            json_response(self, 200, {"ok": True, "token": token, "expiresAt": expires_at,
                                      "label": cred["label"]})
            return

        # ----- 로그아웃 -----
        if self.path == "/api/logout":
            token = bearer_token(self.headers)
            removed = delete_session(token) if token else False
            append_log({"type": "logout",
                        "authorization": ("Bearer " + mask_token(token)) if token else "(없음)",
                        "sessionRemoved": removed})
            json_response(self, 200, {"ok": True, "sessionRemoved": removed})
            return

        self.send_response(404)
        self.end_headers()


def main():
    global INDEX_HTML
    with open(os.path.join(HERE, "index.html"), "r", encoding="utf-8") as f:
        INDEX_HTML = f.read()

    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("로컬 패스키 서버 실행 중: http://localhost:%d" % PORT)
    print("저장 위치: %s" % HERE)
    print("종료하려면 Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
