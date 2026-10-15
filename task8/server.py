#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
카드 2용 로컬 패스키(WebAuthn) 등록 서버.
표준 라이브러리만 사용합니다 (설치 필요 없음). 실행: python server.py
http://localhost:8787 를 브라우저에서 직접 여세요 (localhost는 WebAuthn이
"안전한 컨텍스트"로 인정하는 주소라, claude.ai 아티팩트의 iframe 샌드박스
제약이 전혀 없습니다).

이 서버가 실제로 하는 일:
  1) POST /api/challenge  : 32바이트 난수 challenge를 만들어 challenges.json에
     "미확인" 상태로 저장하고, 그 값을 응답으로 돌려준다.  (T08-19)
  2) POST /api/register   : 브라우저가 navigator.credentials.create()로 받은
     결과(credential.id, clientDataJSON, attestationObject)를 그대로 받아서,
       - clientDataJSON.challenge 가 방금 발급한 challenge와 같은지 확인
       - clientDataJSON.type 이 "webauthn.create" 인지 확인
       - clientDataJSON.origin 이 http://localhost:PORT 인지 확인
       - attestationObject(CBOR)를 직접 파싱해서 authData 안의
         공개키(COSE key)만 뽑아낸다
     이 서버는 받은 요청 본문을 그대로 로그 파일(request_log.jsonl)에 남기므로,
     "개인키가 전송되지 않았다"는 사실을 요청 본문 원문으로 확인할 수 있다. (T08-23)
  3) GET  /api/credentials : 지금까지 저장된 패스키(이름, 생성시각, 공개키,
     알고리즘)를 보여준다. 개인키 필드는 어디에도 없다 — WebAuthn 표준상
     브라우저가 서버로 개인키를 보내는 방법 자체가 없기 때문이다.

저장 파일은 모두 이 스크립트가 있는 폴더에 평문 JSON으로 생성된다:
  challenges.json   : 발급된 challenge와 사용 여부
  credentials.json  : 등록된 패스키(공개키 등)
  request_log.jsonl : 모든 등록 요청의 원본 본문 (증거용)
"""

import base64
import json
import os
import secrets
import struct
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8787
HERE = os.path.dirname(os.path.abspath(__file__))
CHALLENGES_PATH = os.path.join(HERE, "challenges.json")
CREDENTIALS_PATH = os.path.join(HERE, "credentials.json")
LOG_PATH = os.path.join(HERE, "request_log.jsonl")


# ---------------------------------------------------------------------------
# 아주 작은 JSON "파일 DB" 헬퍼
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


def append_log(entry):
    entry = dict(entry)
    entry["loggedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# base64url
# ---------------------------------------------------------------------------
def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


# ---------------------------------------------------------------------------
# 최소 CBOR 디코더 (WebAuthn attestationObject 파싱에 필요한 만큼만 구현)
# ---------------------------------------------------------------------------
class CborDecoder:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _byte(self):
        b = self.data[self.pos]
        self.pos += 1
        return b

    def _read_uint(self, info, extra_len):
        if info < 24:
            return info
        n = int.from_bytes(self.data[self.pos:self.pos + extra_len], "big")
        self.pos += extra_len
        return n

    def decode(self):
        b0 = self._byte()
        major = b0 >> 5
        info = b0 & 0x1F

        if major == 0:  # unsigned int
            return self._read_uint(info, {24: 1, 25: 2, 26: 4, 27: 8}.get(info, 0))
        if major == 1:  # negative int
            n = self._read_uint(info, {24: 1, 25: 2, 26: 4, 27: 8}.get(info, 0))
            return -1 - n
        if major == 2:  # byte string
            length = self._read_uint(info, {24: 1, 25: 2, 26: 4, 27: 8}.get(info, 0))
            val = self.data[self.pos:self.pos + length]
            self.pos += length
            return bytes(val)
        if major == 3:  # text string
            length = self._read_uint(info, {24: 1, 25: 2, 26: 4, 27: 8}.get(info, 0))
            val = self.data[self.pos:self.pos + length]
            self.pos += length
            return val.decode("utf-8")
        if major == 4:  # array
            length = self._read_uint(info, {24: 1, 25: 2, 26: 4, 27: 8}.get(info, 0))
            return [self.decode() for _ in range(length)]
        if major == 5:  # map
            length = self._read_uint(info, {24: 1, 25: 2, 26: 4, 27: 8}.get(info, 0))
            result = {}
            for _ in range(length):
                k = self.decode()
                v = self.decode()
                result[k] = v
            return result
        if major == 6:  # tag — skip tag, decode inner value
            self._read_uint(info, {24: 1, 25: 2, 26: 4, 27: 8}.get(info, 0))
            return self.decode()
        if major == 7:  # simple/float/bool/null
            if info == 20:
                return False
            if info == 21:
                return True
            if info == 22:
                return None
            if info == 25:
                raw = self.data[self.pos:self.pos + 2]
                self.pos += 2
                return struct.unpack(">e", raw)[0] if hasattr(struct, "pack") else None
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


# ---------------------------------------------------------------------------
# WebAuthn authData 파싱 (attestationObject.authData 바이트열에서
# credentialId / COSE 공개키를 뽑아낸다 — 스펙 §6.1)
# ---------------------------------------------------------------------------
def parse_auth_data(auth_data: bytes):
    rp_id_hash = auth_data[0:32]
    flags = auth_data[32]
    counter = int.from_bytes(auth_data[33:37], "big")
    pos = 37

    at_present = bool(flags & 0x40)
    result = {
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

    # 나머지는 COSE_Key(공개키) — CBOR 맵 하나, 길이는 모르니 디코더가
    # 알아서 소비한 바이트 수를 보고한다.
    decoder = CborDecoder(auth_data[pos:])
    cose_key = decoder.decode()

    result["credentialId"] = credential_id
    result["cosePublicKey"] = cose_key
    result["aaguidB64"] = b64url_encode(aaguid)
    return result


COSE_ALG_NAMES = {-7: "ES256", -257: "RS256", -8: "EdDSA"}
COSE_CRV_NAMES = {1: "P-256", 2: "P-384", 3: "P-521"}


def describe_cose_key(cose_key: dict):
    """공개키 내용을 사람이 읽을 수 있는 요약 + base64url 원문으로 변환.
    여기엔 개인키에 해당하는 필드(-2/-3 같은 비밀 스칼라 d)가 WebAuthn
    응답 자체에 없다 — 있을 수도 없다. 그래서 이 함수가 뽑아내는 모든
    값은 구조적으로 공개 정보다."""
    kty = cose_key.get(1)
    alg = cose_key.get(3)
    out = {"kty": kty, "alg": alg, "algName": COSE_ALG_NAMES.get(alg, str(alg))}
    if kty == 2:  # EC2
        crv = cose_key.get(-1)
        x = cose_key.get(-2)
        y = cose_key.get(-3)
        out["crv"] = COSE_CRV_NAMES.get(crv, str(crv))
        out["xB64"] = b64url_encode(x) if isinstance(x, bytes) else None
        out["yB64"] = b64url_encode(y) if isinstance(y, bytes) else None
    elif kty == 3:  # RSA
        n = cose_key.get(-1)
        e = cose_key.get(-2)
        out["nB64"] = b64url_encode(n) if isinstance(n, bytes) else None
        out["eB64"] = b64url_encode(e) if isinstance(e, bytes) else None
    return out


# ---------------------------------------------------------------------------
# HTTP 핸들러
# ---------------------------------------------------------------------------
INDEX_HTML = None  # index.html을 읽어서 채운다 (아래 main에서)


def json_response(handler, status, body):
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # 콘솔 조용히

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8")), raw.decode("utf-8")

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
            creds = _load(CREDENTIALS_PATH, [])
            json_response(self, 200, {"credentials": creds})
            return

        if self.path == "/api/events":
            events = []
            if os.path.exists(LOG_PATH):
                with open(LOG_PATH, "r", encoding="utf-8") as f:
                    lines = f.readlines()[-20:]
                for line in lines:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
            events.reverse()
            json_response(self, 200, {"events": events})
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path == "/api/challenge":
            challenge_bytes = secrets.token_bytes(32)
            challenge_b64 = b64url_encode(challenge_bytes)
            store = _load(CHALLENGES_PATH, [])
            entry = {
                "challenge": challenge_b64,
                "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "used": False,
            }
            store.append(entry)
            # 메모리 사용량 방지용으로 최근 200개만 보관
            store = store[-200:]
            _save(CHALLENGES_PATH, store)
            append_log({"type": "challenge_issued", "challenge": challenge_b64})
            json_response(self, 200, {"challenge": challenge_b64})
            return

        if self.path == "/api/register":
            body, raw_text = self._read_json_body()
            append_log({"type": "register_request_received", "requestBody": body})

            challenge_b64 = body.get("challenge")
            label = (body.get("label") or "").strip()
            client_data_json_b64 = body.get("clientDataJSON")
            attestation_object_b64 = body.get("attestationObject")
            credential_id_b64 = body.get("credentialId")

            # 1) challenge가 우리가 발급해서 "미사용" 상태로 들고 있던 값인지 확인
            store = _load(CHALLENGES_PATH, [])
            match = None
            for e in store:
                if e["challenge"] == challenge_b64:
                    match = e
                    break
            if match is None:
                json_response(self, 400, {"error": "unknown_challenge"})
                return
            if match.get("used"):
                json_response(self, 400, {"error": "challenge_already_used"})
                return

            # 2) clientDataJSON 검증
            try:
                client_data_raw = b64url_decode(client_data_json_b64)
                client_data = json.loads(client_data_raw.decode("utf-8"))
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

            # 3) attestationObject(CBOR) 직접 파싱 — 공개키만 뽑아낸다
            try:
                attestation_raw = b64url_decode(attestation_object_b64)
                attestation = cbor_decode(attestation_raw)
                auth_data_bytes = attestation.get("authData")
                parsed = parse_auth_data(auth_data_bytes)
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
                "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "fmt": attestation.get("fmt"),
            }
            creds.append(record)
            _save(CREDENTIALS_PATH, creds)

            # challenge를 "사용됨"으로 표시 — 같은 challenge로 다시 등록 불가 (재사용 방지)
            for e in store:
                if e["challenge"] == challenge_b64:
                    e["used"] = True
                    e["usedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            _save(CHALLENGES_PATH, store)

            append_log({"type": "registered", "challenge": challenge_b64, "stored": record})
            json_response(self, 200, {"ok": True, "credential": record})
            return

        self.send_response(404)
        self.end_headers()


def main():
    global INDEX_HTML
    index_path = os.path.join(HERE, "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        INDEX_HTML = f.read()

    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("카드 2 로컬 패스키 서버 실행 중: http://localhost:%d" % PORT)
    print("저장 위치: %s" % HERE)
    print("종료하려면 Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
