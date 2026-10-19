"""
카드 5 서버 자체 테스트 (합성 키 사용, 임시 폴더에서 서버를 따로 띄움).
계정 두 개 / 서로의 자료 차단 / 남의 패스키 / 질문 재사용 / 삭제 뒤 로그인 / 등록(설정 코드) 등을 확인합니다.
실제 기기 패스키가 아니라 테스트용 키이므로 "서버 코드가 맞게 판정한다"는 확인용입니다.
실행: python test_all.py   (cryptography 필요: pip install cryptography)
"""
import hashlib, importlib.util, json, os, re, shutil, struct, subprocess, sys, tempfile, time, threading
import urllib.request, urllib.error

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("server", os.path.join(HERE, "server.py"))
server = importlib.util.module_from_spec(spec); spec.loader.exec_module(server)
b64e = server.b64url_encode

# ---- 1) ES256 직접 검증 vs cryptography ----
for _ in range(10):
    k = ec.generate_private_key(ec.SECP256R1()); n = k.public_key().public_numbers(); m = os.urandom(40)
    s = k.sign(m, ec.ECDSA(hashes.SHA256()))
    assert server.ecdsa_p256_verify(n.x, n.y, m, s) is True
    assert server.ecdsa_p256_verify(n.x, n.y, m + b"x", s) is False
    o = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    assert server.ecdsa_p256_verify(o.x, o.y, m, s) is False
print("1) ES256 직접 검증이 cryptography 판정과 일치 OK")

PORT = 8798
tmp = tempfile.mkdtemp(prefix="pk5_")
src = open(os.path.join(HERE, "server.py"), encoding="utf-8").read().replace("PORT = 8787", "PORT = %d" % PORT)
open(os.path.join(tmp, "server.py"), "w", encoding="utf-8").write(src)
for f in ("intro.html", "private.html"):
    shutil.copy(os.path.join(HERE, f), os.path.join(tmp, f))
proc = subprocess.Popen([sys.executable, "-u", os.path.join(tmp, "server.py")], stdout=subprocess.PIPE, text=True)
setup_code = None
for _ in range(20):
    line = proc.stdout.readline()
    m = re.search(r"설정 코드.*: ([A-Z0-9]{4}-[A-Z0-9]{4})", line)
    if m:
        setup_code = m.group(1); break
assert setup_code, "설정 코드를 못 읽음"
time.sleep(0.4)
BASE = "http://127.0.0.1:%d" % PORT


def call(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None)
    if body is not None: req.add_header("Content-Type", "application/json")
    if token: req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.startswith("{") else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, (json.loads(raw) if raw.startswith("{") else raw)


# ---- 합성 인증기 ----
def cbor_uint(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    return bytes([major << 5 | 25]) + struct.pack(">H", n)
def cbor(v):
    if isinstance(v, int): return cbor_uint(0, v) if v >= 0 else cbor_uint(1, -1 - v)
    if isinstance(v, bytes): return cbor_uint(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return cbor_uint(3, len(b)) + b
    if isinstance(v, dict): return cbor_uint(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise ValueError


class Auth:
    def __init__(self):
        self.priv = ec.generate_private_key(ec.SECP256R1()); self.cid = b64e(os.urandom(32)); self.count = 0
    def attestation(self, challenge):
        n = self.priv.public_key().public_numbers()
        cose = cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
        cid = server.b64url_decode(self.cid)
        auth = hashlib.sha256(b"localhost").digest() + bytes([0x45]) + (0).to_bytes(4, "big") + os.urandom(16) + len(cid).to_bytes(2, "big") + cid + cose
        cd = json.dumps({"type": "webauthn.create", "challenge": challenge, "origin": "http://localhost:%d" % PORT}).encode()
        return {"challenge": challenge, "credentialId": self.cid, "clientDataJSON": b64e(cd),
                "attestationObject": b64e(cbor({"fmt": "none", "attStmt": {}, "authData": auth}))}
    def assertion(self, challenge, tamper=False):
        self.count += 1
        cd = json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": "http://localhost:%d" % PORT}).encode()
        auth = hashlib.sha256(b"localhost").digest() + bytes([0x01]) + self.count.to_bytes(4, "big")
        sig = self.priv.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        if tamper: sig = sig[:-1] + bytes([sig[-1] ^ 1])
        return {"challenge": challenge, "credentialId": self.cid, "clientDataJSON": b64e(cd),
                "authenticatorData": b64e(auth), "signature": b64e(sig)}


def register(acct, auth, label, token=None, code=None):
    body = {"accountId": acct}
    if code: body["setupCode"] = code
    st, ch = call("POST", "/api/challenge", body, token)
    if st != 200: return st, ch
    return call("POST", "/api/register", dict(auth.attestation(ch["challenge"]), label=label), token)


def login(acct, auth, tamper=False):
    st, ch = call("POST", "/api/login/challenge", {"accountId": acct})
    assert st == 200, (st, ch)
    body = auth.assertion(ch["challenge"], tamper)
    return call("POST", "/api/login/verify", body), body


try:
    # ---- 2) 공개 페이지 ----
    st, intro = call("GET", "/")
    assert st == 200 and "나를 소개합니다" in intro and "나의 강점 3가지" in intro and "고메스퀘어" in intro
    assert "fetch(" not in intro and "/api/" not in intro          # 공개 페이지는 서버 API를 부르지 않는다
    st, priv_page = call("GET", "/private")
    assert st == 200
    for acct_items in server.SEED_PRIVATE.values():
        for it in acct_items:
            assert it["body"] not in intro and it["body"] not in priv_page and it["title"] not in intro
    assert 'type="password"' not in priv_page and "type='password'" not in priv_page
    print("2) 공개 소개 페이지는 로그인 없이 열림(1번 내용 그대로), API 호출 없음, 비공개 내용은 두 페이지 소스 어디에도 없음 OK")

    # ---- 3) 비공개 자리는 로그인 없이 안 열림 ----
    assert call("GET", "/api/private")[0] == 401
    assert call("GET", "/api/private", token="x" * 43)[0] == 401
    assert call("GET", "/api/accounts/a2/private")[0] == 401
    assert call("GET", "/api/credentials")[0] == 401
    print("3) 토큰 없음/엉터리 토큰으로 /api/private, 상대 계정 주소, 패스키 목록 -> 모두 401 OK")

    # ---- 4) 등록: 설정 코드, 계정 두 개 ----
    A, B = Auth(), Auth()
    st, r = call("POST", "/api/challenge", {"accountId": "a1"})
    assert st == 401 and r["error"] == "bad_setup_code"
    st, r = call("POST", "/api/challenge", {"accountId": "zzz"}); assert st == 404
    st, r = register("a1", A, "가온 노트북", code=setup_code); assert st == 200, r
    st, r = register("a2", B, "나래 노트북", code=setup_code); assert st == 200, r
    creds = json.load(open(os.path.join(tmp, "credentials.json")))
    assert {c["accountId"] for c in creds} == {"a1", "a2"} and len(creds) == 2
    assert "priv" not in json.dumps(creds).lower()
    print("4) 설정 코드로 계정 두 개에 각자 패스키 등록(공개키만 저장, accountId 기록) OK")

    # ---- 5) 로그인 + 각자 자기 자료 ----
    (st, la), bodyA = login("a1", A); assert st == 200 and la["accountId"] == "a1"
    (st, lb), bodyB = login("a2", B); assert st == 200 and lb["accountId"] == "a2"
    tA, tB = la["token"], lb["token"]
    st, ra = call("GET", "/api/private", token=tA); st2, rb = call("GET", "/api/private", token=tB)
    assert st == 200 and st2 == 200 and ra["accountId"] == "a1" and rb["accountId"] == "a2"
    titlesA = {i["title"] for i in ra["items"]}; titlesB = {i["title"] for i in rb["items"]}
    assert len(ra["items"]) == 3 and len(rb["items"]) == 4 and not (titlesA & titlesB)
    print("5) 각자 로그인 -> 가온 3건 / 나래 4건, 서로 다른 내용 OK")

    # ---- 6) 남의 패스키 (서명은 진짜인데 계정이 다름) ----
    (st, r), _ = login("a2", A)       # 나래용 질문에 가온의 패스키
    assert st == 401 and r["error"] == "credential_not_for_this_account", r
    (st, r), _ = login("a1", B)       # 가온용 질문에 나래의 패스키
    assert st == 401 and r["error"] == "credential_not_for_this_account", r
    print("6) 남의 패스키(서명은 유효) -> 401 credential_not_for_this_account, 양방향 OK")

    # ---- 7) 남의 자료 주소 직접 요청, 전후 개수 ----
    nB = len(call("GET", "/api/private", token=tB)[1]["items"]); nA = len(call("GET", "/api/private", token=tA)[1]["items"])
    st, r = call("GET", "/api/accounts/a2/private", token=tA)
    assert st == 403 and r["error"] == "forbidden_other_account" and r["targetCountBefore"] == r["targetCountAfter"] == 4
    st, r = call("GET", "/api/accounts/a1/private", token=tB)
    assert st == 403 and r["targetCountBefore"] == r["targetCountAfter"] == 3
    assert "items" not in r
    assert len(call("GET", "/api/private", token=tB)[1]["items"]) == nB == 4 and len(call("GET", "/api/private", token=tA)[1]["items"]) == nA == 3
    st, r = call("GET", "/api/accounts/a1/private", token=tA); assert st == 200 and len(r["items"]) == 3
    assert call("GET", "/api/accounts/nope/private", token=tA)[0] == 404
    print("7) 가온->나래, 나래->가온 자료 주소 직접 요청 -> 403, 거절 전후 개수 동일(4/3), 자기 주소는 200 OK")

    # ---- 8) 주소·본문에 다른 계정을 적어도 내 자료만 ----
    st, r = call("GET", "/api/private?account=a2", token=tA); assert st == 200 and r["accountId"] == "a1" and len(r["items"]) == 3
    st, r = call("GET", "/api/private?accountId=a2", token=tA); assert st == 200 and r["accountId"] == "a1"
    st, r = call("POST", "/api/private", {"accountId": "a2"}, tA); assert st == 200 and r["accountId"] == "a1" and len(r["items"]) == 3
    st, r = call("POST", "/api/challenge", {"accountId": "a2"}, tA); assert st == 403 and r["error"] == "forbidden_other_account"
    print("8) 주소(?account=a2)·본문(accountId=a2)에 남의 계정을 적어도 가온 자료만 돌려줌, 남의 계정에 패스키 추가 질문은 403 OK")

    # ---- 9) 남의 패스키 목록/삭제 ----
    st, r = call("GET", "/api/credentials", token=tA); assert st == 200 and len(r["credentials"]) == 1 and r["credentials"][0]["accountId"] == "a1"
    st, r = call("POST", "/api/credentials/delete", {"credentialId": B.cid, "confirmLast": True}, tA)
    assert st == 403 and r["error"] == "forbidden_other_account"
    assert len(json.load(open(os.path.join(tmp, "credentials.json")))) == 2
    print("9) 내 목록에는 내 패스키만, 남의 패스키 삭제 요청 -> 403 이고 서버 패스키 수 그대로 OK")

    # ---- 10) 질문 재사용 ----
    st, r = call("POST", "/api/login/verify", bodyA); assert st == 401 and r["error"] == "challenge_already_used"
    (st, r), bad = login("a1", A, tamper=True); assert st == 401 and r["error"] == "bad_signature"
    st, r = call("POST", "/api/login/verify", bad); assert st == 401 and r["error"] == "challenge_already_used"
    print("10) 이미 쓴 질문 재사용 -> 401 challenge_already_used (성공/실패에 쓴 질문 모두) OK")

    # ---- 11) 등록 질문 만료 ----
    st, ch = call("POST", "/api/challenge", {"accountId": "a1"}, tA); assert st == 200 and ch["ttlSeconds"] == 120
    chs = json.load(open(os.path.join(tmp, "challenges.json")))
    for e in chs:
        if e["challenge"] == ch["challenge"]: e["createdEpoch"] -= 1000
    json.dump(chs, open(os.path.join(tmp, "challenges.json"), "w"))
    A2 = Auth()
    st, r = call("POST", "/api/register", dict(A2.attestation(ch["challenge"]), label="늦은 등록"), tA)
    assert st == 400 and r["error"] == "challenge_expired"
    print("11) 120초 지난 등록 질문 -> 400 challenge_expired OK")

    # ---- 12) 패스키 두 개 → 하나 지우고 그 패스키로 로그인 ----
    st, r = register("a1", A2, "가온 휴대폰", token=tA); assert st == 200, r
    st, r = call("POST", "/api/credentials/delete", {"credentialId": A.cid}, tA)
    assert st == 200 and r["remaining"] == 1 and r["loggedOut"] is True      # tA는 A로 연 세션이므로 끊김
    assert call("GET", "/api/private", token=tA)[0] == 401
    assert call("GET", "/api/private", token=tB)[0] == 200                   # 나래 세션은 영향 없음
    (st, r), _ = login("a1", A); assert st == 401 and r["error"] == "unknown_credential"
    (st, la2), _ = login("a1", A2); assert st == 200
    print("12) 지운 패스키 로그인 -> 401 unknown_credential, 옛 세션 401, 다른 계정 세션은 유지, 남은 패스키로 로그인 OK")

    # ---- 13) 마지막 패스키 ----
    t = la2["token"]
    st, r = call("POST", "/api/credentials/delete", {"credentialId": A2.cid}, t); assert st == 409 and r["error"] == "last_passkey"
    st, r = call("POST", "/api/credentials/delete", {"credentialId": A2.cid, "confirmLast": True}, t)
    assert st == 200 and r["remaining"] == 0 and r["loggedOut"] is True
    st, r = call("POST", "/api/login/challenge", {"accountId": "a1"}); assert st == 400 and r["error"] == "no_credentials_registered"
    assert call("GET", "/api/private", token=tB)[0] == 200
    print("13) 마지막 패스키: 확인 없이 409, 확인 후 삭제되면 그 계정 로그인 질문 자체가 거절(400) OK")

    # ---- 14) 파일에 토큰 원문 없음 / 설정 코드 잠금 / 증거 저장 ----
    for name in ("sessions.json", "request_log.jsonl"):
        txt = open(os.path.join(tmp, name), encoding="utf-8").read()
        for tok in (tA, tB, t): assert tok not in txt, name
    for _ in range(5): call("POST", "/api/challenge", {"accountId": "a1", "setupCode": "WRONG-000"})
    st, r = call("POST", "/api/challenge", {"accountId": "a1", "setupCode": setup_code}); assert st == 429
    st, r = call("POST", "/api/evidence", {"name": "t", "pairs": [{"a": 1}]}); assert st == 200
    assert os.path.exists(os.path.join(tmp, "evidence_checks.jsonl"))
    print("14) 토큰 원문은 sessions.json/request_log에 없음, 설정 코드 5번 틀리면 429 잠금, 증거 저장 OK")

    log = [json.loads(l) for l in open(os.path.join(tmp, "request_log.jsonl"), encoding="utf-8")]
    assert any(e.get("type") == "cross_account_denied" and e.get("targetCountBefore") == e.get("targetCountAfter") for e in log)
    print("\nALL CARD-5 SELF-TESTS PASSED")
finally:
    proc.terminate()
    shutil.rmtree(tmp, ignore_errors=True)
