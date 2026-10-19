"""
카드 4 서버 로직 자체 테스트 (합성 키 사용): 패스키 여러 개, 삭제, 마지막 패스키, 설정 코드 복구.
실제 기기 패스키가 아니라 테스트용 키로 서명한 것이라 "서버 코드가 맞게 판정한다"는 확인용입니다.
실행: python test_card4.py   (cryptography 패키지 필요: pip install cryptography)
"""
import hashlib, importlib.util, json, os, re, shutil, subprocess, sys, tempfile, time, urllib.request, urllib.error
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("server", os.path.join(HERE, "server.py"))
server = importlib.util.module_from_spec(spec); spec.loader.exec_module(server)
b64e = server.b64url_encode

# ---- CBOR 인코더(테스트용): 가짜 attestationObject를 만들기 위해 ----
def enc(v):
    def hd(m, n):
        if n < 24: return bytes([m << 5 | n])
        if n < 256: return bytes([m << 5 | 24, n])
        return bytes([m << 5 | 25]) + n.to_bytes(2, "big")
    if isinstance(v, int): return hd(0, v) if v >= 0 else hd(1, -1 - v)
    if isinstance(v, bytes): return hd(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return hd(3, len(b)) + b
    if isinstance(v, dict): return hd(5, len(v)) + b"".join(enc(k) + enc(x) for k, x in v.items())
    raise ValueError

PORT = 8798
tmp = tempfile.mkdtemp(prefix="pk4_")
src = open(os.path.join(HERE, "server.py"), encoding="utf-8").read().replace("PORT = 8787", "PORT = %d" % PORT)
open(os.path.join(tmp, "server.py"), "w", encoding="utf-8").write(src)
shutil.copy(os.path.join(HERE, "index.html"), os.path.join(tmp, "index.html"))

class Key:
    def __init__(self, label):
        self.label = label
        self.priv = ec.generate_private_key(ec.SECP256R1())
        n = self.priv.public_key().public_numbers()
        self.x, self.y = n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")
        self.cid = os.urandom(32)
        self.count = 0
    def sign_login(self, challenge):
        cd = json.dumps({"type": "webauthn.get", "challenge": challenge,
                         "origin": "http://localhost:%d" % PORT, "crossOrigin": False}).encode()
        self.count += 1
        auth = hashlib.sha256(b"localhost").digest() + bytes([0x01]) + self.count.to_bytes(4, "big")
        sig = self.priv.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"challenge": challenge, "credentialId": b64e(self.cid), "clientDataJSON": b64e(cd),
                "authenticatorData": b64e(auth), "signature": b64e(sig)}
    def register_body(self, challenge):
        cd = json.dumps({"type": "webauthn.create", "challenge": challenge,
                         "origin": "http://localhost:%d" % PORT, "crossOrigin": False}).encode()
        cose = enc({1: 2, 3: -7, -1: 1, -2: self.x, -3: self.y})
        auth = (hashlib.sha256(b"localhost").digest() + bytes([0x41]) + (0).to_bytes(4, "big") +
                os.urandom(16) + len(self.cid).to_bytes(2, "big") + self.cid + cose)
        return {"challenge": challenge, "label": self.label, "credentialId": b64e(self.cid),
                "clientDataJSON": b64e(cd),
                "attestationObject": b64e(enc({"fmt": "none", "attStmt": {}, "authData": auth}))}

env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
proc = subprocess.Popen([sys.executable, os.path.join(tmp, "server.py")], stdout=subprocess.PIPE, env=env)
time.sleep(1.5)
BASE = "http://127.0.0.1:%d" % PORT

def call(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None)
    if body is not None: req.add_header("Content-Type", "application/json")
    if token: req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req) as r: return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read().decode() or "{}")

def login(key):
    st, c = call("POST", "/api/login/challenge")
    assert st == 200, (st, c)
    return call("POST", "/api/login/verify", key.sign_login(c["challenge"]))

def add(key, token=None, setup=None):
    st, c = call("POST", "/api/challenge", {"setupCode": setup} if setup is not None else {}, token)
    if st != 200: return st, c, None
    st2, r = call("POST", "/api/register", key.register_body(c["challenge"]), token)
    return st2, r, c

try:
    out = proc.stdout.readline().decode() + proc.stdout.readline().decode() + proc.stdout.readline().decode()
    code = re.search(r"([A-Z0-9]{4}-[A-Z0-9]{4})", out).group(1)
    print("0) 서버 콘솔에 설정 코드가 표시됨:", code)

    a, b = Key("폰"), Key("노트북")

    # 패스키가 없을 때
    assert call("GET", "/api/status")[1]["passkeyCount"] == 0
    st, r = call("POST", "/api/login/challenge"); assert st == 400 and r["error"] == "no_credentials_registered"
    print("1) 패스키 0개: 로그인 질문 자체가 안 만들어짐(400) OK")
    st, r, _ = add(a, setup="WRONG-CODE"); assert st == 401 and r["error"] == "bad_setup_code"
    st, r, _ = add(a); assert st == 401
    print("2) 설정 코드 없음/틀림 -> 첫 패스키 등록 거절(401) OK")
    st, r, _ = add(a, setup=code); assert st == 200, r
    print("3) 올바른 설정 코드 -> 첫 패스키(폰) 등록 OK")

    # 로그인 필요 규칙
    st, r = call("POST", "/api/challenge", {}); assert st == 401
    st, r = call("GET", "/api/credentials"); assert st == 401
    print("4) 로그인 없이: 패스키 추가 질문 401, 목록 보기 401 OK")

    st, ok = login(a); assert st == 200; tok_a = ok["token"]
    # 두 번째 패스키 + excludeCredentials
    st, c = call("POST", "/api/challenge", {}, tok_a)
    assert st == 200 and c["excludeCredentials"] == [b64e(a.cid)]
    st, r = call("POST", "/api/register", b.register_body(c["challenge"]), tok_a); assert st == 200, r
    st, lst = call("GET", "/api/credentials", token=tok_a)
    assert [x["label"] for x in lst["credentials"]] == ["폰", "노트북"]
    assert all(x["createdAt"] for x in lst["credentials"])
    assert lst["currentCredentialId"] == b64e(a.cid)
    print("5) 로그인 후 두 번째 패스키(노트북) 추가: excludeCredentials에 폰 포함, 목록에 이름·등록일 2개 OK")

    # 두 패스키 모두 로그인 가능
    st, ok_b = login(b); assert st == 200; tok_b = ok_b["token"]
    print("6) 두 패스키 모두 각각 로그인 성공 OK")

    # 하나 지우기 -> 남은 것으로 로그인, 지운 것으로 거절
    st, r = call("POST", "/api/credentials/delete", {"credentialId": b64e(b.cid)}); assert st == 401
    st, r = call("POST", "/api/credentials/delete", {"credentialId": b64e(b.cid)}, tok_a)
    assert st == 200 and r["remaining"] == 1 and r["sessionsRevoked"] == 1 and r["loggedOut"] is False
    assert call("GET", "/api/private", token=tok_b)[0] == 401      # 지운 패스키로 연 세션도 끊김
    assert call("GET", "/api/private", token=tok_a)[0] == 200      # 남은 패스키 세션은 유지
    print("7) 삭제: 로그인 없이는 401, 로그인 후 삭제 성공, 지운 패스키로 열었던 세션 끊김 OK")
    st, r = login(b); assert st == 401 and r["error"] == "unknown_credential"
    print("8) 지운 패스키(노트북)로 로그인 -> 401 unknown_credential OK:", r["message"])
    st, ok = login(a); assert st == 200
    print("9) 남은 패스키(폰)로 로그인 -> 성공 OK")
    tok_a = ok["token"]

    # 마지막 패스키
    st, r = call("POST", "/api/credentials/delete", {"credentialId": b64e(a.cid)}, tok_a)
    assert st == 409 and r["error"] == "last_passkey"
    st, r = call("POST", "/api/credentials/delete", {"credentialId": b64e(a.cid), "confirmLast": True}, tok_a)
    assert st == 200 and r["remaining"] == 0 and r["loggedOut"] is True
    assert call("GET", "/api/private", token=tok_a)[0] == 401
    assert call("GET", "/api/status")[1]["passkeyCount"] == 0
    st, r = call("POST", "/api/login/challenge"); assert st == 400
    print("10) 마지막 패스키: 확인 없이 삭제 409, 확인 후 삭제 -> 세션 전부 끊김, 로그인 불가(400) OK")

    # 복구: 설정 코드
    c2 = Key("복구한 폰")
    st, r, _ = add(c2, setup=code); assert st == 200
    st, ok = login(c2); assert st == 200
    print("11) 설정 코드로 새 패스키 등록 -> 다시 로그인 OK")

    # 설정 코드 5회 실패 잠금
    call("POST", "/api/credentials/delete", {"credentialId": b64e(c2.cid), "confirmLast": True}, ok["token"])
    for i in range(5):
        st, r = call("POST", "/api/challenge", {"setupCode": "AAAA-%04d" % i}); assert st == 401
    st, r = call("POST", "/api/challenge", {"setupCode": code}); assert st == 429 and r["error"] == "setup_code_locked"
    print("12) 설정 코드 5번 틀리면 잠김(429), 그 뒤엔 맞는 코드도 거절 OK")

    # 기록/파일에 토큰·설정 코드 원문 없음
    for name in ("sessions.json", "request_log.jsonl", "credentials.json", "challenges.json"):
        txt = open(os.path.join(tmp, name), encoding="utf-8").read() if os.path.exists(os.path.join(tmp, name)) else ""
        for secret in (tok_a, tok_b, ok_b["token"], ok["token"], code):
            assert secret not in txt, (name, secret[:4])
    print("13) 파일·기록 어디에도 세션 토큰/설정 코드 원문 없음 OK")

    print("\nALL CARD-4 SELF-TESTS PASSED")
finally:
    proc.terminate()
    shutil.rmtree(tmp, ignore_errors=True)
