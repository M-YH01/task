"""
카드 3 서버 로직 자체 테스트 (합성 키 사용).
- server.py의 ES256 직접 검증 함수가 표준 라이브러리(cryptography)와 같은 판정을 내리는지
- 임시 폴더에서 서버를 띄우고 성공/실패/재사용/로그아웃 시나리오가 의도대로 동작하는지
실제 기기 패스키가 아니라 테스트용으로 만든 키로 서명한 것이므로, "서버 코드가 맞게 판정한다"는
확인용입니다. 실제 패스키 로그인은 브라우저에서 따로 확인합니다.
실행: python test_login.py   (cryptography 패키지가 있어야 함: pip install cryptography)
"""
import hashlib, importlib.util, json, os, shutil, subprocess, sys, tempfile, time, urllib.request, urllib.error

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))

spec = importlib.util.spec_from_file_location("server", os.path.join(HERE, "server.py"))
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)
b64e, b64d = server.b64url_encode, server.b64url_decode

# ---------- 1) ES256 직접 검증 vs cryptography ----------
for i in range(15):
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    msg = os.urandom(50)
    sig = key.sign(msg, ec.ECDSA(hashes.SHA256()))
    assert server.ecdsa_p256_verify(nums.x, nums.y, msg, sig) is True
    assert server.ecdsa_p256_verify(nums.x, nums.y, msg + b"x", sig) is False          # 메시지 변조
    bad = bytearray(sig); bad[-1] ^= 1
    assert server.ecdsa_p256_verify(nums.x, nums.y, msg, bytes(bad)) is False           # 서명 변조
    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    assert server.ecdsa_p256_verify(other.x, other.y, msg, sig) is False                # 다른 사람 공개키
print("1) ES256 직접 검증: 15쌍 모두 cryptography 판정과 일치 (올바른 서명 통과, 변조/다른 키 거절) OK")

# ---------- 2) 서버 end-to-end ----------
PORT = 8799
tmp = tempfile.mkdtemp(prefix="pk_test_")
src = open(os.path.join(HERE, "server.py"), encoding="utf-8").read().replace("PORT = 8787", "PORT = %d" % PORT)
open(os.path.join(tmp, "server.py"), "w", encoding="utf-8").write(src)
shutil.copy(os.path.join(HERE, "index.html"), os.path.join(tmp, "index.html"))

priv = ec.generate_private_key(ec.SECP256R1())
nums = priv.public_key().public_numbers()
cred_id = b64e(os.urandom(32))
json.dump([{
    "credentialId": cred_id, "label": "테스트키", "algorithm": "ES256",
    "publicKey": {"kty": 2, "alg": -7, "algName": "ES256", "crv": "P-256",
                  "xB64": b64e(nums.x.to_bytes(32, "big")), "yB64": b64e(nums.y.to_bytes(32, "big"))},
    "signCount": 1, "createdAt": "2026-01-01T00:00:00Z", "fmt": "none"}],
    open(os.path.join(tmp, "credentials.json"), "w"))

proc = subprocess.Popen([sys.executable, os.path.join(tmp, "server.py")], stdout=subprocess.DEVNULL)
time.sleep(1.2)
BASE = "http://127.0.0.1:%d" % PORT


def call(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


counter = [1]


def make_assertion(challenge, tamper=False, count=None, kind="webauthn.get"):
    cd = json.dumps({"type": kind, "challenge": challenge, "origin": "http://localhost:%d" % PORT,
                     "crossOrigin": False}).encode()
    if count is None:
        counter[0] += 1
        count = counter[0]
    auth = hashlib.sha256(b"localhost").digest() + bytes([0x01]) + count.to_bytes(4, "big")
    sig = priv.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
    if tamper:
        sig = sig[:-1] + bytes([sig[-1] ^ 1])
    return {"challenge": challenge, "credentialId": cred_id, "clientDataJSON": b64e(cd),
            "authenticatorData": b64e(auth), "signature": b64e(sig)}


try:
    # C27/C28: 매번 다른 질문
    cs = []
    for _ in range(3):
        st, r = call("POST", "/api/login/challenge")
        assert st == 200
        cs.append(r["challenge"])
    assert len(set(cs)) == 3
    print("2-a) 로그인 질문 3번 요청 -> 값 3개 모두 다름 OK")

    # C29/C30: 성공 / 실패 나란히
    st, ok = call("POST", "/api/login/verify", make_assertion(cs[0]))
    assert st == 200 and ok["ok"] and ok["token"]
    token = ok["token"]
    print("2-b) 올바른 서명 -> 200, 세션 토큰 발급 OK")
    st, bad = call("POST", "/api/login/verify", make_assertion(cs[1], tamper=True))
    assert st == 401 and bad["error"] == "bad_signature"
    print("2-c) 틀린 서명 -> 401 bad_signature OK")

    # C31: 이미 쓴 질문 재사용 (성공에 쓴 것 / 실패에 쓴 것 둘 다)
    st, rep = call("POST", "/api/login/verify", make_assertion(cs[0]))
    assert st == 401 and rep["error"] == "challenge_already_used"
    st, rep2 = call("POST", "/api/login/verify", make_assertion(cs[1]))
    assert st == 401 and rep2["error"] == "challenge_already_used"
    print("2-d) 이미 쓴 질문 재사용 -> 401 challenge_already_used (성공에 쓴 질문도, 실패에 쓴 질문도) OK")

    # 등록용 질문을 로그인에 쓰기 / 모르는 질문
    st, rc = call("POST", "/api/challenge")
    st, r = call("POST", "/api/login/verify", make_assertion(rc["challenge"]))
    assert st == 401 and r["error"] == "wrong_challenge_purpose"
    st, r = call("POST", "/api/login/verify", make_assertion(b64e(os.urandom(32))))
    assert st == 401 and r["error"] == "unknown_challenge"
    print("2-e) 등록용 질문/서버가 모르는 질문으로 로그인 -> 401 OK")

    # signCount 후퇴
    st, c = call("POST", "/api/login/challenge")
    st, r = call("POST", "/api/login/verify", make_assertion(c["challenge"], count=1))
    assert st == 401 and r["error"] == "sign_count_not_increasing"
    print("2-f) signCount가 늘지 않는 요청(복제 의심) -> 401 OK")

    # 만료
    st, c = call("POST", "/api/login/challenge")
    ch = json.load(open(os.path.join(tmp, "challenges.json")))
    for e in ch:
        if e["challenge"] == c["challenge"]:
            e["createdEpoch"] -= 1000
    json.dump(ch, open(os.path.join(tmp, "challenges.json"), "w"))
    st, r = call("POST", "/api/login/verify", make_assertion(c["challenge"]))
    assert st == 401 and r["error"] == "challenge_expired"
    print("2-g) 120초 지난 질문 -> 401 challenge_expired OK")

    # 비공개 자리
    st, r = call("GET", "/api/private")
    assert st == 401
    st, r = call("GET", "/api/private", token="x" * 43)
    assert st == 401
    st, r = call("GET", "/api/private", token=token)
    assert st == 200 and len(r["items"]) == 3
    print("2-h) /api/private: 토큰 없음 401, 엉터리 토큰 401, 올바른 토큰 200(항목 3건) OK")

    # 로그아웃 후 같은 값
    st, r = call("POST", "/api/logout", token=token)
    assert st == 200 and r["sessionRemoved"] is True
    st, r = call("GET", "/api/private", token=token)
    assert st == 401
    print("2-i) 로그아웃 후 같은 토큰으로 /api/private -> 401 OK")

    # C34: 파일/로그에 토큰 원문이 없는지
    for name in ("sessions.json", "request_log.jsonl"):
        assert token not in open(os.path.join(tmp, name), encoding="utf-8").read(), name
    print("2-j) sessions.json / request_log.jsonl 어디에도 토큰 원문 없음 OK")

    # 공개 페이지 소스에 비공개 내용이 없는지
    page = urllib.request.urlopen(BASE + "/").read().decode()
    for item in server.PRIVATE_ITEMS:
        assert item["body"] not in page and item["title"] not in page
    assert 'type="password"' not in page and "type='password'" not in page
    print("2-k) 로그인 전 페이지 소스에 비공개 내용 없음, 비밀번호 입력칸 없음 OK")

    print("\nALL CARD-3 SELF-TESTS PASSED")
finally:
    proc.terminate()
    shutil.rmtree(tmp, ignore_errors=True)
