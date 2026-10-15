import importlib.util, os, struct, secrets

spec = importlib.util.spec_from_file_location("server", os.path.join(os.path.dirname(__file__), "server.py"))
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


def cbor_encode_uint(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    elif n < 256:
        return bytes([major << 5 | 24, n])
    elif n < 65536:
        return bytes([major << 5 | 25]) + struct.pack(">H", n)
    else:
        return bytes([major << 5 | 26]) + struct.pack(">I", n)


def cbor_encode(val):
    if isinstance(val, bool):
        return b"\xf5" if val else b"\xf4"
    if isinstance(val, int):
        if val >= 0:
            return cbor_encode_uint(0, val)
        else:
            return cbor_encode_uint(1, -1 - val)
    if isinstance(val, bytes):
        return cbor_encode_uint(2, len(val)) + val
    if isinstance(val, str):
        b = val.encode("utf-8")
        return cbor_encode_uint(3, len(b)) + b
    if isinstance(val, list):
        out = cbor_encode_uint(4, len(val))
        for item in val:
            out += cbor_encode(item)
        return out
    if isinstance(val, dict):
        out = cbor_encode_uint(5, len(val))
        for k, v in val.items():
            out += cbor_encode(k)
            out += cbor_encode(v)
        return out
    raise ValueError("unsupported type")


# --- build a synthetic COSE EC2 public key (P-256) ---
fake_x = secrets.token_bytes(32)
fake_y = secrets.token_bytes(32)
cose_key = {1: 2, 3: -7, -1: 1, -2: fake_x, -3: fake_y}  # kty=EC2, alg=ES256, crv=P-256
cose_key_cbor = cbor_encode(cose_key)

# --- round-trip test of the generic decoder ---
decoded = server.cbor_decode(cose_key_cbor)
assert decoded == cose_key, "cbor round-trip mismatch: %r != %r" % (decoded, cose_key)
print("1) generic CBOR map round-trip: OK")

# --- build synthetic authData: rpIdHash(32) + flags(1) + counter(4) + aaguid(16) + credIdLen(2) + credId + COSE key ---
rp_id_hash = secrets.token_bytes(32)
flags = 0x41  # AT flag (0x40) + UP flag (0x01)
counter = struct.pack(">I", 7)
aaguid = secrets.token_bytes(16)
cred_id = secrets.token_bytes(20)
cred_id_len = struct.pack(">H", len(cred_id))

auth_data = rp_id_hash + bytes([flags]) + counter + aaguid + cred_id_len + cred_id + cose_key_cbor

parsed = server.parse_auth_data(auth_data)
assert parsed["credentialId"] == cred_id, "credentialId mismatch"
assert parsed["cosePublicKey"] == cose_key, "cose key mismatch: %r" % parsed["cosePublicKey"]
assert parsed["signCount"] == 7
print("2) parse_auth_data extraction: OK (credentialId, signCount, COSE key all match)")

desc = server.describe_cose_key(parsed["cosePublicKey"])
assert desc["kty"] == 2 and desc["algName"] == "ES256" and desc["crv"] == "P-256"
assert desc["xB64"] == server.b64url_encode(fake_x)
assert desc["yB64"] == server.b64url_encode(fake_y)
print("3) describe_cose_key: OK ->", {k: v for k, v in desc.items() if k not in ("xB64", "yB64")})

# --- build a full attestationObject (fmt + attStmt + authData) and decode it end-to-end ---
attestation_object = {"fmt": "none", "attStmt": {}, "authData": auth_data}
ao_cbor = cbor_encode(attestation_object)
decoded_ao = server.cbor_decode(ao_cbor)
assert decoded_ao["fmt"] == "none"
assert decoded_ao["authData"] == auth_data
print("4) full attestationObject round-trip: OK")

print("\nALL CBOR/authData SELF-TESTS PASSED")
print("(이 테스트는 실제 브라우저 응답이 아니라, 같은 구조를 가진 합성 데이터로")
print(" server.py의 CBOR 디코더·authData 파서 로직 자체가 올바른지만 확인한 것입니다.")
print(" 실제 기기 패스키 등록 시 진짜 공개키로 다시 한 번 확인됩니다.)")
