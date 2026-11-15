from app.security import crypto


def test_aes_gcm_roundtrip_and_binding():
    ct = crypto.encrypt("secret-value", "row-1")
    assert crypto.decrypt(ct, "row-1") == "secret-value"
    try:
        crypto.decrypt(ct, "row-2")
    except Exception:
        pass
    else:
        raise AssertionError("ciphertext must be bound to associated data")
