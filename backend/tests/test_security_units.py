import time

import pyotp

from app.security import crypto, totp
from app.security.passwords import hash_password, password_problems, verify_password


def test_argon2id_hash_and_verify():
    h = hash_password("Some-Strong-Pass-42")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "Some-Strong-Pass-42")
    assert not verify_password(h, "wrong")
    assert not verify_password(None, "anything")


def test_password_policy():
    assert password_problems("Correct-Horse-Battery-9") == []
    assert password_problems("short")
    assert password_problems("alllowercaseletters")  # one character class
    assert password_problems("Password123!")  # common base word
    assert password_problems("Johnathan-Smith-99", full_name="Johnathan Smith")
    assert password_problems("Alice.Example-2026", email="alice.example@example.com")


def test_aes_gcm_roundtrip_and_binding():
    ct = crypto.encrypt("secret-value", "row-1")
    assert crypto.decrypt(ct, "row-1") == "secret-value"
    try:
        crypto.decrypt(ct, "row-2")
    except Exception:
        pass
    else:
        raise AssertionError("ciphertext must be bound to associated data")


def test_totp_replay_protection():
    secret = totp.new_secret()
    code = pyotp.TOTP(secret).now()
    step = totp.verify(secret, code, None)
    assert step is not None
    assert totp.verify(secret, code, step) is None  # same code cannot be replayed
    assert totp.verify(secret, "000000" if code != "000000" else "111111", None) is None
    assert totp.verify(secret, "abc", None) is None
    assert step >= int(time.time()) // 30 - 1
