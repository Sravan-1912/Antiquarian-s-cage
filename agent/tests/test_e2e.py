"""Unit tests for the end-to-end (zero-knowledge relay) encryption core.

These exercise the full handshake + framed AEAD without any sockets: the operator (initiator) and endpoint (responder)
derive matching keys, encrypt both directions, and every tampering / impersonation path fails closed.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from cage_agent.remote import e2e


def _device_keypair():
    """Mimic the endpoint's ECDSA P-256 device key and the operator's verifier."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()

    def sign(msg: bytes) -> bytes:
        return priv.sign(msg, ec.ECDSA(hashes.SHA256()))

    def verify(msg: bytes, sig: bytes) -> bool:
        try:
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    return sign, verify


def _handshake():
    sign, verify = _device_keypair()
    eph, hello = e2e.initiate()                       # operator step 1
    auth, endpoint = e2e.respond(hello, sign)         # endpoint
    operator = e2e.complete_initiator(eph, hello, auth, verify)  # operator step 2
    return operator, endpoint


def test_handshake_and_bidirectional_traffic():
    operator, endpoint = _handshake()
    # operator -> endpoint
    for msg in (b"", b"mstsc hello", b"\x00\x01\x02" * 5000):
        assert endpoint.open(operator.seal(msg)) == msg
    # endpoint -> operator
    for msg in (b"screen frame", bytes(range(256)) * 40):
        assert operator.open(endpoint.seal(msg)) == msg


def test_relay_sees_only_ciphertext():
    operator, _ = _handshake()
    plaintext = b"secret RDP bytes"
    ct = operator.seal(plaintext)
    assert plaintext not in ct and len(ct) > len(plaintext)  # AEAD tag + no plaintext leak


def test_tampered_frame_is_rejected():
    operator, endpoint = _handshake()
    ct = bytearray(operator.seal(b"important"))
    ct[-1] ^= 0x01  # flip a tag bit
    with pytest.raises(e2e.E2EError):
        endpoint.open(bytes(ct))


def test_forged_endpoint_signature_is_rejected():
    # A relay-in-the-middle substitutes its own ephemeral key + a signature from the WRONG device key.
    _, verify_real = _device_keypair()
    attacker_sign, _ = _device_keypair()
    eph, hello = e2e.initiate()
    forged_auth, _ = e2e.respond(hello, attacker_sign)
    with pytest.raises(e2e.E2EError, match="signature invalid"):
        e2e.complete_initiator(eph, hello, forged_auth, verify_real)


def test_out_of_order_frames_fail_closed():
    operator, endpoint = _handshake()
    f0 = operator.seal(b"zero")
    f1 = operator.seal(b"one")
    endpoint.open(f0)
    with pytest.raises(e2e.E2EError):   # counter is now 1; replaying f0 (nonce 0) fails
        endpoint.open(f0)
    assert endpoint.open(f1) == b"one"  # correct next frame still opens


def test_independent_sessions_have_independent_keys():
    op1, ep1 = _handshake()
    op2, ep2 = _handshake()
    sealed = op1.seal(b"cross")
    with pytest.raises(e2e.E2EError):   # a different session cannot open it
        ep2.open(sealed)
    assert ep1.open(sealed) == b"cross"
