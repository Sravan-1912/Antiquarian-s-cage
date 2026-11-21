"""End-to-end encryption for the remote-session relay (zero-knowledge relay).

The backend relay copies bytes between the operator and the endpoint; with this layer it only ever sees **ciphertext**.
The two ends run an authenticated X25519 handshake *through* the relay, derive per-direction ChaCha20-Poly1305 keys, and
AEAD-seal every RDP/shell chunk. A passive or honest-but-curious backend (logs, memory, a breach beyond TLS) cannot read
or tamper with the session.

Roles: the **operator is the initiator**, the **endpoint is the responder**. The responder signs its ephemeral key with
the endpoint's **device key** (ECDSA P-256), so the initiator knows it is talking to the real endpoint and not a relay
that substituted its own key. (A fully-compromised backend that *also* substitutes the endpoint's device identity is out
of scope — that needs out-of-band key pinning; documented in SECURITY.md.)

Wire format (each message is length-prefixed by the transport in rdp.py):
    initiator → responder   HELLO = epk_o(32)
    responder → initiator   AUTH  = epk_e(32) || sig_len(2 BE) || sig(DER ECDSA over PROTO||epk_o||epk_e)
    both directions         FRAME = ChaCha20Poly1305(key_dir, nonce=counter, data)   (counter is per-key, from 0)

Keys: HKDF-SHA256(master=X25519(my_eph, peer_eph), salt=epk_o||epk_e, info=PROTO) → 64 bytes → k_i2r || k_r2i.
This module is sans-IO (no sockets) so it is fully unit-testable and can be mirrored byte-for-byte in the Node operator.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTO = b"cage-rdp-e2e-v1"
_KEY_LEN = 32


class E2EError(Exception):
    pass


@dataclass
class Session:
    """A one-session secure channel. seal() for our direction, open() for the peer's."""
    _send_key: bytes
    _recv_key: bytes
    _send_ctr: int = 0
    _recv_ctr: int = 0

    @staticmethod
    def _nonce(ctr: int) -> bytes:
        if ctr >= (1 << 96):
            raise E2EError("nonce space exhausted; rekey required")
        return ctr.to_bytes(12, "big")

    def seal(self, plaintext: bytes) -> bytes:
        ct = ChaCha20Poly1305(self._send_key).encrypt(self._nonce(self._send_ctr), plaintext, None)
        self._send_ctr += 1
        return ct

    def open(self, ciphertext: bytes) -> bytes:
        try:
            pt = ChaCha20Poly1305(self._recv_key).decrypt(self._nonce(self._recv_ctr), ciphertext, None)
        except Exception as exc:  # cryptography.exceptions.InvalidTag etc. — fail closed
            raise E2EError("decryption failed (tampered or out-of-order frame)") from exc
        self._recv_ctr += 1
        return pt


def _derive(my_eph: x25519.X25519PrivateKey, peer_eph_raw: bytes, epk_o: bytes, epk_e: bytes) -> tuple[bytes, bytes]:
    master = my_eph.exchange(x25519.X25519PublicKey.from_public_bytes(peer_eph_raw))
    okm = HKDF(algorithm=hashes.SHA256(), length=2 * _KEY_LEN, salt=epk_o + epk_e, info=PROTO).derive(master)
    return okm[:_KEY_LEN], okm[_KEY_LEN:]  # (k_i2r, k_r2i)


def _raw(priv: x25519.X25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# ----------------------------------------------------------------------------- initiator (operator; mirrored in Node)
def initiate() -> tuple[x25519.X25519PrivateKey, bytes]:
    """Returns (ephemeral private key, HELLO bytes to send to the endpoint)."""
    eph = x25519.X25519PrivateKey.generate()
    return eph, _raw(eph)


def complete_initiator(eph: x25519.X25519PrivateKey, hello: bytes, auth: bytes,
                       verify_sig: Callable[[bytes, bytes], bool]) -> Session:
    """Consume the responder's AUTH, verify the device signature, return the operator's Session."""
    if len(auth) < 34:
        raise E2EError("truncated AUTH")
    epk_e = auth[:32]
    (sig_len,) = struct.unpack(">H", auth[32:34])
    sig = auth[34:34 + sig_len]
    if len(sig) != sig_len:
        raise E2EError("truncated signature")
    if not verify_sig(PROTO + hello + epk_e, sig):
        raise E2EError("endpoint device signature invalid — possible relay MITM")
    k_i2r, k_r2i = _derive(eph, epk_e, hello, epk_e)
    return Session(_send_key=k_i2r, _recv_key=k_r2i)


# ----------------------------------------------------------------------------- responder (endpoint agent)
def respond(hello: bytes, sign: Callable[[bytes], bytes]) -> tuple[bytes, Session]:
    """Consume the operator's HELLO, sign our ephemeral key with the device key, return (AUTH bytes, endpoint Session)."""
    if len(hello) != 32:
        raise E2EError("bad HELLO length")
    eph = x25519.X25519PrivateKey.generate()
    epk_e = _raw(eph)
    sig = sign(PROTO + hello + epk_e)
    auth = epk_e + struct.pack(">H", len(sig)) + sig
    k_i2r, k_r2i = _derive(eph, hello, hello, epk_e)
    return auth, Session(_send_key=k_r2i, _recv_key=k_i2r)  # responder sends on k_r2i, receives on k_i2r
