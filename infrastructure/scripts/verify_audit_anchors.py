"""Offline verification of an audit-anchor file.

Usage: python verify_audit_anchors.py <org-id>.jsonl anchor-public.pem

Needs only the `cryptography` package, the external anchor file and the anchor public key (console API:
GET /api/v1/audit/anchors/public-key). Checks every line's Ed25519 signature and that sequence numbers only grow.
Exit code 0 = all anchors valid; 1 = at least one invalid line. Compare the last valid (seq, hash) with the audit
log in the console or a database backup: if that record is missing or different, the log was truncated or rewritten.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(d: dict) -> bytes:
    body = {"v": 1, "org": d["org"], "seq": d["seq"], "hash": d["hash"], "ts": d["ts"], "key_id": d["key_id"]}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def main(path: str, key_path: str) -> int:
    pub = serialization.load_pem_public_key(Path(key_path).read_bytes())
    if not isinstance(pub, Ed25519PublicKey):
        print("public key is not Ed25519")
        return 1
    bad, last_seq, last = 0, 0, None
    for n, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            d = json.loads(raw)
            pub.verify(base64.b64decode(d["sig"]), canonical(d))
            if d["seq"] <= last_seq:
                raise ValueError(f"sequence went backwards ({d['seq']} after {last_seq})")
            last_seq, last = d["seq"], d
        except (InvalidSignature, ValueError, KeyError, TypeError) as exc:
            bad += 1
            print(f"line {n}: INVALID ({exc.__class__.__name__}: {exc})")
    if last:
        print(f"last valid anchor: seq={last['seq']} hash={last['hash']} at {last['ts']}")
    print("RESULT:", "OK" if bad == 0 else f"{bad} invalid line(s)")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
