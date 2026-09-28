"""Shared utilities for audit ledger."""

from __future__ import annotations

import hashlib
import json


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def entry_hash(prev_hash: str, signed: bytes, mldsa_sig: str, hbs_sig: dict | None) -> str:
    h = hashlib.sha3_512()
    h.update(prev_hash.encode())
    h.update(signed)
    h.update(mldsa_sig.encode())
    h.update(canonical(hbs_sig) if hbs_sig else b"")
    return h.hexdigest()


GENESIS_PREV = "0" * 128
