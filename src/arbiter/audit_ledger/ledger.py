"""Append-only, hash-chained, dual-signed audit ledger (Crosby & Wallach 2009).

    signed_i = canonical({index, timestamp, prev_hash, payload})
    hash_i   = SHA3-512(hash_{i-1} || signed_i || mldsa_sig_i || hbs_sig_i)

Entry 0 (genesis) publishes the ML-DSA public key and the Merkle-Lamport
root; its hash is the trust anchor to publish out-of-band. Editing,
reordering, dropping or re-signing any later entry breaks the chain or a
signature, and :meth:`AuditLedger.verify` reports the first bad index.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from arbiter.audit_ledger.signatures import MLDSA, HashSignature, MerkleLamport

GENESIS_PREV = "0" * 128


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _entry_hash(prev_hash: str, signed: bytes, mldsa_sig: str, hbs_sig: dict | None) -> str:
    h = hashlib.sha3_512()
    h.update(prev_hash.encode())
    h.update(signed)
    h.update(mldsa_sig.encode())
    h.update(canonical(hbs_sig) if hbs_sig else b"")
    return h.hexdigest()


@dataclass
class LedgerKeys:
    mldsa: MLDSA
    hbs: MerkleLamport

    @classmethod
    def generate(cls, hbs_height: int = 10) -> LedgerKeys:
        return cls(MLDSA(), MerkleLamport(secrets.token_bytes(32), hbs_height))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "mldsa_pk": base64.b64encode(self.mldsa.public_key).decode(),
                    "mldsa_sk": base64.b64encode(self.mldsa.secret_key).decode(),
                    "hbs_seed": self.hbs.seed.hex(),
                    "hbs_height": self.hbs.height,
                }
            )
        )

    @classmethod
    def load(cls, path: Path) -> LedgerKeys:
        d = json.loads(path.read_text())
        return cls(
            MLDSA(base64.b64decode(d["mldsa_pk"]), base64.b64decode(d["mldsa_sk"])),
            MerkleLamport(bytes.fromhex(d["hbs_seed"]), d["hbs_height"]),
        )


@dataclass
class VerificationReport:
    ok: bool
    entries: int
    first_bad_index: int | None = None
    problems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class AuditLedger:
    def __init__(self, keys: LedgerKeys, path: Path | None = None):
        self.keys = keys
        self.path = path
        self.entries: list[dict] = []
        if path is not None and path.exists():
            self.entries = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
            g = self.entries[0]["payload"]
            pk = base64.b64encode(keys.mldsa.public_key).decode()
            if g["mldsa_pk"] != pk or g["hbs_root"] != keys.hbs.root.hex():
                raise ValueError(f"ledger at {path} was created with different keys")
        if not self.entries:
            self._append_raw(
                {
                    "type": "genesis",
                    "mldsa_algorithm": MLDSA.ALGORITHM,
                    "mldsa_backend": keys.mldsa.backend.name,
                    "mldsa_pk": base64.b64encode(keys.mldsa.public_key).decode(),
                    "hbs_scheme": "merkle-lamport-sha3-256",
                    "hbs_root": keys.hbs.root.hex(),
                    "hbs_height": keys.hbs.height,
                },
                sign=False,
            )

    @property
    def genesis_hash(self) -> str:
        return self.entries[0]["hash"]

    def append(self, payload: dict) -> dict:
        return self._append_raw(payload, sign=True)

    def restore(self) -> None:
        """Discard in-memory changes and reload the persisted ledger.

        The demo tamper endpoint deliberately edits ``entries`` without writing
        the JSON-lines file.  Restoring must therefore be a read-only reload,
        never a repair or a rewrite of the audit trail.
        """
        if self.path is None:
            raise ValueError("cannot restore a ledger without a persisted path")
        if not self.path.exists():
            raise ValueError(f"persisted ledger does not exist: {self.path}")
        self.entries = [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def recompute_hashes_from(self, index: int) -> None:
        """Recompute the hash chain from ``index`` without replacing signatures.

        This is solely a demo aid.  It models an attacker who can rewrite all
        downstream hashes but cannot forge either signing key, so verification
        should fail on a signature rather than on the chain link.
        """
        if not 1 <= index < len(self.entries):
            raise ValueError("index must identify a signed ledger entry")
        for current in range(index, len(self.entries)):
            entry = self.entries[current]
            entry["prev_hash"] = self.entries[current - 1]["hash"]
            header = {key: entry[key] for key in ("index", "timestamp", "prev_hash", "payload")}
            signatures = entry["signatures"]
            entry["hash"] = _entry_hash(entry["prev_hash"], canonical(header), signatures["mldsa"], signatures["hbs"])

    def _append_raw(self, payload: dict, sign: bool) -> dict:
        index = len(self.entries)
        prev = self.entries[-1]["hash"] if self.entries else GENESIS_PREV
        header = {
            "index": index,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            "prev_hash": prev,
            "payload": payload,
        }
        signed = canonical(header)
        mldsa_sig, hbs_sig = "", None
        if sign:
            mldsa_sig = base64.b64encode(self.keys.mldsa.sign(signed)).decode()
            hbs_sig = self.keys.hbs.sign(signed, leaf=index - 1).to_dict()
        entry = header | {
            "signatures": {"mldsa": mldsa_sig, "hbs": hbs_sig},
            "hash": _entry_hash(prev, signed, mldsa_sig, hbs_sig),
        }
        self.entries.append(entry)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        return entry

    def verify(self) -> VerificationReport:
        return verify_entries(self.entries)


def verify_entries(entries: list[dict], expected_genesis_hash: str | None = None) -> VerificationReport:
    """Verify a ledger using only its own genesis keys (plus, optionally, a
    genesis hash obtained out-of-band)."""
    report = VerificationReport(ok=True, entries=len(entries))

    def fail(i: int, why: str) -> VerificationReport:
        report.ok = False
        report.first_bad_index = i
        report.problems.append(f"entry {i}: {why}")
        return report

    if not entries:
        return fail(0, "empty ledger")
    genesis = entries[0]
    if genesis.get("payload", {}).get("type") != "genesis" or genesis.get("prev_hash") != GENESIS_PREV:
        return fail(0, "missing genesis")
    header0 = {k: genesis[k] for k in ("index", "timestamp", "prev_hash", "payload")}
    if _entry_hash(GENESIS_PREV, canonical(header0), "", None) != genesis["hash"]:
        return fail(0, "genesis hash mismatch")
    if expected_genesis_hash and genesis["hash"] != expected_genesis_hash:
        return fail(0, "genesis differs from the published trust anchor")
    pk = base64.b64decode(genesis["payload"]["mldsa_pk"])
    root = bytes.fromhex(genesis["payload"]["hbs_root"])

    for i, e in enumerate(entries[1:], start=1):
        if e.get("index") != i:
            return fail(i, "index out of sequence")
        if e.get("prev_hash") != entries[i - 1]["hash"]:
            return fail(i, "prev_hash does not match previous entry (chain broken)")
        header = {k: e[k] for k in ("index", "timestamp", "prev_hash", "payload")}
        signed = canonical(header)
        sigs = e.get("signatures") or {}
        if _entry_hash(e["prev_hash"], signed, sigs.get("mldsa", ""), sigs.get("hbs")) != e.get("hash"):
            return fail(i, "entry hash mismatch (content altered)")
        if not MLDSA.verify(pk, signed, base64.b64decode(sigs.get("mldsa", ""))):
            return fail(i, "ML-DSA-65 signature invalid")
        try:
            hbs = HashSignature.from_dict(sigs["hbs"])
        except Exception:
            return fail(i, "hash-based signature malformed")
        if hbs.leaf != i - 1:
            return fail(i, "hash-based one-time key reused or out of order")
        if not MerkleLamport.verify(root, signed, hbs):
            return fail(i, "hash-based signature invalid")
    return report
