"""Append-only, hash-chained, dual-signed audit ledger (Crosby & Wallach 2009).

    signed_i = canonical({index, timestamp, prev_hash, payload})
    hash_i   = SHA3-512(hash_{i-1} || signed_i || mldsa_sig_i || hbs_sig_i)

Entry 0 (genesis) publishes the ML-DSA public key and the Merkle-Lamport
root; its hash is the trust anchor to publish out-of-band. Editing,
reordering, dropping or re-signing any later entry breaks the chain or a
signature, and :meth:`AuditLedger.verify` reports the first bad index.

Supports:
- Encrypted at-rest key storage (AES-256-GCM + Argon2id)
- Epoch-based key rotation with cross-signed transitions
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from arbiter.audit_ledger.common import GENESIS_PREV, canonical, entry_hash
from arbiter.audit_ledger.epoch import EpochKeys, EpochManager, EpochMetadata
from arbiter.audit_ledger.signatures import MLDSA, HashSignature, MerkleLamport
from arbiter.audit_ledger.storage import EncryptedKeyStore


@dataclass
class LedgerKeys:
    mldsa: MLDSA
    hbs: MerkleLamport
    epoch_id: int = 0
    hbs_leaf: int = 0  # next leaf index to use

    @classmethod
    def generate(cls, hbs_height: int = 10, epoch_id: int = 0) -> LedgerKeys:
        return cls(MLDSA(), MerkleLamport(secrets.token_bytes(32), hbs_height), epoch_id=epoch_id, hbs_leaf=0)

    def to_dict(self) -> dict:
        return {
            "mldsa_pk": base64.b64encode(self.mldsa.public_key).decode(),
            "mldsa_sk": base64.b64encode(self.mldsa.secret_key).decode(),
            "hbs_seed": self.hbs.seed.hex(),
            "hbs_height": self.hbs.height,
            "epoch_id": self.epoch_id,
            "hbs_leaf": self.hbs_leaf,
        }

    @classmethod
    def from_dict(cls, d: dict) -> LedgerKeys:
        return cls(
            MLDSA(base64.b64decode(d["mldsa_pk"]), base64.b64decode(d["mldsa_sk"])),
            MerkleLamport(bytes.fromhex(d["hbs_seed"]), d["hbs_height"]),
            epoch_id=d.get("epoch_id", 0),
            hbs_leaf=d.get("hbs_leaf", 0),
        )

    def save(self, path: Path) -> None:
        """Save keys in plaintext (legacy)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict()))

    def save_encrypted(self, path: Path, passphrase: str) -> None:
        """Save keys encrypted with passphrase."""
        store = EncryptedKeyStore(path)
        store.save(self.to_dict(), passphrase)

    @classmethod
    def load(cls, path: Path, *, allow_plaintext: bool = True) -> LedgerKeys:
        """Load keys from plaintext (legacy).

        Args:
            path: Path to key file
            allow_plaintext: If False, refuse to load plaintext keys (enforces encrypted storage)
        """
        if not allow_plaintext:
            raise ValueError("plaintext key loading disabled; use load_encrypted with passphrase")
        d = json.loads(path.read_text())
        return cls.from_dict(d)

    @classmethod
    def load_encrypted(cls, path: Path, passphrase: str) -> LedgerKeys:
        """Load keys from encrypted storage."""
        store = EncryptedKeyStore(path)
        d = store.load(passphrase)
        return cls.from_dict(d)


@dataclass
class VerificationReport:
    ok: bool
    entries: int
    first_bad_index: int | None = None
    problems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class AuditLedger:
    def __init__(
        self,
        keys: LedgerKeys,
        path: Path | None = None,
        epoch_manager: EpochManager | None = None,
        *,
        require_passphrase: bool = False,
    ):
        self.keys = keys
        self.path = path
        self.entries: list[dict] = []
        # Rotation is on by default.  An injected manager is retained so callers
        # can choose a lower threshold for tests or operational policy.
        self.epoch_manager = epoch_manager or EpochManager(keys.hbs.height)
        self.require_passphrase = require_passphrase
        if path is not None and path.exists():
            self.entries = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
            g = self.entries[0]["payload"]
            pk = base64.b64encode(keys.mldsa.public_key).decode()
            if g["mldsa_pk"] != pk or g["hbs_root"] != keys.hbs.root.hex():
                raise ValueError(f"ledger at {path} was created with different keys")
        if not self.entries:
            genesis_payload = {
                "type": "genesis",
                "mldsa_algorithm": MLDSA.ALGORITHM,
                "mldsa_backend": keys.mldsa.backend.name,
                "mldsa_pk": base64.b64encode(keys.mldsa.public_key).decode(),
                "hbs_scheme": "merkle-lamport-sha3-256",
                "hbs_root": keys.hbs.root.hex(),
                "hbs_height": keys.hbs.height,
                "epoch": keys.epoch_id,
            }
            if keys.epoch_id > 0 and self.epoch_manager and self.epoch_manager.previous_epoch:
                # Add cross-signature reference
                genesis_payload["cross_signature"] = self.epoch_manager.previous_epoch.cross_signature
            self._append_raw(genesis_payload, sign=False)
        # The manager tracks the ledger's actual keys, never an unrelated
        # throw-away keypair created while configuring it.
        self.epoch_manager.current_epoch = EpochKeys(
            keys.epoch_id, keys.mldsa, keys.hbs, self.genesis_hash, hbs_leaf=keys.hbs_leaf
        )
        if not self.epoch_manager.epochs:
            self.epoch_manager.epochs.append(EpochMetadata(epoch_id=keys.epoch_id, start_index=0))

    @property
    def genesis_hash(self) -> str:
        return self.entries[0]["hash"]

    def append(self, payload: dict) -> dict:
        entry = self._append_raw(payload, sign=True)
        # Reserve one remaining one-time key for the transition itself.
        if self.epoch_manager.should_rotate(self.keys.hbs_leaf):
            self._rotate_epoch()
        return entry

    def rotate_now(self) -> dict:
        """Manually trigger a key rotation (for API endpoint).

        Returns the key_transition entry that was written.
        """
        self._rotate_epoch()
        # Return the key_transition entry we just wrote
        return self.entries[-1]

    def _rotate_epoch(self) -> None:
        """Rotate to a new epoch, writing a key_transition entry."""
        if self.keys.hbs_leaf >= self.keys.hbs.capacity:
            raise ValueError("hash-based key exhausted before rotation")
        old_keys = self.keys
        global_index = len(self.entries) - 1
        new_epoch_keys = LedgerKeys.generate(old_keys.hbs.height, old_keys.epoch_id + 1)
        transition_payload = {
            "type": "key_transition",
            "prev_epoch": old_keys.epoch_id,
            "new_epoch": new_epoch_keys.epoch_id,
            "prev_mldsa_pk": base64.b64encode(old_keys.mldsa.public_key).decode(),
            "new_mldsa_pk": base64.b64encode(new_epoch_keys.mldsa.public_key).decode(),
            "prev_hbs_root": old_keys.hbs.root.hex(),
            "new_hbs_root": new_epoch_keys.hbs.root.hex(),
        }
        # The retiring keys sign the containing ledger entry.  The incoming
        # keys independently sign this immutable transition statement.
        statement = canonical(transition_payload)
        transition_payload["new_key_signature"] = {
            "mldsa": base64.b64encode(new_epoch_keys.mldsa.sign(statement)).decode(),
            "hbs": new_epoch_keys.hbs.sign(statement, leaf=0).to_dict(),
        }
        # Compatibility alias for older audit consumers.  The verifier uses
        # new_key_signature; this field is covered by the retiring-key entry.
        transition_payload["cross_signature"] = transition_payload["new_key_signature"]
        self._append_raw(transition_payload, sign=True)
        self.keys = LedgerKeys(new_epoch_keys.mldsa, new_epoch_keys.hbs, new_epoch_keys.epoch_id, hbs_leaf=1)
        previous = self.epoch_manager.current_epoch
        if self.epoch_manager.epochs:
            self.epoch_manager.epochs[-1].end_index = global_index + 1
            self.epoch_manager.epochs[-1].status = "retired"
        self.epoch_manager.previous_epoch = previous
        self.epoch_manager.current_epoch = EpochKeys(
            self.keys.epoch_id,
            self.keys.mldsa,
            self.keys.hbs,
            self.entries[-1]["hash"],
            cross_signature=transition_payload["new_key_signature"],
            hbs_leaf=1,
        )
        self.epoch_manager.epochs.append(EpochMetadata(epoch_id=self.keys.epoch_id, start_index=global_index))

    def restore(self) -> None:
        """Reload the untouched persisted JSON-lines ledger for the demo API."""
        if self.path is None:
            raise ValueError("cannot restore a ledger without a persisted path")
        if not self.path.exists():
            raise ValueError(f"persisted ledger does not exist: {self.path}")
        self.entries = [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def recompute_hashes_from(self, index: int) -> None:
        """Demo-only hash-chain rewrite; signatures intentionally remain invalid."""
        if not 1 <= index < len(self.entries):
            raise ValueError("index must identify a signed ledger entry")
        for current in range(index, len(self.entries)):
            entry = self.entries[current]
            entry["prev_hash"] = self.entries[current - 1]["hash"]
            header = {key: entry[key] for key in ("index", "timestamp", "prev_hash", "payload")}
            signatures = entry["signatures"]
            entry["hash"] = entry_hash(entry["prev_hash"], canonical(header), signatures["mldsa"], signatures["hbs"])

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
            hbs_sig = self.keys.hbs.sign(signed, leaf=self.keys.hbs_leaf).to_dict()
            # Increment leaf counter for next entry
            self.keys.hbs_leaf += 1
        entry = header | {
            "signatures": {"mldsa": mldsa_sig, "hbs": hbs_sig},
            "hash": entry_hash(prev, signed, mldsa_sig, hbs_sig),
        }
        self.entries.append(entry)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        return entry

    def verify(self) -> VerificationReport:
        return verify_entries(self.entries)

    def verify_cross_epoch(self, expected_genesis_hash: str | None = None) -> VerificationReport:
        """Verify the same authenticated epoch chain, with an optional trust anchor."""
        return verify_entries(self.entries, expected_genesis_hash)


def verify_entries(entries: list[dict], expected_genesis_hash: str | None = None) -> VerificationReport:
    """Verify untrusted entries, following only dual-authorised transitions."""
    try:
        return _verify_entries(entries, expected_genesis_hash)
    except Exception as exc:
        return VerificationReport(False, len(entries), 0, [f"malformed ledger entry: {type(exc).__name__}"])


def _verify_entries(entries: list[dict], expected_genesis_hash: str | None = None) -> VerificationReport:
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
    if genesis.get("signatures") != {"mldsa": "", "hbs": None}:
        return fail(0, "genesis must not contain signatures")
    header0 = {k: genesis[k] for k in ("index", "timestamp", "prev_hash", "payload")}
    if entry_hash(GENESIS_PREV, canonical(header0), "", None) != genesis["hash"]:
        return fail(0, "genesis hash mismatch")
    if expected_genesis_hash and genesis["hash"] != expected_genesis_hash:
        return fail(0, "genesis differs from the published trust anchor")
    pk = base64.b64decode(genesis["payload"]["mldsa_pk"])
    root = bytes.fromhex(genesis["payload"]["hbs_root"])
    next_leaf = 0
    epoch = genesis["payload"].get("epoch", 0)

    for i, e in enumerate(entries[1:], start=1):
        if e.get("index") != i:
            return fail(i, "index out of sequence")
        if e.get("prev_hash") != entries[i - 1]["hash"]:
            return fail(i, "prev_hash does not match previous entry (chain broken)")
        header = {k: e[k] for k in ("index", "timestamp", "prev_hash", "payload")}
        signed = canonical(header)
        sigs = e.get("signatures") or {}
        if entry_hash(e["prev_hash"], signed, sigs.get("mldsa", ""), sigs.get("hbs")) != e.get("hash"):
            return fail(i, "entry hash mismatch (content altered)")
        if not MLDSA.verify(pk, signed, base64.b64decode(sigs.get("mldsa", ""))):
            return fail(i, "ML-DSA-65 signature invalid")
        try:
            hbs = HashSignature.from_dict(sigs["hbs"])
        except Exception:
            return fail(i, "hash-based signature malformed")
        if hbs.leaf != next_leaf:
            return fail(i, "hash-based one-time key reused or out of order")
        if not MerkleLamport.verify(root, signed, hbs):
            return fail(i, "hash-based signature invalid")
        next_leaf += 1
        payload = e.get("payload", {})
        if payload.get("type") == "key_transition":
            required = {
                "prev_epoch",
                "new_epoch",
                "prev_mldsa_pk",
                "new_mldsa_pk",
                "prev_hbs_root",
                "new_hbs_root",
                "new_key_signature",
            }
            if not required.issubset(payload):
                return fail(i, "key transition is incomplete")
            if payload["prev_epoch"] != epoch or base64.b64decode(payload["prev_mldsa_pk"]) != pk:
                return fail(i, "key transition does not name the active epoch")
            if bytes.fromhex(payload["prev_hbs_root"]) != root or payload["new_epoch"] != epoch + 1:
                return fail(i, "key transition has inconsistent epoch keys")
            statement = {
                key: value for key, value in payload.items() if key not in {"new_key_signature", "cross_signature"}
            }
            new_signed = canonical(statement)
            new_pk = base64.b64decode(payload["new_mldsa_pk"])
            new_root = bytes.fromhex(payload["new_hbs_root"])
            new_sigs = payload["new_key_signature"]
            if not MLDSA.verify(new_pk, new_signed, base64.b64decode(new_sigs.get("mldsa", ""))):
                return fail(i, "incoming ML-DSA signature invalid")
            try:
                new_hbs = HashSignature.from_dict(new_sigs["hbs"])
            except Exception:
                return fail(i, "incoming hash-based signature malformed")
            if new_hbs.leaf != 0 or not MerkleLamport.verify(new_root, new_signed, new_hbs):
                return fail(i, "incoming hash-based signature invalid")
            pk, root, epoch, next_leaf = new_pk, new_root, payload["new_epoch"], 1
    return report
