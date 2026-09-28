"""Epoch-based key rotation for audit ledger.

Supports cross-signed epoch transitions with dual-signature scheme.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from arbiter.audit_ledger.common import canonical
from arbiter.audit_ledger.signatures import MLDSA, HashSignature, MerkleLamport


@dataclass
class EpochKeys:
    """Keys for a single ledger epoch."""

    epoch_id: int
    mldsa: MLDSA
    hbs: MerkleLamport
    genesis_hash: str  # hash of this epoch's genesis entry
    cross_signature: dict | None = None  # previous epoch's signature of this genesis
    hbs_leaf: int = 0  # next leaf index to use

    @classmethod
    def generate(cls, epoch_id: int, hbs_height: int = 10) -> EpochKeys:
        mldsa = MLDSA()
        hbs = MerkleLamport(secrets.token_bytes(32), hbs_height)
        genesis_payload = {
            "type": "genesis",
            "mldsa_algorithm": MLDSA.ALGORITHM,
            "mldsa_backend": mldsa.backend.name,
            "mldsa_pk": base64.b64encode(mldsa.public_key).decode(),
            "hbs_scheme": "merkle-lamport-sha3-256",
            "hbs_root": hbs.root.hex(),
            "hbs_height": hbs.height,
            "epoch": epoch_id,
        }
        genesis_header = {
            "index": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            "prev_hash": "0" * 128,
            "payload": genesis_payload,
        }
        genesis_hash = hashlib.sha3_512(canonical(genesis_header)).hexdigest()
        return cls(epoch_id=epoch_id, mldsa=mldsa, hbs=hbs, genesis_hash=genesis_hash, hbs_leaf=0)

    def sign_genesis(self, prev_epoch_mldsa: MLDSA, prev_epoch_hbs: MerkleLamport, prev_leaf: int) -> dict:
        """Create cross-signature from previous epoch's keys."""
        payload = {
            "type": "epoch_transition",
            "prev_epoch": self.epoch_id - 1,
            "new_epoch": self.epoch_id,
            "new_genesis_hash": self.genesis_hash,
            "new_mldsa_pk": base64.b64encode(self.mldsa.public_key).decode(),
            "new_hbs_root": self.hbs.root.hex(),
        }
        signed = canonical(payload)
        mldsa_sig = base64.b64encode(prev_epoch_mldsa.sign(signed)).decode()
        hbs_sig = prev_epoch_hbs.sign(signed, leaf=prev_leaf).to_dict()
        return {
            "payload": payload,
            "mldsa_signature": mldsa_sig,
            "hbs_signature": hbs_sig,
        }

    def verify_cross_signature(
        self,
        cross_sig: dict,
        prev_mldsa_pk: bytes,
        prev_hbs_root: bytes,
        prev_leaf: int,
    ) -> bool:
        """Verify cross-signature from previous epoch."""
        signed = canonical(cross_sig["payload"])
        if not MLDSA.verify(prev_mldsa_pk, signed, base64.b64decode(cross_sig["mldsa_signature"])):
            return False
        try:
            hbs = HashSignature.from_dict(cross_sig["hbs_signature"])
        except Exception:
            return False
        if hbs.leaf != prev_leaf:
            return False
        if not MerkleLamport.verify(prev_hbs_root, signed, hbs):
            return False
        return True


@dataclass
class EpochMetadata:
    """Metadata tracking epoch lifecycle."""

    epoch_id: int
    start_index: int  # global ledger index where this epoch starts
    end_index: int | None = None  # global index where epoch ends (None = active)
    hbs_leaves_used: int = 0
    status: str = "active"  # active | retired | compromised
    cross_signature: dict | None = None


class EpochManager:
    """Manages epoch transitions and key rotation."""

    def __init__(self, hbs_height: int = 10, max_hbs_usage_ratio: float = 0.9):
        self.hbs_height = hbs_height
        self.max_hbs_usage = int((2**hbs_height) * max_hbs_usage_ratio)
        self.epochs: list[EpochMetadata] = []
        self.current_epoch: EpochKeys | None = None
        self.previous_epoch: EpochKeys | None = None

    def initialize_genesis(self) -> EpochKeys:
        """Create epoch 0 (genesis)."""
        self.current_epoch = EpochKeys.generate(0, self.hbs_height)
        self.epochs.append(EpochMetadata(epoch_id=0, start_index=0))
        return self.current_epoch

    def rotate_keys(self, global_index: int) -> EpochKeys:
        """Rotate to a new epoch, cross-signed by previous epoch."""
        if self.current_epoch is None:
            raise ValueError("no current epoch to rotate from")

        # Record end of previous epoch
        self.epochs[-1].end_index = global_index
        self.epochs[-1].status = "retired"
        self.epochs[-1].hbs_leaves_used = self.current_epoch.hbs_leaf

        # Generate new epoch
        new_epoch = EpochKeys.generate(self.current_epoch.epoch_id + 1, self.hbs_height)

        # Cross-sign: previous epoch signs new genesis
        cross_sig = new_epoch.sign_genesis(
            self.current_epoch.mldsa,
            self.current_epoch.hbs,
            self.current_epoch.hbs_leaf,
        )
        new_epoch.cross_signature = cross_sig

        # Update tracking
        self.previous_epoch = self.current_epoch
        self.current_epoch = new_epoch
        self.epochs.append(
            EpochMetadata(
                epoch_id=new_epoch.epoch_id,
                start_index=global_index + 1,
            )
        )

        return new_epoch

    def should_rotate(self, hbs_leaves_used: int) -> bool:
        """Check if HBS usage has exceeded threshold."""
        return hbs_leaves_used >= self.max_hbs_usage

    def get_verification_chain(self) -> list[dict]:
        """Get the chain of cross-signatures for verification."""
        chain = []
        for epoch in self.epochs:
            if epoch.cross_signature:
                chain.append(
                    {
                        "epoch": epoch.epoch_id,
                        "cross_signature": epoch.cross_signature,
                    }
                )
        return chain
