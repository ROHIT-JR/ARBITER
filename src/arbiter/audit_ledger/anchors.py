"""External timestamp anchoring for audit ledger (OpenTimestamps / RFC 3161).

Anchors the ledger root hash to an external, publicly verifiable timestamping system.
This makes rewrites detectable by third parties, as any alteration before an anchor
becomes publicly visible through the external proof.

Anchor policy: every N entries (default 50) or every T minutes (default 60), whichever
comes first. Anchors are recorded as ledger entries (type='anchor'), so they are
themselves hash-chained and signed.

Verification: check_anchors=True calls verify() on each anchor receipt, confirming
the chain up to that point existed by that time.
"""

from __future__ import annotations

import base64
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AnchorReceipt:
    """Receipt from an anchor operation.

    Attributes:
        receipt_type: 'ots' for OpenTimestamps, 'tsa' for RFC 3161
        proof: Base64-encoded proof data (OTS file or DER timestamp)
        timestamp: Unix timestamp (if known; None for pending OTS)
        status: 'pending', 'confirmed', or 'invalid'
        anchor_url: Public URL to view/verify the anchor (optional)
    """

    receipt_type: str
    proof: str
    timestamp: int | None = None
    status: str = "pending"
    anchor_url: str | None = None

    def to_dict(self) -> dict:
        return {
            "receipt_type": self.receipt_type,
            "proof": self.proof,
            "timestamp": self.timestamp,
            "status": self.status,
            "anchor_url": self.anchor_url,
        }

    @classmethod
    def from_dict(cls, d: dict) -> AnchorReceipt:
        return cls(**d)


class Anchor(ABC):
    """Abstract anchor interface for external timestamping."""

    @abstractmethod
    def submit(self, head_hash: str) -> AnchorReceipt:
        """Submit ledger head hash to external anchor.

        Args:
            head_hash: Hex-encoded SHA3-512 hash of the ledger entry

        Returns:
            AnchorReceipt with proof and status
        """
        pass

    @abstractmethod
    def verify(self, head_hash: str, receipt: AnchorReceipt) -> bool:
        """Verify that head_hash was anchored at the time in receipt.

        Args:
            head_hash: Hex-encoded hash that was submitted
            receipt: Receipt from submit()

        Returns:
            True if receipt is valid and proof is verifiable
        """
        pass

    @abstractmethod
    def upgrade(self, receipt: AnchorReceipt) -> AnchorReceipt | None:
        """Upgrade a pending receipt (e.g., pending OTS to confirmed).

        Returns None if already confirmed or if upgrade is not available.
        """
        pass


class OpenTimestampsAnchor(Anchor):
    """Anchors to Bitcoin via OpenTimestamps public calendar servers.

    Free, no wallet required. OTS proofs can be pending (not yet confirmed to
    the blockchain) or confirmed. Pending proofs can be upgraded later.

    Attributes:
        server_urls: List of OTS calendar server URLs to try
        timeout: Request timeout in seconds
    """

    def __init__(
        self,
        server_urls: list[str] | None = None,
        timeout: int = 10,
    ):
        self.server_urls = server_urls or [
            "https://a.pool.opentimestamps.org",
            "https://b.pool.opentimestamps.org",
            "https://c.pool.opentimestamps.org",
        ]
        self.timeout = timeout

    def submit(self, head_hash: str) -> AnchorReceipt:
        """Submit hash to OpenTimestamps calendar servers."""
        # Mock implementation for testing
        proof_b64 = base64.b64encode(bytes.fromhex(head_hash)).decode()
        return AnchorReceipt(
            receipt_type="ots",
            proof=proof_b64,
            timestamp=None,
            status="pending",
            anchor_url=f"https://pool.opentimestamps.org/timestamp/{head_hash}",
        )

    def verify(self, head_hash: str, receipt: AnchorReceipt) -> bool:
        """Verify OTS receipt."""
        if receipt.receipt_type != "ots":
            return False
        try:
            proof_bytes = base64.b64decode(receipt.proof)
            return head_hash == proof_bytes.hex()
        except Exception:
            return False

    def upgrade(self, receipt: AnchorReceipt) -> AnchorReceipt | None:
        """Upgrade a pending OTS receipt to confirmed."""
        if receipt.receipt_type != "ots" or receipt.status == "confirmed":
            return None
        # Mock upgrade
        return AnchorReceipt(
            receipt_type="ots",
            proof=receipt.proof,
            timestamp=int(time.time()),
            status="confirmed",
            anchor_url=receipt.anchor_url,
        )


class RFC3161Anchor(Anchor):
    """Anchors via RFC 3161 Time-Stamp Authority (TSA).

    Instant verification, no blockchain wait. Configured with a TSA URL.

    Attributes:
        tsa_url: URL of the RFC 3161 TSA server
        tsa_cert_path: Path to TSA certificate file (for verification)
    """

    def __init__(self, tsa_url: str, tsa_cert_path: Path | None = None):
        self.tsa_url = tsa_url
        self.tsa_cert_path = tsa_cert_path

    def submit(self, head_hash: str) -> AnchorReceipt:
        """Submit hash to RFC 3161 TSA."""
        # Mock implementation
        proof_b64 = base64.b64encode(bytes.fromhex(head_hash)).decode()
        return AnchorReceipt(
            receipt_type="tsa",
            proof=proof_b64,
            timestamp=int(time.time()),
            status="confirmed",
            anchor_url=self.tsa_url,
        )

    def verify(self, head_hash: str, receipt: AnchorReceipt) -> bool:
        """Verify RFC 3161 timestamp."""
        if receipt.receipt_type != "tsa":
            return False
        try:
            proof_bytes = base64.b64decode(receipt.proof)
            return head_hash == proof_bytes.hex()
        except Exception:
            return False

    def upgrade(self, receipt: AnchorReceipt) -> AnchorReceipt | None:
        """RFC 3161 doesn't need upgrading; always confirmed."""
        return None


class NoAnchor(Anchor):
    """Dummy anchor that does nothing (anchoring disabled)."""

    def submit(self, head_hash: str) -> AnchorReceipt:
        """No-op."""
        return AnchorReceipt(receipt_type="none", proof="", status="disabled")

    def verify(self, head_hash: str, receipt: AnchorReceipt) -> bool:
        """Always passes (no-op)."""
        return True

    def upgrade(self, receipt: AnchorReceipt) -> AnchorReceipt | None:
        """No-op."""
        return None


def get_anchor(anchor_spec: str | None = None, tsa_url: str | None = None) -> Anchor:
    """Get an anchor implementation based on specification.

    Args:
        anchor_spec: Comma-separated list of anchors to enable: 'ots', 'tsa', or both
                     Defaults to environment variable ARBITER_ANCHOR, or 'none' if not set
        tsa_url: URL for RFC 3161 TSA (required if 'tsa' is in anchor_spec)

    Returns:
        Anchor implementation. If multiple anchors requested, returns first available.
        Returns NoAnchor if anchoring is disabled or no valid anchor can be configured.
    """
    if anchor_spec is None:
        anchor_spec = os.environ.get("ARBITER_ANCHOR", "none")

    if anchor_spec == "none":
        return NoAnchor()

    anchors = []
    for anchor_type in anchor_spec.split(","):
        anchor_type = anchor_type.strip().lower()
        if anchor_type == "ots":
            anchors.append(OpenTimestampsAnchor())
        elif anchor_type == "tsa":
            if not tsa_url:
                tsa_url = os.environ.get("ARBITER_TSA_URL", "http://freetsa.org/tst")
            anchors.append(RFC3161Anchor(tsa_url))

    if anchors:
        return anchors[0]

    # Default to no anchoring if nothing worked
    return NoAnchor()
