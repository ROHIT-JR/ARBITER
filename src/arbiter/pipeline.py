"""End-to-end verification: every layer runs on a transcript, the combined
verdict is decided, and the result is appended to the audit ledger.

Decision order:
1. Classical freshness -- a reused session nonce is a verbatim resubmission.
2. CHSH pre-check -- S below threshold means the channel cannot be trusted.
3. Unified detector -- level-alpha GLRT with maximum-likelihood attribution.
The sequential (anytime-valid) result is reported alongside as the
early-abort view of the same evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from arbiter.audit_ledger import AuditLedger
from arbiter.detection import (
    ChshResult,
    NonceRegistry,
    SequentialDetector,
    SequentialVerdict,
    UnifiedDetector,
    UnifiedVerdict,
    chsh_precheck,
    freshness_test,
)
from arbiter.detection.freshness import FreshnessResult
from arbiter.qds_simulation.model import ChannelParams, Hypothesis
from arbiter.qds_simulation.protocol import Transcript


@dataclass
class ArbiterVerdict:
    transcript: Transcript
    decision: str  # "ACCEPT" | "REJECT"
    attribution: Hypothesis
    reasons: list[str]
    nonce_fresh: bool
    chsh: ChshResult
    freshness: FreshnessResult
    unified: UnifiedVerdict
    sequential: SequentialVerdict
    ledger_entry: dict | None = None

    def to_dict(self, trajectory: bool = False) -> dict:
        t = self.transcript
        n, _ = t.counts()
        d = {
            "session": {
                "id": t.session_id,
                "message": t.message,
                "nonce": t.nonce,
                "backend": t.backend,
                "rounds": int(len(t.cells)),
                "rounds_per_cell": n.tolist(),
                "transcript_digest": t.digest(),
            },
            "decision": self.decision,
            "attribution": self.attribution.value,
            "reasons": self.reasons,
            "layers": {
                "nonce_fresh": self.nonce_fresh,
                "chsh": self.chsh.to_dict(),
                "freshness": self.freshness.to_dict(),
                "unified": self.unified.to_dict(),
                "sequential": self.sequential.to_dict(trajectory),
            },
            "simulation_ground_truth": {"hypothesis": t.truth.value, "theta": t.theta},
        }
        if self.ledger_entry is not None:
            d["ledger"] = {"index": self.ledger_entry["index"], "hash": self.ledger_entry["hash"]}
        return d


class Arbiter:
    def __init__(
        self,
        params: ChannelParams | None = None,
        alpha: float = 0.01,
        ledger: AuditLedger | None = None,
        chsh_threshold: float = 2.0,
    ):
        self.params = params or ChannelParams()
        self.alpha = alpha
        self.chsh_threshold = chsh_threshold
        self.unified = UnifiedDetector(self.params, alpha)
        self.sequential = SequentialDetector(self.params, alpha)
        self.nonces = NonceRegistry()
        self.ledger = ledger

    def verify(self, transcript: Transcript) -> ArbiterVerdict:
        nonce_fresh = self.nonces.check_and_register(transcript.nonce)
        chsh = chsh_precheck(transcript, self.chsh_threshold)
        fresh = freshness_test(transcript, self.params, self.alpha)
        unified = self.unified.evaluate(transcript)
        sequential = self.sequential.evaluate(transcript)

        reasons: list[str] = []
        attribution = unified.attribution
        if not nonce_fresh:
            reasons.append("session nonce already used: verbatim resubmission")
            attribution = Hypothesis.REPLAY
        if chsh.flagged:
            reasons.append(f"CHSH S={chsh.S:.3f} below {self.chsh_threshold}: channel integrity not certified")
            if not unified.rejected and nonce_fresh:
                attribution = Hypothesis.CHANNEL_MANIPULATION
        if unified.rejected:
            reasons.append(
                f"unified GLRT {unified.statistic:.2f} > {unified.threshold:.2f} (alpha={self.alpha}); "
                f"most likely: {unified.attribution.value}"
            )
        decision = "REJECT" if reasons else "ACCEPT"
        if decision == "ACCEPT":
            attribution = Hypothesis.LEGITIMATE

        verdict = ArbiterVerdict(
            transcript, decision, attribution, reasons, nonce_fresh, chsh, fresh, unified, sequential
        )
        if self.ledger is not None:
            payload = verdict.to_dict()
            payload["type"] = "verdict"
            verdict.ledger_entry = self.ledger.append(payload)
        return verdict
