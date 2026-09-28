"""End-to-end verification: every layer runs on a transcript, the combined
verdict is decided, and the result is appended to the audit ledger.

Decision order:
1. Classical freshness -- a reused session nonce is a verbatim resubmission.
2. CHSH pre-check -- S below threshold means the channel cannot be trusted.
3. Unified detector and temporal family -- Bonferroni-split calibrated tests.
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
    TemporalDetector,
    TemporalVerdict,
    UnifiedDetector,
    UnifiedVerdict,
    chsh_precheck,
    freshness_test,
)
from arbiter.detection.freshness import FreshnessResult
from arbiter.qds_simulation.model import ChannelParams, Hypothesis, _normalise_protocol
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
    temporal: TemporalVerdict
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
                "protocol": t.protocol,
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
                "temporal": self.temporal.to_dict(),
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
        nonces: NonceRegistry | None = None,
        *,
        protocol: str = "prf",
    ):
        self.params = params or ChannelParams()
        self.alpha = alpha
        # The ordered-data additions are another decision layer, not an
        # uncalibrated dashboard heuristic.  Split the configured family-wise
        # rate over the three independent rejection paths.  The CHSH result is
        # retained as a physical diagnostic; it only supplies a rejection when
        # the calibrated GLRT has already rejected, so it cannot add FWER.
        self.layer_alpha = alpha / 3
        self.chsh_threshold = chsh_threshold
        self.protocol = _normalise_protocol(protocol)
        self.unified = UnifiedDetector(self.params, self.layer_alpha, protocol=self.protocol)
        self.sequential = SequentialDetector(self.params, alpha, protocol=self.protocol)
        self.temporal = TemporalDetector(self.params, self.layer_alpha)
        self.nonces = nonces or NonceRegistry()
        self.ledger = ledger

    def verify(self, transcript: Transcript) -> ArbiterVerdict:
        if transcript.protocol != self.protocol:
            raise ValueError(
                f"transcript protocol {transcript.protocol!r} does not match ARBITER protocol {self.protocol!r}"
            )
        nonce_fresh = self.nonces.check_and_register(transcript.nonce)
        chsh = chsh_precheck(transcript, self.chsh_threshold)
        fresh = freshness_test(transcript, self.params, self.layer_alpha)
        unified = self.unified.evaluate(transcript)
        sequential = self.sequential.evaluate(transcript)
        temporal = self.temporal.evaluate(transcript)

        reasons: list[str] = []
        attribution = unified.attribution
        if not nonce_fresh:
            reasons.append("session nonce already used: verbatim resubmission")
            attribution = Hypothesis.REPLAY
        if chsh.flagged and unified.rejected:
            reasons.append(f"CHSH S={chsh.S:.3f} below {self.chsh_threshold}: channel integrity not certified")
        if unified.rejected:
            reasons.append(
                f"unified GLRT {unified.statistic:.2f} > {unified.threshold:.2f} (alpha={self.layer_alpha}); "
                f"most likely: {unified.attribution.value}"
            )
        if fresh.flagged and not unified.rejected:
            reasons.append(f"freshness mismatch tail p={fresh.p_value:.3g} < {self.layer_alpha:.3g}; probable replay")
            attribution = Hypothesis.REPLAY
        if temporal.rejected:
            flagged = [name for name, stream in temporal.streams.items() if stream.flagged]
            reasons.append(f"temporal family test flagged {', '.join(flagged)} (Bonferroni alpha={temporal.alpha:.3g})")
            if not unified.rejected and nonce_fresh:
                # Temporal statistics detect structure, not the identity of an
                # attacker.  Use the conservative existing channel-anomaly
                # label rather than claiming a new ML-style classification.
                attribution = Hypothesis.CHANNEL_MANIPULATION
        decision = "REJECT" if reasons else "ACCEPT"
        if decision == "ACCEPT":
            attribution = Hypothesis.LEGITIMATE

        verdict = ArbiterVerdict(
            transcript, decision, attribution, reasons, nonce_fresh, chsh, fresh, unified, sequential, temporal
        )
        if self.ledger is not None:
            payload = verdict.to_dict()
            payload["type"] = "verdict"
            verdict.ledger_entry = self.ledger.append(payload)
        return verdict
