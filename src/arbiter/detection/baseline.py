"""Fixed-threshold baseline and reproducible head-to-head comparison.

The baseline intentionally mirrors the common "one threshold per symptom"
design.  It does not combine evidence: rules are checked in a fixed order and
the first firing rule supplies the attribution.  The default thresholds are
jointly calibrated under H0 so the *family-wise* false-alarm rate is ``alpha``.
Set ``bonferroni=True`` for the conventional ``alpha / 4`` per-rule variant.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

import numpy as np

from arbiter.qds_simulation.model import ATTACKS, CELLS, ChannelParams, Hypothesis, cell_probabilities
from arbiter.qds_simulation.protocol import Transcript

RULE_PRIORITY = (
    Hypothesis.FORGERY,
    Hypothesis.REPLAY,
    Hypothesis.CHANNEL_MANIPULATION,
    Hypothesis.IMPERSONATION,
)


def balanced_cell_counts(n_rounds: int, round_mix: tuple[float, float, float] = (0.5, 0.25, 0.25)) -> np.ndarray:
    """Allocate a session deterministically across signature/freshness/CHSH cells."""
    if n_rounds < len(CELLS):
        raise ValueError(f"n_rounds must be at least {len(CELLS)}")
    weights = np.array([round_mix[0], round_mix[1], *(round_mix[2] / 4 for _ in range(4))], float)
    if np.any(weights <= 0) or not np.isclose(weights.sum(), 1):
        raise ValueError("round_mix must contain positive probabilities summing to one")
    exact = n_rounds * weights
    counts = np.floor(exact).astype(int)
    order = np.argsort(-(exact - counts), kind="stable")
    counts[order[: n_rounds - int(counts.sum())]] += 1
    return counts


@dataclass(frozen=True)
class BaselineThresholds:
    forgery: float
    replay: float
    channel_manipulation: float
    impersonation: float
    per_rule_alpha: float
    calibration_false_alarm_rate: float

    def to_dict(self) -> dict[str, float]:
        return {name: round(float(value), 6) for name, value in self.__dict__.items()}


@dataclass(frozen=True)
class BaselineVerdict:
    rejected: bool
    attribution: Hypothesis
    rules: dict[str, bool]
    statistics: dict[str, float]
    thresholds: BaselineThresholds

    def to_dict(self) -> dict:
        return {
            "rejected": self.rejected,
            "attribution": self.attribution.value,
            "rules": self.rules,
            "statistics": {k: round(v, 6) for k, v in self.statistics.items()},
            "thresholds": self.thresholds.to_dict(),
        }


class BaselineDetector:
    """Four independent fixed rules with first-match attribution.

    Thresholds are calibrated once for a balanced session of ``n_rounds`` and
    then remain fixed.  This is deliberately less adaptive than ARBITER's
    count-conditional GLRT, but its overall H0 rejection probability is still
    matched fairly to ``alpha``.
    """

    def __init__(
        self,
        params: ChannelParams | None = None,
        alpha: float = 0.01,
        n_rounds: int = 1200,
        round_mix: tuple[float, float, float] = (0.5, 0.25, 0.25),
        n_calibration: int = 50_000,
        seed: int | None = 0,
        *,
        bonferroni: bool = False,
    ) -> None:
        if not 0 < alpha < 1:
            raise ValueError("alpha must lie in (0, 1)")
        if n_calibration < 100:
            raise ValueError("n_calibration must be at least 100")
        self.params = params or ChannelParams()
        self.alpha = float(alpha)
        self.n_rounds = int(n_rounds)
        self.cell_counts = balanced_cell_counts(self.n_rounds, round_mix)
        self.n_calibration = int(n_calibration)
        self.seed = seed
        self.bonferroni = bonferroni
        self.thresholds = self._calibrate()

    @staticmethod
    def _metrics(n: np.ndarray, k: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        n = np.asarray(n, float)
        k = np.asarray(k, float)
        signature = np.divide(k[..., 0], n[..., 0], out=np.zeros_like(k[..., 0]), where=n[..., 0] > 0)
        freshness = np.divide(k[..., 1], n[..., 1], out=np.zeros_like(k[..., 1]), where=n[..., 1] > 0)
        chsh_rates = np.divide(k[..., 2:], n[..., 2:], out=np.full_like(k[..., 2:], np.inf), where=n[..., 2:] > 0)
        chsh_s = np.sum(1 - 2 * chsh_rates, axis=-1)
        impersonation = np.minimum(signature, freshness)
        return signature, freshness, chsh_s, impersonation

    @staticmethod
    def _thresholds_for(metrics: tuple[np.ndarray, ...], tail_probability: float) -> tuple[float, ...]:
        signature, freshness, chsh_s, impersonation = metrics
        return (
            float(np.quantile(signature, 1 - tail_probability, method="higher")),
            float(np.quantile(freshness, 1 - tail_probability, method="higher")),
            float(np.quantile(chsh_s, tail_probability, method="lower")),
            float(np.quantile(impersonation, 1 - tail_probability, method="higher")),
        )

    @staticmethod
    def _rule_matrix(metrics: tuple[np.ndarray, ...], thresholds: tuple[float, ...]) -> np.ndarray:
        signature, freshness, chsh_s, impersonation = metrics
        forgery_tau, replay_tau, channel_tau, impersonation_tau = thresholds
        return np.column_stack(
            (
                signature > forgery_tau,
                freshness > replay_tau,
                chsh_s < channel_tau,
                impersonation > impersonation_tau,
            )
        )

    def _calibrate(self) -> BaselineThresholds:
        rng = np.random.default_rng(self.seed)
        p0 = cell_probabilities(Hypothesis.LEGITIMATE, 0.0, self.params)
        k = rng.binomial(self.cell_counts, p0, size=(self.n_calibration, len(CELLS)))
        n = np.broadcast_to(self.cell_counts, k.shape)
        metrics = self._metrics(n, k)

        if self.bonferroni:
            per_rule_alpha = self.alpha / 4
        else:
            # Find the least-conservative common marginal tail probability
            # whose four-rule union still has empirical size <= alpha.
            low, high = 0.0, self.alpha
            for _ in range(30):
                candidate = (low + high) / 2
                taus = self._thresholds_for(metrics, candidate)
                far = float(self._rule_matrix(metrics, taus).any(axis=1).mean())
                if far <= self.alpha:
                    low = candidate
                else:
                    high = candidate
            per_rule_alpha = low

        taus = self._thresholds_for(metrics, per_rule_alpha)
        far = float(self._rule_matrix(metrics, taus).any(axis=1).mean())
        return BaselineThresholds(*taus, per_rule_alpha, far)

    def evaluate_counts(self, n: np.ndarray, k: np.ndarray) -> BaselineVerdict:
        values = tuple(float(x) for x in self._metrics(np.asarray(n), np.asarray(k)))
        taus = (
            self.thresholds.forgery,
            self.thresholds.replay,
            self.thresholds.channel_manipulation,
            self.thresholds.impersonation,
        )
        fired = self._rule_matrix(tuple(np.array(x) for x in values), taus)[0]
        rules = {h.value: bool(flag) for h, flag in zip(RULE_PRIORITY, fired, strict=True)}
        attribution = next((h for h in RULE_PRIORITY if rules[h.value]), Hypothesis.LEGITIMATE)
        return BaselineVerdict(
            rejected=any(rules.values()),
            attribution=attribution,
            rules=rules,
            statistics={
                "signature_mismatch_rate": values[0],
                "freshness_mismatch_rate": values[1],
                "chsh_s": values[2],
                "impersonation_joint_rate": values[3],
            },
            thresholds=self.thresholds,
        )

    def evaluate(self, transcript: Transcript) -> BaselineVerdict:
        return self.evaluate_counts(*transcript.counts())


def compare_detectors(
    theta: float,
    sessions: int,
    seed: int,
    *,
    params: ChannelParams | None = None,
    n_rounds: int = 1200,
    alpha: float = 0.01,
) -> dict:
    """Run a balanced, paired Monte-Carlo comparison and return JSON-ready results."""
    if not 0 < theta <= 1:
        raise ValueError("theta must lie in (0, 1]")
    if sessions < 1:
        raise ValueError("sessions must be positive")

    # Imports stay local so using BaselineDetector alone does not import the
    # heavier GLRT implementation.
    from arbiter.detection.unified import UnifiedDetector

    params = params or ChannelParams()
    n = balanced_cell_counts(n_rounds)
    calibration_seed = int(np.random.SeedSequence(seed).generate_state(1)[0])
    detectors = {
        "unified": UnifiedDetector(params, alpha=alpha, seed=calibration_seed),
        "baseline": BaselineDetector(params, alpha, n_rounds, seed=calibration_seed),
        "baseline_bonferroni": BaselineDetector(params, alpha, n_rounds, seed=calibration_seed, bonferroni=True),
    }
    labels = [h.value for h in Hypothesis]
    predictions = {name: {h.value: Counter() for h in Hypothesis} for name in detectors}
    rng = np.random.default_rng(seed)

    for truth in Hypothesis:
        strength = 0.0 if truth is Hypothesis.LEGITIMATE else (1.0 if truth is Hypothesis.IMPERSONATION else theta)
        p = cell_probabilities(truth, strength, params)
        samples = rng.binomial(n, p, size=(sessions, len(CELLS)))
        for k in samples:
            for name, detector in detectors.items():
                verdict = detector.evaluate_counts(n, k)
                predictions[name][truth.value][verdict.attribution.value] += 1

    def summarise(name: str) -> dict:
        matrix = {truth: {predicted: predictions[name][truth][predicted] for predicted in labels} for truth in labels}
        legitimate = matrix[Hypothesis.LEGITIMATE.value]
        attacks = {}
        for attack in ATTACKS:
            row = matrix[attack.value]
            attacks[attack.value] = {
                "detection_rate": round(1 - row[Hypothesis.LEGITIMATE.value] / sessions, 6),
                "correct_attribution_rate": round(row[attack.value] / sessions, 6),
            }
        result = {
            "confusion_matrix": matrix,
            "false_alarm_rate": round(1 - legitimate[Hypothesis.LEGITIMATE.value] / sessions, 6),
            "attacks": attacks,
        }
        if name.startswith("baseline"):
            result["thresholds"] = detectors[name].thresholds.to_dict()
        return result

    return {
        "metadata": {
            "theta": theta,
            "sessions_per_hypothesis": sessions,
            "seed": seed,
            "n_rounds": n_rounds,
            "alpha": alpha,
            "cell_counts": n.tolist(),
            "design": "balanced paired Monte Carlo",
        },
        "labels": labels,
        "detectors": {name: summarise(name) for name in detectors},
    }
