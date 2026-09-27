"""Unified multi-hypothesis attack-attribution detector.

One test replaces four independent per-attack thresholds:

    H0 : legitimate session
    H1 : union over h in {forgery, impersonation, replay, channel} and
         attack strength theta in (0, 1]

For any *simple* alternative (h, theta) the likelihood-ratio test is the most
powerful level-alpha test (Neyman-Pearson lemma). The alternative here is
composite, so we use the generalised likelihood ratio

    Lambda = max_{h, theta} log L(h, theta) - log L(H0),

whose level-alpha threshold is calibrated by exact Monte-Carlo under H0
*conditional on the observed per-cell round counts*, so the false-alarm rate
is alpha by construction (up to MC error) rather than by asymptotics.

All likelihoods come from the Born-rule model in
:mod:`arbiter.qds_simulation.model`; optimality is therefore relative to that
model (see docs/threat-model.md).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.special import logsumexp

from arbiter.qds_simulation.model import (
    ALL_OR_NOTHING,
    ATTACKS,
    ChannelParams,
    Hypothesis,
    cell_probabilities,
)
from arbiter.qds_simulation.protocol import Transcript

DEFAULT_THETA_GRID = np.linspace(0.05, 1.0, 20)


def build_alternatives(params: ChannelParams, theta_grid: np.ndarray):
    """Enumerate the composite alternative as (hypothesis, theta) components.

    Returns ``(components, probs, groups)``: probs[j] is the per-cell
    outcome-1 probability of component j, and groups[h] the component indices
    belonging to attack h. All-or-nothing attacks get the single theta = 1.
    """
    components = [(h, float(t)) for h in ATTACKS for t in ((1.0,) if h in ALL_OR_NOTHING else theta_grid)]
    probs = np.array([cell_probabilities(h, t, params) for h, t in components])
    groups = {h: np.array([j for j, (g, _) in enumerate(components) if g is h]) for h in ATTACKS}
    return components, probs, groups


@dataclass
class UnifiedVerdict:
    rejected: bool
    statistic: float
    threshold: float
    alpha: float
    attribution: Hypothesis  # LEGITIMATE when not rejected
    posterior: dict[str, float]  # over all five hypotheses (uniform priors)
    theta_hat: dict[str, float]  # MLE attack strength per attack
    loglik: dict[str, float]  # profile log-likelihood per hypothesis

    def to_dict(self) -> dict:
        return {
            "rejected": self.rejected,
            "statistic": round(self.statistic, 4),
            "threshold": round(self.threshold, 4),
            "alpha": self.alpha,
            "attribution": self.attribution.value,
            "posterior": {k: round(v, 6) for k, v in self.posterior.items()},
            "theta_hat": {k: round(v, 3) for k, v in self.theta_hat.items()},
            "loglik": {k: round(v, 3) for k, v in self.loglik.items()},
        }


class UnifiedDetector:
    def __init__(
        self,
        params: ChannelParams | None = None,
        alpha: float = 0.01,
        theta_grid: np.ndarray = DEFAULT_THETA_GRID,
        n_calibration: int = 4000,
        seed: int | None = 0,
    ):
        self.params = params or ChannelParams()
        self.alpha = alpha
        self.theta_grid = np.asarray(theta_grid, float)
        self.n_calibration = n_calibration
        self._rng = np.random.default_rng(seed)
        self.p0 = cell_probabilities(Hypothesis.LEGITIMATE, 0.0, self.params)
        self.components, self.alt, self.groups = build_alternatives(self.params, self.theta_grid)
        self._logp0 = np.log(np.clip(np.stack([1 - self.p0, self.p0]), 1e-300, None))
        self._logalt = np.log(np.clip(np.stack([1 - self.alt, self.alt]), 1e-300, None))

    # log-likelihood kernels (binomial coefficients cancel in every ratio)
    def _ll0(self, n: np.ndarray, k: np.ndarray) -> np.ndarray:
        return k @ self._logp0[1] + (n - k) @ self._logp0[0]

    def _llalt(self, n: np.ndarray, k: np.ndarray) -> np.ndarray:
        return k @ self._logalt[1].T + (n - k) @ self._logalt[0].T

    def _glr(self, n: np.ndarray, k: np.ndarray) -> np.ndarray:
        return self._llalt(n, k).max(axis=-1) - self._ll0(n, k)

    def threshold(self, n: np.ndarray) -> float:
        """Level-alpha GLR threshold for per-cell round counts ``n``."""
        n = np.asarray(n, np.int64)
        k_sim = self._rng.binomial(n, self.p0, size=(self.n_calibration, len(n)))
        stats = self._glr(np.broadcast_to(n, k_sim.shape), k_sim)
        return float(np.quantile(stats, 1 - self.alpha))

    def evaluate_counts(self, n: np.ndarray, k: np.ndarray) -> UnifiedVerdict:
        n = np.asarray(n, float)
        k = np.asarray(k, float)
        ll0 = float(self._ll0(n, k))
        llalt = self._llalt(n, k)
        stat = float(llalt.max() - ll0)
        tau = self.threshold(n.astype(np.int64))

        # Posterior with uniform prior over the five hypotheses and over theta.
        log_marg = {Hypothesis.LEGITIMATE: ll0}
        for h, idx in self.groups.items():
            log_marg[h] = float(logsumexp(llalt[idx]) - np.log(len(idx)))
        z = logsumexp(list(log_marg.values()))
        posterior = {h.value: float(np.exp(v - z)) for h, v in log_marg.items()}

        rejected = stat > tau
        if rejected:
            attribution = max(ATTACKS, key=lambda h: log_marg[h])
        else:
            attribution = Hypothesis.LEGITIMATE
        return UnifiedVerdict(
            rejected=rejected,
            statistic=stat,
            threshold=tau,
            alpha=self.alpha,
            attribution=attribution,
            posterior=posterior,
            theta_hat={h.value: self.components[idx[llalt[idx].argmax()]][1] for h, idx in self.groups.items()},
            loglik={Hypothesis.LEGITIMATE.value: ll0}
            | {h.value: float(llalt[idx].max()) for h, idx in self.groups.items()},
        )

    def evaluate(self, transcript: Transcript) -> UnifiedVerdict:
        return self.evaluate_counts(*transcript.counts())
