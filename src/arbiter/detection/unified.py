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

When visibility is treated as a nuisance parameter (v_min < v_max), the GLR
statistic becomes:

    Lambda = max_{h, theta, v in [v_min, v_max]} log L(h, theta, v) - max_{v in [v_min, v_max]} log L(H0, v)

The threshold is calibrated at the worst-case visibility in [v_min, v_max]
to guarantee FAR ≤ alpha across the entire range.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import numpy as np
from scipy.special import logsumexp

from arbiter.qds_simulation.model import (
    ALL_OR_NOTHING,
    ATTACKS,
    ChannelParams,
    Hypothesis,
    cell_probabilities,
    estimate_visibility,
    visibility_ci,
)
from arbiter.qds_simulation.protocol import Transcript

DEFAULT_THETA_GRID = np.linspace(0.0, 1.0, 21)


def build_alternatives(params: ChannelParams, theta_grid: np.ndarray, protocol: str = "prf"):
    """Enumerate the composite alternative as (hypothesis, theta) components.

    Returns ``(components, probs, groups)``: probs[j] is the per-cell
    outcome-1 probability of component j, and groups[h] the component indices
    belonging to attack h. All-or-nothing attacks get the single theta = 1.
    """
    components = [(h, float(t)) for h in ATTACKS for t in ((1.0,) if h in ALL_OR_NOTHING else theta_grid)]
    probs = np.array([cell_probabilities(h, t, params, protocol) for h, t in components])
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
    v_hat: float | None = None  # MLE visibility under H0
    v_ci: tuple[float, float] | None = None  # 95% CI for visibility
    v_design: float | None = None  # Detector's assumed visibility (params.visibility)

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
            "v_hat": round(self.v_hat, 4) if self.v_hat is not None else None,
            "v_ci": [round(self.v_ci[0], 4), round(self.v_ci[1], 4)] if self.v_ci is not None else None,
            "v_design": round(self.v_design, 4) if self.v_design is not None else None,
        }


class UnifiedDetector:
    def __init__(
        self,
        params: ChannelParams | None = None,
        alpha: float = 0.01,
        theta_grid: np.ndarray = DEFAULT_THETA_GRID,
        n_calibration: int = 4000,
        seed: int | None = 0,
        protocol: str = "prf",
        v_min: float | None = None,
        v_max: float | None = None,
    ):
        self.params = params or ChannelParams()
        self.alpha = alpha
        self.theta_grid = np.asarray(theta_grid, float)
        self.n_calibration = n_calibration
        self.protocol = protocol
        self.v_min = v_min if v_min is not None else self.params.visibility
        self.v_max = v_max if v_max is not None else self.params.visibility
        # Keep calibration reproducible without sharing mutable RNG state
        # between cache entries. ``None`` still chooses fresh entropy for each
        # detector instance, but an entry is fixed for the life of that
        # instance once its count-vector key has been selected.
        self._calibration_seed = tuple(int(x) for x in np.random.SeedSequence(seed).generate_state(4, dtype=np.uint32))
        self.p0 = cell_probabilities(Hypothesis.LEGITIMATE, 0.0, self.params, protocol)
        self.components, self.alt, self.groups = build_alternatives(self.params, self.theta_grid, protocol)
        self._logp0 = np.log(np.clip(np.stack([1 - self.p0, self.p0]), 1e-300, None))
        self._logalt = np.log(np.clip(np.stack([1 - self.alt, self.alt]), 1e-300, None))
        self._threshold_cached = lru_cache(maxsize=1024)(self._calibrate_threshold)

    # log-likelihood kernels (binomial coefficients cancel in every ratio)
    def _ll0(self, n: np.ndarray, k: np.ndarray, p0: np.ndarray | None = None) -> np.ndarray:
        if p0 is None:
            p0 = self.p0
        logp0 = np.log(np.clip(np.stack([1 - p0, p0]), 1e-300, None))
        return k @ logp0[1] + (n - k) @ logp0[0]

    def _ll0_v(self, n: np.ndarray, k: np.ndarray, v: float) -> np.ndarray:
        """Log-likelihood under H0 at specific visibility v."""
        from arbiter.qds_simulation.model import _legit_cell_probabilities
        p0_v = _legit_cell_probabilities(v, self.protocol)
        logp0_v = np.log(np.clip(np.stack([1 - p0_v, p0_v]), 1e-300, None))
        return k @ logp0_v[1] + (n - k) @ logp0_v[0]

    def _llalt(self, n: np.ndarray, k: np.ndarray, alt: np.ndarray | None = None) -> np.ndarray:
        if alt is None:
            alt = self.alt
        logalt = np.log(np.clip(np.stack([1 - alt, alt]), 1e-300, None))
        return k @ logalt[1].T + (n - k) @ logalt[0].T

    def _glr(self, n: np.ndarray, k: np.ndarray, p0: np.ndarray | None = None, alt: np.ndarray | None = None) -> np.ndarray:
        return self._llalt(n, k, alt).max(axis=-1) - self._ll0(n, k, p0)

    def _glr_with_v(self, n: np.ndarray, k: np.ndarray) -> np.ndarray:
        """GLR with visibility as nuisance parameter: max over v in [v_min, v_max].

        Correct GLR: max_{h,θ,v} L(h,θ,v) - max_v L(H0,v)
        Handles both single sample (n, k 1D) and batched (n, k 2D) inputs.
        """
        # Handle both 1D and 2D inputs
        n = np.asarray(n)
        k = np.asarray(k)
        if n.ndim == 1:
            n = n[None, :]
            k = k[None, :]
            squeeze_output = True
        else:
            squeeze_output = False

        v_grid = np.linspace(self.v_min, self.v_max, 20)

        # Precompute alternative likelihoods for all (h,θ,v) combinations
        from arbiter.qds_simulation.model import ALL_OR_NOTHING, ATTACKS, _legit_cell_probabilities, cell_probabilities
        components = [(h, float(t)) for h in ATTACKS for t in ((1.0,) if h in ALL_OR_NOTHING else self.theta_grid)]

        # Compute max_{h,θ,v} L(h,θ,v) for each sample
        max_alt_ll = -np.inf
        for v in v_grid:
            alt_v = np.array([cell_probabilities(h, t, ChannelParams(visibility=v), self.protocol) for h, t in components])
            logalt_v = np.log(np.clip(np.stack([1 - alt_v, alt_v]), 1e-300, None))
            llalt = k @ logalt_v[1].T + (n - k) @ logalt_v[0].T
            max_alt_ll = np.maximum(max_alt_ll, llalt.max(axis=-1))

        # Compute max_v L(H0,v)
        max_null_ll = -np.inf
        for v in v_grid:
            p0_v = _legit_cell_probabilities(v, self.protocol)
            logp0_v = np.log(np.clip(np.stack([1 - p0_v, p0_v]), 1e-300, None))
            ll0 = k @ logp0_v[1] + (n - k) @ logp0_v[0]
            max_null_ll = np.maximum(max_null_ll, ll0)

        result = max_alt_ll - max_null_ll
        return result.squeeze() if squeeze_output else result

    def _draw_null_counts(self, n: np.ndarray, rng: np.random.Generator, p0: np.ndarray | None = None) -> np.ndarray:
        """Draw calibration counts under H0 (split out for instrumentation)."""
        if p0 is None:
            p0 = self.p0
        return rng.binomial(n, p0, size=(self.n_calibration, len(n)))

    def _draw_null_counts_v(self, n: np.ndarray, rng: np.random.Generator, v: float) -> np.ndarray:
        """Draw calibration counts under H0 at specific visibility v."""
        from arbiter.qds_simulation.model import _legit_cell_probabilities
        p0_v = _legit_cell_probabilities(v, self.protocol)
        return rng.binomial(n, p0_v, size=(self.n_calibration, len(n)))

    def _calibrate_threshold(self, n_key: tuple[int, ...]) -> float:
        """Calibrate threshold for given n at detector's design visibility.

        If v_min < v_max (nuisance parameter), calibrate at worst-case v
        to guarantee FAR ≤ alpha across the entire range.
        """
        n = np.asarray(n_key, dtype=np.int64)

        if self.v_min < self.v_max - 1e-10:
            # Nuisance parameter case: calibrate at worst-case v
            v_grid = np.linspace(self.v_min, self.v_max, 10)
            worst_threshold = 0.0
            for v in v_grid:
                entry_seed = np.random.SeedSequence([*self._calibration_seed, *n_key, int(v * 1000)])
                rng = np.random.default_rng(entry_seed)
                k_sim = self._draw_null_counts_v(n, rng, v)
                stats = self._glr_with_v(n, k_sim)
                threshold_v = float(np.quantile(stats, 1 - self.alpha))
                worst_threshold = max(worst_threshold, threshold_v)
            return worst_threshold
        else:
            # Standard case: calibrate at design visibility
            entry_seed = np.random.SeedSequence([*self._calibration_seed, *n_key])
            rng = np.random.default_rng(entry_seed)
            k_sim = self._draw_null_counts(n, rng)
            stats = self._glr(np.broadcast_to(n, k_sim.shape), k_sim)
            return float(np.quantile(stats, 1 - self.alpha))

    def threshold(self, n: np.ndarray) -> float:
        """Level-alpha GLR threshold for per-cell round counts ``n``."""
        n_key = tuple(int(x) for x in np.asarray(n, dtype=np.int64))
        return self._threshold_cached(n_key)

    def evaluate_counts(self, n: np.ndarray, k: np.ndarray) -> UnifiedVerdict:
        n = np.asarray(n, float)
        k = np.asarray(k, float)

        # Compute MLE visibility and CI under H0
        v_hat = estimate_visibility(n.astype(int), k.astype(int), self.params, self.protocol)
        v_ci = visibility_ci(n.astype(int), k.astype(int), protocol=self.protocol)

        if self.v_min < self.v_max - 1e-10:
            # Nuisance parameter case: use GLR with v maximization
            stat = float(self._glr_with_v(n, k).max())
            tau = self.threshold(n.astype(np.int64))
        else:
            # Standard case
            ll0 = float(self._ll0(n, k))
            llalt = self._llalt(n, k)
            stat = float(llalt.max() - ll0)
            tau = self.threshold(n.astype(np.int64))

        # Posterior with uniform prior over the five hypotheses and over theta.
        log_marg = {Hypothesis.LEGITIMATE: float(self._ll0(n, k))}
        for h, idx in self.groups.items():
            log_marg[h] = float(logsumexp(self._llalt(n, k)[idx]) - np.log(len(idx)))
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
            theta_hat={h.value: self.components[idx[self._llalt(n, k)[idx].argmax()]][1] for h, idx in self.groups.items()},
            loglik={Hypothesis.LEGITIMATE.value: float(self._ll0(n, k))}
            | {h.value: float(self._llalt(n, k)[idx].max()) for h, idx in self.groups.items()},
            v_hat=v_hat,
            v_ci=v_ci,
            v_design=self.params.visibility,
        )

    def evaluate(self, transcript: Transcript) -> UnifiedVerdict:
        return self.evaluate_counts(*transcript.counts())
