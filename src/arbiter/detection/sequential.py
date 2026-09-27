"""Anytime-valid sequential detection (adaptive stopping).

Each component (h, theta) of the alternative defines a likelihood ratio
``L_t = prod_{i<=t} p_{h,theta}(x_i) / p_0(x_i)``, which under H0 is a
nonnegative martingale with mean 1. A fixed-weight mixture ``E_t = sum w L_t``
is therefore also one (an e-process), and Ville's inequality gives

    P_H0( exists t : E_t >= 1/alpha ) <= alpha.

So the verifier may look after *every* round and stop the moment
``E_t >= 1/alpha`` without inflating the false-alarm rate -- the threshold
adapts to the data actually seen instead of a fixed, pre-calibrated sample
size. If the budget is exhausted without crossing, the session is accepted.

Raising the alarm and naming the attack are separate questions: evidence
that *something* is wrong accrues faster than evidence of *which* attack. So
after the alarm we keep reading rounds until the attack posterior reaches
``attribution_confidence`` (or the budget runs out) and report both times.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.special import logsumexp

from arbiter.detection.unified import DEFAULT_THETA_GRID, build_alternatives
from arbiter.qds_simulation.model import ATTACKS, ChannelParams, Hypothesis, cell_probabilities
from arbiter.qds_simulation.protocol import Transcript


@dataclass
class SequentialVerdict:
    rejected: bool
    stopped_at: int                 # alarm time (== budget if never rejected)
    attributed_at: int              # rounds used for the attribution
    budget: int
    log_threshold: float
    attribution: Hypothesis
    posterior: dict[str, float]     # over attacks, at the stopping time
    log_evidence: np.ndarray        # log E_t for t = 1..budget

    def to_dict(self, trajectory: bool = False) -> dict:
        d = {
            "rejected": self.rejected,
            "stopped_at": self.stopped_at,
            "attributed_at": self.attributed_at,
            "budget": self.budget,
            "log_threshold": round(self.log_threshold, 4),
            "attribution": self.attribution.value,
            "posterior": {k: round(v, 6) for k, v in self.posterior.items()},
        }
        if trajectory:
            d["log_evidence"] = [round(float(x), 4) for x in self.log_evidence]
        return d


class SequentialDetector:
    def __init__(self, params: ChannelParams | None = None, alpha: float = 0.01,
                 theta_grid: np.ndarray = DEFAULT_THETA_GRID, attribution_confidence: float = 0.99):
        self.params = params or ChannelParams()
        self.alpha = alpha
        self.attribution_confidence = attribution_confidence
        self.theta_grid = np.asarray(theta_grid, float)
        p0 = cell_probabilities(Hypothesis.LEGITIMATE, 0.0, self.params)
        _, alt, self.groups = build_alternatives(self.params, self.theta_grid)
        # increment[outcome, cell, component] = log p_alt - log p_0
        self._inc = np.stack([
            np.log(1 - alt).T - np.log(1 - p0)[:, None],
            np.log(alt).T - np.log(p0)[:, None],
        ])
        # Prior weight: uniform over attacks, then uniform over each one's thetas.
        self._logw = np.empty(alt.shape[0])
        for idx in self.groups.values():
            self._logw[idx] = -np.log(len(self.groups)) - np.log(len(idx))

    def run(self, cells: np.ndarray, outcomes: np.ndarray) -> SequentialVerdict:
        cum = np.cumsum(self._inc[outcomes, cells], axis=0)  # (T, components)
        log_e = logsumexp(cum + self._logw, axis=1)
        log_thr = float(np.log(1 / self.alpha))
        crossed = np.flatnonzero(log_e >= log_thr)
        rejected = crossed.size > 0
        t = int(crossed[0]) + 1 if rejected else len(cells)

        # attack posterior after every round, shape (T, n_attacks)
        marg = np.stack(
            [logsumexp(cum[:, idx] + self._logw[idx], axis=1) for idx in self.groups.values()], axis=1
        )
        posts = np.exp(marg - logsumexp(marg, axis=1, keepdims=True))
        t_attr = t
        if rejected:
            confident = np.flatnonzero(posts[t - 1 :].max(axis=1) >= self.attribution_confidence)
            t_attr = t + int(confident[0]) if confident.size else len(cells)
        post = posts[t_attr - 1]
        return SequentialVerdict(
            rejected=rejected,
            stopped_at=t,
            attributed_at=t_attr,
            budget=len(cells),
            log_threshold=log_thr,
            attribution=ATTACKS[int(post.argmax())] if rejected else Hypothesis.LEGITIMATE,
            posterior={h.value: float(p) for h, p in zip(ATTACKS, post)},
            log_evidence=log_e,
        )

    def evaluate(self, transcript: Transcript) -> SequentialVerdict:
        return self.run(transcript.cells, transcript.outcomes.astype(int))
