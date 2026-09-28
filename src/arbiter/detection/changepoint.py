"""Change-point detection with a Shiryaev--Roberts style e-detector.

For every possible change round ``s`` and every attack-model component, the
detector starts a likelihood-ratio e-process at ``s``.  Their
Shiryaev--Roberts sum is updated recursively, so no detector ever looks at
the simulator's injected onset.  Unlike the ordinary sequential test this
allows evidence before a late change to be discarded.  The threshold is an
average-run-length (ARL) operating point rather than a finite-session
false-alarm probability.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.special import logsumexp

from arbiter.detection.unified import DEFAULT_THETA_GRID, build_alternatives
from arbiter.qds_simulation.model import ATTACKS, ChannelParams, Hypothesis, cell_probabilities
from arbiter.qds_simulation.protocol import Transcript


@dataclass
class ChangePointVerdict:
    """Outcome of a change-point e-detector run.

    ``detection_delay`` is evaluation metadata only: it is populated by
    :meth:`ChangePointDetector.evaluate` for a simulator transcript with a
    declared onset, never used to form an alarm or attribution.
    """

    rejected: bool
    stopped_at: int
    budget: int
    arl_target: float
    log_threshold: float
    estimated_onset: int | None
    detection_delay: int | None
    attribution: Hypothesis
    posterior: dict[str, float]
    log_evidence: np.ndarray

    @property
    def change_point(self) -> int | None:
        """Alias for callers that use the standard change-point terminology."""
        return self.estimated_onset

    def to_dict(self, trajectory: bool = False) -> dict:
        result = {
            "rejected": self.rejected,
            "stopped_at": self.stopped_at,
            "budget": self.budget,
            "arl_target": self.arl_target,
            "log_threshold": round(self.log_threshold, 4),
            "estimated_onset": self.estimated_onset,
            "detection_delay": self.detection_delay,
            "attribution": self.attribution.value,
            "posterior": {name: round(value, 6) for name, value in self.posterior.items()},
        }
        if trajectory:
            result["log_evidence"] = [round(float(value), 4) for value in self.log_evidence]
        return result


class ChangePointDetector:
    """Detect a persistent change while controlling an ARL operating point.

    ``arl_target`` is in rounds.  When omitted it is ``1 / alpha`` nominal
    sessions of ``reference_session_rounds`` rounds.  The statistic is the
    mixture Shiryaev--Roberts e-detector

    ``R_t = sum_j w_j sum_(s <= t) prod_(i=s)^t LR_{i,j}``.

    The recursion is numerically evaluated in log space.  Its expectation
    under the legitimate model grows at one unit per round, giving the
    threshold a direct ARL interpretation; deployments should validate the
    selected operating point against their calibrated legitimate traffic.
    """

    def __init__(
        self,
        params: ChannelParams | None = None,
        alpha: float = 0.01,
        theta_grid: np.ndarray = DEFAULT_THETA_GRID,
        *,
        arl_target: float | None = None,
        reference_session_rounds: int = 1200,
    ) -> None:
        if not 0 < alpha < 1:
            raise ValueError("alpha must lie in (0, 1)")
        if reference_session_rounds < 1:
            raise ValueError("reference_session_rounds must be positive")
        self.params = params or ChannelParams()
        self.alpha = float(alpha)
        self.theta_grid = np.asarray(theta_grid, dtype=float)
        invalid_theta_grid = (
            self.theta_grid.ndim != 1
            or self.theta_grid.size == 0
            or np.any((self.theta_grid <= 0) | (self.theta_grid > 1))
        )
        if invalid_theta_grid:
            raise ValueError("theta_grid values must lie in (0, 1]")
        self.arl_target = float(arl_target if arl_target is not None else reference_session_rounds / alpha)
        if self.arl_target <= 1:
            raise ValueError("arl_target must exceed one round")

        p0 = cell_probabilities(Hypothesis.LEGITIMATE, 0.0, self.params)
        _, alt, self.groups = build_alternatives(self.params, self.theta_grid)
        self._inc = np.stack(
            [
                np.log(1 - alt).T - np.log(1 - p0)[:, None],
                np.log(alt).T - np.log(p0)[:, None],
            ]
        )
        self._logw = np.empty(alt.shape[0])
        for indexes in self.groups.values():
            self._logw[indexes] = -np.log(len(self.groups)) - np.log(len(indexes))

    def run(self, cells: np.ndarray, outcomes: np.ndarray) -> ChangePointVerdict:
        cells = np.asarray(cells, dtype=int)
        outcomes = np.asarray(outcomes, dtype=int)
        if cells.ndim != 1 or outcomes.ndim != 1 or len(cells) != len(outcomes):
            raise ValueError("cells and outcomes must be one-dimensional arrays of equal length")
        if len(cells) == 0:
            raise ValueError("at least one round is required")
        if np.any((cells < 0) | (cells >= self._inc.shape[1])) or np.any((outcomes < 0) | (outcomes > 1)):
            raise ValueError("cells or outcomes are outside the model domain")

        # ``log_sr`` is the log of the summed LR processes, one begun at each
        # candidate onset.  The recurrence avoids retaining a T × components
        # matrix at every round.  Candidate-onset likelihoods are reconstructed
        # once only if this inexpensive statistic actually crosses.
        log_sr = np.full(self._inc.shape[-1], -np.inf)
        cumulative = np.zeros(self._inc.shape[-1])
        prefix_sums = [cumulative.copy()]
        log_evidence = np.empty(len(cells))
        threshold = float(np.log(self.arl_target))
        rejected = False
        stopped_at = len(cells)
        estimate: int | None = None
        posterior = {attack.value: 0.0 for attack in ATTACKS}

        for t, (cell, outcome) in enumerate(zip(cells, outcomes, strict=True), start=1):
            increment = self._inc[outcome, cell]
            log_sr = np.logaddexp(0.0, log_sr) + increment
            cumulative = cumulative + increment
            prefix_sums.append(cumulative.copy())
            log_evidence[t - 1] = logsumexp(log_sr + self._logw)

            if log_evidence[t - 1] >= threshold:
                rejected = True
                stopped_at = t
                # L(s:t) = cumulative(t) - cumulative(s-1), with s one-based.
                candidate_log_lrs = cumulative - np.asarray(prefix_sums[:-1])
                candidate_scores = logsumexp(candidate_log_lrs + self._logw, axis=1)
                estimate = int(candidate_scores.argmax()) + 1
                winning = candidate_log_lrs[estimate - 1]
                grouped = np.array(
                    [logsumexp(winning[indexes] + self._logw[indexes]) for indexes in self.groups.values()]
                )
                probabilities = np.exp(grouped - logsumexp(grouped))
                posterior = {attack.value: float(value) for attack, value in zip(ATTACKS, probabilities, strict=True)}
                break

        return ChangePointVerdict(
            rejected=rejected,
            stopped_at=stopped_at,
            budget=len(cells),
            arl_target=self.arl_target,
            log_threshold=threshold,
            estimated_onset=estimate,
            detection_delay=None,
            attribution=ATTACKS[int(np.argmax(list(posterior.values())))] if rejected else Hypothesis.LEGITIMATE,
            posterior=posterior,
            log_evidence=log_evidence[:stopped_at],
        )

    def evaluate(self, transcript: Transcript) -> ChangePointVerdict:
        verdict = self.run(transcript.cells, transcript.outcomes.astype(int))
        if verdict.rejected and transcript.attack_onset is not None:
            verdict.detection_delay = verdict.stopped_at - transcript.attack_onset
        return verdict


# The longer spelling makes the e-process construction explicit without
# forcing callers to use a non-idiomatic class name.
ChangePointEDetector = ChangePointDetector
