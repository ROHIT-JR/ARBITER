"""Freshness checks.

Two layers, catching two different replays:

* :class:`NonceRegistry` -- classical: a transcript whose QRNG session nonce
  was already verified is a verbatim resubmission.
* :func:`freshness_test` -- quantum: freshness rounds encode eigenstates
  derived from *today's* nonce, so states recorded in an earlier session
  mismatch at rate ~1/2. A one-sided exact binomial test flags an excess
  over the calibrated legitimate mismatch rate. (The unified detector uses
  the same rounds jointly; this is the standalone, per-layer view.)
"""

from __future__ import annotations

from dataclasses import dataclass

from scipy.stats import binom

from arbiter.qds_simulation.model import ChannelParams, Hypothesis, cell_probabilities
from arbiter.qds_simulation.protocol import Transcript


class NonceRegistry:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    def check_and_register(self, nonce: str) -> bool:
        """True if the nonce is fresh (and records it); False on reuse."""
        if nonce in self._seen:
            return False
        self._seen.add(nonce)
        return True


@dataclass
class FreshnessResult:
    rounds: int
    mismatches: int
    observed_rate: float
    expected_rate: float
    p_value: float
    flagged: bool

    def to_dict(self) -> dict:
        return {k: (round(v, 6) if isinstance(v, float) else v) for k, v in self.__dict__.items()}


def freshness_test(transcript: Transcript, params: ChannelParams, alpha: float = 0.01) -> FreshnessResult:
    n, k = transcript.counts()
    n_f, k_f = int(n[1]), int(k[1])
    p0 = float(cell_probabilities(Hypothesis.LEGITIMATE, 0.0, params)[1])
    p_value = float(binom.sf(k_f - 1, n_f, p0)) if n_f else 1.0
    return FreshnessResult(n_f, k_f, k_f / n_f if n_f else 0.0, p0, p_value, p_value < alpha)
