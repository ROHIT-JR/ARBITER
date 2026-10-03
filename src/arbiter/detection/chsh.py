"""CHSH Bell-test channel-integrity pre-check.

S = E00 + E01 + E10 - E11. Any local (classical / intercept-resend) channel
obeys |S| <= 2; an ideal Bell pair gives 2*sqrt(2); a Werner pair with
visibility v gives 2*sqrt(2)*v.

Confidence half-width
---------------------
``S_hat - S`` is a *single* sum of independent, bounded, zero-mean terms: one
per sampled round, each of the form ``(s_ab / n_ab)(X_i - E X_i)`` with
``X_i`` in {-1, +1} and therefore of range ``2 / n_ab``. Applying Hoeffding
once to that whole linear combination gives

    P( |S_hat - S| >= t ) <= 2 exp( -2 t^2 / sum_k range_k^2 )
                           = 2 exp( -t^2 / (2 sum_ab 1/n_ab) )

    =>  t(delta) = sqrt( 2 ln(2/delta) * sum_ab 1/n_ab ).

The previous form bounded each of the four E_ab separately and *added* the
four half-widths under a union bound. That is valid but needlessly loose: it
pays the union penalty and then sums deviations which are independent and
largely cancel. At equal counts the two compare as

    4 sqrt(2 ln(8/delta) / m)    vs    sqrt(8 ln(2/delta) / m),

a half-width ratio of ~2.35 regardless of m. Half-widths scale as 1/sqrt(m),
so the saving in *rounds* is the square of that, ~5.5x: certifying a violation
at v = 0.92, delta = 0.05 needs ~328 CHSH rounds rather than ~1792, which is
the difference between certification being unreachable at a realistic session
length and comfortably within it.

``tests/test_chsh_bound.py`` checks the coverage claim by Monte Carlo rather
than trusting the algebra: the realised miss rate is ~0.002 against a 0.05
budget, so the bound remains conservative (Hoeffding ignores the binomial
variance, which is well below the worst case here).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from arbiter.qds_simulation.model import CHSH_CELLS, CHSH_SETTINGS
from arbiter.qds_simulation.protocol import Transcript


@dataclass
class ChshResult:
    S: float
    half_width: float  # (1 - delta) confidence half-width
    delta: float
    threshold: float
    n_per_setting: list[int]
    certified: bool  # S - half_width > 2: Bell violation certified
    flagged: bool  # S < threshold: channel integrity compromised

    def to_dict(self) -> dict:
        return {
            "S": round(self.S, 4),
            "half_width": round(self.half_width, 4),
            "delta": self.delta,
            "threshold": self.threshold,
            "n_per_setting": self.n_per_setting,
            "certified": self.certified,
            "flagged": self.flagged,
        }


def chsh_half_width(n_ab: np.ndarray, delta: float = 0.05) -> float:
    """Two-sided (1-delta) Hoeffding half-width for S_hat; see module docstring."""
    n_ab = np.asarray(n_ab, float)
    if np.any(n_ab <= 0):
        return float("inf")
    return float(np.sqrt(2 * np.log(2 / delta) * np.sum(1.0 / n_ab)))


def chsh_rounds_for_certification(visibility: float = 0.92, delta: float = 0.05) -> int:
    """Total CHSH rounds (over all four settings) needed to certify S > 2.

    Useful for sizing ``SessionConfig.round_mix``: the CHSH weight must be at
    least this many rounds divided by ``n_rounds``.
    """
    margin = 2 * np.sqrt(2) * visibility - 2.0
    if margin <= 0:
        return 0  # no violation to certify at this visibility
    settings = len(CHSH_SETTINGS)
    per_setting = 2 * np.log(2 / delta) * settings / margin**2
    return int(settings * np.ceil(per_setting))


def chsh_precheck(transcript: Transcript, threshold: float = 2.0, delta: float = 0.05) -> ChshResult:
    n, k = transcript.counts()
    # Only the four CHSH cells enter S. Slice by name: the Bell-fidelity cells
    # sit immediately after them and measure the same pair in aligned bases,
    # so an open-ended [2:] would silently fold them into the Bell parameter.
    n_ab, k_ab = n[CHSH_CELLS], k[CHSH_CELLS]
    if np.any(n_ab == 0):
        return ChshResult(float("nan"), float("inf"), delta, threshold, n_ab.tolist(), False, True)
    S = float(np.sum(1 - 2 * k_ab / n_ab))
    hw = chsh_half_width(n_ab, delta)
    return ChshResult(S, hw, delta, threshold, n_ab.tolist(), S - hw > 2, S < threshold)
