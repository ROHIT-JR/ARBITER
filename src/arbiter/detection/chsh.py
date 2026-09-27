"""CHSH Bell-test channel-integrity pre-check.

S = E00 + E01 + E10 - E11. Any local (classical / intercept-resend) channel
obeys |S| <= 2; an ideal Bell pair gives 2*sqrt(2); a Werner pair with
visibility v gives 2*sqrt(2)*v. Each E_ab is a mean of +-1 variables, so by
Hoeffding plus a union bound over the four settings,

    P( |S_hat - S| >= sum_ab sqrt(2 ln(8/delta) / n_ab) ) <= delta.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from arbiter.qds_simulation.protocol import Transcript


@dataclass
class ChshResult:
    S: float
    half_width: float           # (1 - delta) confidence half-width
    delta: float
    threshold: float
    n_per_setting: list[int]
    certified: bool             # S - half_width > 2: Bell violation certified
    flagged: bool               # S < threshold: channel integrity compromised

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


def chsh_precheck(transcript: Transcript, threshold: float = 2.0, delta: float = 0.05) -> ChshResult:
    n, k = transcript.counts()
    n_ab, k_ab = n[2:], k[2:]
    if np.any(n_ab == 0):
        return ChshResult(float("nan"), float("inf"), delta, threshold, n_ab.tolist(), False, True)
    S = float(np.sum(1 - 2 * k_ab / n_ab))
    hw = float(np.sum(np.sqrt(2 * np.log(8 / delta) / n_ab)))
    return ChshResult(S, hw, delta, threshold, n_ab.tolist(), S - hw > 2, S < threshold)
