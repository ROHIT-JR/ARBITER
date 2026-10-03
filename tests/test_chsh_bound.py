"""The tightened CHSH confidence half-width (issue #23).

The half-width was changed from a union bound over the four settings (whose
half-widths were *added*) to a single Hoeffding application to the linear
combination S_hat = E00 + E01 + E10 - E11. That is ~5.46x tighter, which is
what makes certification reachable at a realistic session length -- so the
coverage guarantee is worth checking directly rather than trusting the algebra.
"""

import numpy as np
import pytest

from arbiter.detection.chsh import chsh_half_width, chsh_precheck, chsh_rounds_for_certification
from arbiter.qds_simulation import SessionConfig, simulate_session
from arbiter.qds_simulation.model import CHSH_SIGNS

DELTA = 0.05


def _union_half_width(n_ab, delta=DELTA):
    """The previous, looser bound -- kept here only for comparison."""
    return float(np.sum(np.sqrt(2 * np.log(8 / delta) / np.asarray(n_ab, float))))


@pytest.mark.parametrize("m", [50, 75, 150, 400])
@pytest.mark.parametrize("v", [0.92, 0.70])
def test_half_width_covers_at_one_minus_delta(m, v):
    """Monte-Carlo the realised miss rate against the delta budget."""
    trials = 40_000
    rng = np.random.default_rng(abs(hash((m, v))) % 2**32)
    e_true = CHSH_SIGNS * v / np.sqrt(2)
    s_true = float(np.sum(CHSH_SIGNS * e_true))
    p_mismatch = (1 - CHSH_SIGNS * e_true) / 2

    k = rng.binomial(m, p_mismatch[None, :], size=(trials, len(CHSH_SIGNS)))
    s_hat = (1 - 2 * k / m).sum(axis=1)

    hw = chsh_half_width(np.full(len(CHSH_SIGNS), m), DELTA)
    miss_rate = float(np.mean(np.abs(s_hat - s_true) >= hw))
    assert miss_rate <= DELTA, f"coverage violated: {miss_rate:.4f} > {DELTA}"


@pytest.mark.parametrize("m", [50, 200])
def test_tighter_than_the_union_bound(m):
    n_ab = np.full(len(CHSH_SIGNS), m)
    assert chsh_half_width(n_ab, DELTA) < _union_half_width(n_ab, DELTA)
    # At equal counts the half-width ratio is a constant, independent of m.
    ratio = _union_half_width(n_ab, DELTA) / chsh_half_width(n_ab, DELTA)
    assert ratio == pytest.approx(2.35, abs=0.02)
    # Half-width scales as 1/sqrt(m), so the saving in *rounds* is the square.
    assert ratio**2 == pytest.approx(5.5, abs=0.1)


def test_half_width_shrinks_with_more_rounds():
    counts = [np.full(4, m) for m in (50, 100, 200, 400)]
    widths = [chsh_half_width(c, DELTA) for c in counts]
    assert widths == sorted(widths, reverse=True)


def test_half_width_is_infinite_for_unsampled_settings():
    assert chsh_half_width(np.array([10, 10, 10, 0]), DELTA) == float("inf")


def test_rounds_for_certification_matches_the_half_width():
    """The advertised budget must actually certify, and one step less must not."""
    v = 0.92
    total = chsh_rounds_for_certification(v, DELTA)
    margin = 2 * np.sqrt(2) * v - 2.0
    per_setting = total // len(CHSH_SIGNS)
    assert chsh_half_width(np.full(4, per_setting), DELTA) < margin
    assert chsh_half_width(np.full(4, per_setting - 1), DELTA) >= margin


def test_no_certification_budget_without_a_violation_to_certify():
    # 2*sqrt(2)*v <= 2 for v <= 1/sqrt(2): nothing to certify.
    assert chsh_rounds_for_certification(0.70, DELTA) == 0


def test_certification_is_reachable_at_a_realistic_session_length():
    """With the loose bound this needed ~8000 rounds; it should now certify
    well below that."""
    transcript = simulate_session(config=SessionConfig(n_rounds=2500, round_mix=(0.5, 0.25, 0.25)), seed=11)
    assert chsh_precheck(transcript).certified


def test_precheck_excludes_bell_fidelity_cells_from_s():
    """Regression: an open-ended n[2:] folded the aligned cells into S and
    pushed it past the Tsirelson bound."""
    transcript = simulate_session(config=SessionConfig(n_rounds=3000), seed=4)
    result = chsh_precheck(transcript)
    assert len(result.n_per_setting) == len(CHSH_SIGNS)
    assert result.S <= 2 * np.sqrt(2) + 0.2  # sampling slack, but nowhere near 5+


def test_honest_channel_is_not_flagged_at_the_default_mix():
    """The default round mix must keep the point-estimate check quiet."""
    flags = 0
    for seed in range(20):
        transcript = simulate_session(config=SessionConfig(n_rounds=1200), seed=seed)
        flags += chsh_precheck(transcript).flagged
    assert flags == 0, f"{flags}/20 honest sessions flagged"
