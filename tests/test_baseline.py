import numpy as np
import pytest

from arbiter.detection import BaselineDetector
from arbiter.detection.baseline import balanced_cell_counts
from arbiter.qds_simulation import ATTACKS, ChannelParams, Hypothesis, cell_probabilities
from arbiter.qds_simulation.model import BELL_FIDELITY_CELLS, CELLS


@pytest.fixture(scope="module")
def setup():
    params = ChannelParams()
    detector = BaselineDetector(params, alpha=0.01, n_calibration=50_000, seed=7)
    return params, detector, balanced_cell_counts(1200)


def test_baseline_false_alarm_rate_is_calibrated(setup):
    params, detector, n = setup
    rng = np.random.default_rng(101)
    p0 = cell_probabilities(Hypothesis.LEGITIMATE, 0, params)
    alarms = sum(detector.evaluate_counts(n, k).rejected for k in rng.binomial(n, p0, size=(5000, len(CELLS))))
    # At alpha=.01 the 99.9% binomial upper bound is below .018.
    assert alarms / 5000 <= 0.018
    assert detector.thresholds.calibration_false_alarm_rate <= detector.alpha


@pytest.mark.parametrize("attack", ATTACKS)
def test_baseline_detects_every_full_strength_attack(setup, attack):
    params, detector, n = setup
    rng = np.random.default_rng(200 + list(ATTACKS).index(attack))
    p = cell_probabilities(attack, 1, params)
    assert all(detector.evaluate_counts(n, k).rejected for k in rng.binomial(n, p, size=(30, len(CELLS))))


def test_bonferroni_splits_alpha_over_the_marginal_tests():
    """Five marginal tests back four rules: the channel-manipulation rule
    screens both shared-pair witnesses (CHSH S and Bell fidelity), so alpha/4
    would overspend the family-wise budget."""
    detector = BaselineDetector(alpha=0.01, n_calibration=10_000, seed=3, bonferroni=True)
    assert detector.thresholds.per_rule_alpha == pytest.approx(0.002)
    assert detector.thresholds.calibration_false_alarm_rate <= detector.alpha


def test_baseline_uses_the_bell_fidelity_rounds():
    """The baseline must see every round the detector does, or the head-to-head
    comparison flatters ARBITER."""
    counts = balanced_cell_counts(1200)
    assert np.all(counts[BELL_FIDELITY_CELLS] > 0)


def test_legacy_three_tuple_mix_leaves_bell_cells_empty():
    counts = balanced_cell_counts(1200, (0.5, 0.25, 0.25))
    assert np.all(counts[BELL_FIDELITY_CELLS] == 0)
    assert counts.sum() == 1200
