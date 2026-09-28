import numpy as np
import pytest

from arbiter.detection import BaselineDetector
from arbiter.detection.baseline import balanced_cell_counts
from arbiter.qds_simulation import ATTACKS, ChannelParams, Hypothesis, cell_probabilities


@pytest.fixture(scope="module")
def setup():
    params = ChannelParams()
    detector = BaselineDetector(params, alpha=0.01, n_calibration=50_000, seed=7)
    return params, detector, balanced_cell_counts(1200)


def test_baseline_false_alarm_rate_is_calibrated(setup):
    params, detector, n = setup
    rng = np.random.default_rng(101)
    p0 = cell_probabilities(Hypothesis.LEGITIMATE, 0, params)
    alarms = sum(detector.evaluate_counts(n, k).rejected for k in rng.binomial(n, p0, size=(5000, 6)))
    # At alpha=.01 the 99.9% binomial upper bound is below .018.
    assert alarms / 5000 <= 0.018
    assert detector.thresholds.calibration_false_alarm_rate <= detector.alpha


@pytest.mark.parametrize("attack", ATTACKS)
def test_baseline_detects_every_full_strength_attack(setup, attack):
    params, detector, n = setup
    rng = np.random.default_rng(200 + list(ATTACKS).index(attack))
    p = cell_probabilities(attack, 1, params)
    assert all(detector.evaluate_counts(n, k).rejected for k in rng.binomial(n, p, size=(30, 6)))


def test_bonferroni_uses_alpha_over_four():
    detector = BaselineDetector(alpha=0.01, n_calibration=10_000, seed=3, bonferroni=True)
    assert detector.thresholds.per_rule_alpha == pytest.approx(0.0025)
