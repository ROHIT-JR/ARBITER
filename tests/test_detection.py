import numpy as np
import pytest

from arbiter.detection import (
    SequentialDetector,
    UnifiedDetector,
    attack_bounds,
    chsh_precheck,
    freshness_test,
)
from arbiter.qds_simulation import ATTACKS, ChannelParams, Hypothesis, SessionConfig, simulate_session

PARAMS = ChannelParams()


@pytest.fixture(scope="module")
def unified():
    return UnifiedDetector(PARAMS, alpha=0.01)


@pytest.fixture(scope="module")
def sequential():
    return SequentialDetector(PARAMS, alpha=0.01)


# One fixture set per attack class, at full and partial strength.
@pytest.mark.parametrize("h", ATTACKS)
@pytest.mark.parametrize("theta", [1.0, 0.3])
def test_unified_detects_and_attributes(unified, h, theta):
    hits = 0
    for s in range(15):
        v = unified.evaluate(simulate_session(h, theta, seed=1000 + s))
        hits += v.rejected and v.attribution is h
    assert hits >= 14


@pytest.mark.parametrize("h", ATTACKS)
def test_sequential_detects_early_and_attributes(sequential, h):
    results = [sequential.evaluate(simulate_session(h, 1.0, seed=2000 + s)) for s in range(15)]
    assert all(r.rejected for r in results)
    assert np.median([r.stopped_at for r in results]) < 60  # of a 1200-round budget
    assert sum(r.attribution is h for r in results) >= 13


@pytest.mark.slow
def test_false_alarm_rates_are_controlled(unified, sequential):
    n = 400
    u = s = 0
    for i in range(n):
        t = simulate_session(seed=10_000 + i)
        u += unified.evaluate(t).rejected
        s += sequential.evaluate(t).rejected
    # alpha = 0.01 -> expect ~4; binomial 99.9% upper bound for n=400 is ~12
    assert u <= 12
    assert s <= 12  # Ville: anytime-valid, even though we look after every round


def test_unified_threshold_is_positive_and_stable(unified):
    n, _ = simulate_session(seed=1).counts()
    taus = [unified.threshold(n) for _ in range(3)]
    assert all(t > 0 for t in taus)
    assert np.ptp(taus) < 1.5


def test_theta_estimate_tracks_true_strength(unified):
    t = simulate_session(Hypothesis.CHANNEL_MANIPULATION, 0.5, SessionConfig(n_rounds=6000), seed=5)
    assert abs(unified.evaluate(t).theta_hat["channel_manipulation"] - 0.5) <= 0.1


def test_chsh_precheck():
    ok = chsh_precheck(simulate_session(config=SessionConfig(n_rounds=6000), seed=3))
    assert ok.S == pytest.approx(2 * np.sqrt(2) * PARAMS.visibility, abs=0.35)
    assert not ok.flagged
    bad = chsh_precheck(simulate_session(Hypothesis.CHANNEL_MANIPULATION, 1.0, seed=3))
    assert bad.flagged and bad.S < 2
    big = chsh_precheck(simulate_session(config=SessionConfig(n_rounds=20000), seed=4))
    assert big.certified  # Bell violation certified at 95% with enough rounds


def test_freshness_layer_flags_replay_only():
    assert freshness_test(simulate_session(Hypothesis.REPLAY, 1.0, seed=9), PARAMS).flagged
    assert not freshness_test(simulate_session(Hypothesis.FORGERY, 1.0, seed=9), PARAMS).flagged


def test_bounds_are_consistent():
    rows = attack_bounds(1.0)
    by = {r["attack"]: r for r in rows}
    for r in rows:
        assert 0 < r["measured_chernoff"] <= r["quantum_chernoff"] + 1e-9
        assert 0 <= r["helstrom_error_single_round"] <= 0.5
    # Forgery only perturbs signature rounds, where the Pauli projective
    # measurement is Helstrom-optimal -> ARBITER attains the quantum limit.
    assert by["forgery"]["measurement_efficiency"] == pytest.approx(1.0, abs=1e-4)
