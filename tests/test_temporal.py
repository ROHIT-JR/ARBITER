"""Deterministic, hardware-free tests for the temporal detection layer."""

from dataclasses import replace

import numpy as np
import pytest

from arbiter.detection import TemporalDetector, UnifiedDetector
from arbiter.detection.temporal import (
    fisher_g_statistic,
    longest_mismatch_run,
    maximum_windowed_mismatches,
    sliding_window_moments,
)
from arbiter.pipeline import Arbiter
from arbiter.qds_simulation import ChannelParams, Hypothesis, SessionConfig, simulate_session
from arbiter.qds_simulation.model import cell_probabilities


def _signature_transcript(outcomes: np.ndarray):
    base = simulate_session(config=SessionConfig(n_rounds=len(outcomes)), seed=701)
    return replace(base, cells=np.zeros(len(outcomes), dtype=np.int64), outcomes=np.asarray(outcomes, dtype=np.int8))


def test_sliding_moments_and_burst_primitives_are_explicit_at_edges():
    outcomes = np.array([0, 1, 1, 0, 1], dtype=np.int8)
    windows = sliding_window_moments(outcomes, window=3, stride=2)
    assert [(w.start, w.stop, w.count) for w in windows] == [(0, 3, 3), (2, 5, 3), (4, 5, 1)]
    assert windows[0].mismatch_rate == pytest.approx(2 / 3)
    assert longest_mismatch_run(outcomes) == 2
    assert maximum_windowed_mismatches(outcomes, window=3) == 2
    assert fisher_g_statistic([0, 1, 0]) == 0


def test_temporal_detector_is_deterministic_and_declares_bonferroni_budget():
    transcript = simulate_session(seed=91)
    detector = TemporalDetector(alpha=0.09, n_calibration=600, seed=9)
    first = detector.evaluate(transcript)
    second = detector.evaluate(transcript)
    assert first.to_dict() == second.to_dict()
    assert first.per_test_alpha == pytest.approx(0.01)
    assert first.to_dict()["multiple_testing"] == "Bonferroni across 3 streams × 3 tests"
    assert set(first.streams) == {"signature", "freshness", "chsh"}


def test_periodic_interference_is_caught_by_calibrated_spectral_test():
    # A clean period-12 mismatch train is deliberately outside the i.i.d.
    # Bernoulli model.  The test is calibrated from H0, not an ML score.
    outcomes = np.zeros(1200, dtype=np.int8)
    outcomes[::12] = 1
    detector = TemporalDetector(alpha=0.09, n_calibration=1200, seed=4)
    result = detector.evaluate(_signature_transcript(outcomes))
    spectral = result.streams["signature"].fisher_g
    assert spectral.flagged
    assert spectral.p_value <= spectral.alpha


def test_burst_test_beats_pooled_glrt_for_local_error_burst():
    """A 60-round block has the same pooled count as diffuse errors but is temporal."""
    params = ChannelParams()
    p0 = cell_probabilities(Hypothesis.LEGITIMATE, 0, params)
    p_attack = cell_probabilities(Hypothesis.FORGERY, 1, params)[0]
    temporal = TemporalDetector(params, alpha=0.09, n_calibration=1200, seed=17)
    glrt = UnifiedDetector(params, alpha=0.09, n_calibration=1200, seed=17)
    temporal_hits = pooled_hits = 0
    base = simulate_session(config=SessionConfig(n_rounds=1200), seed=701)
    for seed in range(16):
        rng = np.random.default_rng(seed)
        outcomes = (rng.random(1200) < p0[base.cells]).astype(np.int8)
        attack_block = (np.arange(1200) >= 480) & (np.arange(1200) < 540) & (base.cells == 0)
        outcomes[attack_block] = (rng.random(attack_block.sum()) < p_attack).astype(np.int8)
        transcript = replace(base, outcomes=outcomes)
        temporal_hits += temporal.evaluate(transcript).streams["signature"].flagged
        pooled_hits += glrt.evaluate(transcript).rejected
    assert temporal_hits > pooled_hits
    assert temporal_hits >= 12


def test_null_rate_is_at_or_below_temporal_family_budget_for_fixed_schedule():
    """Empirical check conditional on a fixed observed schedule (no hardware)."""
    transcript = simulate_session(seed=111)
    detector = TemporalDetector(alpha=0.09, n_calibration=1600, seed=31)
    p0 = cell_probabilities(Hypothesis.LEGITIMATE, 0, ChannelParams())[transcript.cells]
    rng = np.random.default_rng(55)
    flags = 0
    for _ in range(250):
        null = replace(transcript, outcomes=(rng.random(len(p0)) < p0).astype(np.int8))
        flags += detector.evaluate(null).rejected
    # A binomial 99% upper bound at p=.09 is about .14 for 250 sessions;
    # the assertion is intentionally conservative but catches alpha leaks.
    assert flags / 250 <= 0.14


def test_periodic_simulator_fixture_has_the_requested_schedule():
    transcript = simulate_session(
        Hypothesis.FORGERY,
        config=SessionConfig(n_rounds=31, periodic_attack_every=7),
        seed=12,
    )
    assert np.array_equal(np.flatnonzero(transcript.attacked), np.array([0, 7, 14, 21, 28]))
    assert transcript.theta == pytest.approx(5 / 31)


def test_pipeline_spends_overall_alpha_across_rejection_layers():
    arbiter = Arbiter(alpha=0.03)
    verdict = arbiter.verify(simulate_session(seed=321))
    assert arbiter.layer_alpha == pytest.approx(0.01)
    assert verdict.temporal.alpha == pytest.approx(0.01)
    assert verdict.unified.alpha == pytest.approx(0.01)
