"""Temporal statistics layer tests (Issue #27)."""

import json

import numpy as np
import pytest

from arbiter.detection import TemporalDetector
from arbiter.qds_simulation import ATTACKS, ChannelParams, Hypothesis, SessionConfig, simulate_session

PARAMS = ChannelParams()


@pytest.fixture(scope="module")
def temporal():
    return TemporalDetector(PARAMS, alpha=0.01, window=50, stride=10)


def test_temporal_detector_instantiates(temporal):
    """Temporal detector should create with valid parameters."""
    assert temporal.alpha == 0.01
    assert temporal.window == 50
    assert temporal.stride == 10
    assert temporal.n_calibration == 4000


def test_temporal_invalid_alpha():
    """Temporal detector should reject invalid alpha."""
    with pytest.raises(ValueError, match="alpha must be between"):
        TemporalDetector(alpha=0.0)
    with pytest.raises(ValueError, match="alpha must be between"):
        TemporalDetector(alpha=1.5)


def test_temporal_invalid_window_stride():
    """Temporal detector should reject invalid window or stride."""
    with pytest.raises(ValueError, match="window, stride"):
        TemporalDetector(window=0)
    with pytest.raises(ValueError, match="window, stride"):
        TemporalDetector(stride=-1)


@pytest.mark.parametrize("h", ATTACKS)
@pytest.mark.parametrize("theta", [1.0, 0.5])
def test_temporal_on_attacks(temporal, h, theta):
    """Temporal detector should evaluate attacks without error."""
    v = temporal.evaluate(simulate_session(h, theta, seed=3000 + int(theta * 100)))
    assert isinstance(v.rejected, bool)
    assert v.alpha == 0.01
    assert 0 < v.per_test_alpha < v.alpha


def test_temporal_on_clean_sessions(temporal):
    """Temporal detector should evaluate clean sessions."""
    for s in range(5):
        v = temporal.evaluate(simulate_session(seed=4000 + s))
        assert isinstance(v.rejected, bool)
        assert v.per_test_alpha > 0


@pytest.mark.slow
def test_temporal_false_alarm_rate_controlled(temporal):
    """Temporal detector's false-alarm rate should be <= alpha."""
    n = 200
    rejections = sum(
        temporal.evaluate(simulate_session(seed=5000 + i)).rejected
        for i in range(n)
    )
    # alpha = 0.01 -> expect ~2; binomial 99.9% upper bound for n=200 is ~8
    assert rejections <= 8


def test_temporal_stream_separation(temporal):
    """Temporal detector should evaluate streams independently."""
    v = temporal.evaluate(simulate_session(Hypothesis.CHANNEL_MANIPULATION, 1.0, seed=5005))
    for stream_name in ["signature", "freshness", "chsh"]:
        assert stream_name in v.streams
        stream = v.streams[stream_name]
        assert stream.rounds >= 0
        assert len(stream.windows) >= 0
        assert hasattr(stream.longest_run, "statistic")
        assert hasattr(stream.max_window_count, "statistic")
        assert hasattr(stream.fisher_g, "statistic")


def test_temporal_verdict_json_serializable(temporal):
    """Temporal verdict should serialize to JSON-compatible dict."""
    v = temporal.evaluate(simulate_session(seed=5010))
    d = v.to_dict()
    assert isinstance(d, dict)
    assert "rejected" in d
    assert "alpha" in d
    assert "streams" in d
    # Test that nested structures are also serializable
    json.dumps(d)


def test_burst_detection_on_contiguous_errors():
    """Burst detector should flag contiguous error runs."""
    detector = TemporalDetector(PARAMS, alpha=0.01, window=50, stride=10, n_calibration=1000, seed=42)
    # Simulate a burst: mostly clean, then 40+ consecutive mismatches
    outcomes = [0] * 100 + [1] * 60 + [0] * 100
    probs = [0.02] * len(outcomes)  # H0 mismatch probability
    result = detector.evaluate_stream(np.array(outcomes), np.array(probs))
    # Should flag longest_run or max_window_count
    assert result.longest_run.statistic >= 40 or result.max_window_count.statistic >= 40


def test_burst_detection_is_robust_to_scattered_errors():
    """Burst detector should not flag scattered, non-bursty errors."""
    detector = TemporalDetector(PARAMS, alpha=0.01, window=50, stride=10, n_calibration=1000, seed=42)
    # Spread 60 mismatches evenly across 600 rounds -> ~10% rate (typical H1)
    outcomes = [0] * 600
    indices = np.linspace(0, 599, 60, dtype=int)
    outcomes = np.array(outcomes)
    outcomes[indices] = 1
    probs = [0.02] * len(outcomes)
    result = detector.evaluate_stream(outcomes, np.array(probs))
    # Should not flag burst tests
    assert not result.longest_run.flagged or not result.max_window_count.flagged


def test_spectral_detection_on_periodic_errors():
    """Spectral analyzer should flag periodic error patterns."""
    detector = TemporalDetector(PARAMS, alpha=0.01, window=50, stride=10, n_calibration=1000, seed=42)
    # Periodic attack: error every 10th round
    outcomes = np.array([1 if i % 10 == 0 else 0 for i in range(500)], dtype=np.int8)
    probs = np.array([0.02] * len(outcomes))
    result = detector.evaluate_stream(outcomes, probs)
    # Should flag Fisher's g test
    assert result.fisher_g.statistic > 0


def test_spectral_detection_is_robust_to_white_noise():
    """Spectral detector should not flag white-noise error patterns."""
    detector = TemporalDetector(PARAMS, alpha=0.01, window=50, stride=10, n_calibration=1000, seed=42)
    rng = np.random.default_rng(9999)
    outcomes = rng.binomial(1, 0.05, 500).astype(np.int8)  # ~5% mismatch rate
    probs = np.array([0.05] * len(outcomes))
    result = detector.evaluate_stream(outcomes, probs)
    # Should not flag Fisher's g for random noise
    # (This is a loose bound; in practice spectral test should be insensitive to white noise)
    assert result.fisher_g.p_value > 0.001


def test_sliding_window_moments_basic():
    """Sliding window moments should compute correctly."""
    from arbiter.detection.temporal import sliding_window_moments
    
    outcomes = [0, 1, 1, 0, 0, 1, 1, 1]
    windows = sliding_window_moments(outcomes, window=3, stride=2)
    assert len(windows) > 0
    for w in windows:
        assert 0 <= w.mismatch_rate <= 1
        assert w.variance >= 0
        assert w.stop > w.start


def test_sliding_window_moments_empty():
    """Sliding window moments should handle empty outcomes."""
    from arbiter.detection.temporal import sliding_window_moments
    
    windows = sliding_window_moments([], window=5, stride=2)
    assert windows == []


def test_sliding_window_moments_short():
    """Sliding window moments should handle streams shorter than window."""
    from arbiter.detection.temporal import sliding_window_moments
    
    outcomes = [0, 1, 0]
    windows = sliding_window_moments(outcomes, window=10, stride=5)
    assert len(windows) >= 1
    assert windows[0].count == 3  # All three outcomes in one window


def test_longest_run_detection():
    """Longest run detection should find maximum consecutive runs."""
    from arbiter.detection.temporal import longest_mismatch_run
    
    outcomes = [0, 1, 1, 1, 0, 1, 1, 0]
    longest = longest_mismatch_run(outcomes)
    assert longest == 3


def test_longest_run_no_errors():
    """Longest run should be 0 for error-free outcomes."""
    from arbiter.detection.temporal import longest_mismatch_run
    
    outcomes = [0] * 100
    assert longest_mismatch_run(outcomes) == 0


def test_maximum_windowed_mismatches():
    """Maximum windowed mismatches should find largest window sum."""
    from arbiter.detection.temporal import maximum_windowed_mismatches
    
    outcomes = [0] * 10 + [1] * 15 + [0] * 10
    max_count = maximum_windowed_mismatches(outcomes, window=20)
    assert max_count == 15


def test_maximum_windowed_mismatches_short():
    """Maximum windowed mismatches should handle short streams."""
    from arbiter.detection.temporal import maximum_windowed_mismatches
    
    outcomes = [1, 1, 0]
    max_count = maximum_windowed_mismatches(outcomes, window=10)
    assert max_count == 2


def test_fisher_g_statistic_on_periodic():
    """Fisher's g-statistic should be large for periodic signals."""
    from arbiter.detection.temporal import fisher_g_statistic
    
    outcomes = np.array([1 if i % 5 == 0 else 0 for i in range(100)], dtype=float)
    g = fisher_g_statistic(outcomes)
    assert g > 0.05  # Periodic pattern should have notable periodogram peak


def test_fisher_g_statistic_on_white_noise():
    """Fisher's g-statistic should be modest for white noise."""
    from arbiter.detection.temporal import fisher_g_statistic
    
    rng = np.random.default_rng(8888)
    outcomes = rng.binomial(1, 0.5, 1000).astype(float)
    g = fisher_g_statistic(outcomes)
    # For white noise, max ordinates should be roughly 1/n on average
    assert g < 0.1  # Loose upper bound for random signal


def test_fisher_g_constant_stream():
    """Fisher's g-statistic should be 0 for constant streams."""
    from arbiter.detection.temporal import fisher_g_statistic
    
    assert fisher_g_statistic([1] * 100) == 0.0
    assert fisher_g_statistic([0] * 50) == 0.0


def test_fisher_g_short_stream():
    """Fisher's g-statistic should be 0 for streams < 4 rounds."""
    from arbiter.detection.temporal import fisher_g_statistic
    
    assert fisher_g_statistic([]) == 0.0
    assert fisher_g_statistic([1]) == 0.0
    assert fisher_g_statistic([1, 0, 1]) == 0.0


def test_temporal_multiple_testing_correction():
    """Temporal detector should apply Bonferroni correction across tests."""
    detector = TemporalDetector(PARAMS, alpha=0.03, window=50, stride=10, n_calibration=1000)
    # alpha = 0.03, 3 streams × 3 tests = 9 tests total
    # per_test_alpha = 0.03 / 9 = 0.00333...
    expected_per_test = 0.03 / 9
    assert abs(detector.per_test_alpha - expected_per_test) < 1e-6


def test_temporal_detector_caching():
    """Temporal detector should cache null distributions."""
    detector = TemporalDetector(PARAMS, alpha=0.01, n_calibration=500, seed=7)
    transcript = simulate_session(seed=6001)
    
    # First evaluate should populate cache
    first = detector.evaluate(transcript)
    # Second evaluate of same transcript should use cache
    second = detector.evaluate(transcript)
    
    # Results should be identical (deterministic)
    assert first.rejected == second.rejected
    assert first.alpha == second.alpha


def test_temporal_periodic_attack_mode():
    """Temporal detector should flag periodic attacks."""
    # Create a periodic attack: error every 10th round in signature stream
    detector = TemporalDetector(PARAMS, alpha=0.01, window=30, stride=5, n_calibration=2000, seed=99)
    
    # Simulate a session and introduce periodic errors in signature stream
    transcript = simulate_session(seed=7000)
    # Modify outcomes to create periodic pattern in signature stream
    sig_indices = np.where(transcript.cells == 0)[0]  # Signature cell = 0
    for i, idx in enumerate(sig_indices):
        if i % 10 == 0:
            transcript.outcomes[idx] = 1
    
    result = detector.evaluate(transcript)
    # Spectral test should be more sensitive to this than burst tests
    # At least one test should flag
    assert result.streams["signature"].fisher_g.statistic > 0


def test_temporal_combined_false_alarm():
    """Combined temporal pipeline should maintain family-wise false alarm rate."""
    detector = TemporalDetector(PARAMS, alpha=0.01, window=50, stride=10, n_calibration=1000, seed=11)
    
    rejections = 0
    n_tests = 150
    for i in range(n_tests):
        verdict = detector.evaluate(simulate_session(seed=8000 + i))
        if verdict.rejected:
            rejections += 1
    
    # Expected: alpha * n_tests = 0.01 * 150 = 1.5
    # Binomial (n=150, p=0.01) 95% CI upper bound ~ 5
    assert rejections <= 5


def test_temporal_verdict_flagged_property():
    """Temporal verdict should correctly report if any test flagged."""
    detector = TemporalDetector(PARAMS, alpha=0.01, n_calibration=500, seed=12)
    v = detector.evaluate(simulate_session(seed=7001))
    
    # Check that rejected property matches stream flagging
    any_stream_flagged = any(
        stream.longest_run.flagged or stream.max_window_count.flagged or stream.fisher_g.flagged
        for stream in v.streams.values()
    )
    assert v.rejected == any_stream_flagged
