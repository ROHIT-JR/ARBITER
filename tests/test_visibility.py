"""Tests for visibility estimation (Issue #24)"""

import numpy as np
import pytest

from arbiter.detection.unified import UnifiedDetector
from arbiter.pipeline import Arbiter
from arbiter.qds_simulation.model import (
    BELL_FIDELITY_CELLS,
    CELLS,
    CHSH_CELLS,
    ChannelParams,
    Hypothesis,
    _legit_cell_probabilities,
    cell_probabilities,
    estimate_visibility,
    visibility_ci,
)
from arbiter.qds_simulation.protocol import (
    DriftConfig,
    SessionConfig,
    simulate_session,
)


def test_legit_cell_probabilities():
    """Test that legitimate cell probabilities are correct."""
    p = _legit_cell_probabilities(0.92)
    assert p.shape == (len(CELLS),)
    # signature, freshness: p = (1-v)/2 = 0.04
    assert abs(p[0] - 0.04) < 1e-10
    assert abs(p[1] - 0.04) < 1e-10
    # Every cell records a *mismatch* bit, (1 - sign*correlator)/2. The ideal
    # correlator already carries the cell's sign, so sign*correlator is
    # positive everywhere and all four CHSH cells share one probability.
    sqrt2 = np.sqrt(2)
    np.testing.assert_allclose(p[CHSH_CELLS], (1 - 0.92 / sqrt2) / 2, rtol=1e-10)
    # Aligned stabiliser settings keep the full visibility (no 1/sqrt2 loss).
    np.testing.assert_allclose(p[BELL_FIDELITY_CELLS], (1 - 0.92) / 2, rtol=1e-10)


def test_legit_cell_probabilities_agree_with_the_born_rule():
    """Regression for the chsh11 sign-handling bug: the closed form must agree
    with the density-matrix computation in every cell."""
    np.testing.assert_allclose(
        _legit_cell_probabilities(0.92),
        cell_probabilities(Hypothesis.LEGITIMATE, 0.0, ChannelParams(visibility=0.92)),
        atol=1e-12,
    )


def test_estimate_visibility_known_v():
    """Test MLE visibility estimation when true v is known."""
    v_true = 0.92
    params = ChannelParams(visibility=v_true)
    n = np.full(len(CELLS), 200)
    # Expected counts under H0 at v=0.92
    p = _legit_cell_probabilities(v_true)
    k = np.round(n * p).astype(int)

    v_hat = estimate_visibility(n, k, params)
    assert abs(v_hat - v_true) < 0.01


def test_estimate_visibility_low_counts():
    """Test MLE with low counts falls back gracefully."""
    params = ChannelParams(visibility=0.92)
    n = np.zeros(len(CELLS), dtype=int)
    k = np.zeros(len(CELLS), dtype=int)

    v_hat = estimate_visibility(n, k, params)
    assert v_hat == params.visibility


def test_visibility_ci():
    """Test profile likelihood confidence interval."""
    v_true = 0.92
    n = np.full(len(CELLS), 300)
    p = _legit_cell_probabilities(v_true)
    k = np.round(n * p).astype(int)

    ci = visibility_ci(n, k, confidence=0.95)
    assert ci[0] <= v_true <= ci[1]
    assert ci[1] - ci[0] < 0.1  # reasonable width


def test_estimate_visibility_is_unbiased_on_sampled_sessions():
    """The chsh11 sign bug biased this low by ~0.024; it should now sit within
    sampling noise of the true visibility."""
    estimates = []
    for seed in range(12):
        transcript = simulate_session(config=SessionConfig(n_rounds=4000), seed=100 + seed)
        n, k = transcript.counts()
        estimates.append(float(estimate_visibility(n, k)))
    assert abs(float(np.mean(estimates)) - 0.92) < 0.01


def test_drift_config_static_offset():
    """Test static offset drift configuration.

    Pools counts across several seeded sessions rather than reading a single
    500-round sample: at n~166 per cell the standard error (~0.018) is too
    close to the 0.01 gap between the true rate (~0.06) and the 0.05
    threshold, so a single session is flaky regardless of which seed is
    picked (confirmed: seed=0 alone also fails, at p_sf=0.049). Pooling 20
    sessions shrinks the standard error by ~4.5x and removes that flakiness
    without touching the pass/fail question the test actually cares about
    (does static-offset drift shift the observed rate, at all).
    """
    config = SessionConfig(
        n_rounds=500,
        params=ChannelParams(visibility=0.92),
        drift=DriftConfig(type="static_offset", true_visibility=0.88),
    )
    n_sf = k_sf = 0
    for i in range(20):
        t = simulate_session(Hypothesis.LEGITIMATE, 0.0, config, seed=i, backend="analytic")
        n, k = t.counts()
        n_sf += n[0] + n[1]
        k_sf += k[0] + k[1]
    p_sf = k_sf / n_sf
    # True visibility is 0.88, so mismatch rate should be ~0.06 not 0.04
    assert p_sf > 0.05  # Higher than 0.04


def test_drift_config_linear():
    """Test linear drift configuration. Pooled across seeds; see
    test_drift_config_static_offset above for why."""
    config = SessionConfig(
        n_rounds=500,
        params=ChannelParams(visibility=0.92),
        drift=DriftConfig(type="linear_drift", v_start=0.92, v_end=0.85),
    )
    n_sf = k_sf = 0
    for i in range(20):
        t = simulate_session(Hypothesis.LEGITIMATE, 0.0, config, seed=i, backend="analytic")
        n, k = t.counts()
        n_sf += n[0] + n[1]
        k_sf += k[0] + k[1]
    p_sf = k_sf / n_sf
    # Average visibility ~0.885, mismatch ~0.0575
    assert p_sf > 0.05


def test_unified_detector_v_hat():
    """Test that UnifiedDetector reports v_hat and v_ci."""
    detector = UnifiedDetector(alpha=0.01)
    # Simulate a session with known visibility
    config = SessionConfig(n_rounds=500, params=ChannelParams(visibility=0.92))
    t = simulate_session(Hypothesis.LEGITIMATE, 0.0, config, seed=0, backend="analytic")

    verdict = detector.evaluate(t)
    assert verdict.v_hat is not None
    assert 0.85 < verdict.v_hat < 1.0
    assert verdict.v_ci is not None
    assert verdict.v_ci[0] < verdict.v_hat < verdict.v_ci[1]
    assert verdict.v_design == 0.92


def test_unified_detector_nuisance_parameter():
    """Test detector with visibility as nuisance parameter."""
    detector = UnifiedDetector(
        alpha=0.01,
        v_min=0.85,
        v_max=0.97,
    )
    # Simulate honest session with true v=0.88
    config = SessionConfig(
        n_rounds=500,
        params=ChannelParams(visibility=0.88),  # True visibility
        drift=DriftConfig(type="static_offset", true_visibility=0.88),
    )
    t = simulate_session(Hypothesis.LEGITIMATE, 0.0, config, backend="analytic")

    verdict = detector.evaluate(t)
    # Should report v_hat close to true visibility
    assert verdict.v_hat is not None
    assert abs(verdict.v_hat - 0.88) < 0.05
    # Should not reject (FAR controlled at worst-case v)
    assert not verdict.rejected


def test_far_control_under_drift():
    """Test that FAR ≤ alpha under drift when using nuisance parameter mode."""
    detector = UnifiedDetector(
        alpha=0.01,
        v_min=0.85,
        v_max=0.97,
    )

    n_trials = 200
    false_alarms = 0
    for i in range(n_trials):
        config = SessionConfig(
            n_rounds=200,
            params=ChannelParams(visibility=0.88),
            drift=DriftConfig(type="static_offset", true_visibility=0.88),
        )
        t = simulate_session(Hypothesis.LEGITIMATE, 0.0, config, seed=i, backend="analytic")
        verdict = detector.evaluate(t)
        if verdict.rejected:
            false_alarms += 1

    far = false_alarms / n_trials
    # FAR should be ≤ alpha (0.01) with high probability
    # With 200 trials, expected false alarms ≤ 2
    assert false_alarms <= 5, f"FAR {far:.3f} exceeds alpha=0.01 (false_alarms={false_alarms})"


def test_detector_without_nuisance_fails_under_drift():
    """Test that standard detector (fixed v) has elevated FAR under drift."""
    detector = UnifiedDetector(alpha=0.01)  # Fixed v=0.92

    n_trials = 200
    false_alarms = 0
    for i in range(n_trials):
        config = SessionConfig(
            n_rounds=200,
            params=ChannelParams(visibility=0.88),
            drift=DriftConfig(type="static_offset", true_visibility=0.88),
        )
        t = simulate_session(Hypothesis.LEGITIMATE, 0.0, config, seed=i, backend="analytic")
        verdict = detector.evaluate(t)
        if verdict.rejected:
            false_alarms += 1

    far = false_alarms / n_trials
    # Standard detector should have FAR > alpha when true v differs from assumed
    assert far > 0.05, f"Expected elevated FAR, got {far:.3f}"


def test_attack_power_preserved():
    """Test that attack detection power is preserved with nuisance parameter."""
    detector_fixed = UnifiedDetector(alpha=0.01)
    detector_nuisance = UnifiedDetector(alpha=0.01, v_min=0.85, v_max=0.97)

    n_trials = 100
    detected_fixed = 0
    detected_nuisance = 0
    for i in range(n_trials):
        config = SessionConfig(
            n_rounds=300,
            params=ChannelParams(visibility=0.92),
            drift=DriftConfig(type="static_offset", true_visibility=0.92),
        )
        t = simulate_session(Hypothesis.FORGERY, 0.5, config, seed=i, backend="analytic")

        v1 = detector_fixed.evaluate(t)
        v2 = detector_nuisance.evaluate(t)
        if v1.rejected:
            detected_fixed += 1
        if v2.rejected:
            detected_nuisance += 1

    power_fixed = detected_fixed / n_trials
    power_nuisance = detected_nuisance / n_trials
    # Power drop should be < 5 percentage points
    assert power_fixed - power_nuisance < 0.05, f"Power drop too large: {power_fixed:.2f} vs {power_nuisance:.2f}"


def test_v_hat_accuracy():
    """Test that v_hat is within ±0.02 of true v for 1200-round sessions."""
    detector = UnifiedDetector(alpha=0.01)

    n_trials = 50
    errors = []
    for i in range(n_trials):
        config = SessionConfig(
            n_rounds=1200,
            params=ChannelParams(visibility=0.88),
            drift=DriftConfig(type="static_offset", true_visibility=0.88),
        )
        t = simulate_session(Hypothesis.LEGITIMATE, 0.0, config, seed=i, backend="analytic")
        verdict = detector.evaluate(t)
        errors.append(abs(verdict.v_hat - 0.88))

    median_error = np.median(errors)
    assert median_error < 0.02, f"Median |v_hat - v_true| = {median_error:.4f} exceeds 0.02"


def test_arbiter_pipeline_v_estimates():
    """Test that Arbiter pipeline passes through visibility estimates."""
    from pathlib import Path
    from tempfile import TemporaryDirectory

    from arbiter.audit_ledger import AuditLedger, LedgerKeys

    with TemporaryDirectory() as tmpdir:
        keys = LedgerKeys.generate(hbs_height=4)
        # AuditLedger.__init__ calls path.exists(), so this must be a Path,
        # not a str (matches the convention used everywhere else, e.g.
        # test_ledger.py's `tmp_path / "ledger.jsonl"`).
        ledger = AuditLedger(keys, Path(tmpdir) / "ledger.jsonl")
        arb = Arbiter(
            ChannelParams(visibility=0.92),
            alpha=0.01,
            ledger=ledger,
            v_min=0.85,
            v_max=0.97,
        )

        config = SessionConfig(
            n_rounds=500,
            params=ChannelParams(visibility=0.88),
            drift=DriftConfig(type="static_offset", true_visibility=0.88),
        )
        t = simulate_session(Hypothesis.LEGITIMATE, 0.0, config, seed=0, backend="analytic")
        verdict = arb.verify(t)

        assert verdict.unified.v_hat is not None
        assert verdict.unified.v_ci is not None
        assert verdict.unified.v_design == 0.92


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
