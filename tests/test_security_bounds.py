"""Finite-size QDS security bounds; sources are named beside checked equations."""

import math

import numpy as np
import pytest

from arbiter.detection.security import (
    honest_mismatch_rate,
    minimum_signature_parameters,
    protocol_security_bounds,
    security_curve,
)
from arbiter.qds_simulation import ChannelParams, distribute_qds_keys


def test_forgery_bound_reproduces_wallden_2015_equation_5_at_zero_abort_rate():
    """Wallden et al., PRA 91, 042304 (2015), Eq. (5), with r=0.

    Their exponent becomes ``-2 L (1/4-s_v)^2``, exactly the BB84-USE
    keyless-forger Hoeffding tail implemented here.
    """
    result = protocol_security_bounds(100, ChannelParams(visibility=0.92), s_a=0.10, s_v=0.20)
    assert result.p_forge == pytest.approx(math.exp(-2 * 100 * (0.25 - 0.20) ** 2))


def test_bounds_decrease_with_length_and_robustness_worsens_with_noise():
    clean = ChannelParams(visibility=0.95)
    noisy = ChannelParams(visibility=0.80)
    short = protocol_security_bounds(100, clean, s_a=0.08, s_v=0.18)
    long = protocol_security_bounds(200, clean, s_a=0.08, s_v=0.18)
    noise_clean = protocol_security_bounds(1000, clean, s_a=0.08, s_v=0.18)
    worse_channel = protocol_security_bounds(1000, noisy, s_a=0.08, s_v=0.18)
    assert long.p_forge < short.p_forge
    assert long.p_rep < short.p_rep
    assert long.p_rob < short.p_rob
    assert worse_channel.p_rob > noise_clean.p_rob
    assert worse_channel.epsilon > noise_clean.epsilon


def test_minimum_length_achieves_target_and_is_monotonic_in_noise():
    target = 1e-8
    clean = minimum_signature_parameters(target, ChannelParams(visibility=0.95))
    noisy = minimum_signature_parameters(target, ChannelParams(visibility=0.80))
    assert clean.bounds.epsilon <= target
    assert noisy.bounds.epsilon <= target
    assert noisy.bounds.length > clean.bounds.length


def test_qds_distribution_monte_carlo_forgery_rate_is_below_bound():
    """A #20 BB84-USE distribution simulation obeys the Hoeffding upper tail."""
    length = 80
    params = ChannelParams(visibility=0.92)
    threshold = 0.20
    bound = protocol_security_bounds(length, params, s_a=0.10, s_v=threshold).p_forge
    successes = 0
    for seed in range(100):
        distribution = distribute_qds_keys(length=length, params=params, seed=seed)
        forged_reveal = np.zeros(length, dtype=np.int8)
        successes += distribution.mismatch_rate(0, 0, forged_reveal) < threshold
    assert successes / 100 <= bound


def test_invalid_thresholds_are_rejected():
    with pytest.raises(ValueError, match="thresholds"):
        protocol_security_bounds(100, s_a=0.24, s_v=0.20)


def test_honest_mismatch_rate_for_default_channel():
    """Honest mismatch rate is derived from QDS model, not a constant."""
    rate = honest_mismatch_rate(ChannelParams())
    assert 0 < rate < 1
    assert 0.01 < rate < 0.03  # typical visibility ~0.92


def test_honest_mismatch_rate_decreases_with_visibility():
    """Higher visibility means fewer honest mismatches."""
    clean = honest_mismatch_rate(ChannelParams(visibility=0.95))
    noisy = honest_mismatch_rate(ChannelParams(visibility=0.80))
    assert clean < noisy


def test_security_bounds_epsilon_is_max_of_three_tails():
    """The epsilon property reports the maximum of the three bounds."""
    bounds = protocol_security_bounds(100, ChannelParams(visibility=0.92), s_a=0.10, s_v=0.20)
    assert bounds.epsilon == max(bounds.p_forge, bounds.p_rep, bounds.p_rob)


def test_security_bounds_to_dict_includes_epsilon_and_assumptions():
    """The to_dict() output includes epsilon and the list of assumptions."""
    bounds = protocol_security_bounds(100, ChannelParams(visibility=0.92))
    d = bounds.to_dict()
    assert "epsilon" in d
    assert "assumptions" in d
    assert isinstance(d["assumptions"], list)
    assert len(d["assumptions"]) > 0


def test_minimum_signature_parameters_to_dict():
    """The SecurityParameters to_dict() output has required keys."""
    params = minimum_signature_parameters(epsilon=1e-8)
    d = params.to_dict()
    assert d["target_epsilon"] == 1e-8
    assert "minimum_length" in d
    assert "bounds" in d
    assert d["minimum_length"] > 0


def test_security_curve_returns_list_around_optimum():
    """The security_curve() returns a display list around the optimum length."""
    params = minimum_signature_parameters(1e-6, ChannelParams(visibility=0.92))
    curve = security_curve(params, ChannelParams(visibility=0.92))
    assert isinstance(curve, list)
    assert len(curve) > 0
    assert all(isinstance(d, dict) for d in curve)
    assert all("length" in d and "p_forge" in d for d in curve)


def test_repudiation_coefficient_affects_repudiation_bound():
    """Changing repudiation_coefficient scales the P_rep exponent."""
    bounds_default = protocol_security_bounds(100, ChannelParams(visibility=0.92), s_a=0.10, s_v=0.20)
    bounds_half = protocol_security_bounds(
        100, ChannelParams(visibility=0.92), s_a=0.10, s_v=0.20, repudiation_coefficient=0.5
    )
    # With half the coefficient, exponent is doubled, so P_rep improves (becomes smaller)
    assert bounds_half.p_rep < bounds_default.p_rep
