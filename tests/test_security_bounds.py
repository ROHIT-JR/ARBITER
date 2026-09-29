"""Finite-size QDS security bounds; sources are named beside checked equations."""

import math

import numpy as np
import pytest

from arbiter.detection.security import minimum_signature_parameters, protocol_security_bounds
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
