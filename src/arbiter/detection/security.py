"""Finite-size, stand-alone security bounds for the BB84-USE QDS mode.

The bounds are deliberately kept separate from the detector: they quantify the
signature protocol's chance of an unwanted outcome, rather than the chance of
detecting an observed attack.  They assume independently sampled key elements
and a collective attacker.  See ``docs/math-derivations.md`` for the exact
assumptions and references.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass

from arbiter.qds_simulation.model import (
    BB84_LABELS,
    ChannelParams,
    Hypothesis,
    RoundType,
    qds_forgery_mismatch_rate,
    received_state,
    use_mismatch_probability,
)

# Eq. (2) in Dunjko, Wallden and Andersson, PRL 112, 040502 (2014), has
# exp[-p_USD^2 (s_v - s_a)^2 L / 2].  BB84 USE has p_USD = 1/2.
DEFAULT_REPUDIATION_COEFFICIENT = 1 / 8
DEFAULT_CHANNEL_PARAMS = ChannelParams()

ASSUMPTIONS = (
    "stand-alone, one-bit QDS security (not composable security)",
    "independent BB84 USE elements and collective attacks; coherent attacks are out of scope",
    "Hoeffding finite-size tails for Bernoulli mismatch variables",
    "ideal random half-exchange symmetrisation is assumed analytically; no #21 implementation is required",
    "authenticated classical communication and calibrated, stationary channel visibility",
)


@dataclass(frozen=True)
class SecurityBounds:
    """Security tail bounds at one signature length and pair of thresholds."""

    length: int
    p_err: float
    p_forge_mismatch: float
    s_a: float
    s_v: float
    p_forge: float
    p_rep: float
    p_rob: float
    repudiation_coefficient: float = DEFAULT_REPUDIATION_COEFFICIENT

    @property
    def epsilon(self) -> float:
        return max(self.p_forge, self.p_rep, self.p_rob)

    def to_dict(self) -> dict:
        return asdict(self) | {"epsilon": self.epsilon, "assumptions": list(ASSUMPTIONS)}


@dataclass(frozen=True)
class SecurityParameters:
    """The minimum-length threshold choice for a requested protocol epsilon."""

    target_epsilon: float
    bounds: SecurityBounds

    def to_dict(self) -> dict:
        return {
            "target_epsilon": self.target_epsilon,
            "minimum_length": self.bounds.length,
            "bounds": self.bounds.to_dict(),
        }


def honest_mismatch_rate(params: ChannelParams) -> float:
    """Return ``p_err`` from the Born-rule QDS USE model, not a fitted constant."""
    probabilities = [
        use_mismatch_probability(received_state(Hypothesis.LEGITIMATE, RoundType.SIGNATURE, label, params), label)
        for label in BB84_LABELS
    ]
    return sum(probabilities) / len(probabilities)


def _validate_thresholds(p_err: float, p_forge_mismatch: float, s_a: float, s_v: float) -> None:
    if not 0 <= p_err < s_a < s_v < p_forge_mismatch <= 1:
        raise ValueError("thresholds must satisfy 0 <= p_err < s_a < s_v < p_forge_mismatch <= 1")


def protocol_security_bounds(
    length: int,
    params: ChannelParams = DEFAULT_CHANNEL_PARAMS,
    *,
    s_a: float | None = None,
    s_v: float | None = None,
    repudiation_coefficient: float = DEFAULT_REPUDIATION_COEFFICIENT,
) -> SecurityBounds:
    """Compute Hoeffding upper bounds for forgery, repudiation and robustness.

    ``s_a`` is the direct-authentication threshold and ``s_v`` is the stricter
    transfer-verification threshold.  With ``p_f`` the keyless-forger USE
    mismatch rate, the three tails are:

    ``P_forge <= exp[-2 (p_f-s_v)^2 L]``;
    ``P_rep <= exp[-(s_v-s_a)^2 L/8]`` for ideal BB84 symmetrisation; and
    ``P_rob <= 2 exp[-2 (s_a-p_err)^2 L]``.
    """
    if length < 1:
        raise ValueError("length must be positive")
    if not 0 < repudiation_coefficient <= 1:
        raise ValueError("repudiation_coefficient must be in (0, 1]")
    p_err = honest_mismatch_rate(params)
    p_forge_mismatch = qds_forgery_mismatch_rate()
    gap = p_forge_mismatch - p_err
    s_a = p_err + gap / 3 if s_a is None else s_a
    s_v = p_err + 2 * gap / 3 if s_v is None else s_v
    _validate_thresholds(p_err, p_forge_mismatch, s_a, s_v)

    p_forge = math.exp(-2 * (p_forge_mismatch - s_v) ** 2 * length)
    p_rep = math.exp(-repudiation_coefficient * (s_v - s_a) ** 2 * length)
    p_rob = min(1.0, 2 * math.exp(-2 * (s_a - p_err) ** 2 * length))
    return SecurityBounds(
        length=length,
        p_err=p_err,
        p_forge_mismatch=p_forge_mismatch,
        s_a=s_a,
        s_v=s_v,
        p_forge=p_forge,
        p_rep=p_rep,
        p_rob=p_rob,
        repudiation_coefficient=repudiation_coefficient,
    )


def minimum_signature_parameters(
    epsilon: float = 1e-10,
    params: ChannelParams = DEFAULT_CHANNEL_PARAMS,
    *,
    threshold_steps: int = 96,
    repudiation_coefficient: float = DEFAULT_REPUDIATION_COEFFICIENT,
) -> SecurityParameters:
    """Find the threshold pair with the smallest integer ``L`` for ``epsilon``.

    This is a deterministic grid search over the physically usable interval;
    each candidate length is solved analytically from the three exponential
    tails, then verified by :func:`protocol_security_bounds`.
    """
    if not 0 < epsilon < 1:
        raise ValueError("epsilon must be in (0, 1)")
    if threshold_steps < 3:
        raise ValueError("threshold_steps must be at least 3")
    p_err = honest_mismatch_rate(params)
    p_forge_mismatch = qds_forgery_mismatch_rate()
    gap = p_forge_mismatch - p_err
    if gap <= 0:
        raise ValueError("channel mismatch rate leaves no security threshold gap")

    best: SecurityBounds | None = None
    log_epsilon = math.log(1 / epsilon)
    for a_index in range(1, threshold_steps - 1):
        s_a = p_err + gap * a_index / threshold_steps
        for v_index in range(a_index + 1, threshold_steps):
            s_v = p_err + gap * v_index / threshold_steps
            required = max(
                log_epsilon / (2 * (p_forge_mismatch - s_v) ** 2),
                log_epsilon / (repudiation_coefficient * (s_v - s_a) ** 2),
                math.log(2 / epsilon) / (2 * (s_a - p_err) ** 2),
            )
            candidate = protocol_security_bounds(
                math.ceil(required),
                params,
                s_a=s_a,
                s_v=s_v,
                repudiation_coefficient=repudiation_coefficient,
            )
            if candidate.epsilon <= epsilon and (best is None or candidate.length < best.length):
                best = candidate
    if best is None:  # pragma: no cover - a positive threshold gap always gives a finite answer
        raise RuntimeError("could not find finite security parameters")
    return SecurityParameters(target_epsilon=epsilon, bounds=best)


def security_curve(parameters: SecurityParameters, params: ChannelParams = DEFAULT_CHANNEL_PARAMS) -> list[dict]:
    """Small log-spaced display curve around the selected minimum length."""
    optimum = parameters.bounds
    lengths = sorted({max(1, optimum.length // 4), max(1, optimum.length // 2), optimum.length, optimum.length * 2})
    return [
        protocol_security_bounds(
            length,
            params,
            s_a=optimum.s_a,
            s_v=optimum.s_v,
            repudiation_coefficient=optimum.repudiation_coefficient,
        ).to_dict()
        for length in lengths
    ]
