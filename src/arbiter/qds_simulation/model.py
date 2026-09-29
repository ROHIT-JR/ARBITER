"""Physical model of the teleportation-based QDS session and its attacks.

A session interleaves three kinds of rounds, chosen at random by the verifier
so an adversary cannot tell them apart in advance:

* ``SIGNATURE``  -- the signer teleports a Pauli eigenstate selected by her
  private key; the verifier applies the Pauli correction and measures in that
  eigenstate's basis. Outcome = mismatch bit.
* ``FRESHNESS``  -- same, but the eigenstate is derived from the verifier's
  per-session QRNG nonce (public challenge). Outcome = mismatch bit.
* ``CHSH``       -- signer and verifier measure their halves of a Bell pair in
  random CHSH settings. Outcome = parity of the two +-1 results.

Each hypothesis is a (possibly partial, strength ``theta``) replacement of the
per-round quantum state. The verifier's outcome probabilities are computed
here with the Born rule from explicit density matrices -- including an
explicit teleportation map -- so the detector's likelihoods are derived, not
hand-tuned. See ``docs/threat-model.md`` for the adversary definitions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import lru_cache

import numpy as np

from arbiter.quantum.states import (
    ALL_LABELS,
    I2,
    MAXIMALLY_MIXED,
    PauliLabel,
    X,
    Z,
    apply_on_second,
    depolarize,
    measure_resend,
    pauli_state,
    projector,
    werner,
)

PROTOCOLS = frozenset({"prf", "qds"})


class Hypothesis(str, Enum):
    LEGITIMATE = "legitimate"
    FORGERY = "forgery"
    IMPERSONATION = "impersonation"
    REPLAY = "replay"
    CHANNEL_MANIPULATION = "channel_manipulation"


ATTACKS = tuple(h for h in Hypothesis if h is not Hypothesis.LEGITIMATE)

# An impersonator holds none of the signer's entanglement, so she produces the
# whole session or none of it. (A *partial* I/2 substitution would also be
# observationally identical to intercept-resend on 1.5x as many rounds -- both
# are depolarizing -- so it could not be attributed separately anyway.)
ALL_OR_NOTHING = frozenset({Hypothesis.IMPERSONATION})


class RoundType(str, Enum):
    SIGNATURE = "signature"
    FRESHNESS = "freshness"
    CHSH = "chsh"


# The four BB84 states used for the quantum-public-key distribution phase.
# ``PauliLabel`` is deliberately reused so state preparation and teleportation
# stay identical to the rest of the simulator.  Their indices in ``ALL_LABELS``
# are not contiguous, hence callers should use these labels rather than infer a
# BB84 index from ``PauliLabel.index``.
BB84_LABELS = (
    PauliLabel("Z", 0),
    PauliLabel("Z", 1),
    PauliLabel("X", 0),
    PauliLabel("X", 1),
)


# Observation "cells": each is a Bernoulli outcome the detector counts.
CHSH_SETTINGS = ((0, 0), (0, 1), (1, 0), (1, 1))
CELLS = ("signature", "freshness", "chsh00", "chsh01", "chsh10", "chsh11")
CHSH_SIGNS = np.array([1, 1, 1, -1])  # S = E00 + E01 + E10 - E11

_B0 = (Z + X) / np.sqrt(2)
_B1 = (Z - X) / np.sqrt(2)
ALICE_OBS = (Z, X)
BOB_OBS = (_B0, _B1)


@dataclass(frozen=True)
class ChannelParams:
    """Calibrated properties of the *legitimate* link.

    visibility          Werner visibility of distributed Bell pairs. The
                        teleportation channel it induces is depolarizing with
                        the same parameter, and the ideal CHSH value is
                        2*sqrt(2)*visibility.
    storage_visibility  Extra depolarization a state suffers while an attacker
                        holds it in quantum memory for replay.
    """

    visibility: float = 0.92
    storage_visibility: float = 0.85


# --- teleportation --------------------------------------------------------


def _cnot(control: int, target: int, n: int = 3) -> np.ndarray:
    dim = 2**n
    U = np.zeros((dim, dim))
    for i in range(dim):
        bits = [(i >> (n - 1 - k)) & 1 for k in range(n)]
        if bits[control]:
            bits[target] ^= 1
        j = sum(b << (n - 1 - k) for k, b in enumerate(bits))
        U[j, i] = 1
    return U


_H = np.array([[1, 1], [1, -1]]) / np.sqrt(2)
_BELL_MEASURE_U = np.kron(np.kron(_H, I2), I2) @ _cnot(0, 1)


def teleport(rho_in: np.ndarray, resource: np.ndarray) -> np.ndarray:
    """Teleport single-qubit ``rho_in`` through two-qubit ``resource`` (A|B).

    Qubit order C (input), A (signer's half), B (verifier's half). Bell
    measurement = CNOT(C->A), H(C), measure C->m1, A->m2; the verifier then
    applies X^m2 followed by Z^m1. Returns the verifier's state, averaged over
    the four outcomes.
    """
    state = np.kron(rho_in, resource)
    state = _BELL_MEASURE_U @ state @ _BELL_MEASURE_U.conj().T
    t = state.reshape(2, 2, 2, 2, 2, 2)  # [c, a, b, c', a', b']
    out = np.zeros((2, 2), dtype=complex)
    for m1 in (0, 1):
        for m2 in (0, 1):
            rho_b = t[m1, m2, :, m1, m2, :]
            corr = np.linalg.matrix_power(Z, m1) @ np.linalg.matrix_power(X, m2)
            out += corr @ rho_b @ corr.conj().T
    return out


def resource_state(h: Hypothesis, params: ChannelParams) -> np.ndarray:
    """Shared two-qubit state (signer half, verifier half) on an attacked round."""
    v = params.visibility
    if h in (Hypothesis.LEGITIMATE, Hypothesis.FORGERY, Hypothesis.REPLAY):
        return werner(v)
    if h is Hypothesis.CHANNEL_MANIPULATION:
        # Eve intercepts the verifier's half in transit and measure-resends it
        # in a random Pauli basis.
        return apply_on_second(measure_resend, werner(v))
    if h is Hypothesis.IMPERSONATION:
        # The impersonator holds none of the signer's registered halves, so
        # whatever she does is uncorrelated with the verifier's qubit.
        return np.kron(MAXIMALLY_MIXED, MAXIMALLY_MIXED)
    raise ValueError(h)


def received_state(h: Hypothesis, round_type: RoundType, label: PauliLabel, params: ChannelParams) -> np.ndarray:
    """Verifier's post-correction state on an attacked SIGNATURE/FRESHNESS round
    whose honest content is ``label``."""
    honest = pauli_state(label)
    if h is Hypothesis.FORGERY and round_type is RoundType.SIGNATURE:
        # Forger lacks the key. Averaged over the 6 eigenstates she can guess,
        # her input is I/2 -- and any fixed guess gives the same 1/2 mismatch.
        sent = MAXIMALLY_MIXED
    elif h is Hypothesis.REPLAY:
        if round_type is RoundType.FRESHNESS:
            # Recorded under an old nonce: independent of today's challenge.
            sent = MAXIMALLY_MIXED
        else:
            sent = depolarize(honest, params.storage_visibility)
    else:
        sent = honest
    return teleport(sent, resource_state(h, params))


def chsh_state(h: Hypothesis, params: ChannelParams) -> np.ndarray:
    if h is Hypothesis.REPLAY:
        # Replayed outcomes were produced for old settings on old pairs.
        return np.kron(MAXIMALLY_MIXED, MAXIMALLY_MIXED)
    return resource_state(h, params)


# --- outcome probabilities ------------------------------------------------


def mismatch_probability(rho: np.ndarray, label: PauliLabel) -> float:
    wrong = projector(label.basis, 1 - label.bit)
    return float(np.real(np.trace(wrong @ rho)))


def use_eliminated_label(measurement_basis: str, outcome: int) -> PauliLabel:
    """Return the BB84 state ruled out by one USE measurement outcome.

    Bob randomly measures in the X or Z basis.  An outcome ``s`` rules out
    the opposite state ``|basis, 1-s>``: that state could never produce ``s``
    in that basis.  This is state *elimination*, not an attempted state ID.
    """
    if measurement_basis not in ("X", "Z") or outcome not in (0, 1):
        raise ValueError("USE requires an X/Z basis and a bit outcome")
    return PauliLabel(measurement_basis, 1 - outcome)


def use_mismatch_probability(rho: np.ndarray, revealed: PauliLabel) -> float:
    """Probability that USE rules out the subsequently revealed BB84 state.

    The verifier chooses the revealed state's basis with probability 1/2.  In
    that branch a contradictory outcome has Born probability
    ``Tr(P_wrong rho)``; the other basis can never eliminate ``revealed``.
    Therefore an honest Werner link of visibility ``v`` has mismatch rate
    ``(1-v)/4`` (zero on a noiseless link).
    """
    if revealed not in BB84_LABELS:
        raise ValueError("USE is defined for the BB84 state set only")
    return 0.5 * mismatch_probability(rho, revealed)


def qds_forgery_mismatch_rate() -> float:
    """Best keyless messaging-forgery mismatch probability for BB84 USE.

    The recipient's eliminated state is uniform over the four labels when the
    private key is uniform.  A forger with no key can choose any revealed
    label, but it equals that eliminated label with probability 1/4.
    """
    return 0.25


def chsh_correlator(rho_ab: np.ndarray, a: int, b: int) -> float:
    return float(np.real(np.trace(np.kron(ALICE_OBS[a], BOB_OBS[b]) @ rho_ab)))


def _normalise_protocol(protocol: str) -> str:
    if protocol not in PROTOCOLS:
        raise ValueError(f"unknown protocol {protocol!r}; choose from {sorted(PROTOCOLS)}")
    return protocol


@lru_cache(maxsize=512)
def _attack_cell_probs(h: Hypothesis, params: ChannelParams, protocol: str = "prf") -> tuple[float, ...]:
    """P(outcome = 1) for each cell on a *fully* attacked round (theta = 1).

    For SIGNATURE/FRESHNESS the result is averaged over the six labels (the
    models here are label-symmetric, which the tests check). For CHSH the
    outcome bit is 1 when the parity differs from the sign of the ideal
    correlation, so an ideal Bell pair gives P = (1 - 1/sqrt2)/2 in every cell.
    """
    protocol = _normalise_protocol(protocol)
    probs = []
    if protocol == "prf":
        signature = float(
            np.mean(
                [mismatch_probability(received_state(h, RoundType.SIGNATURE, lab, params), lab) for lab in ALL_LABELS]
            )
        )
    elif h in (Hypothesis.FORGERY, Hypothesis.REPLAY, Hypothesis.IMPERSONATION):
        # These are messaging attacks in QDS mode: the attacker supplies a
        # keyless reveal instead of altering the distributed public key.
        signature = qds_forgery_mismatch_rate()
    else:
        # Channel manipulation occurs during distribution.  The recipient's
        # USE record is compared to Alice's later, honest reveal.
        signature = float(
            np.mean(
                [
                    use_mismatch_probability(received_state(h, RoundType.SIGNATURE, lab, params), lab)
                    for lab in BB84_LABELS
                ]
            )
        )
    probs.append(signature)
    probs.append(
        float(
            np.mean(
                [mismatch_probability(received_state(h, RoundType.FRESHNESS, lab, params), lab) for lab in ALL_LABELS]
            )
        )
    )
    rho = chsh_state(h, params)
    for (a, b), sign in zip(CHSH_SETTINGS, CHSH_SIGNS, strict=True):
        probs.append((1 - sign * chsh_correlator(rho, a, b)) / 2)
    return tuple(probs)


def cell_probabilities(h: Hypothesis, theta: float, params: ChannelParams, protocol: str = "prf") -> np.ndarray:
    """Per-cell outcome-1 probability when a fraction ``theta`` of rounds are attacked."""
    protocol = _normalise_protocol(protocol)
    legit = np.array(_attack_cell_probs(Hypothesis.LEGITIMATE, params, protocol))
    if h is Hypothesis.LEGITIMATE or theta == 0:
        return legit
    attacked = np.array(_attack_cell_probs(h, params, protocol))
    return (1 - theta) * legit + theta * attacked


def expected_chsh(h: Hypothesis, theta: float, params: ChannelParams, protocol: str = "prf") -> float:
    p = cell_probabilities(h, theta, params, protocol)[2:]
    return float(np.sum(1 - 2 * p))


def _legit_cell_probabilities(v: float, protocol: str = "prf") -> np.ndarray:
    """Per-cell outcome-1 probabilities under H0 (legitimate) for given visibility v.

    Cells: 0=signature, 1=freshness, 2=chsh00, 3=chsh01, 4=chsh10, 5=chsh11
    - signature, freshness: p = (1-v)/2
    - CHSH (setting a,b with sign s): p = (1 - s*v/sqrt(2))/2
    """
    sqrt2 = np.sqrt(2)
    p_sf = (1 - v) / 2
    p_chsh = (1 - CHSH_SIGNS * v / sqrt2) / 2
    return np.array([p_sf, p_sf, *p_chsh])


def _neg_log_likelihood(v: float, n: np.ndarray, k: np.ndarray, protocol: str = "prf") -> float:
    """Negative log-likelihood for visibility v given per-cell counts."""
    p = _legit_cell_probabilities(v, protocol)
    # Clip for numerical stability
    p = np.clip(p, 1e-15, 1 - 1e-15)
    return -np.sum(k * np.log(p) + (n - k) * np.log(1 - p))


def estimate_visibility(
    n: np.ndarray,
    k: np.ndarray,
    params: ChannelParams | None = None,
    protocol: str = "prf",
) -> float:
    """MLE of Werner visibility v from per-cell counts under H0 (legitimate).

    Maximizes the joint log-likelihood over all 6 cells:
    ℓ(v) = Σᵢ [kᵢ log pᵢ(v) + (nᵢ - kᵢ) log(1 - pᵢ(v))]

    where p₀(v) = p₁(v) = (1-v)/2 (signature, freshness)
    and pᵢ(v) = (1 - sᵢ v/√2)/2 for CHSH cells (i=2,3,4,5).

    Returns v in [0.5, 1.0] clipped. Falls back to params.visibility if optimization fails.
    """
    if params is None:
        params = ChannelParams()

    n = np.asarray(n, float)
    k = np.asarray(k, float)

    if n.sum() == 0:
        return params.visibility

    # Initial guess from method of moments
    n_sf = n[0] + n[1]
    if n_sf > 0:
        p_sf = (k[0] + k[1]) / n_sf
        v0 = 1 - 2 * p_sf
    else:
        v0 = params.visibility
    v0 = float(np.clip(v0, 0.5, 1.0))

    # Brent's method for robust 1D optimization
    try:
        from scipy.optimize import minimize_scalar

        res = minimize_scalar(
            _neg_log_likelihood,
            bounds=(0.5, 1.0),
            args=(n, k, protocol),
            method="bounded",
            options={"xatol": 1e-8, "maxiter": 50},
        )
        if res.success:
            return float(np.clip(res.x, 0.5, 1.0))
    except Exception:
        pass

    # Fallback: Newton step from v0
    for _ in range(10):
        p = _legit_cell_probabilities(v0, protocol)
        p = np.clip(p, 1e-15, 1 - 1e-15)
        score = np.sum((k / p - (n - k) / (1 - p)) * np.gradient(p, 1e-6))
        fisher = np.sum(n / (p * (1 - p)) * (np.gradient(p, 1e-6)) ** 2)
        if fisher > 0:
            v_new = v0 + score / fisher
            if abs(v_new - v0) < 1e-8:
                v0 = v_new
                break
            v0 = np.clip(v_new, 0.5, 1.0)

    return float(np.clip(v0, 0.5, 1.0))


def visibility_ci(n: np.ndarray, k: np.ndarray, confidence: float = 0.95, protocol: str = "prf") -> tuple[float, float]:
    """Profile likelihood confidence interval for visibility v.

    Returns (v_lower, v_upper) such that 2(ℓ(v̂) - ℓ(v)) < χ²₁,₁₋α
    """
    from scipy.stats import chi2

    v_hat = estimate_visibility(n, k, protocol=protocol)
    ll_max = -_neg_log_likelihood(v_hat, n, k, protocol)
    threshold = ll_max - 0.5 * chi2.ppf(confidence, 1)

    # Search for interval bounds
    v_grid = np.linspace(0.5, 1.0, 1000)
    ll_grid = -np.array([_neg_log_likelihood(v, n, k, protocol) for v in v_grid])
    valid = v_grid[ll_grid >= threshold]

    if len(valid) == 0:
        return (0.5, 1.0)
    return (float(valid[0]), float(valid[-1]))
