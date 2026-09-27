import numpy as np
import pytest

from arbiter.qds_simulation.model import teleport
from arbiter.quantum.info import (
    classical_chernoff,
    fidelity,
    helstrom_error,
    optimal_povm,
    quantum_chernoff,
    relative_entropy,
    trace_distance,
)
from arbiter.quantum.states import (
    ALL_LABELS,
    BELL_PHI_PLUS,
    MAXIMALLY_MIXED,
    apply_on_second,
    depolarize,
    measure_resend,
    partial_trace_first,
    pauli_state,
    projector,
    werner,
)


@pytest.mark.parametrize("label", ALL_LABELS)
def test_perfect_teleportation_is_identity(label):
    assert np.allclose(teleport(pauli_state(label), BELL_PHI_PLUS), pauli_state(label))


@pytest.mark.parametrize("v", [1.0, 0.9, 0.5, 0.0])
def test_teleporting_through_werner_is_depolarizing(v):
    rho = pauli_state(ALL_LABELS[3])
    assert np.allclose(teleport(rho, werner(v)), depolarize(rho, v))


def test_measure_resend_is_depolarizing_one_third():
    for label in ALL_LABELS:
        rho = pauli_state(label)
        assert np.allclose(measure_resend(rho), depolarize(rho, 1 / 3))


def test_channel_on_second_qubit_matches_werner():
    assert np.allclose(apply_on_second(lambda r: depolarize(r, 0.7), BELL_PHI_PLUS), werner(0.7))
    assert np.allclose(partial_trace_first(BELL_PHI_PLUS), MAXIMALLY_MIXED)


def test_distinguishability_measures_on_known_cases():
    zero, one = projector("Z", 0), projector("Z", 1)
    assert trace_distance(zero, one) == pytest.approx(1)
    assert helstrom_error(zero, one) == pytest.approx(0, abs=1e-12)
    assert helstrom_error(zero, zero) == pytest.approx(0.5)
    plus = projector("X", 0)
    # Helstrom for two pure states: (1 - sqrt(1 - |<a|b>|^2)) / 2
    assert helstrom_error(zero, plus) == pytest.approx((1 - np.sqrt(0.5)) / 2)
    assert fidelity(zero, plus) == pytest.approx(0.5)
    # Pure states: Chernoff exponent = -log |<a|b>|^2
    xi, _ = quantum_chernoff(zero, plus)
    assert xi == pytest.approx(np.log(2), rel=1e-6)
    assert relative_entropy(zero, MAXIMALLY_MIXED) == pytest.approx(np.log(2))
    assert relative_entropy(zero, one) == float("inf")


def test_commuting_states_quantum_chernoff_equals_classical():
    p, q = np.array([0.9, 0.1]), np.array([0.4, 0.6])
    xi_q, _ = quantum_chernoff(np.diag(p).astype(complex), np.diag(q).astype(complex))
    assert xi_q == pytest.approx(classical_chernoff(p, q), rel=1e-6)


def test_projective_pauli_measurement_is_helstrom_optimal():
    """Legitimate vs forged signature round: the PS's projective measurement in
    the key basis attains the Helstrom bound (checked by SDP)."""
    pytest.importorskip("cvxpy")
    label = ALL_LABELS[4]
    legit, forged = depolarize(pauli_state(label), 0.92), MAXIMALLY_MIXED
    p_succ, povm = optimal_povm([legit, forged])
    assert 1 - p_succ == pytest.approx(helstrom_error(legit, forged), abs=1e-5)
    proj_success = (
        0.5
        * (
            np.trace(projector(label.basis, label.bit) @ legit)
            + np.trace(projector(label.basis, 1 - label.bit) @ forged)
        ).real
    )
    assert proj_success == pytest.approx(p_succ, abs=1e-5)
