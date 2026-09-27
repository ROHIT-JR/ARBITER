"""Density-matrix primitives: Pauli eigenstates, Bell states and the channels
used by the ARBITER protocol and attack models.

Everything here is plain NumPy so the detector can compute exact Born-rule
probabilities; the Qiskit circuits in :mod:`arbiter.qds_simulation.circuits`
are checked against these in the test suite.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

I2 = np.eye(2, dtype=complex)
X = np.array([[0, 1], [1, 0]], dtype=complex)
Y = np.array([[0, -1j], [1j, 0]], dtype=complex)
Z = np.array([[1, 0], [0, -1]], dtype=complex)
PAULIS = {"X": X, "Y": Y, "Z": Z}
BASES = ("X", "Y", "Z")


@dataclass(frozen=True)
class PauliLabel:
    """One of the six Pauli eigenstates, e.g. ``PauliLabel("Y", 1)`` is |-i>.

    ``bit`` is the measurement outcome a projective measurement in ``basis``
    returns for this state: 0 for the +1 eigenvalue, 1 for the -1 eigenvalue.
    """

    basis: str
    bit: int

    @property
    def index(self) -> int:
        return BASES.index(self.basis) * 2 + self.bit

    @classmethod
    def from_index(cls, i: int) -> PauliLabel:
        return cls(BASES[i // 2], i % 2)


ALL_LABELS = tuple(PauliLabel.from_index(i) for i in range(6))


def projector(basis: str, bit: int) -> np.ndarray:
    """Projector onto the eigenstate of ``basis`` with outcome ``bit``."""
    sign = 1 - 2 * bit
    return (I2 + sign * PAULIS[basis]) / 2


def pauli_state(label: PauliLabel) -> np.ndarray:
    return projector(label.basis, label.bit)


PHI_PLUS = np.array([1, 0, 0, 1], dtype=complex) / np.sqrt(2)
BELL_PHI_PLUS = np.outer(PHI_PLUS, PHI_PLUS.conj())
MAXIMALLY_MIXED = I2 / 2


def depolarize(rho: np.ndarray, visibility: float) -> np.ndarray:
    """Single-qubit depolarizing channel: rho -> v*rho + (1-v)*I/2."""
    return visibility * rho + (1 - visibility) * np.trace(rho) * MAXIMALLY_MIXED


def werner(visibility: float) -> np.ndarray:
    """Bell pair with visibility v, i.e. (id x depolarize_v)|Phi+><Phi+|."""
    return visibility * BELL_PHI_PLUS + (1 - visibility) * np.eye(4) / 4


def measure_resend(rho: np.ndarray) -> np.ndarray:
    """Intercept-resend in a uniformly random Pauli basis (single qubit).

    Averaging the three complete dephasings shrinks the Bloch vector by 1/3,
    so this equals ``depolarize(rho, 1/3)`` -- asserted in the tests.
    """
    out = np.zeros((2, 2), dtype=complex)
    for b in BASES:
        for bit in (0, 1):
            P = projector(b, bit)
            out += P @ rho @ P
    return out / 3


def apply_on_second(channel, rho_ab: np.ndarray) -> np.ndarray:
    """Apply a single-qubit channel (given as a function on 2x2 matrices) to
    the second qubit of a two-qubit state, by linearity on the operator basis."""
    out = np.zeros((4, 4), dtype=complex)
    for i in range(2):
        for j in range(2):
            Eij = np.zeros((2, 2), dtype=complex)
            Eij[i, j] = 1
            # rho_ab = sum_{ij} A_ij (x) E_ij  with A_ij the (i,j) block over qubit 2
            A_ij = rho_ab.reshape(2, 2, 2, 2)[:, i, :, j]
            out += np.kron(A_ij, channel(Eij))
    return out


def partial_trace_first(rho_ab: np.ndarray) -> np.ndarray:
    return np.einsum("ijik->jk", rho_ab.reshape(2, 2, 2, 2))
