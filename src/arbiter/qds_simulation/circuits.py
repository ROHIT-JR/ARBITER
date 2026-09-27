"""Qiskit circuits realising every round type under every hypothesis.

These are the "physical" counterpart of :mod:`arbiter.qds_simulation.model`:
Bell-pair distribution, (attacked) channel, Bell measurement, classically
controlled Pauli correction, and projective verification measurement. The
test suite checks their sampled statistics against the density-matrix model.

Qubits: q0 = signer's input, q1 = signer's Bell half, q2 = verifier's Bell half.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister
from qiskit_aer.noise import depolarizing_error

from arbiter.quantum.states import PauliLabel


@dataclass(frozen=True)
class TeleportSpec:
    """Everything that determines one teleportation-round circuit."""

    sent: PauliLabel  # eigenstate the (claimed) signer feeds in
    verify: PauliLabel  # eigenstate the verifier expects
    visibility: float  # legitimate link visibility
    pre_noise: float = 0.0  # depolarizing prob on the input (replay storage)
    intercept_basis: str | None = None  # Eve's measure-resend basis on q2
    impersonated: bool = False  # corrections come from Eve, not a Bell measurement


@dataclass(frozen=True)
class ChshSpec:
    a: int
    b: int
    visibility: float
    intercept_basis: str | None = None
    signer_uncorrelated: bool = False  # impersonation / replayed outcomes


def _prepare(qc: QuantumCircuit, q, label: PauliLabel) -> None:
    if label.bit:
        qc.x(q)
    if label.basis in ("X", "Y"):
        qc.h(q)
    if label.basis == "Y":
        qc.s(q)


def _rotate_to_z(qc: QuantumCircuit, q, basis: str) -> None:
    """Rotate so that a Z measurement measures ``basis``."""
    if basis == "Y":
        qc.sdg(q)
    if basis in ("X", "Y"):
        qc.h(q)


def _rotate_from_z(qc: QuantumCircuit, q, basis: str) -> None:
    if basis in ("X", "Y"):
        qc.h(q)
    if basis == "Y":
        qc.s(q)


def _distribute_bell_pair(qc, q1, q2, visibility: float, intercept_basis, scratch) -> None:
    qc.h(q1)
    qc.cx(q1, q2)
    if visibility < 1:
        qc.append(depolarizing_error(1 - visibility, 1), [q2])
    if intercept_basis is not None:
        # Measure-resend: measuring collapses q2 onto an eigenstate of the
        # chosen basis, which is then forwarded to the verifier.
        _rotate_to_z(qc, q2, intercept_basis)
        qc.measure(q2, scratch)
        _rotate_from_z(qc, q2, intercept_basis)


def teleport_circuit(spec: TeleportSpec) -> QuantumCircuit:
    q = QuantumRegister(3, "q")
    bell = ClassicalRegister(2, "bell")
    scratch = ClassicalRegister(1, "scratch")
    out = ClassicalRegister(1, "out")
    qc = QuantumCircuit(q, bell, scratch, out)

    _distribute_bell_pair(qc, q[1], q[2], spec.visibility, spec.intercept_basis, scratch[0])

    if spec.impersonated:
        # Eve never touches the signer's half q1; she sends random correction
        # bits (drawn here from a fresh |+> qubit).
        for k in range(2):
            qc.h(q[0])
            qc.measure(q[0], bell[k])
            qc.reset(q[0])
    else:
        _prepare(qc, q[0], spec.sent)
        if spec.pre_noise > 0:
            qc.append(depolarizing_error(spec.pre_noise, 1), [q[0]])
        qc.cx(q[0], q[1])
        qc.h(q[0])
        qc.measure(q[0], bell[0])
        qc.measure(q[1], bell[1])

    with qc.if_test((bell[1], 1)):
        qc.x(q[2])
    with qc.if_test((bell[0], 1)):
        qc.z(q[2])

    _rotate_to_z(qc, q[2], spec.verify.basis)
    qc.measure(q[2], out[0])
    return qc


def chsh_circuit(spec: ChshSpec) -> QuantumCircuit:
    """Alice measures A_a in {Z, X}; Bob measures B_b in {(Z+X)/sqrt2, (Z-X)/sqrt2}."""
    q = QuantumRegister(3, "q")
    scratch = ClassicalRegister(1, "scratch")
    ab = ClassicalRegister(2, "ab")
    qc = QuantumCircuit(q, scratch, ab)

    _distribute_bell_pair(qc, q[1], q[2], spec.visibility, spec.intercept_basis, scratch[0])

    alice = q[1]
    if spec.signer_uncorrelated:
        alice = q[0]
        qc.h(alice)  # reported outcome is a fair coin, unrelated to q2
    elif spec.a == 1:
        qc.h(alice)
    qc.ry(-np.pi / 4 if spec.b == 0 else np.pi / 4, q[2])
    qc.measure(alice, ab[0])
    qc.measure(q[2], ab[1])
    return qc
