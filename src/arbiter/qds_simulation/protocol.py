"""Session-level simulation: QDS key distribution, messaging and sampling.

Two interchangeable backends produce identical transcript formats:

* ``"analytic"`` samples each round from the Born-rule probabilities of the
  density-matrix model (fast; used for threshold calibration and sweeps).
* ``"qiskit"`` builds and runs the actual Aer circuits for every round, with
  the attack realised as circuit operations (the "physical" demo path).
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Literal

import numpy as np
from qiskit import transpile
from qiskit_aer import AerSimulator

from arbiter.qds_simulation.circuits import ChshSpec, TeleportSpec, UseSpec, chsh_circuit, teleport_circuit, use_circuit
from arbiter.qds_simulation.model import (
    ALL_OR_NOTHING,
    BB84_LABELS,
    CELLS,
    CHSH_SETTINGS,
    CHSH_SIGNS,
    ChannelParams,
    Hypothesis,
    RoundType,
    _attack_cell_probs,
    _normalise_protocol,
    received_state,
    use_eliminated_label,
)
from arbiter.qrng import QRNG
from arbiter.quantum.states import BASES, PauliLabel, projector

ROUND_TYPES = (RoundType.SIGNATURE, RoundType.FRESHNESS, RoundType.CHSH)


@dataclass(frozen=True)
class DriftConfig:
    """Configuration for visibility drift during a session.

    type="static_offset": True visibility differs from calibrated by a fixed offset.
    type="linear_drift": True visibility changes linearly from v_start to v_end.
    type="step_change": Visibility jumps from v_before to v_after at change_round.
    """

    type: Literal["static_offset", "linear_drift", "step_change"]
    true_visibility: float = 0.0  # for static_offset: actual v (calibrated v is in params)
    v_start: float = 0.0  # for linear_drift: visibility at round 0
    v_end: float = 0.0  # for linear_drift: visibility at round n_rounds
    v_before: float = 0.0  # for step_change: visibility before change_round
    v_after: float = 0.0  # for step_change: visibility after change_round
    change_round: int = 0  # for step_change: round index where change occurs


@dataclass(frozen=True)
class SessionConfig:
    n_rounds: int = 1200
    round_mix: tuple[float, float, float] = (0.5, 0.25, 0.25)  # sig, fresh, chsh
    params: ChannelParams = field(default_factory=ChannelParams)
    protocol: str = "prf"
    drift: DriftConfig | None = None


@dataclass(frozen=True)
class QDSDistribution:
    """Classical record left by distribution of two BB84 quantum public keys.

    ``private_keys[b, i]`` and ``eliminated[recipient, b, i]`` are indices in
    :data:`BB84_LABELS`.  Recipients retain only their eliminated labels; the
    signer keeps the private keys until the later messaging stage.
    """

    private_keys: np.ndarray
    eliminated: np.ndarray

    @property
    def length(self) -> int:
        return int(self.private_keys.shape[1])

    @property
    def recipients(self) -> int:
        return int(self.eliminated.shape[0])

    def reveal(self, message_bit: int) -> np.ndarray:
        if message_bit not in (0, 1):
            raise ValueError("message_bit must be 0 or 1")
        return self.private_keys[message_bit].copy()

    def mismatch_count(self, recipient: int, message_bit: int, revealed: np.ndarray | None = None) -> int:
        if not 0 <= recipient < self.recipients:
            raise ValueError("unknown recipient")
        key = self.reveal(message_bit) if revealed is None else np.asarray(revealed, dtype=np.int8)
        if key.shape != (self.length,) or np.any((key < 0) | (key >= len(BB84_LABELS))):
            raise ValueError("revealed key must contain one BB84 label per position")
        return int(np.count_nonzero(self.eliminated[recipient, message_bit] == key))

    def mismatch_rate(self, recipient: int, message_bit: int, revealed: np.ndarray | None = None) -> float:
        return self.mismatch_count(recipient, message_bit, revealed) / self.length


@dataclass
class Transcript:
    """What the verifier observed, in round order.

    ``cells[i]`` indexes :data:`CELLS`; ``outcomes[i]`` is 1 for a mismatch
    (signature/freshness) or a CHSH parity against the ideal correlation sign.
    ``truth``/``theta``/``attacked`` are simulation ground truth and are never
    read by the detector.
    """

    session_id: str
    message: str
    nonce: str
    cells: np.ndarray
    outcomes: np.ndarray
    truth: Hypothesis
    theta: float
    attacked: np.ndarray
    backend: str
    protocol: str = "prf"

    def counts(self) -> tuple[np.ndarray, np.ndarray]:
        n = np.bincount(self.cells, minlength=len(CELLS))
        k = np.bincount(self.cells, weights=self.outcomes, minlength=len(CELLS)).astype(int)
        return n, k

    def digest(self) -> str:
        h = hashlib.sha3_256()
        h.update(f"{self.session_id}|{self.message}|{self.nonce}|".encode())
        h.update(self.cells.astype(np.uint8).tobytes())
        h.update(self.outcomes.astype(np.uint8).tobytes())
        # Keep the pre-QDS PRF digest byte-for-byte compatible with persisted
        # sessions, while binding QDS transcripts to their distinct protocol.
        if self.protocol != "prf":
            h.update(f"|protocol={self.protocol}".encode())
        return h.hexdigest()


def derive_labels(seed: bytes, context: bytes, n: int) -> np.ndarray:
    """PRF (SHAKE-256) -> n uniform Pauli-eigenstate indices in 0..5, by
    rejection sampling bytes below 252 = 42 * 6."""
    out: list[int] = []
    counter = 0
    while len(out) < n:
        stream = hashlib.shake_256(seed + context + counter.to_bytes(4, "big")).digest(2 * n)
        out.extend(b % 6 for b in stream if b < 252)
        counter += 1
    return np.array(out[:n], dtype=np.int8)


def derive_qds_private_keys(signer_key: bytes, length: int) -> np.ndarray:
    """Derive the two uniformly random BB84 private keys held by the signer.

    This is only a deterministic simulator convenience.  In a deployed QDS
    system Alice samples these labels from private entropy before distribution.
    """
    if length < 1:
        raise ValueError("QDS key length must be positive")
    keys = []
    for message_bit in (0, 1):
        stream = hashlib.shake_256(signer_key + b"qds-distribution|" + bytes([message_bit])).digest(length)
        keys.append(np.frombuffer(stream, dtype=np.uint8).astype(np.int8) & 0b11)
    return np.stack(keys)


def _distribution_hypothesis(hypothesis: Hypothesis) -> Hypothesis:
    """Only channel manipulation changes public-key distribution in this model."""
    return hypothesis if hypothesis is Hypothesis.CHANNEL_MANIPULATION else Hypothesis.LEGITIMATE


def _sample_use_outcome(
    label: PauliLabel,
    basis: str,
    hypothesis: Hypothesis,
    params: ChannelParams,
    rng: np.random.Generator,
) -> int:
    rho = received_state(_distribution_hypothesis(hypothesis), RoundType.SIGNATURE, label, params)
    p_one = float(np.real(np.trace(projector(basis, 1) @ rho)))
    return int(rng.random() < p_one)


def distribute_qds_keys(
    signer_key: bytes = b"arbiter-demo-signing-key",
    length: int = 1200,
    recipients: int = 1,
    params: ChannelParams | None = None,
    seed: int | None = None,
    distribution_attack: Hypothesis = Hypothesis.LEGITIMATE,
    backend: str = "analytic",
) -> QDSDistribution:
    """Run the QDS distribution stage for both message bits.

    Alice teleports every BB84 public-key state across a separate Bell pair.
    Each recipient chooses X or Z uniformly and records only the state
    eliminated by that USE measurement.  ``distribution_attack`` models Eve's
    intercept-resend channel during this stage; keyless forgery belongs to the
    later messaging reveal and is represented by ``mismatch_count(...,
    revealed=...)``.
    """
    if recipients < 1:
        raise ValueError("at least one recipient is required")
    if backend not in ("analytic", "qiskit"):
        raise ValueError(f"unknown backend {backend!r}")
    params = params or ChannelParams()
    private_keys = derive_qds_private_keys(signer_key, length)
    rng = np.random.default_rng(seed)
    bases = np.where(rng.integers(0, 2, size=(recipients, 2, length)) == 0, "Z", "X")
    eliminated = np.empty((recipients, 2, length), dtype=np.int8)

    if backend == "analytic":
        for recipient in range(recipients):
            for message_bit in (0, 1):
                for position, code in enumerate(private_keys[message_bit]):
                    outcome = _sample_use_outcome(
                        BB84_LABELS[int(code)],
                        str(bases[recipient, message_bit, position]),
                        distribution_attack,
                        params,
                        rng,
                    )
                    eliminated_label = use_eliminated_label(str(bases[recipient, message_bit, position]), outcome)
                    eliminated[recipient, message_bit, position] = BB84_LABELS.index(eliminated_label)
    else:
        eliminated = _distribute_qds_keys_qiskit(private_keys, bases, params, distribution_attack, rng)
    return QDSDistribution(private_keys=private_keys, eliminated=eliminated)


def _distribute_qds_keys_qiskit(
    private_keys: np.ndarray,
    bases: np.ndarray,
    params: ChannelParams,
    distribution_attack: Hypothesis,
    rng: np.random.Generator,
) -> np.ndarray:
    """Aer counterpart of :func:`distribute_qds_keys`, batched by USE spec."""
    shape = bases.shape
    eliminated = np.empty(shape, dtype=np.int8)
    groups: dict[UseSpec, list[tuple[int, int, int]]] = defaultdict(list)
    intercepts = (
        rng.integers(0, len(BASES), size=shape) if distribution_attack is Hypothesis.CHANNEL_MANIPULATION else None
    )
    for recipient in range(shape[0]):
        for message_bit in (0, 1):
            for position, code in enumerate(private_keys[message_bit]):
                spec = UseSpec(
                    BB84_LABELS[int(code)],
                    str(bases[recipient, message_bit, position]),
                    params.visibility,
                    (BASES[int(intercepts[recipient, message_bit, position])] if intercepts is not None else None),
                )
                groups[spec].append((recipient, message_bit, position))

    specs = list(groups)
    sim = AerSimulator()
    circuits = transpile([use_circuit(spec) for spec in specs], sim, num_processes=1)
    result = sim.run(
        circuits,
        shots=max(len(indices) for indices in groups.values()),
        memory=True,
        seed_simulator=int(rng.integers(2**31)),
    ).result()
    for circuit_index, spec in enumerate(specs):
        for (recipient, message_bit, position), memory in zip(
            groups[spec], result.get_memory(circuit_index)[: len(groups[spec])], strict=True
        ):
            outcome = int(memory.split()[0])
            eliminated[recipient, message_bit, position] = BB84_LABELS.index(
                use_eliminated_label(spec.elimination_basis, outcome)
            )
    return eliminated


def _get_visibility_at_round(config: SessionConfig, round_idx: int) -> float:
    """Get the true visibility at a specific round, considering drift config."""
    if config.drift is None:
        return config.params.visibility

    drift = config.drift
    n = config.n_rounds
    if drift.type == "static_offset":
        return drift.true_visibility
    elif drift.type == "linear_drift":
        t = round_idx / max(n - 1, 1)
        return drift.v_start + t * (drift.v_end - drift.v_start)
    elif drift.type == "step_change":
        if round_idx < drift.change_round:
            return drift.v_before
        else:
            return drift.v_after
    return config.params.visibility


def simulate_session(
    hypothesis: Hypothesis = Hypothesis.LEGITIMATE,
    theta: float = 1.0,
    config: SessionConfig | None = None,
    message: str = "transfer 100 units to account 42",
    signer_key: bytes = b"arbiter-demo-signing-key",
    seed: int | None = None,
    backend: str = "analytic",
) -> Transcript:
    """Simulate one session. ``seed`` makes it reproducible; it is mixed with the
    scenario so that different scenarios run under the same seed still get
    distinct QRNG nonces (identical calls do reproduce the same nonce, which
    the verifier correctly treats as a resubmission).

    If ``config.drift`` is provided, the true visibility varies per round
    according to the drift configuration, while ``config.params.visibility``
    remains the calibrated (assumed) visibility used by the detector.
    """
    config = config or SessionConfig()
    protocol = _normalise_protocol(config.protocol)
    if hypothesis is Hypothesis.LEGITIMATE:
        theta = 0.0
    elif hypothesis in ALL_OR_NOTHING:
        theta = 1.0
    theta = float(theta)
    if seed is not None:
        scenario = f"{seed}|{hypothesis.value}|{theta!r}|{config.n_rounds}|{message}".encode()
        seed = int.from_bytes(hashlib.sha256(scenario).digest()[:4], "big") >> 1
    qrng = QRNG(seed)
    nonce = qrng.token_bytes(32)
    rng = np.random.default_rng(qrng.seed_int())
    n = config.n_rounds

    rtypes = rng.choice(3, size=n, p=config.round_mix)
    settings = rng.integers(0, 4, size=n)
    cells = np.where(rtypes == 2, 2 + settings, rtypes).astype(np.int64)
    attacked = rng.random(n) < theta

    if protocol == "qds":
        message_bit = hashlib.sha256(message.encode()).digest()[0] & 1
        qds_keys = derive_qds_private_keys(signer_key, n)
        sig_labels = np.array([BB84_LABELS[int(code)].index for code in qds_keys[message_bit]], dtype=np.int8)
    else:
        sig_labels = derive_labels(signer_key, b"sig|" + message.encode(), n)
    fresh_labels = derive_labels(nonce, b"fresh", n)
    honest = np.where(rtypes == 0, sig_labels, fresh_labels)

    if backend == "analytic":
        # With drift, compute per-round probabilities using true visibility at each round
        if config.drift is not None:
            outcomes = np.zeros(n, dtype=np.int8)
            for i in range(n):
                v_true = _get_visibility_at_round(config, i)
                params_i = ChannelParams(visibility=v_true, storage_visibility=config.params.storage_visibility)
                legit_i = np.array(_attack_cell_probs(Hypothesis.LEGITIMATE, params_i, protocol))
                attack_i = np.array(_attack_cell_probs(hypothesis, params_i, protocol))
                p_i = attack_i[cells[i]] if attacked[i] else legit_i[cells[i]]
                outcomes[i] = int(rng.random() < p_i)
        else:
            legit = np.array(_attack_cell_probs(Hypothesis.LEGITIMATE, config.params, protocol))
            attack = np.array(_attack_cell_probs(hypothesis, config.params, protocol))
            p = np.where(attacked, attack[cells], legit[cells])
            outcomes = (rng.random(n) < p).astype(np.int8)
    elif backend == "qiskit":
        # For qiskit backend with drift, we'd need per-round circuits with different noise.
        # For now, fall back to analytic with drift warning, or use average visibility.
        if config.drift is not None:
            # Use average visibility for qiskit (approximation)
            v_avg = np.mean([_get_visibility_at_round(config, i) for i in range(n)])
            params_avg = ChannelParams(visibility=v_avg, storage_visibility=config.params.storage_visibility)
            outcomes = _run_qiskit(hypothesis, rtypes, settings, honest, attacked, params_avg, rng, protocol)
        else:
            outcomes = _run_qiskit(hypothesis, rtypes, settings, honest, attacked, config.params, rng, protocol)
    else:
        raise ValueError(f"unknown backend {backend!r}")

    return Transcript(
        session_id=str(uuid.UUID(bytes=qrng.token_bytes(16), version=4)),
        message=message,
        nonce=nonce.hex(),
        cells=cells,
        outcomes=outcomes,
        truth=hypothesis,
        theta=theta,
        attacked=attacked,
        backend=backend,
        protocol=protocol,
    )


def _round_spec(
    h: Hypothesis,
    rtype: int,
    setting: int,
    label_idx: int,
    attacked: bool,
    params: ChannelParams,
    rng: np.random.Generator,
):
    v = params.visibility
    h = h if attacked else Hypothesis.LEGITIMATE
    intercept = BASES[rng.integers(3)] if h is Hypothesis.CHANNEL_MANIPULATION else None
    if ROUND_TYPES[rtype] is RoundType.CHSH:
        a, b = CHSH_SETTINGS[setting]
        return ChshSpec(a, b, v, intercept, h in (Hypothesis.IMPERSONATION, Hypothesis.REPLAY))
    rt = ROUND_TYPES[rtype]
    honest = PauliLabel.from_index(int(label_idx))
    sent, pre_noise = honest, 0.0
    if (h is Hypothesis.FORGERY and rt is RoundType.SIGNATURE) or (
        h is Hypothesis.REPLAY and rt is RoundType.FRESHNESS
    ):
        sent = PauliLabel.from_index(int(rng.integers(6)))  # guess / stale-nonce state
    elif h is Hypothesis.REPLAY:
        pre_noise = 1 - params.storage_visibility
    return TeleportSpec(sent, honest, v, pre_noise, intercept, h is Hypothesis.IMPERSONATION)


def _run_qiskit(h, rtypes, settings, labels, attacked, params, rng, protocol: str = "prf") -> np.ndarray:
    groups: dict[object, list[int]] = defaultdict(list)
    for i in range(len(rtypes)):
        if protocol == "qds" and ROUND_TYPES[rtypes[i]] is RoundType.SIGNATURE:
            effective = h if attacked[i] and h is Hypothesis.CHANNEL_MANIPULATION else Hypothesis.LEGITIMATE
            intercept = BASES[int(rng.integers(3))] if effective is Hypothesis.CHANNEL_MANIPULATION else None
            spec = UseSpec(
                PauliLabel.from_index(int(labels[i])),
                ("Z", "X")[int(rng.integers(2))],
                params.visibility,
                intercept,
            )
        else:
            spec = _round_spec(h, rtypes[i], settings[i], labels[i], attacked[i], params, rng)
        groups[spec].append(i)

    specs = list(groups)
    circuits = []
    for spec in specs:
        if isinstance(spec, ChshSpec):
            circuits.append(chsh_circuit(spec))
        elif isinstance(spec, UseSpec):
            circuits.append(use_circuit(spec))
        else:
            circuits.append(teleport_circuit(spec))

    sim = AerSimulator()
    circuits = transpile(circuits, sim, num_processes=1)
    max_shots = max(len(idx) for idx in groups.values())
    # Aer derives a different experiment seed for every circuit in a batched
    # job. Supplying one fresh job seed therefore stays reproducible without
    # repeating the same random stream across distinct circuits.
    result = sim.run(
        circuits,
        shots=max_shots,
        memory=True,
        seed_simulator=int(rng.integers(2**31)),
    ).result()

    outcomes = np.zeros(len(rtypes), dtype=np.int8)
    for circuit_index, spec in enumerate(specs):
        idx = groups[spec]
        memory = result.get_memory(circuit_index)[: len(idx)]
        for i, shot in zip(idx, memory, strict=True):
            regs = shot.split()  # registers appear in reverse order of qc.cregs
            if isinstance(spec, ChshSpec):
                ab = regs[0]  # last register, bits written as "b a"
                parity = int(ab[0]) ^ int(ab[1])
                sign = CHSH_SIGNS[CHSH_SETTINGS.index((spec.a, spec.b))]
                outcomes[i] = parity if sign == 1 else 1 - parity
            elif isinstance(spec, UseSpec):
                eliminated = use_eliminated_label(spec.elimination_basis, int(regs[0]))
                if attacked[i] and h in (Hypothesis.FORGERY, Hypothesis.REPLAY, Hypothesis.IMPERSONATION):
                    revealed = BB84_LABELS[int(rng.integers(len(BB84_LABELS)))]
                else:
                    revealed = spec.sent
                outcomes[i] = int(eliminated == revealed)
            else:
                got = int(regs[0])
                outcomes[i] = int(got != spec.verify.bit)
    return outcomes
