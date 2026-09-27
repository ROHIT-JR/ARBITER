"""Session-level simulation: key/nonce derivation, round scheduling and
sampling outcomes under a chosen hypothesis.

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

import numpy as np
from qiskit_aer import AerSimulator

from arbiter.qds_simulation.circuits import ChshSpec, TeleportSpec, chsh_circuit, teleport_circuit
from arbiter.qds_simulation.model import (
    ALL_OR_NOTHING,
    CELLS,
    CHSH_SETTINGS,
    CHSH_SIGNS,
    ChannelParams,
    Hypothesis,
    RoundType,
    _attack_cell_probs,
)
from arbiter.qrng import QRNG
from arbiter.quantum.states import BASES, PauliLabel

ROUND_TYPES = (RoundType.SIGNATURE, RoundType.FRESHNESS, RoundType.CHSH)


@dataclass(frozen=True)
class SessionConfig:
    n_rounds: int = 1200
    round_mix: tuple[float, float, float] = (0.5, 0.25, 0.25)  # sig, fresh, chsh
    params: ChannelParams = field(default_factory=ChannelParams)


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

    def counts(self) -> tuple[np.ndarray, np.ndarray]:
        n = np.bincount(self.cells, minlength=len(CELLS))
        k = np.bincount(self.cells, weights=self.outcomes, minlength=len(CELLS)).astype(int)
        return n, k

    def digest(self) -> str:
        h = hashlib.sha3_256()
        h.update(f"{self.session_id}|{self.message}|{self.nonce}|".encode())
        h.update(self.cells.astype(np.uint8).tobytes())
        h.update(self.outcomes.astype(np.uint8).tobytes())
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
    the verifier correctly treats as a resubmission)."""
    config = config or SessionConfig()
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

    sig_labels = derive_labels(signer_key, b"sig|" + message.encode(), n)
    fresh_labels = derive_labels(nonce, b"fresh", n)
    honest = np.where(rtypes == 0, sig_labels, fresh_labels)

    if backend == "analytic":
        legit = np.array(_attack_cell_probs(Hypothesis.LEGITIMATE, config.params))
        attack = np.array(_attack_cell_probs(hypothesis, config.params))
        p = np.where(attacked, attack[cells], legit[cells])
        outcomes = (rng.random(n) < p).astype(np.int8)
    elif backend == "qiskit":
        outcomes = _run_qiskit(hypothesis, rtypes, settings, honest, attacked, config.params, rng)
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


def _run_qiskit(h, rtypes, settings, labels, attacked, params, rng) -> np.ndarray:
    groups: dict[object, list[int]] = defaultdict(list)
    for i in range(len(rtypes)):
        spec = _round_spec(h, rtypes[i], settings[i], labels[i], attacked[i], params, rng)
        groups[spec].append(i)

    sim = AerSimulator()
    outcomes = np.zeros(len(rtypes), dtype=np.int8)
    for spec, idx in groups.items():
        if isinstance(spec, ChshSpec):
            qc = chsh_circuit(spec)
        else:
            qc = teleport_circuit(spec)
        memory = sim.run(qc, shots=len(idx), memory=True, seed_simulator=int(rng.integers(2**31))).result().get_memory()
        for i, shot in zip(idx, memory, strict=True):
            regs = shot.split()  # registers appear in reverse order of qc.cregs
            if isinstance(spec, ChshSpec):
                ab = regs[0]  # last register, bits written as "b a"
                parity = int(ab[0]) ^ int(ab[1])
                sign = CHSH_SIGNS[CHSH_SETTINGS.index((spec.a, spec.b))]
                outcomes[i] = parity if sign == 1 else 1 - parity
            else:
                got = int(regs[0])
                outcomes[i] = int(got != spec.verify.bit)
    return outcomes
