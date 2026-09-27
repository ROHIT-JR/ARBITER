"""Trapped-ion noise model -> :class:`ChannelParams`.

Every downstream quantity in ARBITER (likelihoods, thresholds, bounds) is
derived from two numbers in ``ChannelParams``: the Werner visibility of the
distributed Bell pairs and the storage visibility of an attacker's memory.
This module computes both from physical trapped-ion parameters, so a hardware
team can replace the generic depolarizing assumption with calibration data.

Composition (each factor is a Bloch-vector / Werner-visibility shrink):

* Molmer-Sorensen entangling gate with average fidelity F2, modelled as
  two-qubit depolarizing: p = (1 - F2) * d/(d-1) with d = 4, v = 1 - p.
* Idle dephasing for time t on each half, with coherence time T2
  (laser phase noise and magnetic-field noise folded into T2). Dephasing
  both qubits of |Phi+> leaves fidelity (1 + e^{-2t/T2})/2. Random
  bilateral Pauli twirling maps any Bell-diagonal state to the Werner state
  with the same fidelity F, whose visibility is (4F - 1)/3, so this is
  exact for a twirled link.
* Motional heating during transport or shuttling, given as a residual
  two-qubit error per link, depolarizing like the gate error.
* Single-qubit gates (preparation, correction, basis change): k gates of
  average fidelity F1, each depolarizing with v = 1 - 2(1 - F1) (d = 2).
* State preparation and measurement error e_spam flips the verifier's
  outcome, which equals depolarizing with v = 1 - 2 e_spam.

The replay attacker's quantum memory dephases with the same T2; twirled,
a single dephased qubit is depolarizing with v = (1 + 2 e^{-t/T2})/3.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass

from arbiter.qds_simulation.model import ChannelParams


@dataclass(frozen=True)
class TrappedIonParams:
    two_qubit_gate_fidelity: float = 0.999
    single_qubit_gate_fidelity: float = 0.99995
    single_qubit_gates_per_round: int = 4
    spam_error: float = 5e-4
    t2_seconds: float = 1.0
    link_idle_seconds: float = 2e-3
    heating_error_per_link: float = 1e-4
    attacker_storage_seconds: float = 0.2

    def __post_init__(self) -> None:
        for name in ("two_qubit_gate_fidelity", "single_qubit_gate_fidelity"):
            if not 0.5 < getattr(self, name) <= 1:
                raise ValueError(f"{name} must be in (0.5, 1]")
        if self.t2_seconds <= 0:
            raise ValueError("t2_seconds must be positive")

    def visibility_budget(self) -> dict[str, float]:
        """The factors whose product is the link's Werner visibility."""
        gate = 1 - (1 - self.two_qubit_gate_fidelity) * 4 / 3
        fid = (1 + math.exp(-2 * self.link_idle_seconds / self.t2_seconds)) / 2
        idle = (4 * fid - 1) / 3
        heating = 1 - self.heating_error_per_link * 4 / 3
        single = (1 - 2 * (1 - self.single_qubit_gate_fidelity)) ** self.single_qubit_gates_per_round
        spam = 1 - 2 * self.spam_error
        return {
            "ms_gate": gate,
            "idle_dephasing": idle,
            "motional_heating": heating,
            "single_qubit_gates": single,
            "spam": spam,
        }

    def visibility(self) -> float:
        return math.prod(self.visibility_budget().values())

    def storage_visibility(self) -> float:
        return (1 + 2 * math.exp(-self.attacker_storage_seconds / self.t2_seconds)) / 3

    def channel_params(self) -> ChannelParams:
        return ChannelParams(visibility=self.visibility(), storage_visibility=self.storage_visibility())

    def to_dict(self) -> dict:
        return asdict(self) | {
            "visibility_budget": self.visibility_budget(),
            "visibility": self.visibility(),
            "storage_visibility": self.storage_visibility(),
        }


# Presets from published figures (see docs/ion-trap-noise-model.md for sources).
# They describe *a* trapped-ion link with those component figures, not any
# specific vendor's device.
PRESETS: dict[str, TrappedIonParams] = {
    # 2025 state of the art: 99.99% two-qubit gates; >1 s T2 without
    # decoupling (minutes to hours with it); low SPAM.
    "state_of_the_art_2025": TrappedIonParams(
        two_qubit_gate_fidelity=0.9999,
        single_qubit_gate_fidelity=0.99999,
        spam_error=2e-4,
        t2_seconds=10.0,
        link_idle_seconds=1e-3,
        heating_error_per_link=5e-5,
    ),
    # Typical lab / early-prototype figures.
    "prototype": TrappedIonParams(),
    # Pessimistic prototype: noisier gates, short coherence, long idle times.
    "conservative": TrappedIonParams(
        two_qubit_gate_fidelity=0.99,
        single_qubit_gate_fidelity=0.9995,
        spam_error=3e-3,
        t2_seconds=0.05,
        link_idle_seconds=5e-3,
        heating_error_per_link=1e-3,
    ),
}
