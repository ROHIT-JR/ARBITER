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

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path

from arbiter.qds_simulation.model import ChannelParams


@dataclass(frozen=True)
class TrappedIonParams:
    two_qubit_gate_fidelity: float = 0.999
    single_qubit_gate_fidelity: float = 0.99995
    single_qubit_gates_per_round: int = 4
    spam_error: float = 5e-4
    t2_seconds: float = 1.0
    t1_seconds: float = 0.1
    link_idle_seconds: float = 2e-3
    heating_error_per_link: float = 1e-4
    ms_overrotation_rad: float = 0.0
    crosstalk_error: float = 0.0
    attacker_storage_seconds: float = 0.2
    twirled: bool = True

    def __post_init__(self) -> None:
        for name in ("two_qubit_gate_fidelity", "single_qubit_gate_fidelity"):
            if not 0.5 < getattr(self, name) <= 1:
                raise ValueError(f"{name} must be in (0.5, 1]")
        if self.t2_seconds <= 0:
            raise ValueError("t2_seconds must be positive")
        if self.t1_seconds <= 0:
            raise ValueError("t1_seconds must be positive")
        if not 0 <= self.crosstalk_error < 1:
            raise ValueError("crosstalk_error must be in [0, 1)")

    def amplitude_damping_factor(self) -> float:
        """Amplitude damping (T1 relaxation) during idle time."""
        if self.link_idle_seconds == 0:
            return 1.0
        decay = math.exp(-self.link_idle_seconds / self.t1_seconds)
        return (1 + 2 * decay) / 3

    def ms_overrotation_factor(self) -> float:
        """Coherent MS gate over-rotation reduces fidelity systematically."""
        if self.ms_overrotation_rad == 0:
            return 1.0
        angle_error_fid_loss = 2 * (self.ms_overrotation_rad**2)
        return max(0.5, 1.0 - angle_error_fid_loss)

    def crosstalk_factor(self) -> float:
        """Two-qubit crosstalk reduces neighboring-qubit gate fidelity."""
        if self.crosstalk_error == 0:
            return 1.0
        v = 1 - self.crosstalk_error * 4 / 3
        return max(0.5, v)

    def visibility_budget(self) -> dict[str, float]:
        """The factors whose product is the link's Werner visibility."""
        gate = 1 - (1 - self.two_qubit_gate_fidelity) * 4 / 3
        gate *= self.ms_overrotation_factor()
        fid = (1 + math.exp(-2 * self.link_idle_seconds / self.t2_seconds)) / 2
        idle = (4 * fid - 1) / 3
        idle *= self.amplitude_damping_factor()
        heating = 1 - self.heating_error_per_link * 4 / 3
        heating *= self.crosstalk_factor()
        single = (1 - 2 * (1 - self.single_qubit_gate_fidelity)) ** self.single_qubit_gates_per_round
        spam = 1 - 2 * self.spam_error
        return {
            "ms_gate": gate,
            "ms_overrotation": self.ms_overrotation_factor(),
            "idle_dephasing": idle,
            "amplitude_damping": self.amplitude_damping_factor(),
            "motional_heating": heating,
            "crosstalk": self.crosstalk_factor(),
            "single_qubit_gates": single,
            "spam": spam,
        }

    def visibility(self) -> float:
        """Compute Werner visibility of the distributed Bell pair."""
        return math.prod(self.visibility_budget().values())

    def storage_visibility(self) -> float:
        """Storage visibility with T1 and T2 relaxation during attacker's hold time."""
        t2_factor = math.exp(-self.attacker_storage_seconds / self.t2_seconds)
        t1_factor = math.exp(-self.attacker_storage_seconds / self.t1_seconds)
        return (1 + 2 * t2_factor * t1_factor) / 3

    def channel_params(self) -> ChannelParams:
        return ChannelParams(visibility=self.visibility(), storage_visibility=self.storage_visibility())

    def to_dict(self) -> dict:
        return asdict(self) | {
            "visibility_budget": self.visibility_budget(),
            "visibility": self.visibility(),
            "storage_visibility": self.storage_visibility(),
        }

    @classmethod
    def from_calibration_file(cls, path: str | Path) -> TrappedIonParams:
        """Load and validate calibration data from a JSON file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Calibration file not found: {path}")
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
        return cls._from_calibration_dict(data)

    @classmethod
    def _from_calibration_dict(cls, data: dict) -> TrappedIonParams:
        """Construct TrappedIonParams from a calibration dictionary."""
        required = {
            "two_qubit_gate_fidelity",
            "single_qubit_gate_fidelity",
            "spam_error",
            "t2_seconds",
            "t1_seconds",
        }
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Calibration data missing required fields: {', '.join(sorted(missing))}")
        params_dict = {
            "two_qubit_gate_fidelity": data["two_qubit_gate_fidelity"],
            "single_qubit_gate_fidelity": data["single_qubit_gate_fidelity"],
            "spam_error": data["spam_error"],
            "t2_seconds": data["t2_seconds"],
            "t1_seconds": data["t1_seconds"],
            "single_qubit_gates_per_round": data.get("single_qubit_gates_per_round", 4),
            "link_idle_seconds": data.get("link_idle_seconds", 2e-3),
            "heating_error_per_link": data.get("heating_error_per_link", 1e-4),
            "ms_overrotation_rad": data.get("ms_overrotation_rad", 0.0),
            "crosstalk_error": data.get("crosstalk_error", 0.0),
            "attacker_storage_seconds": data.get("attacker_storage_seconds", 0.2),
            "twirled": data.get("twirled", True),
        }
        return cls(**params_dict)

    @staticmethod
    def validate_calibration_file(path: str | Path) -> tuple[bool, list[str]]:
        """Validate a calibration JSON file without constructing TrappedIonParams."""
        errors = []
        path = Path(path)
        if not path.exists():
            return False, [f"File not found: {path}"]
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            return False, [f"Invalid JSON: {exc}"]
        if not isinstance(data, dict):
            return False, ["Calibration data must be a JSON object (dict)"]
        required = {
            "two_qubit_gate_fidelity",
            "single_qubit_gate_fidelity",
            "spam_error",
            "t2_seconds",
            "t1_seconds",
        }
        missing = required - set(data.keys())
        if missing:
            errors.append(f"Missing required fields: {', '.join(sorted(missing))}")
        checks = [
            ("device_id", str, None),
            ("date", str, None),
            ("qubit_count", int, lambda x: x >= 2),
            ("two_qubit_gate_fidelity", (int, float), lambda x: 0.5 < x <= 1.0),
            ("single_qubit_gate_fidelity", (int, float), lambda x: 0.5 < x <= 1.0),
            ("spam_error", (int, float), lambda x: 0 <= x <= 0.5),
            ("t2_seconds", (int, float), lambda x: x > 0),
            ("t1_seconds", (int, float), lambda x: x > 0),
            ("link_idle_seconds", (int, float), lambda x: x >= 0),
            ("heating_error_per_link", (int, float), lambda x: 0 <= x <= 1),
            ("ms_overrotation_rad", (int, float), lambda x: x >= 0),
            ("crosstalk_error", (int, float), lambda x: 0 <= x <= 1),
            ("attacker_storage_seconds", (int, float), lambda x: x >= 0),
        ]
        for field, expected_type, constraint in checks:
            if field in data:
                value = data[field]
                if not isinstance(value, expected_type):
                    errors.append(f"{field}: expected {expected_type}, got {type(value).__name__}")
                elif constraint and not constraint(value):
                    errors.append(f"{field}: value {value} violates constraint")
        return len(errors) == 0, errors


# Presets from published figures (see docs/ion-trap-noise-model.md for sources).
# They describe *a* trapped-ion link with those component figures, not any
# specific vendor's device.
PRESETS: dict[str, TrappedIonParams] = {
    # 2025 state of the art: 99.99% two-qubit gates; >1 s T2 without
    # decoupling (minutes to hours with it); low SPAM; long T1 (minutes+).
    "state_of_the_art_2025": TrappedIonParams(
        two_qubit_gate_fidelity=0.9999,
        single_qubit_gate_fidelity=0.99999,
        spam_error=2e-4,
        t2_seconds=10.0,
        t1_seconds=100.0,
        link_idle_seconds=1e-3,
        heating_error_per_link=5e-5,
        ms_overrotation_rad=1e-4,
        crosstalk_error=5e-5,
    ),
    # Typical lab / early-prototype figures.
    "prototype": TrappedIonParams(
        t1_seconds=0.1,
        ms_overrotation_rad=5e-4,
        crosstalk_error=1e-4,
    ),
    # Pessimistic prototype: noisier gates, short coherence, long idle times,
    # shorter T1, larger MS rotation error and crosstalk.
    "conservative": TrappedIonParams(
        two_qubit_gate_fidelity=0.99,
        single_qubit_gate_fidelity=0.9995,
        spam_error=3e-3,
        t2_seconds=0.05,
        t1_seconds=0.05,
        link_idle_seconds=5e-3,
        heating_error_per_link=1e-3,
        ms_overrotation_rad=1e-3,
        crosstalk_error=1e-3,
    ),
}
