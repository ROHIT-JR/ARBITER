import json
import math

import numpy as np
import pytest

from arbiter.detection import UnifiedDetector
from arbiter.noise import PRESETS, TrappedIonParams
from arbiter.qds_simulation import Hypothesis, SessionConfig, simulate_session
from arbiter.qds_simulation.model import teleport
from arbiter.quantum.states import ALL_LABELS, BELL_PHI_PLUS, pauli_state, werner

VALID_CALIBRATION = {
    "device_id": "ion-trap-01",
    "date": "2026-01-01",
    "qubit_count": 8,
    "two_qubit_gate_fidelity": 0.999,
    "single_qubit_gate_fidelity": 0.9999,
    "spam_error": 5e-4,
    "t2_seconds": 1.0,
    "t1_seconds": 50.0,
    "link_idle_seconds": 2e-3,
    "heating_error_per_link": 1e-4,
    "ms_overrotation_rad": 1e-4,
    "crosstalk_error": 5e-5,
    "attacker_storage_seconds": 0.2,
}


def test_perfect_hardware_gives_perfect_link():
    p = TrappedIonParams(
        two_qubit_gate_fidelity=1,
        single_qubit_gate_fidelity=1,
        spam_error=0,
        link_idle_seconds=0,
        heating_error_per_link=0,
        attacker_storage_seconds=0,
    )
    assert p.visibility() == pytest.approx(1)
    assert p.storage_visibility() == pytest.approx(1)


def test_idle_dephasing_factor_matches_twirled_bell_state():
    """Dephase both halves of |Phi+> for time t; the Werner state with the same
    fidelity has exactly the visibility the model reports."""
    t, t2 = 0.3, 1.0
    lam = math.exp(-t / t2)  # off-diagonal decay per qubit
    deph = np.diag([1, 1, 1, 1]).astype(complex)
    deph[0, 3] = deph[3, 0] = lam**2  # both qubits dephase the |00><11| coherence
    rho = BELL_PHI_PLUS * deph
    fid = np.real(np.trace(BELL_PHI_PLUS @ rho))
    v_model = TrappedIonParams(
        two_qubit_gate_fidelity=1,
        single_qubit_gate_fidelity=1,
        spam_error=0,
        link_idle_seconds=t,
        t2_seconds=t2,
        heating_error_per_link=0,
        t1_seconds=1e9,  # isolate dephasing: neutralize amplitude damping
    ).visibility()
    assert np.real(np.trace(BELL_PHI_PLUS @ werner(v_model))) == pytest.approx(fid)


def test_gate_error_is_depolarizing_with_matching_average_fidelity():
    f2 = 0.99
    v = TrappedIonParams(two_qubit_gate_fidelity=f2).visibility_budget()["ms_gate"]
    # Average gate fidelity of 2-qubit depolarizing with p = 1 - v is 1 - 3p/4
    assert 1 - 3 * (1 - v) / 4 == pytest.approx(f2)


def test_presets_are_ordered_and_valid():
    v = {k: p.visibility() for k, p in PRESETS.items()}
    assert v["state_of_the_art_2025"] > v["prototype"] > v["conservative"] > 0.7
    for p in PRESETS.values():
        cp = p.channel_params()
        assert 0 < cp.storage_visibility <= 1 and 0 < cp.visibility < 1
        # The teleportation channel through the induced link keeps S > 2
        assert 2 * math.sqrt(2) * cp.visibility > 2


def test_invalid_params_rejected():
    with pytest.raises(ValueError):
        TrappedIonParams(two_qubit_gate_fidelity=1.2)
    with pytest.raises(ValueError):
        TrappedIonParams(t2_seconds=0)


@pytest.mark.parametrize("preset", sorted(PRESETS))
def test_detector_runs_on_trapped_ion_calibration(preset):
    params = PRESETS[preset].channel_params()
    config = SessionConfig(params=params)
    det = UnifiedDetector(params)
    assert not det.evaluate(simulate_session(config=config, seed=1)).rejected
    v = det.evaluate(simulate_session(Hypothesis.CHANNEL_MANIPULATION, 0.3, config, seed=1))
    assert v.rejected and v.attribution is Hypothesis.CHANNEL_MANIPULATION


def test_teleportation_through_preset_link_has_expected_fidelity():
    cp = PRESETS["prototype"].channel_params()
    psi = pauli_state(ALL_LABELS[4])
    out = teleport(psi, werner(cp.visibility))
    assert np.real(np.trace(out @ psi)) == pytest.approx((1 + cp.visibility) / 2)


def test_from_calibration_file_loads_valid_data(tmp_path):
    path = tmp_path / "calibration.json"
    path.write_text(json.dumps(VALID_CALIBRATION))
    params = TrappedIonParams.from_calibration_file(path)
    assert params.two_qubit_gate_fidelity == VALID_CALIBRATION["two_qubit_gate_fidelity"]
    assert params.t1_seconds == VALID_CALIBRATION["t1_seconds"]
    assert params.ms_overrotation_rad == VALID_CALIBRATION["ms_overrotation_rad"]


def test_from_calibration_file_applies_defaults_for_optional_fields():
    required_only = {
        "two_qubit_gate_fidelity": 0.999,
        "single_qubit_gate_fidelity": 0.9999,
        "spam_error": 5e-4,
        "t2_seconds": 1.0,
        "t1_seconds": 50.0,
    }
    params = TrappedIonParams._from_calibration_dict(required_only)
    assert params.single_qubit_gates_per_round == 4
    assert params.ms_overrotation_rad == 0.0
    assert params.crosstalk_error == 0.0
    assert params.twirled is True


def test_from_calibration_file_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        TrappedIonParams.from_calibration_file(tmp_path / "missing.json")


def test_from_calibration_file_invalid_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json")
    with pytest.raises(ValueError, match="Invalid JSON"):
        TrappedIonParams.from_calibration_file(path)


def test_from_calibration_dict_missing_required_fields_raises():
    with pytest.raises(ValueError, match="missing required fields"):
        TrappedIonParams._from_calibration_dict({"two_qubit_gate_fidelity": 0.999})


def test_validate_calibration_file_accepts_valid_data(tmp_path):
    path = tmp_path / "calibration.json"
    path.write_text(json.dumps(VALID_CALIBRATION))
    ok, errors = TrappedIonParams.validate_calibration_file(path)
    assert ok
    assert errors == []


def test_validate_calibration_file_missing_file():
    ok, errors = TrappedIonParams.validate_calibration_file("/nonexistent/path.json")
    assert not ok
    assert "File not found" in errors[0]


def test_validate_calibration_file_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json")
    ok, errors = TrappedIonParams.validate_calibration_file(path)
    assert not ok
    assert "Invalid JSON" in errors[0]


def test_validate_calibration_file_non_dict_json(tmp_path):
    path = tmp_path / "list.json"
    path.write_text(json.dumps([1, 2, 3]))
    ok, errors = TrappedIonParams.validate_calibration_file(path)
    assert not ok
    assert "JSON object" in errors[0]


def test_validate_calibration_file_missing_required_fields(tmp_path):
    path = tmp_path / "incomplete.json"
    path.write_text(json.dumps({"two_qubit_gate_fidelity": 0.999}))
    ok, errors = TrappedIonParams.validate_calibration_file(path)
    assert not ok
    assert any("Missing required fields" in e for e in errors)


def test_validate_calibration_file_rejects_out_of_range_values(tmp_path):
    bad = dict(VALID_CALIBRATION)
    bad["two_qubit_gate_fidelity"] = 1.5
    bad["qubit_count"] = 1
    path = tmp_path / "out_of_range.json"
    path.write_text(json.dumps(bad))
    ok, errors = TrappedIonParams.validate_calibration_file(path)
    assert not ok
    assert any("two_qubit_gate_fidelity" in e for e in errors)
    assert any("qubit_count" in e for e in errors)


def test_validate_calibration_file_rejects_wrong_type(tmp_path):
    bad = dict(VALID_CALIBRATION)
    bad["t2_seconds"] = "not a number"
    path = tmp_path / "wrong_type.json"
    path.write_text(json.dumps(bad))
    ok, errors = TrappedIonParams.validate_calibration_file(path)
    assert not ok
    assert any("t2_seconds" in e for e in errors)
