import math

import numpy as np
import pytest

from arbiter.detection import UnifiedDetector
from arbiter.noise import PRESETS, TrappedIonParams
from arbiter.qds_simulation import Hypothesis, SessionConfig, simulate_session
from arbiter.qds_simulation.model import teleport
from arbiter.quantum.states import ALL_LABELS, BELL_PHI_PLUS, pauli_state, werner


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
    ).visibility()
    assert np.real(np.trace(BELL_PHI_PLUS @ werner(v_model))) == pytest.approx(fid)


def test_gate_error_is_depolarizing_with_matching_average_fidelity():
    f2 = 0.99
    v = TrappedIonParams(two_qubit_gate_fidelity=f2).visibility_budget()["ms_gate"]
    # Average gate fidelity of 2-qubit depolarizing with p = 1 - v is 1 - 3p/4
    assert 1 - 3 * (1 - v) / 4 == pytest.approx(f2)


def test_presets_are_ordered_and_valid():
    v = {k: p.visibility() for k, p in PRESETS.items()}
    assert v["state_of_the_art_2025"] > v["prototype"] > v["conservative"] > 0.8
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
