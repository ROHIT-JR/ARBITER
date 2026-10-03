"""Bell-fidelity rounds (issue #23).

Covers:
1. The circuits reproduce the density-matrix model.
2. The aligned-stabiliser structure of |Phi+> on a Werner pair.
3. Bell-fidelity rounds attain the *local* measurement optimum, and CHSH
   rounds provably cannot.
4. The new default round mix is a Pareto improvement over the legacy mix.
5. Round-mix validation and 3-tuple backward compatibility.
6. Regression guards for the cell-slicing bugs this round type exposed.
"""

import numpy as np
import pytest
from qiskit import transpile
from qiskit_aer import AerSimulator

from arbiter.detection.bounds import attack_bounds, local_distribution, measured_distribution
from arbiter.qds_simulation import ChannelParams, Hypothesis, SessionConfig, simulate_session
from arbiter.qds_simulation.circuits import BellFidelitySpec, bell_fidelity_circuit
from arbiter.qds_simulation.model import (
    ATTACKS,
    BELL_FIDELITY_BASES,
    BELL_FIDELITY_CELLS,
    BELL_FIDELITY_SIGNS,
    CELLS,
    CHSH_CELLS,
    RoundType,
    _legit_cell_probabilities,
    bell_fidelity_correlator,
    bell_fidelity_mismatch_probability,
    cell_probabilities,
    chsh_state,
    expected_bell_fidelity,
    expected_chsh,
)
from arbiter.qds_simulation.protocol import DEFAULT_ROUND_MIX, _normalise_round_mix

PARAMS = ChannelParams()
LEGACY_MIX = (0.5, 0.25, 0.25, 0.0)


# --- 2. stabiliser structure ---------------------------------------------


@pytest.mark.parametrize("v", [1.0, 0.92, 0.5, 0.0])
def test_werner_aligned_correlators_follow_phi_plus_stabilisers(v):
    """<ZZ> = <XX> = +v and <YY> = -v for a Werner pair."""
    rho = chsh_state(Hypothesis.LEGITIMATE, ChannelParams(visibility=v))
    assert bell_fidelity_correlator(rho, "Z") == pytest.approx(v)
    assert bell_fidelity_correlator(rho, "X") == pytest.approx(v)
    assert bell_fidelity_correlator(rho, "Y") == pytest.approx(-v)


@pytest.mark.parametrize("v", [1.0, 0.92, 0.5])
def test_mismatch_rate_is_one_minus_v_over_two_in_every_basis(v):
    """No 1/sqrt(2) dilution: aligned settings keep the full visibility."""
    rho = chsh_state(Hypothesis.LEGITIMATE, ChannelParams(visibility=v))
    for basis in BELL_FIDELITY_BASES:
        assert bell_fidelity_mismatch_probability(rho, basis) == pytest.approx((1 - v) / 2)


def test_bell_fidelity_beats_chsh_mismatch_contrast():
    """The honest mismatch rate is strictly lower than CHSH's, which is the
    whole reason these rounds carry more information per round."""
    p = cell_probabilities(Hypothesis.LEGITIMATE, 0.0, PARAMS)
    assert np.max(p[BELL_FIDELITY_CELLS]) < np.min(p[CHSH_CELLS])


def test_expected_fidelity_matches_closed_form():
    assert expected_bell_fidelity(Hypothesis.LEGITIMATE, 0.0, PARAMS) == pytest.approx((1 + 3 * 0.92) / 4)
    # A maximally mixed pair has fidelity 1/4 with any pure state.
    assert expected_bell_fidelity(Hypothesis.IMPERSONATION, 1.0, PARAMS) == pytest.approx(0.25)


def test_unknown_basis_rejected():
    rho = chsh_state(Hypothesis.LEGITIMATE, PARAMS)
    with pytest.raises(ValueError, match="basis"):
        bell_fidelity_correlator(rho, "W")


# --- 1. circuits agree with the model ------------------------------------


@pytest.mark.parametrize("basis", BELL_FIDELITY_BASES)
@pytest.mark.parametrize(
    "hypothesis", [Hypothesis.LEGITIMATE, Hypothesis.IMPERSONATION, Hypothesis.CHANNEL_MANIPULATION]
)
def test_circuit_matches_density_matrix_model(basis, hypothesis):
    """Acceptance criterion: |z| < 4.5 against the Born-rule probability."""
    shots = 20_000
    sign = BELL_FIDELITY_SIGNS[BELL_FIDELITY_BASES.index(basis)]
    # Eve picks her measure-resend basis uniformly, so average over it.
    eve_bases = ["Z", "X", "Y"] if hypothesis is Hypothesis.CHANNEL_MANIPULATION else [None]
    sim = AerSimulator()
    rng = np.random.default_rng(17)

    mismatches = 0
    for eve in eve_bases:
        spec = BellFidelitySpec(basis, PARAMS.visibility, eve, hypothesis is Hypothesis.IMPERSONATION)
        qc = transpile(bell_fidelity_circuit(spec), sim, num_processes=1)
        result = sim.run(
            qc, shots=shots // len(eve_bases), memory=True, seed_simulator=int(rng.integers(2**31))
        ).result()
        for shot in result.get_memory(0):
            ab = shot.split()[0]
            parity = int(ab[0]) ^ int(ab[1])
            mismatches += parity if sign == 1 else 1 - parity

    empirical = mismatches / shots
    expected = bell_fidelity_mismatch_probability(chsh_state(hypothesis, PARAMS), basis)
    se = np.sqrt(max(expected * (1 - expected), 1e-9) / shots)
    assert abs(empirical - expected) / se < 4.5


def test_circuit_rejects_non_pauli_basis():
    with pytest.raises(ValueError, match="Z/X/Y"):
        bell_fidelity_circuit(BellFidelitySpec("W", 0.92))


# --- 3. the local-measurement optimum ------------------------------------


def test_bell_fidelity_attains_the_local_ceiling():
    """Spending the whole shared-pair budget on Bell-fidelity rounds saturates
    the best achievable local measurement for every attack."""
    config = SessionConfig(round_mix=(0.5, 0.25, 0.0, 0.25))
    for row in attack_bounds(1.0, config):
        assert row["local_efficiency"] == pytest.approx(1.0, abs=1e-9)


def test_chsh_rounds_fall_short_of_the_local_ceiling():
    """The +-45-degree settings lose a factor sqrt(2) in correlator magnitude,
    so a CHSH-only shared-pair budget cannot reach the local optimum."""
    config = SessionConfig(round_mix=LEGACY_MIX)
    shared_pair_attacks = [r for r in attack_bounds(1.0, config) if r["attack"] != Hypothesis.FORGERY.value]
    assert shared_pair_attacks, "expected attacks visible on the shared pair"
    for row in shared_pair_attacks:
        assert row["local_efficiency"] < 0.9


def test_local_bound_is_between_measured_and_quantum():
    """xi_M <= xi_L <= xi_Q: the local ceiling is achievable, xi_Q is not."""
    for row in attack_bounds(1.0, SessionConfig()):
        assert row["measured_chernoff"] <= row["local_chernoff"] + 1e-9
        assert row["local_chernoff"] <= row["quantum_chernoff"] + 1e-9


def test_quantum_bound_is_invariant_to_the_shared_pair_split():
    """CHSH and Bell-fidelity rounds hold the same physical pair, so moving
    budget between them must not move xi_Q -- only xi_M may improve."""
    a = {r["attack"]: r for r in attack_bounds(1.0, SessionConfig(round_mix=(0.5, 0.25, 0.25, 0.0)))}
    b = {r["attack"]: r for r in attack_bounds(1.0, SessionConfig(round_mix=(0.5, 0.25, 0.0, 0.25)))}
    for attack in a:
        assert a[attack]["quantum_chernoff"] == pytest.approx(b[attack]["quantum_chernoff"])
        assert b[attack]["measured_chernoff"] >= a[attack]["measured_chernoff"] - 1e-9


def test_local_distribution_reallocates_chsh_budget():
    config = SessionConfig(round_mix=LEGACY_MIX)
    local = local_distribution(Hypothesis.LEGITIMATE, 0.0, config)
    ideal = measured_distribution(Hypothesis.LEGITIMATE, 0.0, SessionConfig(round_mix=(0.5, 0.25, 0.0, 0.25)))
    assert local == pytest.approx(ideal)


# --- 4. the new default mix is a Pareto improvement ----------------------


def test_default_mix_never_detects_worse_than_the_legacy_mix():
    """Acceptance criterion: no attack is worse off, and the bottleneck is
    strictly better."""
    legacy = {r["attack"]: r["measured_chernoff"] for r in attack_bounds(1.0, SessionConfig(round_mix=LEGACY_MIX))}
    new = {r["attack"]: r["measured_chernoff"] for r in attack_bounds(1.0, SessionConfig())}
    for attack, xi in legacy.items():
        assert new[attack] >= xi - 1e-9, f"{attack} regressed: {new[attack]:.6f} < {xi:.6f}"
    assert min(new.values()) > min(legacy.values())


def test_default_mix_keeps_enough_chsh_rounds_for_the_flag_check():
    """Below ~140 CHSH rounds the point-estimate `flagged` check false-alarms
    above 1% on an honest channel."""
    assert DEFAULT_ROUND_MIX[2] * 1200 >= 140


# --- 5. round_mix handling -----------------------------------------------


def test_three_tuple_round_mix_is_zero_padded():
    assert SessionConfig(round_mix=(0.5, 0.25, 0.25)).round_mix == (0.5, 0.25, 0.25, 0.0)


def test_legacy_three_tuple_schedules_no_bell_fidelity_rounds():
    transcript = simulate_session(config=SessionConfig(n_rounds=600, round_mix=(0.5, 0.25, 0.25)), seed=3)
    n, _ = transcript.counts()
    assert n[BELL_FIDELITY_CELLS].sum() == 0


@pytest.mark.parametrize("mix", [(0.5, 0.25), (0.4, 0.2, 0.2, 0.1, 0.1)])
def test_round_mix_length_validated(mix):
    with pytest.raises(ValueError, match="3 or 4"):
        _normalise_round_mix(mix)


def test_round_mix_must_sum_to_one():
    with pytest.raises(ValueError, match="sum to 1"):
        _normalise_round_mix((0.5, 0.25, 0.25, 0.25))


def test_round_mix_rejects_negative_weights():
    with pytest.raises(ValueError, match="non-negative"):
        _normalise_round_mix((0.8, 0.4, -0.2, 0.0))


def test_bell_fidelity_rounds_are_scheduled_and_sampled():
    transcript = simulate_session(config=SessionConfig(n_rounds=3000), seed=9)
    n, k = transcript.counts()
    nb, kb = n[BELL_FIDELITY_CELLS], k[BELL_FIDELITY_CELLS]
    assert np.all(nb > 0), "every Bell-fidelity basis should be sampled"
    rates = kb / nb
    expected = (1 - PARAMS.visibility) / 2
    se = np.sqrt(expected * (1 - expected) / nb)
    assert np.all(np.abs(rates - expected) < 4.5 * se)


def test_round_type_enum_and_cells_stay_aligned():
    assert RoundType.BELL_FIDELITY.value == "bell_fidelity"
    assert len(CELLS[BELL_FIDELITY_CELLS]) == len(BELL_FIDELITY_BASES)
    assert all(name.startswith("bell_") for name in CELLS[BELL_FIDELITY_CELLS])


# --- 6. regression guards for the slicing bugs ---------------------------


def test_expected_chsh_excludes_bell_fidelity_cells():
    """An open-ended p[2:] would fold in the aligned cells and push S past the
    Tsirelson bound."""
    s = expected_chsh(Hypothesis.LEGITIMATE, 0.0, PARAMS)
    assert s == pytest.approx(2 * np.sqrt(2) * PARAMS.visibility)
    assert s <= 2 * np.sqrt(2) + 1e-9


def test_legit_cell_probabilities_match_the_born_rule():
    """Regression: the chsh11 cell used to have its sign applied twice, which
    biased estimate_visibility low by ~0.024."""
    closed_form = _legit_cell_probabilities(PARAMS.visibility)
    born = cell_probabilities(Hypothesis.LEGITIMATE, 0.0, PARAMS)
    assert closed_form == pytest.approx(born)


@pytest.mark.parametrize("attack", [h for h in ATTACKS])
def test_attack_cell_probabilities_stay_probabilities(attack):
    p = cell_probabilities(attack, 1.0, PARAMS)
    assert len(p) == len(CELLS)
    assert np.all(p >= 0) and np.all(p <= 1)
