import numpy as np
import pytest
from qiskit_aer import AerSimulator

from arbiter.pipeline import Arbiter
from arbiter.qds_simulation import (
    ATTACKS,
    ChannelParams,
    Hypothesis,
    RoundType,
    SessionConfig,
    cell_probabilities,
    distribute_qds_keys,
    expected_chsh,
    protocol,
    qds_forgery_mismatch_rate,
    simulate_session,
)
from arbiter.qds_simulation.model import mismatch_probability, received_state
from arbiter.qds_simulation.protocol import derive_labels
from arbiter.quantum.states import ALL_LABELS

PARAMS = ChannelParams()


def test_legitimate_statistics():
    p = cell_probabilities(Hypothesis.LEGITIMATE, 0, PARAMS)
    assert p[0] == pytest.approx((1 - PARAMS.visibility) / 2)
    assert expected_chsh(Hypothesis.LEGITIMATE, 0, PARAMS) == pytest.approx(2 * np.sqrt(2) * PARAMS.visibility)


def test_attack_fingerprints():
    """Each attack moves a different combination of observables."""
    legit = cell_probabilities(Hypothesis.LEGITIMATE, 0, PARAMS)
    forg = cell_probabilities(Hypothesis.FORGERY, 1, PARAMS)
    rep = cell_probabilities(Hypothesis.REPLAY, 1, PARAMS)
    imp = cell_probabilities(Hypothesis.IMPERSONATION, 1, PARAMS)
    chan = cell_probabilities(Hypothesis.CHANNEL_MANIPULATION, 1, PARAMS)
    assert forg[0] == pytest.approx(0.5) and forg[1] == pytest.approx(legit[1])
    assert np.allclose(forg[2:], legit[2:])
    assert rep[1] == pytest.approx(0.5) and legit[0] < rep[0] < 0.2
    assert np.allclose(imp, 0.5)
    assert chan[0] == pytest.approx(chan[1]) and chan[0] < 0.5
    # intercept-resend destroys the Bell violation
    assert expected_chsh(Hypothesis.CHANNEL_MANIPULATION, 1, PARAMS) < 2


@pytest.mark.parametrize("h", list(Hypothesis))
@pytest.mark.parametrize("rt", [RoundType.SIGNATURE, RoundType.FRESHNESS])
def test_model_is_label_symmetric(h, rt):
    probs = [mismatch_probability(received_state(h, rt, lab, PARAMS), lab) for lab in ALL_LABELS]
    assert np.allclose(probs, probs[0])


def test_forger_best_guess_is_coin_flip():
    """Any fixed forged state mismatches a uniformly random Pauli key half the time."""
    from arbiter.quantum.states import pauli_state

    for guess in ALL_LABELS:
        rho = pauli_state(guess)
        errs = [mismatch_probability(rho, key) for key in ALL_LABELS]
        assert np.mean(errs) == pytest.approx(0.5)


def test_label_prf_is_deterministic_and_uniform():
    a = derive_labels(b"k", b"ctx", 60000)
    assert np.array_equal(a, derive_labels(b"k", b"ctx", 60000))
    assert not np.array_equal(a[:100], derive_labels(b"k", b"other", 100))
    freq = np.bincount(a, minlength=6) / len(a)
    assert np.allclose(freq, 1 / 6, atol=0.01)


def test_qds_distribution_has_zero_noiseless_mismatches_and_analytic_noise_rate():
    noiseless = distribute_qds_keys(length=2000, params=ChannelParams(visibility=1.0), seed=4)
    assert all(noiseless.mismatch_count(0, bit) == 0 for bit in (0, 1))

    params = ChannelParams(visibility=0.92)
    distributed = distribute_qds_keys(length=30_000, params=params, seed=8)
    observed = sum(distributed.mismatch_count(0, bit) for bit in (0, 1)) / (2 * distributed.length)
    expected = cell_probabilities(Hypothesis.LEGITIMATE, 0, params, protocol="qds")[0]
    z = (observed - expected) / np.sqrt(expected * (1 - expected) / (2 * distributed.length))
    assert expected == pytest.approx((1 - params.visibility) / 4)
    assert abs(z) < 4.5


def test_qds_keyless_forgery_has_one_quarter_mismatch_rate():
    distributed = distribute_qds_keys(length=40_000, params=ChannelParams(visibility=1.0), seed=9)
    forged_reveal = np.zeros(distributed.length, dtype=np.int8)
    observed = distributed.mismatch_rate(0, 0, forged_reveal)
    expected = qds_forgery_mismatch_rate()
    z = (observed - expected) / np.sqrt(expected * (1 - expected) / distributed.length)
    assert abs(z) < 4.5
    assert cell_probabilities(Hypothesis.FORGERY, 1, PARAMS, protocol="qds")[0] == pytest.approx(expected)


def test_qds_distribution_attack_matches_its_born_rule_signature_rate():
    params = ChannelParams(visibility=0.92)
    distributed = distribute_qds_keys(
        length=30_000,
        params=params,
        seed=10,
        distribution_attack=Hypothesis.CHANNEL_MANIPULATION,
    )
    observed = sum(distributed.mismatch_count(0, bit) for bit in (0, 1)) / (2 * distributed.length)
    expected = cell_probabilities(Hypothesis.CHANNEL_MANIPULATION, 1, params, protocol="qds")[0]
    z = (observed - expected) / np.sqrt(expected * (1 - expected) / (2 * distributed.length))
    assert abs(z) < 4.5


@pytest.mark.slow
def test_qds_use_aer_matches_density_matrix_model():
    params = ChannelParams(visibility=0.92)
    distributed = distribute_qds_keys(length=12_000, params=params, seed=12, backend="qiskit")
    observed = sum(distributed.mismatch_count(0, bit) for bit in (0, 1)) / (2 * distributed.length)
    expected = cell_probabilities(Hypothesis.LEGITIMATE, 0, params, protocol="qds")[0]
    z = (observed - expected) / np.sqrt(expected * (1 - expected) / (2 * distributed.length))
    assert abs(z) < 4.5


def test_explicit_prf_protocol_reproduces_the_default_session():
    default = simulate_session(Hypothesis.FORGERY, 0.5, seed=17)
    explicit = simulate_session(Hypothesis.FORGERY, 0.5, SessionConfig(protocol="prf"), seed=17)
    assert default.protocol == explicit.protocol == "prf"
    assert default.nonce == explicit.nonce
    assert np.array_equal(default.cells, explicit.cells)
    assert np.array_equal(default.outcomes, explicit.outcomes)


def test_qds_transcript_is_evaluated_with_the_matching_pipeline_model():
    transcript = simulate_session(config=SessionConfig(n_rounds=100, protocol="qds"), seed=18)
    verdict = Arbiter(protocol="qds").verify(transcript)
    assert verdict.transcript.protocol == "qds"
    with pytest.raises(ValueError, match="does not match"):
        Arbiter(protocol="prf").verify(transcript)


def test_session_is_reproducible_and_counts_add_up():
    a = simulate_session(Hypothesis.FORGERY, 0.5, seed=7)
    b = simulate_session(Hypothesis.FORGERY, 0.5, seed=7)
    assert a.nonce == b.nonce and np.array_equal(a.outcomes, b.outcomes)
    n, k = a.counts()
    assert n.sum() == 1200 and np.all(k <= n)
    assert simulate_session(seed=8).nonce != a.nonce


def test_same_seed_different_scenarios_get_distinct_nonces():
    nonces = {simulate_session(h, seed=42).nonce for h in Hypothesis}
    assert len(nonces) == len(Hypothesis)
    assert (
        simulate_session(Hypothesis.FORGERY, 0.3, seed=42).nonce
        != simulate_session(Hypothesis.FORGERY, 0.4, seed=42).nonce
    )


def test_impersonation_is_all_or_nothing():
    assert simulate_session(Hypothesis.IMPERSONATION, 0.2, seed=1).theta == 1.0


def test_qiskit_circuits_are_submitted_as_one_batch(monkeypatch):
    class CountingAerSimulator(AerSimulator):
        run_calls = 0

        def run(self, circuits, *args, **kwargs):
            type(self).run_calls += 1
            assert isinstance(circuits, list)
            assert len(circuits) > 1
            return super().run(circuits, *args, **kwargs)

    monkeypatch.setattr(protocol, "AerSimulator", CountingAerSimulator)
    simulate_session(config=SessionConfig(n_rounds=100), seed=12, backend="qiskit")
    assert CountingAerSimulator.run_calls == 1


@pytest.mark.slow
@pytest.mark.parametrize("h", list(Hypothesis))
def test_qiskit_circuits_match_density_matrix_model(h):
    """The Aer circuits (Bell pairs, Bell measurement, if_test Pauli correction,
    attack operations) reproduce the Born-rule model the detector uses."""
    config = SessionConfig(n_rounds=12000)
    t = simulate_session(h, 1.0, config, seed=11, backend="qiskit")
    n, k = t.counts()
    p = cell_probabilities(h, 1.0, config.params)
    z = (k / n - p) / np.sqrt(p * (1 - p) / n)
    assert np.all(np.abs(z) < 4.5), z


@pytest.mark.parametrize("h", ATTACKS)
def test_analytic_sampler_matches_model(h):
    config = SessionConfig(n_rounds=40000)
    t = simulate_session(h, 0.6, config, seed=3)
    n, k = t.counts()
    theta = 1.0 if h is Hypothesis.IMPERSONATION else 0.6
    p = cell_probabilities(h, theta, config.params)
    assert np.all(np.abs((k / n - p) / np.sqrt(p * (1 - p) / n)) < 4.5)
