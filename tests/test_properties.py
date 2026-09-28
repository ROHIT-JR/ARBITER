"""Fast invariant checks for public-input and numerical protocol boundaries."""

from __future__ import annotations

import copy
import os

import numpy as np
import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from arbiter.audit_ledger import AuditLedger, LedgerKeys, verify_entries
from arbiter.detection import UnifiedDetector
from arbiter.pki_risk_scoring import assess_key
from arbiter.qds_simulation import ChannelParams, Hypothesis, cell_probabilities
from arbiter.quantum.info import fidelity, helstrom_error, quantum_chernoff, relative_entropy, trace_distance
from arbiter.quantum.states import depolarize, measure_resend

# CI keeps the properties below 60 seconds.  Developers can opt into the more
# exhaustive profile with ``HYPOTHESIS_PROFILE=thorough pytest``.
settings.register_profile("ci", max_examples=20, deadline=None)
settings.register_profile("thorough", max_examples=100, deadline=None)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "ci" if os.getenv("CI") else "thorough"))


@st.composite
def density_matrices(draw):
    values = draw(st.lists(st.floats(-2, 2, allow_nan=False, allow_infinity=False), min_size=8, max_size=8))
    matrix = np.array(values[:4], dtype=float).reshape(2, 2) + 1j * np.array(values[4:], dtype=float).reshape(2, 2)
    rho = matrix @ matrix.conj().T
    trace = float(np.trace(rho).real)
    return rho / trace if trace > 1e-14 else np.eye(2, dtype=complex) / 2


def _is_density_matrix(rho: np.ndarray) -> bool:
    return (
        np.allclose(rho, rho.conj().T, atol=1e-10)
        and np.isclose(np.trace(rho), 1.0, atol=1e-10)
        and np.linalg.eigvalsh(rho).min() >= -1e-10
    )


@given(rho=density_matrices(), sigma=density_matrices())
def test_quantum_metric_ranges_and_symmetry(rho, sigma):
    assert 0 <= trace_distance(rho, sigma) <= 1
    assert 0 <= helstrom_error(rho, sigma) <= 0.5
    assert 0 <= fidelity(rho, sigma) <= 1
    assert fidelity(rho, sigma) == pytest.approx(fidelity(sigma, rho), abs=1e-9)
    assert relative_entropy(rho, sigma) >= 0
    exponent, _ = quantum_chernoff(rho, sigma)
    assert exponent >= 0


@given(rho=density_matrices())
def test_quantum_chernoff_is_zero_for_identical_states(rho):
    exponent, _ = quantum_chernoff(rho, rho)
    assert exponent == 0


@given(rho=density_matrices(), sigma=density_matrices())
def test_quantum_chernoff_is_positive_for_well_separated_states(rho, sigma):
    assume(np.linalg.norm(rho - sigma) > 0.1)
    exponent, _ = quantum_chernoff(rho, sigma)
    assert exponent > 0


@given(rho=density_matrices(), visibility=st.floats(0, 1, allow_nan=False, allow_infinity=False))
def test_single_qubit_channels_preserve_density_matrices(rho, visibility):
    for channel_output in (depolarize(rho, visibility), measure_resend(rho)):
        assert _is_density_matrix(channel_output)


@given(
    visibility=st.floats(0, 1, allow_nan=False, allow_infinity=False),
    storage_visibility=st.floats(0, 1, allow_nan=False, allow_infinity=False),
    theta=st.floats(0, 1, allow_nan=False, allow_infinity=False),
)
def test_model_probabilities_are_valid_and_zero_attack_is_legitimate(visibility, storage_visibility, theta):
    params = ChannelParams(visibility=visibility, storage_visibility=storage_visibility)
    for protocol in ("prf", "qds"):
        legitimate = cell_probabilities(Hypothesis.LEGITIMATE, 0, params, protocol)
        for hypothesis in Hypothesis:
            probabilities = cell_probabilities(hypothesis, theta, params, protocol)
            assert np.all((0 <= probabilities) & (probabilities <= 1))
            assert np.allclose(cell_probabilities(hypothesis, 0, params, protocol), legitimate)


@st.composite
def count_vectors(draw):
    n = draw(st.lists(st.integers(0, 30), min_size=6, max_size=6))
    k = [draw(st.integers(0, count)) for count in n]
    return np.asarray(n), np.asarray(k)


@given(counts=count_vectors())
def test_unified_detector_accepts_all_valid_count_cells(counts):
    n, k = counts
    detector = UnifiedDetector(n_calibration=16, theta_grid=np.array([0.5, 1.0]), seed=23)
    verdict = detector.evaluate_counts(n, k)
    assert np.isfinite(verdict.statistic)
    assert np.isfinite(verdict.threshold)
    assert sum(verdict.posterior.values()) == pytest.approx(1.0)


def _scalar_paths(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _scalar_paths(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _scalar_paths(child, (*path, index))
    else:
        yield path


def _get_at_path(value, path):
    for part in path:
        value = value[part]
    return value


def _set_at_path(value, path, replacement):
    for part in path[:-1]:
        value = value[part]
    value[path[-1]] = replacement


def _single_byte_change(value):
    if isinstance(value, str):
        return ("A" if not value.startswith("A") else "B") + value[1:]
    if isinstance(value, int):
        return value ^ 1
    if value is None:
        return True
    if isinstance(value, bool):
        return not value
    raise TypeError(f"unsupported ledger scalar: {type(value).__name__}")


@given(entry_count=st.integers(1, 3), payload=st.text(max_size=24), data=st.data())
@settings(suppress_health_check=[HealthCheck.data_too_large])
def test_ledger_rejects_a_change_to_any_random_serialised_field(entry_count, payload, data):
    ledger = AuditLedger(LedgerKeys.generate(hbs_height=4))
    for index in range(entry_count):
        ledger.append({"type": "verdict", "index": index, "payload": payload})
    entries = copy.deepcopy(ledger.entries)
    paths = [(index, path) for index, entry in enumerate(entries) for path in _scalar_paths(entry)]
    entry_index, path = data.draw(st.sampled_from(paths))
    original = _get_at_path(entries[entry_index], path)
    _set_at_path(entries[entry_index], path, _single_byte_change(original))
    assert not verify_entries(entries).ok


@given(algorithm=st.text(max_size=40), key_bits=st.integers(-10_000, 1_000_000))
def test_pki_assessment_never_raises_for_algorithm_text_and_key_sizes(algorithm, key_bits):
    assessment = assess_key(algorithm, key_bits)
    assert 0 <= assessment.score <= 100
