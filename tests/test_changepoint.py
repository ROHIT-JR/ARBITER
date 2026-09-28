import numpy as np

from arbiter.detection import ChangePointDetector, SequentialDetector
from arbiter.qds_simulation import Hypothesis, SessionConfig, simulate_session


def test_onset_and_random_bursts_are_reproducible() -> None:
    config = SessionConfig(n_rounds=120)
    first = simulate_session(Hypothesis.FORGERY, 0.3, config, seed=12, onset=41, bursts=4)
    second = simulate_session(Hypothesis.FORGERY, 0.3, config, seed=12, onset=41, bursts=4)

    assert np.array_equal(first.attacked, second.attacked)
    assert not first.attacked[:40].any()
    assert first.attack_onset == 41 and first.burst_length == 4
    # A partial-duty burst has an off-round after every full on-run.
    starts = np.flatnonzero(first.attacked & np.r_[True, ~first.attacked[:-1]])
    ends = np.flatnonzero(first.attacked & np.r_[~first.attacked[1:], True])
    assert all(end - start + 1 == 4 for start, end in zip(starts, ends, strict=True) if end < len(first.attacked) - 1)


def test_late_onset_detector_beats_prefix_diluted_sequential_test() -> None:
    config = SessionConfig(n_rounds=1200)
    changepoint = ChangePointDetector(config.params, alpha=0.01)
    sequential = SequentialDetector(config.params, alpha=0.01)
    onset = 800
    change_results = []
    sequential_delays = []
    for seed in range(20):
        transcript = simulate_session(Hypothesis.FORGERY, 1.0, config, seed=seed, onset=onset)
        change = changepoint.evaluate(transcript)
        legacy = sequential.evaluate(transcript)
        assert change.rejected and change.estimated_onset is not None
        change_results.append(change)
        sequential_delays.append(legacy.stopped_at - onset)

    assert np.median([result.detection_delay for result in change_results]) < np.median(sequential_delays)
    assert np.median([abs(result.estimated_onset - onset) for result in change_results]) <= 30
    assert sum(result.attribution is Hypothesis.FORGERY for result in change_results) >= 12


def test_honest_stream_does_not_cross_configured_arl_operating_point() -> None:
    # This is an empirical reset-at-session ARL estimate over 100,000 honest
    # rounds.  A zero-alarm run is right-censored above the observed horizon.
    config = SessionConfig(n_rounds=1000)
    detector = ChangePointDetector(config.params, alpha=0.01, arl_target=10_000)
    rounds = 100 * config.n_rounds
    alarms = sum(detector.evaluate(simulate_session(config=config, seed=10_000 + seed)).rejected for seed in range(100))
    empirical_arl = float("inf") if alarms == 0 else rounds / alarms
    assert empirical_arl >= detector.arl_target
