"""Calibrated temporal diagnostics for ordered QDS transcripts.

The GLRT in :mod:`arbiter.detection.unified` deliberately pools each cell's
counts.  That is optimal for the i.i.d. alternatives it models, but pooling
also hides *when* errors arrived.  This module adds small, interpretable tests
for two non-i.i.d. patterns without introducing an ML classifier:

* an excess longest run or local mismatch count (bursts), and
* an unusually concentrated periodogram (periodic interference).

Each statistic is calibrated by a conditional Monte-Carlo null distribution.
The simulator retains the observed round-type schedule and uses the
Born-rule H0 probability for every observed cell.  Thus neither calibration
nor evaluation needs a device, a network connection, or simulation ground
truth.  The temporal family spends its supplied ``alpha`` with Bonferroni
across three streams (signature, freshness, CHSH) and three tests per stream.
This makes ``TemporalDetector(alpha)`` a level-``alpha`` family test.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import numpy as np

from arbiter.qds_simulation.model import ChannelParams, Hypothesis, cell_probabilities
from arbiter.qds_simulation.protocol import Transcript

STREAM_CELLS = {
    "signature": (0,),
    "freshness": (1,),
    "chsh": (2, 3, 4, 5),
}
TEST_NAMES = ("longest_run", "max_window_count", "fisher_g")


@dataclass(frozen=True)
class SlidingMoment:
    """Population moments of one outcome window.

    ``skewness`` and ``excess_kurtosis`` are zero for a constant window.  That
    convention makes short, sparse diagnostic streams easy to display while
    avoiding NaNs in JSON responses; they are descriptive features, not tests.
    """

    start: int
    stop: int
    count: int
    mismatch_rate: float
    variance: float
    skewness: float
    excess_kurtosis: float

    def to_dict(self) -> dict:
        return {
            "start": self.start,
            "stop": self.stop,
            "count": self.count,
            "mismatch_rate": round(self.mismatch_rate, 6),
            "variance": round(self.variance, 6),
            "skewness": round(self.skewness, 6),
            "excess_kurtosis": round(self.excess_kurtosis, 6),
        }


@dataclass(frozen=True)
class CalibratedTest:
    statistic: float
    threshold: float
    p_value: float
    alpha: float
    flagged: bool

    def to_dict(self) -> dict:
        return {
            "statistic": round(self.statistic, 6),
            "threshold": round(self.threshold, 6),
            "p_value": round(self.p_value, 6),
            "alpha": self.alpha,
            "flagged": self.flagged,
        }


@dataclass(frozen=True)
class StreamTemporalResult:
    rounds: int
    windows: list[SlidingMoment]
    longest_run: CalibratedTest
    max_window_count: CalibratedTest
    fisher_g: CalibratedTest

    @property
    def flagged(self) -> bool:
        return any(test.flagged for test in (self.longest_run, self.max_window_count, self.fisher_g))

    def to_dict(self) -> dict:
        return {
            "rounds": self.rounds,
            "flagged": self.flagged,
            "windows": [window.to_dict() for window in self.windows],
            "burst": {
                "longest_run": self.longest_run.to_dict(),
                "max_window_count": self.max_window_count.to_dict(),
            },
            "spectral": {"fisher_g": self.fisher_g.to_dict()},
        }


@dataclass(frozen=True)
class TemporalVerdict:
    """The Bonferroni-controlled result of all temporal tests."""

    rejected: bool
    alpha: float
    per_test_alpha: float
    window: int
    stride: int
    streams: dict[str, StreamTemporalResult]

    def to_dict(self) -> dict:
        return {
            "rejected": self.rejected,
            "alpha": self.alpha,
            "per_test_alpha": self.per_test_alpha,
            "multiple_testing": "Bonferroni across 3 streams × 3 tests",
            "window": self.window,
            "stride": self.stride,
            "streams": {name: result.to_dict() for name, result in self.streams.items()},
        }


def sliding_window_moments(outcomes: np.ndarray | list[int], window: int = 50, stride: int = 10) -> list[SlidingMoment]:
    """Return overlapping population moments, including a final partial window.

    Window positions are indexes into one round-type stream, not global
    transcript indexes.  A partial final window is intentional: a dashboard
    should not silently hide the end of a session.
    """
    if window < 1 or stride < 1:
        raise ValueError("window and stride must be positive")
    values = np.asarray(outcomes, dtype=float).reshape(-1)
    if not len(values):
        return []
    starts = list(range(0, len(values), stride))
    if len(values) > window and starts[-1] != len(values) - window:
        starts.append(len(values) - window)
    result: list[SlidingMoment] = []
    for start in sorted(set(starts)):
        x = values[start : min(start + window, len(values))]
        mean = float(x.mean())
        centred = x - mean
        variance = float(np.mean(centred**2))
        if variance == 0:
            skewness = excess_kurtosis = 0.0
        else:
            skewness = float(np.mean(centred**3) / variance**1.5)
            excess_kurtosis = float(np.mean(centred**4) / variance**2 - 3)
        result.append(SlidingMoment(start, start + len(x), len(x), mean, variance, skewness, excess_kurtosis))
    return result


def longest_mismatch_run(outcomes: np.ndarray | list[int]) -> int:
    """Length of the longest consecutive run of one-valued outcomes."""
    x = np.asarray(outcomes, dtype=bool).reshape(-1)
    longest = run = 0
    for mismatch in x:
        run = run + 1 if mismatch else 0
        longest = max(longest, run)
    return longest


def maximum_windowed_mismatches(outcomes: np.ndarray | list[int], window: int = 50) -> int:
    """Largest mismatch count in any contiguous window of up to ``window``."""
    if window < 1:
        raise ValueError("window must be positive")
    x = np.asarray(outcomes, dtype=np.int64).reshape(-1)
    if not len(x):
        return 0
    if len(x) <= window:
        return int(x.sum())
    sums = np.cumsum(np.concatenate(([0], x)))
    return int(np.max(sums[window:] - sums[:-window]))


def fisher_g_statistic(outcomes: np.ndarray | list[int]) -> float:
    """Fisher's maximum-periodogram ratio for a binary outcome stream.

    The zero-frequency component is removed by centring.  A constant or
    fewer-than-four-round stream has no periodic evidence and returns zero.
    The detector calibrates this statistic by Monte Carlo rather than relying
    on Fisher's continuous-Gaussian asymptotic distribution.
    """
    x = np.asarray(outcomes, dtype=float).reshape(-1)
    if len(x) < 4:
        return 0.0
    power = np.abs(np.fft.rfft(x - x.mean())) ** 2
    # Omit DC and, for even n, the Nyquist singleton.  The remaining positive
    # frequencies are the usual Fisher g periodogram ordinates.
    end = -1 if len(x) % 2 == 0 else None
    ordinates = power[1:end]
    total = float(ordinates.sum())
    return float(ordinates.max() / total) if total > 0 else 0.0


class TemporalDetector:
    """Pure, deterministic-seed temporal test family.

    The detector owns no mutable random generator.  Calibration keys include
    the H0 probability vector, so repeated calls for the same observed stream
    are stable and cached while different schedules are calibrated correctly.
    """

    def __init__(
        self,
        params: ChannelParams | None = None,
        alpha: float = 0.01,
        window: int = 50,
        stride: int = 10,
        n_calibration: int = 4000,
        seed: int | None = 0,
    ) -> None:
        if not 0 < alpha < 1:
            raise ValueError("alpha must be between zero and one")
        if window < 1 or stride < 1 or n_calibration < 1:
            raise ValueError("window, stride, and n_calibration must be positive")
        self.params = params or ChannelParams()
        self.alpha = float(alpha)
        self.window = int(window)
        self.stride = int(stride)
        self.n_calibration = int(n_calibration)
        self.per_test_alpha = self.alpha / (len(STREAM_CELLS) * len(TEST_NAMES))
        self._calibration_seed = tuple(int(x) for x in np.random.SeedSequence(seed).generate_state(4, dtype=np.uint32))
        self.p0 = cell_probabilities(Hypothesis.LEGITIMATE, 0.0, self.params)
        self._null_statistics_cached = lru_cache(maxsize=256)(self._null_statistics)

    def _key(self, probabilities: np.ndarray) -> tuple[int, ...]:
        # The model is deterministic; rounded integer keys avoid cache misses
        # caused only by float representation while retaining far more precision
        # than calibration could use.
        return tuple(np.rint(np.asarray(probabilities) * 10**12).astype(np.int64).tolist())

    @staticmethod
    def _longest_runs(samples: np.ndarray) -> np.ndarray:
        longest = np.zeros(samples.shape[0], dtype=np.int64)
        run = np.zeros(samples.shape[0], dtype=np.int64)
        for column in samples.T:
            run = np.where(column, run + 1, 0)
            longest = np.maximum(longest, run)
        return longest

    def _null_statistics(self, probability_key: tuple[int, ...]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        probabilities = np.asarray(probability_key, dtype=float) / 10**12
        seed = np.random.SeedSequence([*self._calibration_seed, *probability_key])
        samples = np.random.default_rng(seed).random((self.n_calibration, len(probabilities))) < probabilities
        longest = self._longest_runs(samples)
        if len(probabilities) <= self.window:
            maximum = samples.sum(axis=1)
        else:
            sums = np.cumsum(np.pad(samples, ((0, 0), (1, 0))), axis=1)
            maximum = (sums[:, self.window :] - sums[:, : -self.window]).max(axis=1)
        if len(probabilities) < 4:
            return longest.astype(float), maximum.astype(float), np.zeros(self.n_calibration)
        # rfft is vectorised along the time dimension.
        centred = samples - samples.mean(axis=1, keepdims=True)
        power = np.abs(np.fft.rfft(centred, axis=1)) ** 2
        end = -1 if len(probabilities) % 2 == 0 else None
        ordinates = power[:, 1:end]
        totals = ordinates.sum(axis=1)
        spectral = np.divide(ordinates.max(axis=1), totals, out=np.zeros_like(totals), where=totals > 0)
        return longest.astype(float), maximum.astype(float), spectral

    def _calibrated(self, statistic: float, null: np.ndarray) -> CalibratedTest:
        # Rank p-values with +1 correction are valid under the exchangeable
        # Monte-Carlo null, including discrete/tied burst statistics.
        p_value = float((1 + np.count_nonzero(null >= statistic)) / (len(null) + 1))
        threshold = float(np.quantile(null, 1 - self.per_test_alpha, method="higher"))
        return CalibratedTest(statistic, threshold, p_value, self.per_test_alpha, p_value <= self.per_test_alpha)

    def evaluate_stream(self, outcomes: np.ndarray, probabilities: np.ndarray) -> StreamTemporalResult:
        outcomes = np.asarray(outcomes, dtype=np.int8).reshape(-1)
        probabilities = np.asarray(probabilities, dtype=float).reshape(-1)
        if len(outcomes) != len(probabilities):
            raise ValueError("outcomes and probabilities must have the same length")
        if not len(outcomes):
            empty = CalibratedTest(0.0, 0.0, 1.0, self.per_test_alpha, False)
            return StreamTemporalResult(0, [], empty, empty, empty)
        longest, maximum, spectral = self._null_statistics_cached(self._key(probabilities))
        return StreamTemporalResult(
            rounds=len(outcomes),
            windows=sliding_window_moments(outcomes, self.window, self.stride),
            longest_run=self._calibrated(float(longest_mismatch_run(outcomes)), longest),
            max_window_count=self._calibrated(float(maximum_windowed_mismatches(outcomes, self.window)), maximum),
            fisher_g=self._calibrated(fisher_g_statistic(outcomes), spectral),
        )

    def evaluate(self, transcript: Transcript) -> TemporalVerdict:
        streams: dict[str, StreamTemporalResult] = {}
        for name, cells in STREAM_CELLS.items():
            mask = np.isin(transcript.cells, cells)
            streams[name] = self.evaluate_stream(transcript.outcomes[mask], self.p0[transcript.cells[mask]])
        return TemporalVerdict(
            rejected=any(stream.flagged for stream in streams.values()),
            alpha=self.alpha,
            per_test_alpha=self.per_test_alpha,
            window=self.window,
            stride=self.stride,
            streams=streams,
        )
