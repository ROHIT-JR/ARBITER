"""Benchmark the analytic and Qiskit session paths.

The defaults match issue #10: 100 analytic sessions and 10 Qiskit sessions.

    python examples/benchmark.py
"""

from __future__ import annotations

import argparse
import time

from arbiter.detection import UnifiedDetector
from arbiter.qds_simulation import Hypothesis, SessionConfig, simulate_session


def run_benchmark(name: str, backend: str, sessions: int, config: SessionConfig) -> None:
    detector = UnifiedDetector(config.params)
    started = time.perf_counter()
    for seed in range(sessions):
        transcript = simulate_session(
            Hypothesis.CHANNEL_MANIPULATION,
            0.3,
            config,
            seed=seed,
            backend=backend,
        )
        detector.evaluate(transcript)
    elapsed = time.perf_counter() - started
    print(f"{name:8s}: {sessions:3d} sessions in {elapsed:8.3f}s ({sessions / elapsed:8.2f} sessions/s)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=1200)
    parser.add_argument("--analytic-sessions", type=int, default=100)
    parser.add_argument("--qiskit-sessions", type=int, default=10)
    args = parser.parse_args()
    config = SessionConfig(n_rounds=args.rounds)

    run_benchmark("analytic", "analytic", args.analytic_sessions, config)
    run_benchmark("qiskit", "qiskit", args.qiskit_sessions, config)


if __name__ == "__main__":
    main()
