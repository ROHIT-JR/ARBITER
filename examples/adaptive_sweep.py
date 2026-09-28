"""Compare late-onset detection delay with the original sequential test.

    python examples/adaptive_sweep.py --sessions 100 --attack forgery

The simulator's ``onset`` metadata is used only after a detector has run to
score delay and onset error; neither detector reads it while forming evidence.
"""

from __future__ import annotations

import argparse
import zlib

import numpy as np

from arbiter.detection import ChangePointDetector, SequentialDetector
from arbiter.qds_simulation import ATTACKS, Hypothesis, SessionConfig, simulate_session


def _median(values: list[int]) -> str:
    return f"{np.median(values):.0f}" if values else "–"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=100)
    parser.add_argument("--rounds", type=int, default=1200)
    parser.add_argument("--attack", choices=[attack.value for attack in ATTACKS], default="forgery")
    parser.add_argument("--alpha", type=float, default=0.01)
    args = parser.parse_args()
    if args.rounds < 800:
        parser.error("--rounds must be at least 800 for the default onset sweep")

    config = SessionConfig(n_rounds=args.rounds)
    sequential = SequentialDetector(config.params, args.alpha)
    changepoint = ChangePointDetector(config.params, args.alpha, reference_session_rounds=args.rounds)
    attack = Hypothesis(args.attack)

    print(
        f"Adaptive sweep: {attack.value}, {args.sessions} analytic sessions × {args.rounds} rounds, "
        f"alpha={args.alpha}, CP ARL target={changepoint.arl_target:.0f} rounds\n"
    )
    print(f"{'onset':>7s} {'theta':>7s} {'CP delay':>10s} {'sequential delay':>18s} {'|t̂₀−t₀|':>12s}")
    for onset in (100, 400, 800):
        for theta in (1.0, 0.3):
            rows = []
            for session in range(args.sessions):
                seed = zlib.crc32(f"adaptive|{attack.value}|{onset}|{theta}|{session}".encode())
                transcript = simulate_session(attack, theta, config, seed=seed, onset=onset)
                cp = changepoint.evaluate(transcript)
                seq = sequential.evaluate(transcript)
                if cp.rejected and cp.estimated_onset is not None:
                    rows.append((cp.stopped_at - onset, seq.stopped_at - onset, abs(cp.estimated_onset - onset)))
            print(
                f"{onset:7d} {theta:7.1f} {_median([row[0] for row in rows]):>10s} "
                f"{_median([row[1] for row in rows]):>18s} {_median([row[2] for row in rows]):>12s}"
            )


if __name__ == "__main__":
    main()
