"""Compare ARBITER's unified GLRT with four fixed-threshold rules.

python examples/compare_baseline.py --sessions 200 --seed 26141
"""

from __future__ import annotations

import argparse

from arbiter.detection import compare_detectors
from arbiter.qds_simulation import ATTACKS, Hypothesis


def _print_matrix(result: dict, detector: str) -> None:
    labels = result["labels"]
    summary = result["detectors"][detector]
    print(f"  {detector} (FAR={summary['false_alarm_rate']:.3f})")
    print(f"    {'true / predicted':22s}" + "".join(f"{x[:8]:>9s}" for x in labels))
    for truth in labels:
        row = summary["confusion_matrix"][truth]
        print(f"    {truth:22s}" + "".join(f"{row[x]:9d}" for x in labels))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=200, help="sessions per hypothesis and theta")
    parser.add_argument("--rounds", type=int, default=1200)
    parser.add_argument("--alpha", type=float, default=0.01)
    parser.add_argument("--seed", type=int, default=26141)
    args = parser.parse_args()

    print(
        f"ARBITER vs fixed thresholds: sessions={args.sessions}, rounds={args.rounds}, "
        f"alpha={args.alpha}, seed={args.seed}"
    )
    for theta in (1.0, 0.3, 0.1):
        result = compare_detectors(theta, args.sessions, args.seed, n_rounds=args.rounds, alpha=args.alpha)
        print(f"\n=== theta={theta} (impersonation remains all-or-nothing) ===")
        for detector in result["detectors"]:
            _print_matrix(result, detector)
        print("\n  detection / correct attribution")
        print(f"    {'attack':22s}" + "".join(f"{name[:12]:>27s}" for name in result["detectors"]))
        for attack in ATTACKS:
            cells = []
            for detector in result["detectors"].values():
                metric = detector["attacks"][attack.value]
                cells.append(f"{metric['detection_rate']:.3f} / {metric['correct_attribution_rate']:.3f}")
            print(f"    {attack.value:22s}" + "".join(f"{cell:>27s}" for cell in cells))

    print("\nRates are detection / correct attribution; matrices are counts.")
    print("Truth labels:", ", ".join(h.value for h in Hypothesis))


if __name__ == "__main__":
    main()
