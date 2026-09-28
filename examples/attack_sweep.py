"""Attack sweep: detection/attribution accuracy, sequential stopping times and
information-theoretic limits for every attack class.

    python examples/attack_sweep.py [--sessions 100] [--backend analytic|qiskit]
"""

from __future__ import annotations

import argparse
import zlib
from collections import Counter

import numpy as np

from arbiter.detection import SequentialDetector, UnifiedDetector, attack_bounds
from arbiter.qds_simulation import Hypothesis, SessionConfig, simulate_session


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=100)
    ap.add_argument("--rounds", type=int, default=1200)
    ap.add_argument("--backend", default="analytic", choices=["analytic", "qiskit"])
    ap.add_argument("--alpha", type=float, default=0.01)
    args = ap.parse_args()

    config = SessionConfig(n_rounds=args.rounds)
    unified = UnifiedDetector(config.params, args.alpha)
    sequential = SequentialDetector(config.params, args.alpha)
    labels = [h.value for h in Hypothesis]

    print(
        f"ARBITER attack sweep: {args.sessions} sessions x {args.rounds} rounds, "
        f"alpha={args.alpha}, visibility={config.params.visibility}, backend={args.backend}\n"
    )
    sweep_rows = []
    for theta in (1.0, 0.3, 0.1):
        for h in Hypothesis:
            transcripts = [
                simulate_session(
                    h, theta, config, seed=zlib.crc32(f"{h.value}|{theta}|{s}".encode()), backend=args.backend
                )
                for s in range(args.sessions)
            ]
            sweep_rows.append((theta, h, transcripts))

    # Keep simulation, matrix-heavy threshold calibration and the sequential
    # pass in separate batches. Alternating them makes small NumPy workloads
    # contend with BLAS worker spin-up.
    unified_rows = [[unified.evaluate(t) for t in transcripts] for _, _, transcripts in sweep_rows]
    sequential_rows = [[sequential.evaluate(t) for t in transcripts] for _, _, transcripts in sweep_rows]

    for theta in (1.0, 0.3, 0.1):
        print(f"=== attack strength theta = {theta} (impersonation is always 1.0) ===")
        header = "true / attributed"
        print(f"{header:24s}" + "".join(f"{lab[:12]:>13s}" for lab in labels) + f"{'alarm@':>9s}{'attrib@':>9s}")
        for row_index, (row_theta, h, _) in enumerate(sweep_rows):
            if row_theta != theta:
                continue
            got = Counter(v.attribution.value for v in unified_rows[row_index])
            alarm = [q.stopped_at for q in sequential_rows[row_index] if q.rejected]
            attrib = [q.attributed_at for q in sequential_rows[row_index] if q.rejected]
            row = "".join(f"{got[lab] / args.sessions:13.2f}" for lab in labels)
            med = lambda xs: f"{np.median(xs):9.0f}" if xs else f"{'-':>9s}"  # noqa: E731
            print(f"{h.value:24s}{row}{med(alarm)}{med(attrib)}")
        print()

    print("=== information-theoretic limits (theta = 1, epsilon = 1e-6) ===")
    print(
        f"{'attack':22s}{'Helstrom/rnd':>13s}{'xi_quantum':>12s}{'xi_ARBITER':>12s}"
        f"{'efficiency':>12s}{'N_quantum':>11s}{'N_ARBITER':>11s}"
    )
    for r in attack_bounds(1.0, config):
        print(
            f"{r['attack']:22s}{r['helstrom_error_single_round']:13.3f}{r['quantum_chernoff']:12.4f}"
            f"{r['measured_chernoff']:12.4f}{r['measurement_efficiency']:12.2f}"
            f"{r['rounds_for_epsilon_quantum']:11.0f}{r['rounds_for_epsilon_measured']:11.0f}"
        )


if __name__ == "__main__":
    main()
