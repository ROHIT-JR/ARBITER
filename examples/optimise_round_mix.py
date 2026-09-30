"""Optimize round_mix to maximize measurement efficiency across attacks.

The goal is to find an allocation of rounds between SIGNATURE, FRESHNESS, CHSH,
and BELL_FIDELITY that:
1. Maximizes the minimum measurement efficiency across all attacks
2. Keeps enough CHSH rounds for the pre-check's Hoeffding certification
3. Achieves efficiency >= 0.85 for every attack, or explains why that's impossible

Usage:
    python examples/optimise_round_mix.py [--n_rounds 1200] [--visibility 0.92]
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import numpy as np
from scipy.optimize import minimize

from arbiter.detection import attack_bounds
from arbiter.qds_simulation import Hypothesis, SessionConfig


@dataclass
class OptimizationResult:
    round_mix: tuple[float, ...]
    efficiencies: dict[str, float]
    min_efficiency: float
    chsh_rounds: int
    attribs: str


def evaluate_mix(
    round_mix_tuple: tuple[float, ...],
    n_rounds: int = 1200,
    params=None,
) -> dict[str, float]:
    """Evaluate measurement efficiency at this round mix."""
    if params is None:
        from arbiter.qds_simulation import ChannelParams

        params = ChannelParams()

    # round_mix must have 3 or 4 elements (backward compat)
    if len(round_mix_tuple) == 3:
        round_mix = round_mix_tuple + (0.0,)
    else:
        round_mix = round_mix_tuple

    try:
        config = SessionConfig(n_rounds=n_rounds, round_mix=round_mix, params=params)
        bounds = attack_bounds(1.0, config)
        effs = {r["attack"]: r["measurement_efficiency"] for r in bounds}
        return effs
    except Exception:
        # Return very poor efficiency on error (invalid mix)
        return {
            h.value: -1.0
            for h in [Hypothesis.FORGERY, Hypothesis.IMPERSONATION, Hypothesis.REPLAY, Hypothesis.CHANNEL_MANIPULATION]
        }


def optimize_round_mix(
    n_rounds: int = 1200,
    visibility: float = 0.92,
    min_chsh_fraction: float = 0.15,  # Ensure enough CHSH for pre-check
    target_efficiency: float = 0.85,
) -> OptimizationResult:
    """Find the optimal round mix maximizing min efficiency.

    Args:
        n_rounds: Total rounds per session
        visibility: Channel visibility (affects fidelity of measurements)
        min_chsh_fraction: Minimum fraction of rounds for CHSH pre-check
        target_efficiency: Target measurement efficiency for all attacks

    Returns:
        OptimizationResult with the best found mix
    """
    from arbiter.qds_simulation import ChannelParams

    params = ChannelParams(visibility=visibility)

    def objective(x):
        """Minimize negative of min efficiency (for minimizer to maximize)."""
        # x = [sig, fresh, chsh, bell] (4 elements)
        # Ensure they sum to 1 and satisfy constraints
        sig, fresh, chsh = x[0], x[1], x[2]
        bell = max(0, 1.0 - sig - fresh - chsh)

        round_mix = (sig, fresh, chsh, bell)

        # Constraint: CHSH fraction >= min_chsh_fraction
        if chsh < min_chsh_fraction:
            return 1000  # Heavy penalty

        effs = evaluate_mix(round_mix, n_rounds, params)

        # If any efficiency is invalid, penalize heavily
        if any(v < 0 for v in effs.values()):
            return 1000

        # Objective: maximize minimum efficiency
        min_eff = min(effs.values())
        return -min_eff  # Negate for minimization

    # Try multiple starting points
    best_result = None
    best_objective = float("inf")

    # Generate initial guesses: vary the bell_fidelity fraction
    for bell_frac in np.linspace(0, 0.15, 8):
        for chsh_frac in np.linspace(0.15, 0.35, 6):
            sig_frac = (1.0 - chsh_frac - bell_frac) * 0.6
            fresh_frac = (1.0 - chsh_frac - bell_frac) * 0.4

            x0 = np.array([sig_frac, fresh_frac, chsh_frac])

            # Bounds: each in [0, 1]
            bounds = [(0, 1), (0, 1), (0, 1)]

            result = minimize(objective, x0, bounds=bounds, method="L-BFGS-B", options={"maxiter": 100})

            if result.fun < best_objective:
                best_objective = result.fun
                best_result = result

    if best_result is None:
        raise RuntimeError("Optimization failed to find any valid solution")

    # Construct final round_mix
    sig, fresh, chsh = best_result.x
    bell = max(0, 1.0 - sig - fresh - chsh)

    # Normalize to ensure exact sum
    total = sig + fresh + chsh + bell
    round_mix = (sig / total, fresh / total, chsh / total, bell / total)

    # Evaluate the best mix
    effs = evaluate_mix(round_mix, n_rounds, params)
    min_eff = min(effs.values())
    chsh_rounds = int(round_mix[2] * n_rounds)

    attribs = ", ".join(f"{k}: {v:.3f}" for k, v in effs.items())

    return OptimizationResult(
        round_mix=round_mix,
        efficiencies=effs,
        min_efficiency=min_eff,
        chsh_rounds=chsh_rounds,
        attribs=attribs,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Optimize ARBITER round_mix for measurement efficiency")
    ap.add_argument("--n_rounds", type=int, default=1200, help="Rounds per session")
    ap.add_argument("--visibility", type=float, default=0.92, help="Channel visibility")
    ap.add_argument("--min_chsh", type=float, default=0.15, help="Min CHSH fraction for pre-check")
    ap.add_argument("--target_eff", type=float, default=0.85, help="Target measurement efficiency")
    args = ap.parse_args()

    print("Optimizing round_mix:")
    print(f"  n_rounds={args.n_rounds}")
    print(f"  visibility={args.visibility}")
    print(f"  min_chsh_fraction={args.min_chsh}")
    print(f"  target_efficiency={args.target_eff}\n")

    result = optimize_round_mix(
        n_rounds=args.n_rounds,
        visibility=args.visibility,
        min_chsh_fraction=args.min_chsh,
        target_efficiency=args.target_eff,
    )

    print("=" * 70)
    print("OPTIMIZED ROUND MIX")
    print("=" * 70)
    print(f"round_mix = {result.round_mix}")
    print(f"\nAllocation (out of {args.n_rounds} rounds):")
    print(f"  Signature:   {int(result.round_mix[0] * args.n_rounds):4d} rounds ({result.round_mix[0]:.1%})")
    print(f"  Freshness:   {int(result.round_mix[1] * args.n_rounds):4d} rounds ({result.round_mix[1]:.1%})")
    print(f"  CHSH:        {result.chsh_rounds:4d} rounds ({result.round_mix[2]:.1%})")
    print(f"  Bell Fidelity: {int(result.round_mix[3] * args.n_rounds):4d} rounds ({result.round_mix[3]:.1%})")

    print("\nMeasurement Efficiency by Attack:")
    for attack, eff in result.efficiencies.items():
        status = "✓" if eff >= args.target_eff else "✗"
        print(f"  {status} {attack:20s}: {eff:.3f}")

    print(f"\nMinimum efficiency: {result.min_efficiency:.3f}")
    if result.min_efficiency >= args.target_eff:
        print(f"✓ All attacks achieve >= {args.target_eff} efficiency!")
    else:
        print(f"✗ Best achieved: {result.min_efficiency:.3f} (target: {args.target_eff})")


if __name__ == "__main__":
    main()
