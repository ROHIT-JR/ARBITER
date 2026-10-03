"""Search ``SessionConfig.round_mix`` for the best detection power per round.

What it optimises
-----------------
The quantity that matters operationally is the *absolute* measured Chernoff
exponent ``xi_M``: rounds-to-decide at error ``eps`` is ``ln(1/eps) / xi_M``.
We maximise the worst attack's ``xi_M`` (max-min), subject to never making any
attack worse than the legacy ``(0.5, 0.25, 0.25)`` mix -- a Pareto constraint,
so adopting the result cannot regress detection of anything.

Note we do *not* maximise ``measurement_efficiency`` (``xi_M / xi_Q``). That
ratio is a poor objective here: moving rounds onto shared-pair round types
raises the unconstrained quantum bound ``xi_Q`` faster than ``xi_M``, so the
ratio can fall while real detection power rises. ``local_efficiency``
(``xi_M / xi_L``) is the meaningful ratio, since ``xi_Q`` needs a non-local
Bell measurement the protocol cannot perform -- see ``detection/bounds.py``.

Floors (all three bind in practice)
-----------------------------------
* ``w_sig   >= 0.50`` -- forgery is visible *only* on signature rounds, so
  anything less regresses forgery against the legacy mix.
* ``w_chsh  >= 0.117`` -- below ~140 CHSH rounds the point-estimate ``flagged``
  check in ``detection.chsh`` false-alarms above 1% on an honest channel.
  Pass ``--require-certification`` to raise this to the much stricter level
  that certifies a Bell violation outright.
* ``w_fresh >= 0.15`` -- keeps the standalone freshness p-value meaningful.
  Without it the search drains freshness to ~1.5% because Bell-fidelity rounds
  happen to catch replay equally well, which is fine for the GLRT but leaves
  that layer with no independent evidence.

Usage
-----
    python examples/optimise_round_mix.py
    python examples/optimise_round_mix.py --n-rounds 2000 --require-certification
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import numpy as np

from arbiter.detection.bounds import attack_bounds
from arbiter.detection.chsh import chsh_rounds_for_certification
from arbiter.qds_simulation import ChannelParams, SessionConfig

LEGACY_MIX = (0.5, 0.25, 0.25, 0.0)
EPSILON = 1e-6

# See the module docstring for where each floor comes from.
MIN_SIGNATURE = 0.50
MIN_FRESHNESS = 0.15
MIN_CHSH_FOR_FLAG = 0.117


@dataclass(frozen=True)
class MixEvaluation:
    round_mix: tuple[float, float, float, float]
    exponents: dict[str, float]
    local_efficiency: dict[str, float]

    @property
    def bottleneck(self) -> float:
        return min(self.exponents.values())

    @property
    def rounds_to_decide(self) -> float:
        return float(np.log(1 / EPSILON) / self.bottleneck)


def evaluate_mix(round_mix, n_rounds: int = 1200, params: ChannelParams | None = None) -> MixEvaluation:
    """Measured Chernoff exponent per attack at this mix."""
    config = SessionConfig(n_rounds=n_rounds, round_mix=round_mix, params=params or ChannelParams())
    rows = attack_bounds(1.0, config)
    return MixEvaluation(
        round_mix=config.round_mix,
        exponents={r["attack"]: r["measured_chernoff"] for r in rows},
        local_efficiency={r["attack"]: r["local_efficiency"] for r in rows},
    )


def optimise_round_mix(
    n_rounds: int = 1200,
    visibility: float = 0.92,
    step: float = 0.005,
    require_certification: bool = False,
) -> tuple[MixEvaluation, MixEvaluation]:
    """Grid-search the simplex for the Pareto-constrained max-min mix.

    Returns ``(baseline, best)``. A grid is used rather than a gradient method
    because the Pareto constraint makes the feasible set non-convex and the
    objective non-smooth; the simplex is only three-dimensional once the
    signature weight is pinned, so this is cheap and has no local minima.
    """
    params = ChannelParams(visibility=visibility)
    baseline = evaluate_mix(LEGACY_MIX, n_rounds, params)

    min_chsh = MIN_CHSH_FOR_FLAG
    if require_certification:
        min_chsh = max(min_chsh, chsh_rounds_for_certification(visibility) / n_rounds)

    best: MixEvaluation | None = None
    for w_chsh in np.arange(min_chsh, 1.0 - MIN_SIGNATURE - MIN_FRESHNESS + 1e-9, step):
        for w_fresh in np.arange(MIN_FRESHNESS, 1.0 - MIN_SIGNATURE - w_chsh + 1e-9, step):
            w_bell = 1.0 - MIN_SIGNATURE - w_fresh - w_chsh
            if w_bell < -1e-9:
                continue
            candidate = evaluate_mix(
                (MIN_SIGNATURE, float(w_fresh), float(w_chsh), float(max(w_bell, 0.0))), n_rounds, params
            )
            # Pareto: never worse than the legacy mix on any attack.
            if any(candidate.exponents[a] < baseline.exponents[a] - 1e-9 for a in baseline.exponents):
                continue
            if best is None or candidate.bottleneck > best.bottleneck:
                best = candidate

    if best is None:
        raise RuntimeError(
            "no Pareto-feasible mix found; the certification floor may be too "
            "strict for this n_rounds (try raising --n-rounds)"
        )
    return baseline, best


def _report(label: str, ev: MixEvaluation, reference: MixEvaluation | None = None) -> None:
    mix = ", ".join(f"{w:.3f}" for w in ev.round_mix)
    print(f"{label}: round_mix = ({mix})")
    print(f"  {'attack':22} {'xi_M':>9} {'rounds':>8} {'xi_M/xi_L':>10}" + ("  vs ref" if reference else ""))
    for attack, xi in ev.exponents.items():
        rounds = np.log(1 / EPSILON) / xi
        line = f"  {attack:22} {xi:9.5f} {rounds:8.1f} {ev.local_efficiency[attack]:10.3f}"
        if reference:
            ref_rounds = np.log(1 / EPSILON) / reference.exponents[attack]
            line += f"  {rounds / ref_rounds - 1:+7.1%}"
        print(line)
    print(f"  bottleneck: {ev.bottleneck:.5f}  ->  {ev.rounds_to_decide:.1f} rounds at eps={EPSILON:g}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n-rounds", type=int, default=1200)
    ap.add_argument("--visibility", type=float, default=0.92)
    ap.add_argument("--step", type=float, default=0.005, help="grid resolution on the simplex")
    ap.add_argument(
        "--require-certification",
        action="store_true",
        help="also demand enough CHSH rounds to certify a Bell violation outright",
    )
    args = ap.parse_args()

    baseline, best = optimise_round_mix(
        n_rounds=args.n_rounds,
        visibility=args.visibility,
        step=args.step,
        require_certification=args.require_certification,
    )
    print(f"n_rounds={args.n_rounds}  visibility={args.visibility}\n")
    _report("legacy  ", baseline)
    print()
    _report("optimised", best, reference=baseline)
    print(
        f"\nbottleneck improves {baseline.rounds_to_decide:.1f} -> {best.rounds_to_decide:.1f} rounds "
        f"({best.rounds_to_decide / baseline.rounds_to_decide - 1:+.1%})"
    )
    chsh_rounds = int(round(best.round_mix[2] * args.n_rounds))
    needed = chsh_rounds_for_certification(args.visibility)
    print(
        f"CHSH rounds at this mix: {chsh_rounds} "
        f"({'certifies' if chsh_rounds >= needed else f'does not certify, needs {needed}'})"
    )


if __name__ == "__main__":
    main()
