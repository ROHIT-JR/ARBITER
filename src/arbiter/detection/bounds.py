"""Information-theoretic limits for each attack, and how close ARBITER's
actual measurements come to them.

Per round the verifier holds the classical-quantum state

    rho_h = sum_t  p_t |t><t| (x) rho_{h,t}

(t = round type, known to the verifier). Its quantum Chernoff exponent xi_Q
against the legitimate state bounds how fast *any* measurement strategy can
drive the error down: P_err ~ exp(-N xi_Q). Comparing with the classical
Chernoff exponent xi_M of the measurement ARBITER actually performs gives a
"measurement efficiency" xi_M / xi_Q <= 1.

Two yardsticks, because xi_Q is not reachable
---------------------------------------------
On the shared-pair rounds xi_Q is attained *exactly* by a Bell-basis
measurement -- the common eigenbasis of the Bell-diagonal states this model
produces. That measurement is non-local: it needs the signer's half and the
verifier's half in the same place. A distributed signature protocol cannot do
that, so xi_Q overstates what any real implementation can reach and
``measurement_efficiency`` is pessimistic by a factor no design choice can
recover.

``local_chernoff`` therefore adds the *achievable* ceiling: the exponent of
the best local (product) measurement plus classical comparison. For a Werner
pair that optimum is the aligned-stabiliser parity the Bell-fidelity rounds
use -- each of ZZ/XX/YY has correlator magnitude v, against v/sqrt(2) for the
+-45-degree CHSH settings -- and a numerical search over all local measurement
directions finds nothing better. ``local_efficiency`` = xi_M / xi_L is the
actionable number: it reaches 1.0 once the shared-pair budget is spent on
Bell-fidelity rather than CHSH rounds.

CHSH rounds are kept regardless, because they certify the Bell violation
*device-independently*, which a fidelity witness cannot do.
"""

from __future__ import annotations

from dataclasses import replace

import numpy as np
from scipy.linalg import block_diag

from arbiter.qds_simulation.model import (
    ATTACKS,
    BELL_FIDELITY_BASES,
    CHSH_SETTINGS,
    Hypothesis,
    RoundType,
    cell_probabilities,
    chsh_state,
    received_state,
)
from arbiter.qds_simulation.protocol import SessionConfig
from arbiter.quantum.info import classical_chernoff, helstrom_error, quantum_chernoff, trace_distance
from arbiter.quantum.states import PauliLabel

_REF_LABEL = PauliLabel("Z", 0)  # the model is label-symmetric; any label works


def cq_state(h: Hypothesis, theta: float, config: SessionConfig) -> np.ndarray:
    p = config.params
    legit, attack = Hypothesis.LEGITIMATE, h
    blocks = []
    for w, rt in zip(config.round_mix[:2], (RoundType.SIGNATURE, RoundType.FRESHNESS), strict=True):
        r0 = received_state(legit, rt, _REF_LABEL, p)
        r1 = received_state(attack, rt, _REF_LABEL, p)
        blocks.append(w * ((1 - theta) * r0 + theta * r1))
    c0, c1 = chsh_state(legit, p), chsh_state(attack, p)
    shared = (1 - theta) * c0 + theta * c1
    # CHSH and Bell-fidelity rounds hold the *same* physical pair and differ
    # only in which local measurement is applied, so they contribute separate
    # blocks (the verifier knows the round type) built from one state. The
    # quantum bound is therefore invariant to how the shared-pair budget is
    # split between them -- only xi_M moves, which keeps the comparison fair.
    blocks.append(config.round_mix[2] * shared)
    blocks.append(config.round_mix[3] * shared)
    return block_diag(*blocks)


def _cell_weights(config: SessionConfig) -> np.ndarray:
    """Per-cell round probability: each round type spreads over its settings."""
    w_sig, w_fresh, w_chsh, w_bell = config.round_mix
    return np.array(
        [
            w_sig,
            w_fresh,
            *(w_chsh / len(CHSH_SETTINGS),) * len(CHSH_SETTINGS),
            *(w_bell / len(BELL_FIDELITY_BASES),) * len(BELL_FIDELITY_BASES),
        ]
    )


def measured_distribution(h: Hypothesis, theta: float, config: SessionConfig) -> np.ndarray:
    """Joint distribution over (cell, outcome) produced by ARBITER's measurements."""
    q = cell_probabilities(h, theta, config.params)
    w = _cell_weights(config)
    return np.concatenate([w * (1 - q), w * q])


def local_distribution(h: Hypothesis, theta: float, config: SessionConfig) -> np.ndarray:
    """``measured_distribution`` with every shared-pair round using the optimal
    local measurement, i.e. the CHSH budget reallocated to Bell-fidelity.

    This is the achievable counterpart to ``cq_state``'s non-local bound.
    """
    w_sig, w_fresh, w_chsh, w_bell = config.round_mix
    ideal = replace(config, round_mix=(w_sig, w_fresh, 0.0, w_chsh + w_bell))
    return measured_distribution(h, theta, ideal)


def attack_bounds(theta: float = 1.0, config: SessionConfig | None = None, epsilon: float = 1e-6) -> list[dict]:
    config = config or SessionConfig()
    rho0 = cq_state(Hypothesis.LEGITIMATE, 0.0, config)
    m0 = measured_distribution(Hypothesis.LEGITIMATE, 0.0, config)
    l0 = local_distribution(Hypothesis.LEGITIMATE, 0.0, config)
    rows = []
    for h in ATTACKS:
        rho1 = cq_state(h, theta, config)
        xi_q, s_opt = quantum_chernoff(rho0, rho1)
        xi_m = classical_chernoff(m0, measured_distribution(h, theta, config))
        xi_l = classical_chernoff(l0, local_distribution(h, theta, config))
        rows.append(
            {
                "attack": h.value,
                "theta": theta,
                "trace_distance": trace_distance(rho0, rho1),
                "helstrom_error_single_round": helstrom_error(rho0, rho1),
                "quantum_chernoff": xi_q,
                "chernoff_s_opt": s_opt,
                "measured_chernoff": xi_m,
                # Best exponent reachable with local measurements. xi_Q needs a
                # non-local Bell measurement, so this is the achievable ceiling.
                "local_chernoff": xi_l,
                "measurement_efficiency": xi_m / xi_q if xi_q > 0 else float("nan"),
                "local_efficiency": xi_m / xi_l if xi_l > 0 else float("nan"),
                "rounds_for_epsilon_quantum": float(np.log(1 / epsilon) / xi_q) if xi_q > 0 else float("inf"),
                "rounds_for_epsilon_local": float(np.log(1 / epsilon) / xi_l) if xi_l > 0 else float("inf"),
                "rounds_for_epsilon_measured": float(np.log(1 / epsilon) / xi_m) if xi_m > 0 else float("inf"),
                "epsilon": epsilon,
            }
        )
    return rows
