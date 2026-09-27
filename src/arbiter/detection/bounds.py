"""Information-theoretic limits for each attack, and how close ARBITER's
actual measurements come to them.

Per round the verifier holds the classical-quantum state

    rho_h = sum_t  p_t |t><t| (x) rho_{h,t}

(t = round type, known to the verifier). Its quantum Chernoff exponent xi_Q
against the legitimate state bounds how fast *any* measurement strategy can
drive the error down: P_err ~ exp(-N xi_Q). Comparing with the classical
Chernoff exponent xi_M of the measurement ARBITER actually performs gives a
"measurement efficiency" xi_M / xi_Q <= 1.
"""

from __future__ import annotations

import numpy as np
from scipy.linalg import block_diag

from arbiter.qds_simulation.model import (
    ATTACKS,
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
    blocks.append(config.round_mix[2] * ((1 - theta) * c0 + theta * c1))
    return block_diag(*blocks)


def measured_distribution(h: Hypothesis, theta: float, config: SessionConfig) -> np.ndarray:
    """Joint distribution over (cell, outcome) produced by ARBITER's measurements."""
    q = cell_probabilities(h, theta, config.params)
    w = np.array(config.round_mix[:2] + (config.round_mix[2] / len(CHSH_SETTINGS),) * 4)
    return np.concatenate([w * (1 - q), w * q])


def attack_bounds(theta: float = 1.0, config: SessionConfig | None = None, epsilon: float = 1e-6) -> list[dict]:
    config = config or SessionConfig()
    rho0 = cq_state(Hypothesis.LEGITIMATE, 0.0, config)
    m0 = measured_distribution(Hypothesis.LEGITIMATE, 0.0, config)
    rows = []
    for h in ATTACKS:
        rho1 = cq_state(h, theta, config)
        xi_q, s_opt = quantum_chernoff(rho0, rho1)
        xi_m = classical_chernoff(m0, measured_distribution(h, theta, config))
        rows.append(
            {
                "attack": h.value,
                "theta": theta,
                "trace_distance": trace_distance(rho0, rho1),
                "helstrom_error_single_round": helstrom_error(rho0, rho1),
                "quantum_chernoff": xi_q,
                "chernoff_s_opt": s_opt,
                "measured_chernoff": xi_m,
                "measurement_efficiency": xi_m / xi_q if xi_q > 0 else float("nan"),
                "rounds_for_epsilon_quantum": float(np.log(1 / epsilon) / xi_q) if xi_q > 0 else float("inf"),
                "rounds_for_epsilon_measured": float(np.log(1 / epsilon) / xi_m) if xi_m > 0 else float("inf"),
                "epsilon": epsilon,
            }
        )
    return rows
