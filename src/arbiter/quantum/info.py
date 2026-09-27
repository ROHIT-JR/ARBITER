"""Distinguishability measures used to bound what any detector can achieve.

* Helstrom: minimum single-shot error for two equiprobable states,
  ``P_err = 1/2 - 1/4 * ||rho - sigma||_1``.
* Quantum Chernoff bound (Audenaert et al., PRL 98, 160501): over N copies
  the optimal symmetric error decays as ``exp(-N * xi)`` with
  ``xi = -log min_{0<=s<=1} Tr(rho^s sigma^(1-s))``.
* Optimal multi-hypothesis POVM via the standard min-error SDP (needs cvxpy).
"""

from __future__ import annotations

import numpy as np
from scipy.optimize import minimize_scalar


def _herm(m: np.ndarray) -> np.ndarray:
    return (m + m.conj().T) / 2


def _mpow(rho: np.ndarray, s: float) -> np.ndarray:
    """Matrix power of a PSD matrix; zero eigenvalues stay zero (0^0 := 0),
    which is the support-projector convention the Chernoff bound needs."""
    w, v = np.linalg.eigh(_herm(rho))
    w = np.clip(w.real, 0, None)
    ws = np.where(w > 1e-14, w**s, 0.0)
    return (v * ws) @ v.conj().T


def trace_norm(m: np.ndarray) -> float:
    return float(np.sum(np.abs(np.linalg.eigvalsh(_herm(m)))))


def trace_distance(rho: np.ndarray, sigma: np.ndarray) -> float:
    return 0.5 * trace_norm(rho - sigma)


def helstrom_error(rho: np.ndarray, sigma: np.ndarray, prior: float = 0.5) -> float:
    """Minimum error probability discriminating rho (prior p) from sigma."""
    return 0.5 * (1 - trace_norm(prior * rho - (1 - prior) * sigma))


def fidelity(rho: np.ndarray, sigma: np.ndarray) -> float:
    """Uhlmann fidelity F = (Tr sqrt(sqrt(rho) sigma sqrt(rho)))^2."""
    sr = _mpow(rho, 0.5)
    return float(np.real(np.trace(_mpow(sr @ sigma @ sr, 0.5))) ** 2)


def quantum_chernoff(rho: np.ndarray, sigma: np.ndarray) -> tuple[float, float]:
    """Return ``(xi, s_opt)``: the quantum Chernoff exponent and its optimiser."""

    def q(s: float) -> float:
        return float(np.real(np.trace(_mpow(rho, s) @ _mpow(sigma, 1 - s))))

    res = minimize_scalar(q, bounds=(0.0, 1.0), method="bounded", options={"xatol": 1e-8})
    candidates = [(res.fun, res.x), (q(0.0), 0.0), (q(1.0), 1.0)]
    qmin, s_opt = min(candidates)
    qmin = max(qmin, 1e-300)
    return float(-np.log(qmin)), float(s_opt)


def classical_chernoff(p: np.ndarray, q: np.ndarray) -> float:
    """Chernoff information between two classical distributions (same support)."""
    p = np.asarray(p, float)
    q = np.asarray(q, float)

    def f(s: float) -> float:
        mask = (p > 0) & (q > 0)
        return float(np.sum(p[mask] ** s * q[mask] ** (1 - s)))

    res = minimize_scalar(f, bounds=(0.0, 1.0), method="bounded", options={"xatol": 1e-8})
    return float(-np.log(max(min(res.fun, f(0.0), f(1.0)), 1e-300)))


def relative_entropy(rho: np.ndarray, sigma: np.ndarray) -> float:
    """Umegaki relative entropy S(rho||sigma) in nats (inf if supp rho not in supp sigma)."""
    wr, vr = np.linalg.eigh(_herm(rho))
    ws, vs = np.linalg.eigh(_herm(sigma))
    wr = np.clip(wr.real, 0, None)
    ws = np.clip(ws.real, 0, None)
    overlap = np.abs(vr.conj().T @ vs) ** 2  # |<r_i|s_j>|^2
    total = 0.0
    for i, p in enumerate(wr):
        if p <= 1e-14:
            continue
        cross = overlap[i] @ np.where(ws > 1e-14, np.log(np.where(ws > 1e-14, ws, 1)), 0.0)
        if np.any((overlap[i] > 1e-12) & (ws <= 1e-14)):
            return float("inf")
        total += p * np.log(p) - p * cross
    return float(total)


def optimal_povm(states: list[np.ndarray], priors: list[float] | None = None):
    """Minimum-error POVM {M_i} discriminating ``states`` (Helstrom/Holevo SDP).

    maximise   sum_i p_i Tr(M_i rho_i)
    subject to M_i >= 0, sum_i M_i = I.

    Returns ``(success_probability, [M_i])``. Requires ``cvxpy``.
    """
    import cvxpy as cp

    n = len(states)
    d = states[0].shape[0]
    priors = priors or [1.0 / n] * n
    Ms = [cp.Variable((d, d), hermitian=True) for _ in range(n)]
    objective = cp.Maximize(cp.real(sum(p * cp.trace(M @ r) for p, M, r in zip(priors, Ms, states, strict=True))))
    constraints = [M >> 0 for M in Ms] + [sum(Ms) == np.eye(d)]
    prob = cp.Problem(objective, constraints)
    prob.solve()
    return float(prob.value), [np.asarray(M.value) for M in Ms]
