# ARBITER

**Unified attack attribution for teleportation-based Quantum Digital Signatures.**

ARBITER simulates a teleportation-based QDS session (Bell pairs, Bell measurement, Pauli correction, projective Pauli verification) and detects **forgery, impersonation, replay and quantum-channel manipulation** with a *single* statistical test. It doesn't stop at accept or reject: it also names the attack. Every verdict goes into a hash-chained audit ledger, signed twice with post-quantum signatures. The system uses no machine learning anywhere, only Born-rule likelihoods and hypothesis testing.

Built for **Smart India Hackathon 2026, Problem Statement 26141** (set by [Egreen Quanta](https://www.egreenquanta.com/)) by Team **F0rg3d** (SIH26-A0H-T043).

## What's different

| | Typical approach | ARBITER |
|---|---|---|
| Decision rule | Four independent, hand-set thresholds | One level-α generalized likelihood-ratio test over all attacks (Neyman–Pearson) |
| Output | accept / reject | accept / reject **plus** a maximum-likelihood attack attribution and strength estimate |
| Sample size | Fixed | Anytime-valid sequential test: raises the alarm after ~10–20 rounds for full-strength attacks |
| Channel check | Error rate only | CHSH Bell test (S < 2 means no entanglement survived) |
| Where the likelihoods come from | Tuned constants | Density matrices, including an explicit teleportation map, cross-checked against Qiskit circuits |
| How good is it? | Not stated | Compared against Helstrom / quantum-Chernoff limits (`/bounds`) |
| Audit | – | SHA3-512 hash chain, each entry signed with **ML-DSA-65 and** a Merkle-Lamport hash-based signature |

## Results

From `python examples/attack_sweep.py --sessions 200`: 1200 rounds per session, α = 0.01, visibility 0.92. Rows are the true hypothesis and columns are ARBITER's attribution.

**Full-strength attacks (θ = 1):**

| true ↓ / attributed → | legit | forgery | imperson. | replay | channel | alarm (median rounds) | attributed (median rounds) |
|---|---|---|---|---|---|---|---|
| legitimate | **1.00** | 0 | 0 | 0 | 0 | – | – |
| forgery | 0 | **1.00** | 0 | 0 | 0 | 12 | 39 |
| impersonation | 0 | 0 | **1.00** | 0 | 0 | 8 | 54 |
| replay | 0 | 0 | 0 | **1.00** | 0 | 19 | 60 |
| channel manipulation | 0 | 0 | 0 | 0 | **1.00** | 12 | 116 |

**Partial attacks:** the diagonal is ≥ 0.99 at θ = 0.3 and 0.77–0.94 at θ = 0.1. At θ = 0.1 only 10% of rounds are attacked, so these are deliberately weak attacks.

**The limits of what any detector could do:**

| attack | quantum Chernoff ξ_Q | ARBITER's measurement ξ_M | efficiency |
|---|---|---|---|
| forgery | 0.0885 | 0.0885 | **1.00** (the PS's projective Pauli measurement is Helstrom-optimal) |
| impersonation | 0.227 | 0.154 | 0.68 |
| replay | 0.132 | 0.064 | 0.49 |
| channel manipulation | 0.114 | 0.080 | 0.70 |

Efficiencies below 1 come from the fixed CHSH settings. That gap is the most concrete open item for the next version.

## Quickstart

```bash
git clone https://github.com/ROHIT-JR/ARBITER && cd ARBITER
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                                   # 72 tests, ~20 s
python examples/attack_sweep.py          # the tables above
uvicorn --factory arbiter.api.app:create_app --reload   # then open http://127.0.0.1:8000/docs
```

From Python:

```python
from arbiter.pipeline import Arbiter
from arbiter.qds_simulation import Hypothesis, simulate_session

t = simulate_session(Hypothesis.REPLAY, theta=1.0, seed=7, backend="qiskit")  # real Aer circuits
v = Arbiter().verify(t)
print(v.decision, v.attribution, v.reasons)
# REJECT Hypothesis.REPLAY ['CHSH S=... below 2.0 ...', 'unified GLRT ... most likely: replay']
```

### API

| endpoint | purpose |
|---|---|
| `POST /sessions` | simulate a session `{hypothesis, theta, n_rounds, backend, seed}` and return the full layered verdict. The verdict is written to the ledger |
| `POST /sessions/{id}/resubmit` | replay a transcript verbatim, which the nonce registry catches |
| `GET /model` | each hypothesis's per-cell outcome probabilities |
| `GET /bounds` | Helstrom / quantum-Chernoff limits against the achieved exponents |
| `GET /ledger`, `/ledger/{i}`, `/ledger/verify` | inspect and verify the audit chain |

## Repository layout

```
src/arbiter/
  quantum/          states, channels, trace distance, Helstrom, quantum Chernoff, min-error POVM SDP
  qds_simulation/   physical model, Qiskit circuits, session simulator
  detection/        unified GLRT, sequential e-process, CHSH, freshness, bounds
  audit_ledger/     hash chain + ML-DSA-65 + Merkle-Lamport
  api/              FastAPI service
  pipeline.py       all layers → verdict → ledger
  qrng.py           Hadamard-measurement QRNG (simulated)
docs/               threat model, math derivations, architecture
examples/           attack sweep
tests/              per-attack fixtures, circuit/model agreement, false-alarm control, ledger tampering
```

## Honest scope

- **Simulation only.** On Aer, the QRNG and the quantum channel are models. The circuits are hardware-ready, but nothing has been run on a device yet.
- **"Optimal" means optimal relative to the model** in [docs/threat-model.md](docs/threat-model.md). That covers i.i.d. individual/collective attacks with a known legitimate visibility. Detector blinding, PNS, Trojan-horse and side-channel attacks are out of scope, and the threat model names them.
- **Partial impersonation is indistinguishable from channel manipulation.** Both are depolarizing, and no detector could separate them with these observables. Impersonation is therefore modelled as all-or-nothing.

## Roadmap

| version | scope |
|---|---|
| **v0.1** (this) | QDS simulation (analytic + Qiskit), unified GLRT detector, sequential test, CHSH pre-check, freshness layers, bounds, dual-signed ledger, API |
| v0.2 | dashboard, trapped-ion noise model (motional heating, laser phase noise, Raman scattering) with public IonQ/Quantinuum parameters, optimized CHSH-round measurements |
| v0.3 | quantum-risk scoring for classical PKI (RSA/ECC certificates), nuisance-parameter estimation of the channel visibility |
| v1.0 | calibration against real trapped-ion hardware data (collaborators welcome), technical report |

## Contributing and citing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), especially if you work on trapped-ion hardware and can check the noise model against real data. If you use ARBITER in research, please cite it using [CITATION.cff](CITATION.cff).

## Acknowledgements

The problem statement is SIH 2026 PS 26141, set by **Egreen Quanta**. The protocol builds on Zeng & Keitel (2002), Wallden et al. (2015) and Amiri et al. (2016). The detection theory builds on Helstrom (1976), Audenaert et al. (2007) and Ville (1939). The full bibliography is in [docs/math-derivations.md](docs/math-derivations.md) and the project proposal.

Licensed under [Apache-2.0](LICENSE).
