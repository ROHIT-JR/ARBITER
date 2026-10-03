# ARBITER

[![CI](https://github.com/ROHIT-JR/ARBITER/actions/workflows/ci.yml/badge.svg)](https://github.com/ROHIT-JR/ARBITER/actions/workflows/ci.yml)
[![Core coverage](https://img.shields.io/badge/core%20coverage-%E2%89%A590%25-brightgreen)](https://github.com/ROHIT-JR/ARBITER/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.10–3.13](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue.svg)

**Unified attack attribution for teleportation-based Quantum Digital Signatures.**

ARBITER simulates a teleportation-based QDS session (Bell pairs, Bell measurement, Pauli correction, projective Pauli verification) and detects **forgery, impersonation, replay and quantum-channel manipulation** with a *single* statistical test. It doesn't stop at accept or reject: it also names the attack. Every verdict goes into a hash-chained audit ledger, signed twice with post-quantum signatures. The system uses no machine learning anywhere, only Born-rule likelihoods and hypothesis testing.

Built for **Smart India Hackathon 2026, Problem Statement 26141** (set by [Egreen Quanta](https://www.egreenquanta.com/)) by Team **F0rg3d** (SIH26-A0H-T043).

## What's different

| | Typical approach | ARBITER |
|---|---|---|
| Decision rule | Four independent, hand-set thresholds | One level-α generalized likelihood-ratio test over all attacks (Neyman–Pearson) |
| Output | accept / reject | accept / reject **plus** a maximum-likelihood attack attribution and strength estimate |
| Sample size | Fixed | Anytime-valid sequential test: raises the alarm after ~6–16 rounds for full-strength attacks |
| Structured errors | Pooled error counts | Calibrated burst and periodogram tests over the ordered stream (no ML) |
| Channel check | Error rate only | CHSH Bell test (S < 2 means no entanglement survived) |
| Where the likelihoods come from | Tuned constants | Density matrices, including an explicit teleportation map, cross-checked against Qiskit circuits |
| Noise | Generic depolarizing | Trapped-ion error budget (MS gate, T₂ dephasing, heating, SPAM) → channel parameters |
| How good is it? | Not stated | Compared against Helstrom / quantum-Chernoff limits |
| Audit | – | SHA3-512 hash chain, each entry signed with **ML-DSA-65 and** a Merkle-Lamport hash-based signature |

## Results

From `python examples/attack_sweep.py --sessions 200`: 1200 rounds per session, α = 0.01, visibility 0.92. Rows are the true hypothesis, columns are ARBITER's attribution, and the last two columns are the sequential test's median alarm and attribution rounds.

**Full-strength attacks (θ = 1):**

| true ↓ / attributed → | legit | forgery | imperson. | replay | channel | alarm | attributed |
|---|---|---|---|---|---|---|---|
| legitimate | **0.99** | 0 | 0 | 0.01 | 0.01 | – | – |
| forgery | 0 | **1.00** | 0 | 0 | 0 | 13 | 45 |
| impersonation | 0 | 0 | **1.00** | 0 | 0 | 7 | 46 |
| replay | 0 | 0 | 0 | **1.00** | 0 | 16 | 59 |
| channel manipulation | 0 | 0 | 0 | 0 | **1.00** | 13 | 116 |

**Partial attacks:** the diagonal is 1.00 at θ = 0.3 and 0.81–0.92 at θ = 0.1. At θ = 0.1 only 10% of rounds are attacked, so these are deliberately weak attacks. The legitimate false-alarm rate stays at the 1–2% implied by α plus the CHSH flag.

## QDS protocol security bounds

For the BB84 state-elimination QDS mode, ARBITER separately reports finite-size
Hoeffding bounds for forgery, repudiation, and honest abort. These are
stand-alone collective-attack bounds with an analytical ideal-symmetrisation
assumption—not claims about the detector's accuracy or a composable proof. See
[the derivation and assumptions](docs/math-derivations.md#12-finite-size-protocol-security).

The following table is generated with `python examples/security_bounds.py`.

| trapped-ion preset | visibility | p_err | minimum L for ε = 10⁻¹⁰ |
|---|---:|---:|---:|
| state_of_the_art_2025 | 0.999187 | 0.000203 | 6,843 |
| prototype | 0.994482 | 0.001379 | 6,908 |
| conservative | 0.857638 | 0.035590 | 9,288 |

**The limits of what any detector could do:**

| attack | ξ_Q (non-local) | ξ_L (best local) | ARBITER's ξ_M | ξ_M/ξ_L | ξ_M/ξ_Q |
|---|---:|---:|---:|---:|---:|
| forgery | 0.0885 | 0.0885 | 0.0885 | **1.00** | **1.00** |
| impersonation | 0.244 | 0.186 | 0.170 | 0.92 | 0.70 |
| replay | 0.147 | 0.093 | 0.079 | 0.85 | 0.54 |
| channel manipulation | 0.121 | 0.097 | 0.088 | 0.92 | 0.73 |

Two yardsticks, because **ξ_Q is not physically reachable.** On the shared-pair rounds ξ_Q is attained *exactly* by a
Bell-basis measurement — the common eigenbasis of the Bell-diagonal states involved — and that measurement is
non-local: it needs the signer's half and the verifier's half in the same place, which defeats the purpose of a
distributed signature protocol. A numerical search over all local measurement directions puts the achievable ceiling
at ξ_L, roughly half of ξ_Q. **ξ_M/ξ_L is therefore the actionable number.**

Closing that gap is what **Bell-fidelity rounds** do: both parties measure the *same* Pauli from {ZZ, XX, YY} and
record the parity against |Φ⁺⟩'s stabiliser signs (+, +, −). Because the settings are aligned each correlator keeps the
full visibility *v*, instead of losing a factor √2 to the ±45° CHSH settings — provably the optimal local measurement
on a Werner pair, and recording both outcome bits rather than their parity adds nothing. CHSH rounds are kept
regardless, since only they certify a Bell violation *device-independently*.

The default `round_mix` is `(0.50, 0.15, 0.12, 0.23)`, a Pareto improvement on the legacy `(0.5, 0.25, 0.25)`: no
attack is detected worse, and the bottleneck attack (replay) needs **215 → 174 rounds** (−19%) at ε = 10⁻⁶. Re-derive
it with `python examples/optimise_round_mix.py`. A legacy 3-tuple `round_mix` is still accepted and zero-pads the
Bell-fidelity weight, so existing configurations keep their exact behaviour.

## vs. fixed thresholds

`BaselineDetector` implements four independent rules in fixed priority order: signature mismatch, freshness mismatch,
channel integrity, then the joint signature-and-freshness rule. The channel-integrity rule screens both shared-pair
witnesses (CHSH S and Bell fidelity), so the baseline sees every round the unified detector does and the comparison
stays fair. Its thresholds are calibrated under legitimate traffic so the *overall* false-alarm rate, not each rule's
rate, is α. A conventional Bonferroni variant splits α over the five marginal tests.

The table below was generated with
`python examples/compare_baseline.py --sessions 1000 --seed 26141` (1200 balanced rounds/session, α = 0.01).
Each cell is **detection rate / correct-attribution rate**. The observed false-alarm rates were 0.007 for the unified
detector, 0.009 for the equally calibrated baseline, and 0.007 for the Bonferroni baseline.

| θ | attack | unified GLRT | fixed thresholds | Bonferroni |
|---:|---|---:|---:|---:|
| 1.0 | forgery | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 |
| 1.0 | impersonation | 1.000 / 1.000 | 1.000 / 0.000 | 1.000 / 0.000 |
| 1.0 | replay | 1.000 / 1.000 | 1.000 / 0.000 | 1.000 / 0.000 |
| 1.0 | channel manipulation | 1.000 / 1.000 | 1.000 / 0.000 | 1.000 / 0.000 |
| 0.3 | forgery | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 |
| 0.3 | impersonation¹ | 1.000 / 1.000 | 1.000 / 0.000 | 1.000 / 0.000 |
| 0.3 | replay | 1.000 / 0.999 | 1.000 / 0.637 | 1.000 / 0.637 |
| 0.3 | channel manipulation | 1.000 / 1.000 | 1.000 / 0.000 | 1.000 / 0.000 |
| 0.1 | forgery | 0.986 / 0.923 | 0.978 / **0.976** | 0.977 / **0.976** |
| 0.1 | impersonation¹ | 1.000 / 1.000 | 1.000 / 0.000 | 1.000 / 0.000 |
| 0.1 | replay | 0.868 / 0.805 | 0.814 / 0.730 | 0.808 / 0.730 |
| 0.1 | channel manipulation | 0.959 / 0.806 | 0.950 / 0.011 | 0.923 / 0.011 |

¹ Impersonation is all-or-nothing in the threat model, so it remains at θ = 1. The fixed baseline ties the unified
detector on full-strength *detection*, and at θ = 0.1 it attributes forgery more often (0.976 vs 0.923). The unified
test nevertheless has the higher forgery detection rate there and is substantially better at distinguishing replay,
channel manipulation, and impersonation instead of merely raising an alarm.

## Quickstart

```bash
git clone https://github.com/ROHIT-JR/ARBITER && cd ARBITER
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                                   # full suite, ~20 s
python examples/attack_sweep.py          # the tables above
uvicorn --factory arbiter.api.app:create_app --port 8000   # API; open http://127.0.0.1:8000/docs
```

## Test coverage

CI enforces at least 90% line coverage for the deterministic protocol and
security core, and publishes HTML/XML coverage artefacts on every run.
Transport and integration adapters (the ASGI API, CLI/demo preflight, SQLite
persistence, certificate/network scanners, and Qiskit Aer circuits) plus the
legacy baseline comparator are exercised by the normal cross-platform suite
but are outside this deterministic-core coverage gate. Hypothesis uses a fast
`ci` profile in GitHub Actions (20 examples per property); run
`HYPOTHESIS_PROFILE=thorough pytest tests/test_properties.py` locally for 100
examples per property.

**Dashboard** (in a second terminal):

```bash
cd frontend && npm install && npm run dev   # http://localhost:5173
```

**Offline finale demo:** build the dashboard once while preparing the release,
then use only Python at the venue:

```bash
cd frontend && npm ci && npm run build && npm run sync:demo
cd ..
arbiter demo --check  # deterministic, headless pre-flight
arbiter demo          # opens http://127.0.0.1:8000/ with throwaway local data
```

The launcher serves `frontend/dist` itself, uses no CDN resources, and enables
the ledger tamper controls only for its localhost demo process.  See
[the timed demo script](docs/demo-script.md) for the five-minute walkthrough
and recording fallback.

**Notebook:** [notebooks/arbiter_demo.ipynb](notebooks/arbiter_demo.ipynb) is committed with its outputs, so you can read it on GitHub. Rebuild it with `python notebooks/build_demo.py`.

**From Python:**

```python
from arbiter.pipeline import Arbiter
from arbiter.qds_simulation import Hypothesis, simulate_session

t = simulate_session(Hypothesis.REPLAY, theta=1.0, seed=7, backend="qiskit")  # real Aer circuits
v = Arbiter().verify(t)
print(v.decision, v.attribution.value)  # REJECT replay
print(v.reasons)
```

### API

| endpoint | purpose |
|---|---|
| `POST /sessions` | simulate a session `{hypothesis, theta, n_rounds, backend, seed, trajectory}` and return the full layered verdict. The verdict is written to the ledger |
| `POST /sessions/{id}/resubmit` | replay a transcript verbatim, which the nonce registry catches |
| `GET /sessions?limit=` and `GET /sessions/{id}` | list persisted sessions or retrieve one stored session and its latest verdict |
| `GET /model` | each hypothesis's per-cell outcome probabilities |
| `GET /bounds` | Helstrom / quantum-Chernoff limits against the achieved exponents |
| `GET /security?epsilon=&visibility=` | finite-size QDS forgery, repudiation and robustness bounds plus minimum signature length |
| `GET /compare?theta=&sessions=&seed=` | unified-vs-fixed confusion matrices, false alarms, detection and attribution rates |
| `GET /ledger`, `/ledger/{i}`, `/ledger/verify` | inspect and verify the audit chain |
| `GET /noise/presets` | trapped-ion presets and the channel parameters they induce |
| `POST /pki/assess`, `/pki/assess-key` | quantum-risk score for certificates (PEM) or single keys |
| `POST /pki/scan` | opt-in, allowlisted scan of public TLS endpoint certificates |

Service configuration includes:

- `ARBITER_DATA_DIR`: where the ledger keys, ledger and SQLite session store (`arbiter.db`) live. The default is `./.arbiter`.
- `ARBITER_NOISE_PRESET`: calibrates the legitimate channel from a trapped-ion preset (`state_of_the_art_2025`, `prototype` or `conservative`).
- `ARBITER_PKI_SCAN=1` plus `ARBITER_PKI_SCAN_ALLOW=example.com,...`: enable the otherwise-disabled TLS scan endpoint for narrow hostname suffixes. It refuses non-public DNS answers; see [PKI scoring](docs/pki-risk-scoring.md).

The API uses SQLite with one connection per storage operation, so session transcripts, verdicts and replay nonces survive a restart. PostgreSQL is deliberately out of scope; a future backend can replace `SQLiteStorage` by providing the same save/load session, verdict and atomic nonce-registration operations without changing the detector or API behavior.

### Temporal diagnostics

Every session verdict includes `layers.temporal`: sliding-window mismatch rate,
variance, skewness and excess kurtosis for signature, freshness and CHSH
streams.  It additionally runs a longest-run test, a maximum window-count test
and Fisher's maximum-periodogram (`g`) test.  These are hypothesis tests, not
features passed to a classifier: each null distribution is simulated from the
observed round schedule and the legitimate Born-rule probabilities.

The temporal family uses Bonferroni allocation across 3 streams × 3 tests.
The pipeline then splits its configured overall α across the unified GLRT,
freshness tail test and temporal family.  Consequently adding diagnostics does
not silently inflate the declared false-alarm budget.  The dashboard plots the
windowed rates after a session; the optional `periodic_attack_every` session
field (`k`) is a reproducible simulation fixture that attacks rounds
`0, k, 2k, …` for testing periodic interference.

## Repository layout

```
src/arbiter/
  quantum/            states, channels, trace distance, Helstrom, quantum Chernoff, min-error POVM SDP
  qds_simulation/     physical model, Qiskit circuits, session simulator
  detection/          unified GLRT, temporal burst/spectral tests, fixed-threshold baseline, sequential e-process, CHSH, freshness, bounds
  audit_ledger/       hash chain + ML-DSA-65 + Merkle-Lamport
  noise/              trapped-ion error budget → channel parameters
  pki_risk_scoring/   X.509 parsing, Shor resource estimates, Mosca's inequality
  api/                FastAPI service
  pipeline.py         all layers → verdict → ledger
  qrng.py             Hadamard-measurement QRNG (simulated)
frontend/             React + TypeScript dashboard (Vite)
notebooks/            executed walkthrough + the script that builds it
examples/             attack sweep and reproducible baseline comparison
docs/                 threat model, math derivations, architecture, noise model, PKI scoring
tests/                per-attack fixtures, circuit/model agreement, false-alarm control,
                      ledger tampering, noise identities, PKI, API
```

## Honest scope

- **Simulation only.** On Aer, the QRNG and the quantum channel are models. The circuits are hardware-ready, but nothing has been run on a device yet.
- **"Optimal" means optimal relative to the model** in [docs/threat-model.md](docs/threat-model.md). That covers i.i.d. individual/collective attacks with a known legitimate visibility. Detector blinding, PNS, Trojan-horse and side-channel attacks are out of scope, and the threat model names them.
- **Partial impersonation is indistinguishable from channel manipulation.** Both are depolarizing, and no detector could separate them with these observables. Impersonation is therefore modelled as all-or-nothing.
- **The trapped-ion model is a twirled Pauli error budget.** It does not capture coherent or correlated errors. See [docs/ion-trap-noise-model.md](docs/ion-trap-noise-model.md).

## Roadmap

| version | scope |
|---|---|
| **v0.1** (this) | QDS simulation (analytic + Qiskit), unified GLRT, sequential test, CHSH, freshness, bounds, dual-signed ledger, trapped-ion error budget, PKI risk scoring, API, dashboard, notebook, CI |
| v0.2 | Bell-fidelity rounds and an optimised round mix (closes the gap to the *local* measurement optimum), tightened CHSH confidence bound, estimating the channel visibility per session as a nuisance parameter, ledger key rotation |
| v0.3 | coherent and correlated trapped-ion errors, hybrid-certificate support in PKI scoring, robust tests against adaptive attacks |
| v1.0 | calibration against real trapped-ion hardware data (collaborators welcome), technical report |

## Contributing, security, presenting and citing

- **Contributing:** see [CONTRIBUTING.md](CONTRIBUTING.md). We especially welcome anyone working on trapped-ion hardware who can check the noise model against real data.
- **Team explainer:** [docs/explainer.md](docs/explainer.md) is the plain-language, judge-facing guide and self-test.
- **Judge Q&A:** [docs/judge-qa.md](docs/judge-qa.md) covers 30+ anticipated questions (physics, stats, security, deployment, "is this real?").
- **Pitch deck:** [docs/pitch/ARBITER_pitch.pptx](docs/pitch/ARBITER_pitch.pptx) — 12-slide, 5-minute presentation. See [docs/PITCH_DECK_OUTLINE.md](docs/PITCH_DECK_OUTLINE.md) for speaker notes.
- **Security:** see [SECURITY.md](SECURITY.md) for how to report issues privately.
- **Citing:** if you use ARBITER in research, please cite it using [CITATION.cff](CITATION.cff).

## Acknowledgements

The problem statement is SIH 2026 PS 26141, set by **Egreen Quanta**. The protocol builds on Zeng & Keitel (2002), Wallden et al. (2015) and Amiri et al. (2016). The detection theory builds on Helstrom (1976), Audenaert et al. (2007) and Ville (1939). Details are in [docs/math-derivations.md](docs/math-derivations.md).

Licensed under [Apache-2.0](LICENSE).
