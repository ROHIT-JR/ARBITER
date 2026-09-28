# Architecture

```
            ┌────────────────────── arbiter.qds_simulation ─────────────────────┐
 QRNG ─► nonce, schedule │  model.py      density matrices + explicit teleportation map   │
 key  ─► PRF labels      │  circuits.py   Qiskit Aer circuits (Bell pair, if_test Pauli   │
                         │                correction, attack ops)                          │
                         │  protocol.py   session → Transcript  (backend: analytic|qiskit)│
                         └───────────────────────────────┬──────────────────────────────────┘
                                                         │ Transcript (cells, outcomes)
                         ┌──────────────── arbiter.detection ──────────────────────────────┐
                         │ freshness.NonceRegistry   classical replay                      │
                         │ chsh.chsh_precheck        Bell-test channel integrity           │
                         │ unified.UnifiedDetector   GLRT + ML attribution (level α)       │
                         │ sequential.SequentialDetector  e-process, alarm/attribution time│
                         │ temporal.TemporalDetector calibrated burst + Fisher-g tests      │
                         │ bounds.attack_bounds      Helstrom / quantum Chernoff limits    │
                         └───────────────────────────────┬──────────────────────────────────┘
                                                         │ ArbiterVerdict   (pipeline.py)
                         ┌──────────────── arbiter.audit_ledger ───────────────────────────┐
                         │ SHA3-512 hash chain; every entry signed by ML-DSA-65 AND         │
                         │ Merkle-Lamport; JSON-lines persistence; verify_entries()         │
                         └───────────────────────────────┬──────────────────────────────────┘
                                                         │
                                          arbiter.api (FastAPI)  →  frontend/ (React dashboard)

 arbiter.noise              trapped-ion error budget ─► ChannelParams (feeds everything above)
 arbiter.pki_risk_scoring   X.509 / key → Shor resources + Mosca risk  (independent of the QDS path)
```

## Design choices

- **One likelihood model, two simulators.** The detector's likelihoods come from `model.py`. `protocol.py` can sample sessions either from those same Born-rule probabilities (`analytic`, which is fast and used for calibration and sweeps) or by running the real circuits (`qiskit`). `test_qiskit_circuits_match_density_matrix_model` keeps them in agreement, so any demo can be rerun on circuits.
- **Transcripts are the interface.** Detectors see only `(cell, outcome)` per round. Ground truth (`truth`, `theta`, `attacked`) is stored for evaluation and never read by the detector.
- **Sufficient statistics.** The fixed-sample test needs only the per-cell counts, so threshold calibration is a vectorized binomial draw, taking milliseconds per session.
- **Ordered-stream diagnostics stay separate.** `temporal.py` sees ordered outcomes only to calculate sliding moments and calibrated burst/periodicity tests.  It conditions its Monte-Carlo null on the observed cell schedule, uses no model training, and returns JSON-safe diagnostics for the dashboard.  The pipeline allocates overall α by Bonferroni across its GLRT, freshness and temporal rejection paths; inside the temporal path it splits again over three streams and three statistics.
- **Deterministic by seed.** `simulate_session(seed=...)` reproduces the nonce, the schedule and the outcomes exactly.

## Extension points

| Want to… | Touch |
|---|---|
| add an attack | `Hypothesis`, `resource_state` / `received_state` / `chsh_state` in `model.py`, `_round_spec` in `protocol.py`, plus a fixture in `tests/test_detection.py` |
| use a different noise model | build `ChannelParams` from `arbiter.noise.TrappedIonParams` (or your own model). Everything downstream is derived from it |
| run on hardware | swap the `AerSimulator` in `protocol._run_qiskit` / `qrng.QRNG` for a hardware backend |
