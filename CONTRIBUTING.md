# Contributing to ARBITER

Thanks for your interest. ARBITER started as a Smart India Hackathon 2026 project (PS 26141). We intend to keep developing it as an open research tool.

## Setup

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .   # lint (CI enforces both)
pytest                                  # full suite
pytest -m "not slow"                    # skip Qiskit-circuit and false-alarm-rate tests
python notebooks/build_demo.py          # re-execute the demo notebook
cd frontend && npm ci && npm run build  # dashboard typecheck + build
```

CI runs all of these on every pull request: Python 3.10–3.13 on Linux plus 3.13 on Windows.

## Ground rules

1. **Physics before code.** Any change to a hypothesis or channel goes in `qds_simulation/model.py` first, as density matrices. Mirror it in `circuits.py` / `protocol._round_spec`. `test_qiskit_circuits_match_density_matrix_model` must still pass.
2. **Every statistical claim needs a test.** New detectors need a false-alarm-rate test under H₀ and a per-attack detection test.
3. **Update the threat model** ([docs/threat-model.md](docs/threat-model.md)) whenever the adversary model changes, including what is newly *out* of scope.
4. **No ML in the detection path.** This is a requirement of the problem statement, and it keeps every decision auditable.
5. Match the surrounding style: type hints, dataclasses for results, NumPy-vectorized hot paths, short docstrings stating the math. Formatting is `ruff format` (line length 120).
6. If you change results that appear in the notebook, rebuild it and commit the outputs.

## Proposing a new attack model

Open an issue labelled `detection-core` covering:

- the adversary's capabilities,
- the per-round state it induces,
- which observables it moves, and
- whether it is identifiable from the existing hypotheses. If it isn't, say which new round type would make it identifiable.

## Hardware collaborators

The trapped-ion noise model ([docs/ion-trap-noise-model.md](docs/ion-trap-noise-model.md), issue label `noise-model`) is designed to take real calibration data: coherence times, two-qubit gate fidelities, motional heating rates and Raman scattering error. We would especially welcome review from anyone working on ion-trap hardware, including the Egreen Quanta team as the problem setter.

## Issue labels

`detection-core` · `noise-model` · `audit-ledger` · `pki-bridge` · `api` · `docs`

## Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
