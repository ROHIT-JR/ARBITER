# ARBITER

[![CI](https://github.com/ROHIT-JR/ARBITER/actions/workflows/ci.yml/badge.svg)](https://github.com/ROHIT-JR/ARBITER/actions/workflows/ci.yml)
[![Release](https://github.com/ROHIT-JR/ARBITER/actions/workflows/release.yml/badge.svg)](https://github.com/ROHIT-JR/ARBITER/actions/workflows/release.yml)
[![Docs](https://github.com/ROHIT-JR/ARBITER/actions/workflows/docs.yml/badge.svg)](https://github.com/ROHIT-JR/ARBITER/actions/workflows/docs.yml)
[![Core coverage](https://img.shields.io/badge/core%20coverage-%E2%89%A590%25-brightgreen)](https://github.com/ROHIT-JR/ARBITER/actions/workflows/ci.yml)
[![PyPI: arbiter-qds](https://img.shields.io/pypi/v/arbiter-qds.svg)](https://pypi.org/project/arbiter-qds)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.10–3.13](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue.svg)
[![Docker Hub](https://img.shields.io/badge/docker-hub-blue.svg)](https://hub.docker.com/r/rohitjr/arbiter)

**Unified attack attribution for teleportation-based Quantum Digital Signatures.**

ARBITER simulates a teleportation-based QDS session (Bell pairs, Bell measurement, Pauli correction, projective Pauli verification) and detects **forgery, impersonation, replay and quantum-channel manipulation** with a *single* statistical test. It doesn't stop at accept or reject: it also names the attack. Every verdict goes into a hash-chained audit ledger, signed twice with post-quantum signatures. The system uses no machine learning anywhere, only Born-rule likelihoods and hypothesis testing.

Built for **Smart India Hackathon 2026, Problem Statement 26141** (set by [Egreen Quanta](https://www.egreenquanta.com/)) by Team **F0rg3d** (SIH26-A0H-T043).

## What's different

| | Typical approach | ARBITER |
|---|---|---|
| Decision rule | Four independent, hand-set thresholds | One level-α generalized likelihood-ratio test over all attacks (Neyman–Pearson) |
| Output | accept / reject | accept / reject **plus** a maximum-likelihood attack attribution and strength estimate |
| Sample size | Fixed | Anytime-valid sequential test: raises the alarm after ~6–16 rounds for full-strength attacks |
| Channel check | Error rate only | CHSH Bell test (S < 2 means no entanglement survived) |
| Where the likelihoods come from | Tuned constants | Density matrices, including an explicit teleportation map, cross-checked against Qiskit circuits |
| Noise | Generic depolarizing | Trapped-ion error budget (MS gate, T₂ dephasing, heating, SPAM) → channel parameters |
| How good is it? | Not stated | Compared against Helstrom / quantum-Chernoff limits |
| Audit | – | SHA3-512 hash chain, each entry signed with **ML-DSA-65 and** a Merkle-Lamport hash-based signature |

## Get Started

### Installation via pip

```bash
pip install arbiter-qds
python -c "import arbiter; print(arbiter.__version__)"
```

### Run with Docker

```bash
docker compose up
# Visit http://localhost:8000
```

### Clone and develop

```bash
git clone https://github.com/ROHIT-JR/ARBITER.git
cd ARBITER
pip install -e ".[dev]"
pytest
python -m arbiter demo  # Run the demo
```

## Documentation

- **[Installation](installation.md)** - pip, Docker, and development setup
- **[Quick Start](quick-start.md)** - Run your first QDS simulation
- **[Architecture](architecture.md)** - System design and components
- **[Threat Model](threat-model.md)** - Attack scenarios and defenses
- **[API Reference](api-reference.md)** - FastAPI endpoints and Python API

## Citation

If you use ARBITER in research, please cite:

```bibtex
@software{arbiter2026,
  title = {ARBITER: Unified Attack Attribution for Quantum Digital Signatures},
  author = {Team F0rg3d},
  year = {2026},
  url = {https://github.com/ROHIT-JR/ARBITER}
}
```

## License

Apache License 2.0. See [LICENSE](https://github.com/ROHIT-JR/ARBITER/blob/main/LICENSE) for details.
