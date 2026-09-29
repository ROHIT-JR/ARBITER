# ARBITER v0.1.0: Optimal Attack Attribution for Quantum Digital Signatures

**Release Date:** September 29, 2026

## Overview

ARBITER is a production-ready system for unified attack attribution in teleportation-based quantum digital signatures. It detects and names forgery, impersonation, replay, and quantum-channel manipulation with a single Neyman–Pearson test backed by density-matrix Born-rule likelihoods and cross-checked against Qiskit circuits.

## What's New in v0.1.0

### Core Detector
- Teleportation-QDS session simulator with analytic (density-matrix) and Qiskit backends
- Unified multi-hypothesis GLRT with exact per-session Monte-Carlo calibration
- Maximum-likelihood attack attribution with confidence scores
- Anytime-valid sequential e-process (alarm and attribution times)
- CHSH channel-integrity check and quantum freshness test

### Security & Audit
- SHA3-512 hash-chained audit ledger
- Dual signatures: ML-DSA-65 (post-quantum) and Merkle-Lamport (hash-based)
- Epoch key rotation with encrypted key storage

### Deployment
- **Docker:** Multi-stage build, non-root user, health checks, Docker Compose
- **PyPI:** Trusted publishing via OIDC, signature verification with twine
- **Documentation:** MkDocs Material site, API reference, architecture guides
- **CI/CD:** Automated release, Docker Hub push, docs deployment to GitHub Pages

### Noise Modeling
- Trapped-ion error budget (MS gate fidelity, T₂ dephasing, heating, SPAM)
- Configurable noise presets for different hardware

### PKI Support
- X.509 certificate parsing and risk scoring
- Shor resource estimates for cryptanalysis
- Mosca's inequality for post-quantum migration planning

## Installation

### Via pip (recommended)
```bash
pip install arbiter-qds
```

### Via Docker
```bash
docker compose up
# Visit http://localhost:8000
```

### Development
```bash
git clone https://github.com/ROHIT-JR/ARBITER.git
pip install -e ".[dev]"
pytest
```

## Documentation

- **Home:** https://arbiter-qds.org
- **Installation:** https://arbiter-qds.org/installation/
- **Quick Start:** https://arbiter-qds.org/quick-start/
- **API Reference:** https://arbiter-qds.org/api-reference/
- **Architecture:** https://arbiter-qds.org/architecture/

## Artifacts

- `arbiter-qds-0.1.0.tar.gz` – Source distribution
- `arbiter_qds-0.1.0-py3-none-any.whl` – Built wheel

Both are signed and verified with twine.

## Docker Images

- **GitHub Container Registry:** `ghcr.io/rohit-jr/arbiter:0.1.0`
- **Docker Hub:** `rohitjr/arbiter:0.1.0`

## Citation

```bibtex
@software{arbiter2026,
  title = {ARBITER: Unified Attack Attribution for Teleportation-Based Quantum Digital Signatures},
  author = {Team F0rg3d},
  year = {2026},
  month = {september},
  url = {https://github.com/ROHIT-JR/ARBITER},
  version = {0.1.0}
}
```

## Contributing

ARBITER is open-source under Apache License 2.0. Contributions welcome!

- **Issues:** https://github.com/ROHIT-JR/ARBITER/issues
- **Discussions:** https://github.com/ROHIT-JR/ARBITER/discussions
- **Contributing Guide:** [CONTRIBUTING.md](../CONTRIBUTING.md)

## Acknowledgments

Built for **Smart India Hackathon 2026, Problem Statement 26141** by Team **F0rg3d** (SIH26-A0H-T043), with problem statement from [Egreen Quanta](https://www.egreenquanta.com/).

## License

Apache License 2.0. See [LICENSE](../LICENSE) for details.

---

**Questions?** Open an issue or visit the [documentation](https://arbiter-qds.org).
