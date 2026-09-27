# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

### Added
- Teleportation-QDS session simulator with two backends, `analytic` (density-matrix Born rule) and `qiskit` (Aer circuits with `if_test` Pauli correction), cross-checked in tests.
- Unified multi-hypothesis GLRT detector with exact per-session Monte-Carlo calibration and maximum-likelihood attack attribution.
- Anytime-valid sequential e-process that reports separate alarm and attribution times.
- CHSH channel-integrity pre-check, a nonce registry and a quantum freshness test.
- Helstrom and quantum-Chernoff bounds, with measurement efficiency.
- SHA3-512 hash-chained audit ledger, dual-signed with ML-DSA-65 and Merkle-Lamport.
- Trapped-ion noise model (`arbiter.noise`) that maps hardware figures to channel parameters, with presets.
- PKI quantum-risk scoring (`arbiter.pki_risk_scoring`): X.509 parsing, Shor resource estimates and Mosca's inequality.
- FastAPI service, React dashboard, demo notebook, attack-sweep example.
- CI (lint, tests on Python 3.10–3.13 and Windows, notebook execution, frontend build).
