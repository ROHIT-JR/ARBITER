# Graph Report - ARBITER  (2026-09-29)

## Corpus Check
- 107 files · ~63,789 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1530 nodes · 4131 edges · 69 communities (59 shown, 10 thin omitted)
- Extraction: 86% EXTRACTED · 14% INFERRED · 0% AMBIGUOUS · INFERRED: 561 edges (avg confidence: 0.88)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Dashboard Bundle Symbols
- Dashboard Bundle Internals
- Quantum Info Bounds
- Key Metadata Registry
- Frontend API Types
- Session Simulation Benchmark
- CBOM Export
- Background Jobs Storage
- Bundle Fragment Cluster
- PKI Risk Scoring
- Bundle Symbol Fragments
- Channel Integrity Prechecks
- Unified GLRT Detector
- Qiskit Circuit Library
- Minified Symbol Shard
- Attack Sweep Harness
- Baseline Comparison
- Frontend Dependencies
- Bundle Fragment Shard A
- Bundle Fragment Shard B
- Certificate Chain Assessment
- TLS Scan Guard
- FastAPI App Wiring
- Bundle Shard Group 23
- Bundle Shard Group 24
- Bundle Shard Group 25
- TypeScript Config
- Offline Demo Runner
- Encrypted Key Storage
- Ledger Test Suite
- Bundle Symbol Fragment Group
- X509 Certificate Parsing
- Post-Quantum Signatures
- Bundle Fragment Group 33
- Ledger Core Verification
- Trapped-Ion Noise Model
- QDS Distribution Model
- Command Line Interface
- API Request Models
- Epoch Key Management
- API Security Middleware
- Key Derivation Primitives
- Ledger Append Rotate
- Merkle-Lamport Signatures
- Epoch Manager
- Ledger Key Persistence
- Project Governance Docs
- QRNG Nonce Source
- Ledger Design Rationale
- GLRT Design Rationale
- Demo Walkthrough Docs
- CHSH Design Rationale
- Sequential Test Rationale
- Noise Calibration Rationale
- Quantum Risk Rationale
- Dashboard Sync Script
- CI Coverage Gate
- Impersonation Identifiability Rationale
- Optimality Bounds Rationale
- Orchestrator Topology Rationale
- Delivery Waves Rationale
- Honest Scope Rationale
- Vite Dev Proxy
- Notebook Build Script
- Package Identity

## God Nodes (most connected - your core abstractions)
1. `zy()` - 399 edges
2. `r()` - 65 edges
3. `e()` - 58 edges
4. `ChannelParams` - 56 edges
5. `hd()` - 53 edges
6. `Hypothesis` - 51 edges
7. `simulate_session()` - 49 edges
8. `create_app()` - 43 edges
9. `assess_certificates()` - 40 edges
10. `a()` - 38 edges

## Surprising Connections (you probably didn't know these)
- `test_bounds_are_consistent()` --calls--> `attack_bounds()`  [INFERRED]
  tests/test_detection.py → src/arbiter/detection/bounds.py
- `test_alternative_signature_extensions_are_recognised()` --calls--> `assess_certificates()`  [INFERRED]
  tests/test_pki.py → src/arbiter/pki_risk_scoring/certificates.py
- `test_baseline_false_alarm_rate_is_calibrated()` --calls--> `cell_probabilities()`  [INFERRED]
  tests/test_baseline.py → src/arbiter/qds_simulation/model.py
- `main()` --calls--> `attack_bounds()`  [INFERRED]
  examples/attack_sweep.py → src/arbiter/detection/bounds.py
- `main()` --calls--> `SequentialDetector`  [INFERRED]
  examples/attack_sweep.py → src/arbiter/detection/sequential.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Unified detection pipeline flow** — readme_unified_glrt_detector, readme_sequential_eprocess, readme_chsh_channel_check, readme_audit_ledger [EXTRACTED 1.00]
- **QDS attack fingerprint set** — docs_threat_model_adversaries_in_scope, docs_threat_model_impersonation_all_or_nothing, docs_math_derivations_observation_model [EXTRACTED 1.00]

## Communities (69 total, 10 thin omitted)

### Community 0 - "Dashboard Bundle Symbols"
Cohesion: 0.04
Nodes (84): zy(), _0(), Aa(), af(), am(), An(), ao(), bc() (+76 more)

### Community 1 - "Dashboard Bundle Internals"
Cohesion: 0.06
Nodes (74): Bt(), by(), A(), Dl(), $l(), r(), Sl(), xl() (+66 more)

### Community 2 - "Quantum Info Bounds"
Cohesion: 0.06
Nodes (69): composite, given, settings, attack_bounds(), Information-theoretic limits for each attack, and how close ARBITER's actual…, Teleport single-qubit ``rho_in`` through two-qubit ``resource`` (A|B). Qubit…, teleport(), classical_chernoff() (+61 more)

### Community 3 - "Key Metadata Registry"
Cohesion: 0.05
Nodes (48): KeyMetadata, KeyMetadataRegistry, KeySource, KeyType, datetime, Enum, Path, str (+40 more)

### Community 4 - "Frontend API Types"
Cohesion: 0.07
Nodes (46): api, AttackAccuracy, BoundRow, ComparisonResult, DemoAccuracyCache, DemoCatalog, DemoScenario, DetectorComparison (+38 more)

### Community 5 - "Session Simulation Benchmark"
Cohesion: 0.06
Nodes (57): main(), main(), Benchmark the analytic and Qiskit session paths. The defaults match issue #10:…, run_benchmark(), DriftConfig, _get_visibility_at_round(), Get the true visibility at a specific round, considering drift config., Simulate one session. ``seed`` makes it reproducible; it is mixed with the… (+49 more)

### Community 6 - "CBOM Export"
Cohesion: 0.07
Nodes (50): _algorithm_to_cbom_component(), cbom_to_json(), certificates_to_cbom(), _create_algorithm_component(), _create_certificate_component(), _create_key_component(), _nist_quantum_security_level(), Any (+42 more)

### Community 7 - "Background Jobs Storage"
Cohesion: 0.08
Nodes (24): Connection, dtype, Row, JobRunner, Persistent, in-process background jobs for expensive API work., _array_bytes(), _array_from_bytes(), Any (+16 more)

### Community 8 - "Bundle Fragment Cluster"
Cohesion: 0.13
Nodes (43): ad(), a(), i(), n(), u(), cd(), co(), di() (+35 more)

### Community 9 - "PKI Risk Scoring"
Cohesion: 0.07
Nodes (42): assess_composite_key(), assess_key(), is_composite_oid(), datetime, Enum, Quantum-risk scoring for classical public-key material. For each key we…, Check if an OID is a recognised composite ML-DSA OID., Assess both components; either surviving component protects the hybrid. (+34 more)

### Community 10 - "Bundle Symbol Fragments"
Cohesion: 0.08
Nodes (43): Be(), cr(), ct(), Df(), e0(), Fh(), fr(), ft() (+35 more)

### Community 11 - "Channel Integrity Prechecks"
Cohesion: 0.11
Nodes (21): chsh_precheck(), ChshResult, CHSH Bell-test channel-integrity pre-check. S = E00 + E01 + E10 - E11. Any…, freshness_test(), FreshnessResult, NonceRegistry, Freshness checks. Two layers, catching two different replays: *…, True if the nonce is fresh (and records it); False on reuse. (+13 more)

### Community 12 - "Unified GLRT Detector"
Cohesion: 0.10
Nodes (24): ndarray, Unified multi-hypothesis attack-attribution detector. One test replaces four…, Log-likelihood under H0 at specific visibility v., GLR with visibility as nuisance parameter: max over v in [v_min, v_max].…, Draw calibration counts under H0 (split out for instrumentation)., Draw calibration counts under H0 at specific visibility v., Calibrate threshold for given n at detector's design visibility. If v_min <…, Level-alpha GLR threshold for per-cell round counts ``n``. (+16 more)

### Community 13 - "Qiskit Circuit Library"
Cohesion: 0.15
Nodes (30): QuantumCircuit, chsh_circuit(), ChshSpec, _distribute_bell_pair(), _prepare(), Qiskit circuits realising every round type under every hypothesis. These are…, Circuit for BB84 unambiguous state elimination after teleportation., Alice measures A_a in {Z, X}; Bob measures B_b in {(Z+X)/sqrt2, (Z-X)/sqrt2}. (+22 more)

### Community 14 - "Minified Symbol Shard"
Cohesion: 0.16
Nodes (32): ar(), c(), e(), f(), g(), H(), j(), m() (+24 more)

### Community 15 - "Attack Sweep Harness"
Cohesion: 0.13
Nodes (29): Attack sweep: detection/attribution accuracy, sequential stopping times and…, cq_state(), measured_distribution(), Hypothesis, ndarray, Joint distribution over (cell, outcome) produced by ARBITER's measurements., _attack_cell_probs(), chsh_correlator() (+21 more)

### Community 16 - "Baseline Comparison"
Cohesion: 0.11
Nodes (19): main(), _print_matrix(), Compare ARBITER's unified GLRT with four fixed-threshold rules. python…, balanced_cell_counts(), BaselineDetector, BaselineThresholds, BaselineVerdict, compare_detectors() (+11 more)

### Community 17 - "Frontend Dependencies"
Cohesion: 0.07
Nodes (28): dependencies, react, react-dom, devDependencies, @types/node, @types/react, @types/react-dom, typescript (+20 more)

### Community 18 - "Bundle Fragment Shard A"
Cohesion: 0.11
Nodes (29): a0(), At(), bf(), Bs(), dd(), Dt(), ee(), ef() (+21 more)

### Community 19 - "Bundle Fragment Shard B"
Cohesion: 0.11
Nodes (29): ac(), al(), au(), av(), Bv(), c0(), cv(), ev() (+21 more)

### Community 20 - "Certificate Chain Assessment"
Cohesion: 0.16
Nodes (20): assess_chains(), ChainLinkReport, ChainReport, _extension_key_identifier(), _hash_assessment(), HashAssessment, _issuer_for(), _level_for_score() (+12 more)

### Community 21 - "TLS Scan Guard"
Cohesion: 0.12
Nodes (23): IPv4Address, IPv6Address, _chain_der(), host_is_allowed(), parse_target(), Safe, opt-in TLS certificate scanning for PKI quantum-risk reports. The scanner…, Fetch and score a public TLS endpoint's certificate chain. TLS certificate…, A requested TLS scan could not be completed safely. (+15 more)

### Community 22 - "FastAPI App Wiring"
Cohesion: 0.10
Nodes (15): create_app(), dashboard_dist(), Path, Build the app. ``$ARBITER_NOISE_PRESET`` (a key of ``arbiter.noise.PRESETS``)…, Return the installed dashboard resource directory, with a test override., client(), fixture, slow (+7 more)

### Community 23 - "Bundle Shard Group 23"
Cohesion: 0.11
Nodes (26): ai(), cf(), Cl(), ei(), er(), Il(), Kd(), lf() (+18 more)

### Community 24 - "Bundle Shard Group 24"
Cohesion: 0.12
Nodes (25): Bn(), ec(), gr(), gs(), _h(), he(), hr(), ht() (+17 more)

### Community 25 - "Bundle Shard Group 25"
Cohesion: 0.17
Nodes (25): ca(), Cu(), Et(), Fu(), gf(), id(), Kc(), kh() (+17 more)

### Community 26 - "TypeScript Config"
Cohesion: 0.09
Nodes (22): compilerOptions, isolatedModules, jsx, lib, module, moduleResolution, noEmit, noFallthroughCasesInSwitch (+14 more)

### Community 27 - "Offline Demo Runner"
Cohesion: 0.13
Nodes (20): RuntimeError, _assert_expected(), _at_path(), dashboard_is_offline(), demo_catalog(), DemoCheckError, DemoCheckResult, Any (+12 more)

### Community 28 - "Encrypted Key Storage"
Cohesion: 0.14
Nodes (14): decrypt_keys(), _derive_key(), encrypt_keys(), EncryptedKeys, EncryptedKeyStore, Path, Encrypted key storage for audit ledger. Uses AES-256-GCM with Argon2id key…, Encrypt key material with a passphrase. (+6 more)

### Community 29 - "Ledger Test Suite"
Cohesion: 0.14
Nodes (18): Load keys from encrypted storage., keys(), ledger(), fixture, parametrize, Test encrypted key storage round-trip., Test that wrong passphrase fails to decrypt., Test epoch key rotation with cross-signing. (+10 more)

### Community 30 - "Bundle Symbol Fragment Group"
Cohesion: 0.19
Nodes (22): I(), ay(), dv(), Es(), ey(), g0(), iv(), Ll() (+14 more)

### Community 31 - "X509 Certificate Parsing"
Cohesion: 0.17
Nodes (21): _algorithm_oid(), assess_certificates(), _decode_oid(), _der_tlv(), _key_info(), load_certificates(), _public_key_oid(), datetime (+13 more)

### Community 32 - "Post-Quantum Signatures"
Cohesion: 0.13
Nodes (8): _b64(), _chunks(), _DilithiumPy, HashSignature, _LibOQS, _mldsa_backend(), The two independent post-quantum signatures on every ledger entry. * **ML-…, _unb64()

### Community 33 - "Bundle Fragment Group 33"
Cohesion: 0.19
Nodes (19): $a(), bd(), bi(), de(), ds(), Fa(), fy(), gi() (+11 more)

### Community 34 - "Ledger Core Verification"
Cohesion: 0.20
Nodes (12): canonical(), entry_hash(), Shared utilities for audit ledger., Epoch-based key rotation for audit ledger. Supports cross-signed epoch…, Append-only, hash-chained, dual-signed audit ledger (Crosby & Wallach 2009).…, Demo-only hash-chain rewrite; signatures intentionally remain invalid., Verify the same authenticated epoch chain, with an optional trust anchor., Verify untrusted entries, following only dual-authorised transitions. (+4 more)

### Community 35 - "Trapped-Ion Noise Model"
Cohesion: 0.18
Nodes (8): Trapped-ion noise model -> :class:`ChannelParams`. Every downstream quantity in…, The factors whose product is the link's Werner visibility., TrappedIonParams, Dephase both halves of |Phi+> for time t; the Werner state with the same…, test_gate_error_is_depolarizing_with_matching_average_fidelity(), test_idle_dephasing_factor_matches_twirled_bell_state(), test_invalid_params_rejected(), test_perfect_hardware_gives_perfect_link()

### Community 36 - "QDS Distribution Model"
Cohesion: 0.20
Nodes (17): cell_probabilities(), ChannelParams, expected_chsh(), Per-cell outcome-1 probability when a fraction ``theta`` of rounds are attacked., Calibrated properties of the *legitimate* link. visibility Werner visibility of…, distribute_qds_keys(), Run the QDS distribution stage for both message bits. Alice teleports every…, slow (+9 more)

### Community 37 - "Command Line Interface"
Cohesion: 0.23
Nodes (15): ArgumentParser, Namespace, build_parser(), _demo(), _demo_check(), _demo_environment(), main(), _pki_scan() (+7 more)

### Community 38 - "API Request Models"
Cohesion: 0.17
Nodes (11): BaseModel, ApiPrefixMiddleware, CertificateRequest, JobRequest, KeyRequest, LedgerTamperRequest, FastAPI service: run attack simulations, get verdicts, inspect the ledger. Run…, Let the static dashboard keep its stable ``/api`` development contract.… (+3 more)

### Community 39 - "Epoch Key Management"
Cohesion: 0.17
Nodes (9): EpochKeys, Create epoch 0 (genesis)., Rotate to a new epoch, cross-signed by previous epoch., Keys for a single ledger epoch., Create cross-signature from previous epoch's keys., Verify cross-signature from previous epoch., MLDSA, ML-DSA-65 keypair with a backend-agnostic interface. (+1 more)

### Community 40 - "API Security Middleware"
Cohesion: 0.24
Nodes (9): FastAPI, Request, Optional API-key authentication and small in-process rate limiter., Security, _request(), test_api_key_auth(), test_job_owner_identity_rejects_another_key(), test_rate_limit_has_retry_after() (+1 more)

### Community 41 - "Key Derivation Primitives"
Cohesion: 0.19
Nodes (8): derive_labels(), derive_qds_private_keys(), ndarray, QDSDistribution, PRF (SHAKE-256) -> n uniform Pauli-eigenstate indices in 0..5, by rejection…, Derive the two uniformly random BB84 private keys held by the signer. This is…, Classical record left by distribution of two BB84 quantum public keys.…, test_label_prf_is_deterministic_and_uniform()

### Community 42 - "Ledger Append Rotate"
Cohesion: 0.24
Nodes (6): EpochMetadata, Metadata tracking epoch lifecycle., AuditLedger, Manually trigger a key rotation (for API endpoint). Returns the key_transition…, Rotate to a new epoch, writing a key_transition entry., Reload the untouched persisted JSON-lines ledger for the demo API.

### Community 43 - "Merkle-Lamport Signatures"
Cohesion: 0.30
Nodes (5): _digest_bits(), _h(), MerkleLamport, 2**height one-time Lamport keys, all derived from ``seed``., test_merkle_lamport_roundtrip()

### Community 44 - "Epoch Manager"
Cohesion: 0.18
Nodes (8): EpochManager, Manages epoch transitions and key rotation., Check if HBS usage has exceeded threshold., Get the chain of cross-signatures for verification., Test epoch manager genesis creation., Test that cross-signatures can be verified., test_epoch_cross_signature_verification(), test_epoch_manager_initialization()

### Community 45 - "Ledger Key Persistence"
Cohesion: 0.25
Nodes (5): LedgerKeys, Path, Save keys in plaintext (legacy)., Save keys encrypted with passphrase., Load keys from plaintext (legacy). Args: path: Path to key file…

### Community 46 - "Project Governance Docs"
Cohesion: 0.25
Nodes (8): Attack-model issue proposal template, PR checklist with physics and threat-model gates, v0.1 feature set changelog, Physics-before-code contribution rule, Transcript cell-outcome interface, Six-cell Bernoulli observation model, In-scope adversaries: forgery, impersonation, replay, channel manipulation, ARBITER Unified Attack Attribution System

### Community 47 - "QRNG Nonce Source"
Cohesion: 0.32
Nodes (3): QRNG, Hadamard-measurement QRNG. On a simulator this is only as random as the…, 64 bits of QRNG output, for seeding bulk classical sampling.

### Community 48 - "Ledger Design Rationale"
Cohesion: 0.50
Nodes (4): Audit ledger explainer, SHA3-512 hash chain with ML-DSA and Lamport signatures, Dual-signed hash-chained audit ledger, Ledger key lifecycle and rotation

### Community 49 - "GLRT Design Rationale"
Cohesion: 0.67
Nodes (3): One likelihood model with analytic and Qiskit simulators, Unified GLRT with Monte-Carlo calibration, Unified multi-hypothesis GLRT detector

### Community 50 - "Demo Walkthrough Docs"
Cohesion: 0.67
Nodes (3): Offline five-minute demo walkthrough, React dashboard with SVG charts, FastAPI service with ledger and session store

### Community 51 - "CHSH Design Rationale"
Cohesion: 0.67
Nodes (3): CHSH entanglement explainer, CHSH pre-check with Hoeffding bound, CHSH channel-integrity pre-check

### Community 52 - "Sequential Test Rationale"
Cohesion: 0.67
Nodes (3): Sequential e-values explainer, Sequential test via Ville inequality, Anytime-valid sequential e-process

### Community 53 - "Noise Calibration Rationale"
Cohesion: 0.67
Nodes (3): Trapped-ion error budget to ChannelParams, Trapped-ion presets: state-of-art, prototype, conservative, Legitimate Werner channel with visibility v

### Community 54 - "Quantum Risk Rationale"
Cohesion: 0.67
Nodes (3): Mosca inequality quantum-risk scoring, Shor logical-qubit resource estimates, Composite ML-DSA RSA certificate fixture

## Ambiguous Edges - Review These
- `Bounded orchestrator DAG over swarm topology` → `File ownership matrix for parallel writers`  [AMBIGUOUS]
  docs/OPENCODE_ISSUE_DELIVERY_PLAYBOOK.md · relation: conceptually_related_to

## Knowledge Gaps
- **92 isolated node(s):** `name`, `private`, `version`, `type`, `dev` (+87 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **10 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `Bounded orchestrator DAG over swarm topology` and `File ownership matrix for parallel writers`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **Why does `zy()` connect `Dashboard Bundle Symbols` to `Dashboard Bundle Internals`, `Bundle Fragment Group 33`, `Bundle Fragment Cluster`, `Bundle Symbol Fragments`, `Minified Symbol Shard`, `Bundle Fragment Shard A`, `Bundle Fragment Shard B`, `Bundle Shard Group 23`, `Bundle Shard Group 24`, `Bundle Shard Group 25`, `Bundle Symbol Fragment Group`?**
  _High betweenness centrality (0.091) - this node is a cross-community bridge._
- **Why does `create_app()` connect `FastAPI App Wiring` to `Quantum Info Bounds`, `QDS Distribution Model`, `Session Simulation Benchmark`, `API Request Models`, `Background Jobs Storage`, `API Security Middleware`, `PKI Risk Scoring`, `Ledger Append Rotate`, `Channel Integrity Prechecks`, `Epoch Manager`, `Ledger Key Persistence`, `Command Line Interface`, `Baseline Comparison`, `Certificate Chain Assessment`, `TLS Scan Guard`, `Offline Demo Runner`, `Ledger Test Suite`, `X509 Certificate Parsing`?**
  _High betweenness centrality (0.069) - this node is a cross-community bridge._
- **Why does `assess_certificates()` connect `X509 Certificate Parsing` to `CBOM Export`, `API Request Models`, `PKI Risk Scoring`, `Certificate Chain Assessment`, `TLS Scan Guard`, `FastAPI App Wiring`?**
  _High betweenness centrality (0.037) - this node is a cross-community bridge._
- **Are the 27 inferred relationships involving `zy()` (e.g. with `ai()` and `Bv()`) actually correct?**
  _`zy()` has 27 INFERRED edges - model-reasoned connections that need verification._
- **Are the 35 inferred relationships involving `e()` (e.g. with `$a()` and `a0()`) actually correct?**
  _`e()` has 35 INFERRED edges - model-reasoned connections that need verification._
- **Are the 24 inferred relationships involving `ChannelParams` (e.g. with `BaselineDetector` and `freshness_test()`) actually correct?**
  _`ChannelParams` has 24 INFERRED edges - model-reasoned connections that need verification._