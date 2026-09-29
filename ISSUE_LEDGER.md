# ARBITER Issue Delivery Ledger

**Last Updated:** 2026-09-29
**Remote Main SHA:** `e37e536c18472d6945865317b295eb6eee55b786`
**TL Model:** Nemotron 3 Ultra
**High-Risk Reviewer:** Nemotron 3 Ultra (separate agent instance)
**Implementation Workers:** Muse Spark 1.3 (multi-file), MiMo-V2.6-Flash (bounded), Nemotron 3.5 Lightning (CI/test/docs)
**Max Concurrent Writers:** 3 (expand to 6 after 2 clean waves)

---

## Open Issues Inventory (18 issues)

| # | Title | Priority | Status | Dependencies | Assigned Writer | Reviewer | Branch | PR |
|---|-------|----------|--------|--------------|-----------------|----------|--------|----|
| 15 | Run detector on real IBM Quantum hardware | finale | not_started | #10✓, #24(rec) | Muse Spark 1.3 | Nemotron 3 Ultra (security) | - | - |
| 18 | Plain-language explainer for team | finale | not_started | None | Ling 3.0 Flash Fin | Human (2 team members) | - | - |
| 19 | Update pitch deck + judge Q&A | finale | not_started | #11✓, #15(opt), #17✓, #18 | Ling 3.0 Flash Fin | Human (rehearsals) | - | - |
| 21 | Three-party QDS: repudiation & transferability | science | not_started | #20✓ | Muse Spark 1.3 | Nemotron 3 Ultra (science) | - | - |
| 22 | Compute ε-security bounds (P_forge, P_rep, P_rob) | science | not_started | #20✓, #21 | Muse Spark 1.3 | Nemotron 3 Ultra (science) | - | - |
| 23 | Bell-fidelity rounds & optimized round mix | science | not_started | None | Muse Spark 1.3 | Nemotron 3 Ultra (science) | - | - |
| 24 | Estimate channel visibility (nuisance parameter) | science | not_started | None | Muse Spark 1.3 | Nemotron 3 Ultra (statistics) | - | - |
| 25 | Change-point e-detector for adaptive attacks | science | not_started | None, benefits from #24 | Muse Spark 1.3 | Nemotron 3 Ultra (statistics) | - | - |
| 26 | POVM freshness test (P_con = 2b²) | science | not_started | None | Muse Spark 1.3 | Nemotron 3 Ultra (science) | - | - |
| 27 | Temporal statistics layer (burst/spectral) | science | not_started | None, pairs with #25 | Muse Spark 1.3 | Nemotron 3 Ultra (statistics) | - | - |
| 28 | Richer trapped-ion noise (T₁, over-rotation, crosstalk, Aer) | science | not_started | None | Muse Spark 1.3 | Nemotron 3 Ultra (science) | - | - |
| 29 | Anchor audit ledger externally (OTS/RFC3161) | science | not_started | None, coord with #30✓ | Muse Spark 1.3 | Nemotron 3 Ultra (security) | - | - |
| 31 | Frontend tests: Vitest + Playwright + a11y | production | not_started | #12✓, #13✓, #17✓ | MiMo-V2.6-Flash | Nemotron 3 Ultra (a11y) | - | - |
| 33 | Packaging: Docker, PyPI, v0.1.0, MkDocs | production | not_started | #17✓, finale set | MiMo-V2.6-Flash | Nemotron 3 Ultra (release) | - | - |
| 37 | PKI: CBOM export (CycloneDX 1.6) | post-sih | not_started | #35✓, #36✓ | MiMo-V2.6-Flash | Nemotron 3 Ultra (security) | - | - |
| 38 | PKI: SSH keys & code-signing inventory | post-sih | not_started | #35✓, #34, #37 | MiMo-V2.6-Flash | Nemotron 3 Ultra (security) | - | - |
| 39 | Technical report / arXiv preprint | post-sih | not_started | #11✓, #15, #20✓, #22, #23, #24 | Ling 3.0 Flash Fin | Human (faculty) | - | - |
| 40 | Hardware-calibration import format | post-sih | not_started | #28, #22 | Ling 3.0 Flash Fin | Human (hardware team) | - | - |
| 41 | Project board, milestones, good-first-issues | post-sih | not_started | None (admin) | Human/Admin | Human (admin) | - | - |

---

## Closed Issues (Baseline)
- #10, #11, #12, #13, #14, #16, #17, #20, #30, #32, #34, #35, #36

---

## Execution Waves (Per Playbook)

### Wave 0 — Research/Scaffolding (Parallel, Read-Only)
| Issue | Start | Writer | Required Output Before PR |
|-------|-------|--------|---------------------------|
| #41 | Human first | GitHub Admin | Verify permissions; milestones/project automation |
| #37 | Yes | MiMo-V2.6-Flash | Contract/schema tests; wait for #36 (closed) |
| #38 | Research only | MiMo-V2.6-Flash | Safe fixture/license plan; wait for #37 |
| #31 | Yes | MiMo-V2.6-Flash | Contract inventory for current UI/API behavior |
| #33 | Docker/docs only | MiMo-V2.6-Flash | Docker/MkDocs plan; no tag/PyPI/Pages claim |
| #39 | Scaffold only | Ling 3.0 Flash Fin | Paper outline, figure manifest, seed/command policy |
| #21 | Yes | Muse Spark 1.3 | Multiparty threat model and test matrix |
| #24 | Yes | Muse Spark 1.3 | Null model, drift simulation, empirical test plan |
| #23/#26/#28 | Research only | Muse Spark 1.3 | Paper citations, shared-file change map |

### Wave 1 — Independent Implementation PRs (3 Writers Max)
**Start with this collision-safe triad:**
1. **#31 Frontend Tests** — `frontend/**`, frontend CI portion only
2. **#24 Visibility/Drift** — `src/arbiter/detection/**`, `pipeline.py`, detector tests, API/dashboard contract
3. **#21 Three-party QDS** — `src/arbiter/qds_simulation/**`, `detection/unified.py`, `pipeline.py`, QDS tests, API/dashboard contract

**Note:** #36 and #30 are already merged. #33 holds until #31 releases CI workflow ownership.

### Wave 2 — Serialized Shared-Core Integration
After each merge, rebase downstream branches:
```
#21 → revise #22
#24 → #25 → #27
#28 → #23 and #26 (one at a time)
#30(closed) → #29
#36(closed) → #37 → #38
#24/#28 → #15
#28 + revised #22 → #40
#39 advances with validated results
```

### Wave 3 — External/Human-Gated
| Issue | Code Can Proceed | Human/External Evidence Required |
|-------|------------------|----------------------------------|
| #15 | Hardware adapter, cached replay, Aer equivalence | IBM token, real device dataset, metadata publish permission |
| #18 | Documentation | Two team member reviews + questions |
| #19 | Deck/Q&A assets | Two timed rehearsals, presenters, spoken Q&A practice |
| #29 | Adapter, offline tests | Real OTS/RFC-3161 proofs, external validation |
| #33 | Docker/MkDocs/CI | PyPI trusted publisher, package availability, Pages/release/tag authority |
| #39 | Report + figures | Faculty review, authorship agreement, arXiv submission |
| #40 | Schema, synthetic sample, importer | #28 + revised #22 merged; hardware team review |
| #41 | CONTRIBUTING note | Repo admin: project, milestones, automation, assignments |

---

## File Ownership Matrix (Per Playbook)

| Lane / First PR | Reserved Path Family | Must Not Run With |
|-----------------|---------------------|-------------------|
| #36 PKI (closed) | `src/arbiter/pki_risk_scoring/**`, `tests/test_pki.py` | #37/#38 impl; unrelated API/CI edits |
| #31 Frontend | `frontend/**`, frontend test config, CI frontend portion | #33, #21/#24 dashboard changes |
| #30 Ledger (closed) | `src/arbiter/audit_ledger/**`, `tests/test_ledger.py` | #21/#24 API edits |
| #24 Detector | `src/arbiter/detection/**`, `src/arbiter/pipeline.py`, detector tests, API/dashboard contract | #21, #25, #27, #30 API edits |
| #21 QDS | `src/arbiter/qds_simulation/**`, `src/arbiter/pipeline.py`, QDS tests, API/dashboard contract | #24/#25/#27 or #30 API edits |
| #28/#23/#26 Simulator | Shared: `model.py`, `circuits.py`, `protocol.py` | One another; one at a time |
| #33 Release | Docker/MkDocs/release files, CI after #31 | #31 or other workflow writers |

---

## Model Assignments

| Model | Role | Issues | Do Not Use For |
|-------|------|--------|----------------|
| Nemotron 3 Ultra | TL + High-Risk Reviewer | All (TL), #15, #21, #22, #23, #24, #25, #26, #27, #28, #29 (review) | Repetitive fixture generation |
| Muse Spark 1.3 | Multi-file Feature Writer | #15, #21, #23, #24, #25, #26, #27, #28, #29 | Security/math self-approval |
| MiMo-V2.6-Flash | Bounded Implementation Writer | #31, #33, #37, #38 | Unreviewed merge decisions |
| Nemotron 3.5 Lightning | CI/Test/Docs Throughput | Test writing, CI triage, fixture chores | Deep scientific/crypto decisions |
| Ling 3.0 Flash Fin | Mechanical Chores | #18, #19, #39, #40 (docs/schema/formatting) | Core implementation, scientific claims, security review |
| Human/Admin | Governance | #41 | - |

---

## Per-Issue Acceptance Criteria Summary

### #15 — Hardware Backend
- [ ] Deferred-measurement circuit matches density-matrix model on Aer (|z| < 4.5)
- [ ] ≥1 real-hardware dataset committed with metadata for all 5 scenarios
- [ ] CI runs detector on cached hardware data, asserts correct attribution at θ=1
- [ ] README honestly reports unidentifiable attacks due to noise
- [ ] No tokens/account IDs in repo/history

### #18 — Plain-Language Explainer
- [ ] Every section has 5 parts: answer, intuition, code pointer, our number, follow-up
- [ ] All numbers match current code output
- [ ] Reviewed by ≥2 team members with added questions
- [ ] No equation without plain-English reading

### #19 — Pitch Deck + Q&A
- [ ] Deck runs ≤5:00 in 2 timed rehearsals
- [ ] No slide number contradicts current code output
- [ ] Q&A covers all "we do not claim" items from README
- [ ] Each member answered Q&A aloud once
- [ ] Backup slide with demo video frame

### #21 — Three-Party QDS
- [ ] Without symmetrisation, repudiation succeeds non-negligibly; with it, falls exponentially matching #22 bound
- [ ] Recipient forgery detected and attributed to recipient
- [ ] Honest runs: Bob accepts AND Charlie verifies with prob ≥ 1−ε_rob
- [ ] False-alarm rate ≤ α for honest 3-party sessions
- [ ] Threat model covers dishonest signers/recipients

### #22 — ε-Security Bounds
- [ ] Reproduces ≥1 numeric example from Wallden et al. 2015 (test cites paper)
- [ ] Bounds decrease monotonically in L, increase with noise (property tests)
- [ ] Simulated forgery rate ≤ computed bound (Monte-Carlo)
- [ ] README table regenerated by script

### #23 — Bell-Fidelity Rounds
- [ ] New round type circuits agree with density-matrix model (|z| < 4.5)
- [ ] Measurement efficiency ≥ 0.85 for every attack at chosen mix, or PR explains why impossible
- [ ] Median alarm/attribution rounds no worse for any attack
- [ ] CHSH pre-check still certifies Bell violation at default session length
- [ ] False-alarm rate ≤ α

### #24 — Visibility Estimation
- [ ] Regression demo: calibrated v=0.92, true v=0.88 → current detector FAR > α; new one ≤ α (≥400 sessions)
- [ ] Attack detection power at θ≥0.3 drops <5pp vs known-v detector
- [ ] Sequential test FAR ≤ α under drift
- [ ] v̂ within ±0.02 of truth for 1200-round sessions

### #25 — Change-Point E-Detector
- [ ] Honest sessions: empirical ARL ≥ configured target (1/α sessions' worth)
- [ ] Late-onset attack (t₀=800, θ=1): median detection delay clearly shorter than sequential test
- [ ] \|t̂₀ − t₀\| ≤ 30 rounds median for θ=1
- [ ] Threat model moves adaptive attacks from out-of-scope to partially covered

### #26 — POVM Freshness
- [ ] POVM elements PSD, sum to identity; circuit matches model (|z| < 4.5)
- [ ] Comparison table of exponents/median replay-detection rounds for both options
- [ ] Default set to better option with reason stated
- [ ] Proposal item marked resolved in threat-model.md

### #27 — Temporal Statistics
- [ ] Each temporal test FAR ≤ its α under H0
- [ ] Combined pipeline FAR ≤ overall α
- [ ] Burst attack (60 consecutive attacked rounds in 1200) flagged by burst test more often than pooled GLRT
- [ ] Periodic attack caught by spectral test

### #28 — Richer Trapped-Ion Noise
- [ ] Each Kraus set trace-preserving (Σ K†K = I)
- [ ] With `twirled=True`, all current noise tests and README numbers unchanged
- [ ] Aer runs with `to_aer_noise_model()` match density-matrix model (|z| < 4.5)
- [ ] Docs include twirled vs untwirled detection-rate difference table per preset

### #29 — External Anchoring
- [ ] Rewriting entry before anchor detected by anchor verification, even with re-signed chain (recorded receipts)
- [ ] With anchoring disabled, behavior identical to today
- [ ] ≥1 real OTS proof and ≥1 RFC 3161 token committed as test fixtures
- [ ] No network access in default test suite

### #31 — Frontend Tests
- [ ] Each of 4 v0.1 UI bugs has regression test
- [ ] E2E suite passes CI in <3 minutes
- [ ] axe finds no serious/critical violations
- [ ] Coverage of `src/` ≥70% lines

### #33 — Packaging/Release
- [ ] `docker compose up` works at localhost:8000 (CI builds and curls /health)
- [ ] `pip install arbiter-qds` works from PyPI/TestPyPI in fresh venv
- [ ] Docs site live with API reference and notebook
- [ ] v0.1.0 release exists with notes; CITATION.cff has version/date

### #37 — CBOM Export
- [ ] Output validates against CycloneDX 1.6 schema
- [ ] nistQuantumSecurityLevel correct for RSA, ECC, ML-DSA-65, hybrid
- [ ] Round-trip: every ARBITER risk finding appears in CBOM
- [ ] Docs include example CBOM snippet

### #38 — SSH/Code-Signing Inventory
- [ ] Every listed SSH key type recognized and scored (fixtures, no real keys)
- [ ] SSH host-key scan opt-in, SSRF-guarded, shares code with #34
- [ ] Signer cert extracted and scored from test .p7s and signed PE
- [ ] Mixed inventories produce single combined report

### #39 — Technical Report
- [ ] `make -C paper` builds PDF; every figure from script
- [ ] All numbers reproducible from tagged release
- [ ] Reviewed by ≥1 faculty advisor/academic partner
- [ ] Posted to arXiv (quant-ph); ID in README and CITATION.cff
- [ ] Authorship/acknowledgements agreed; Egreen Quanta credited

### #40 — Calibration Import
- [ ] Schema validates sample file; invalid files rejected with clear error
- [ ] Importer output matches manually constructed TrappedIonParams for sample
- [ ] Collaboration doc reviewed by team before sharing
- [ ] No implication Egreen Quanta provided data until actually done

### #41 — Project Governance
- [ ] Milestones exist; every open issue in exactly one
- [ ] Project board exists with automation
- [ ] ≥5 `good first issue` items with enough context to start
- [ ] Every finale issue has assignee

---

## PR Template (Required for Every PR)

```markdown
## Issue
Closes #<ISSUE>  <!-- or Tracks #<ISSUE> for external gates -->

## Dependencies
- Upstream: #<ISSUE> / <PR URL>; state: merged | active | none
- Base: `main` at `<full SHA>`
- Rebased on: `<full current-main SHA>`

## Scope
- Implemented:
- Deliberately not implemented:
- Compatibility/security/statistical assumptions:

## Acceptance criteria evidence
| Exact criterion | Evidence: test/command/artifact | Result |
|---|---|---|

## Validation
- Exact local commands and results:
- Fixture/data provenance and license:
- Seed/configuration:
- CI run URL and final head SHA:

## Review focus and external gates
- Specialist review required:
- Known risk / missing human or external evidence:
```

---

## Status Definitions
- `not_started` — No work begun
- `active` — Implementation in progress (branch exists, work ongoing)
- `ready_for_review` — PR opened, awaiting independent review
- `blocked_external` — Code complete but waiting for human/external evidence
- `blocked_decision` — Waiting for TL/human decision on approach
- `merged` — PR merged by non-author integrator after green CI + review

---

## Next Actions

1. **Immediate:** Begin Wave 0 research tasks for #21, #24, #31, #37, #39, #23/#26/#28
2. **Wave 1 Launch:** Once Wave 0 outputs ready, launch #31, #24, #21 as first triad
3. **TL Actions:** Monitor CI, enforce file ownership, assign independent reviewers, report status

---

*This ledger is the single source of truth for issue tracking. Update after every significant event (branch created, PR opened, review completed, CI result, merge).*