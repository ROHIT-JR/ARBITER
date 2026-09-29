# ARBITER Pitch Deck Outline

**5 minutes, 12 slides | F0rg3d (SIH26-A0H-T043) | Smart India Hackathon 2026, PS 26141**

---

## Slide 1: Title (0:30)
**ARBITER** — Unified attack attribution for Quantum Digital Signatures  
F0rg3d | SIH26-A0H-T043 | Egreen Quanta

---

## Slide 2: Problem (0:35)
How do you know a quantum digital signature is not forged?  
Standard QDS: four hand-tuned thresholds (slow, isolated, error-prone).  
**Why it matters:** PS 26141 requires threat detection; Egreen Quanta needs fast, auditable detection.

---

## Slide 3: Our Idea (0:30)
**Unified GLRT, not four thresholds.**  
One generalized likelihood-ratio test over all five hypotheses.  
Output: (1) Attack name (2) Attack strength θ  
Neyman–Pearson optimal.

---

## Slide 4: How It Works (0:40)
1. Alice and Bob share ONE Bell pair
2. Alice teleports signature via TWO classical bits
3. Bob measures in ONE of THREE hidden round types: signature (50%), freshness (25%), CHSH (25%)
4. GLRT updates likelihood ratios after each round
5. When e-value ≥ 1/α: alarm and name the attack
6. Verdict logged to dual-signed, tamper-evident ledger

---

## Slide 5: Fingerprints (0:30)
Each attack hits a unique pattern:  
Legitimate: 4% sig, 4% fresh, S ≈ 2.60  
Forgery: 50% sig, 4% fresh, S ≈ 2.60  
Impersonation: 50% sig, 50% fresh, S ≈ 2.00  
Replay: 4% sig, 50% fresh, S ≈ 2.60  
Channel: 4% sig, 4% fresh, S ≈ 1.50  
**GLRT looks at all three at once.**

---

## Slide 6: Results (0:40)
**99–100% accuracy** (full-strength attacks)  
**1% false-alarm rate** (α = 0.01)  
**No misattribution** (perfectly diagonal confusion matrix)

200 sessions, 1200 rounds per session, visibility = 0.92  
Reproducible: `python examples/attack_sweep.py --sessions 200`

---

## Slide 7: Speed (0:35)
**Median alarm times:**
- Impersonation: 7 rounds
- Forgery: 13 rounds
- Channel: 13 rounds

E-values (Ville's inequality) enable anytime-valid stopping.  
Orders of magnitude faster than classical detectors.

---

## Slide 8: Optimality (0:35)
**Helstrom-optimal measurements** (for forgery & impersonation)  
Efficiency = measured error / Helstrom bound

- Forgery: 1.00 ← Optimal
- Impersonation: 1.00 ← Optimal
- Replay: 0.49 (room for improvement)
- Channel: 0.29 (room for improvement)

---

## Slide 9: Hardware (0:35)
**Built for Egreen Quanta's trapped-ion processors.**  
Error budget → Bell visibility = 0.92

- MS gate: ~99% fidelity
- Dephasing: 10–100 ms
- Heating: ~10 ions/s
- SPAM: ~1%

One-time per-device calibration.  
Circuits are hardware-ready.

---

## Slide 10: Trust (0:35)
**Dual-signed audit ledger** (non-repudiation)

- ML-DSA-65 (NIST post-quantum, general-purpose)
- Merkle-Lamport (hash-based, ultra-fast, quantum-resistant)

Hash chain ensures tampering is detectable.

---

## Slide 11: Deployment (0:35)
**For Egreen Quanta:**
- Calibration: one parameter (Bell visibility)
- Service: FastAPI + React dashboard
- Audit: dual-signed ledger
- License: Apache-2.0 open source

**Roadmap:** v0.2 (key rotation), v0.3 (coherent errors), v1.0 (real hardware)

---

## Slide 12: Honest Scope (0:35)
**Out of scope:**
- Real hardware results (simulation only)
- Detector blinding, PNS, Trojan-horse, side-channel

**Why:** Auditable science. Explicit about limitations.  
**Next:** Calibration on real Egreen Quanta processors.

