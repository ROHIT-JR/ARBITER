# ARBITER: Judge Q&A Cheat Sheet

**30+ questions covering physics, statistics, security, blockchain, business, and reality checks.**

---

## Physics

### Q: Why QDS instead of classical PQC?
**A:** QDS is a *complement* to PQC. ML-DSA signs the audit ledger; QDS detects forgery *as it happens*. Together they defend the entire system.
- **Code:** `src/arbiter/qds_simulation/protocol.py:91–139`
- **Reference:** Zeng & Keitel (2002); Wallden et al. (2015)

### Q: Why is CHSH measured?
**A:** CHSH tests entanglement. Classical channels cannot exceed CHSH = 2; honest Bell pairs achieve ~2.60 at visibility 0.92. A low score flags channel compromise.
- **Code:** `src/arbiter/detection/chsh.py:1–91`

### Q: Why is impersonation all-or-nothing?
**A:** Partial impersonation produces the same observable depolarization as channel noise—no detector can tell them apart. ARBITER treats partial impersonation as channel manipulation.
- **Code:** `src/arbiter/qds_simulation/model.py:17–22, 112–177`
- **Reference:** docs/threat-model.md:34–37

---

## Statistics

### Q: Why one test instead of four thresholds?
**A:** Four independent thresholds risk missing combined signals. ARBITER's *GLRT* asks: "Which attack hypothesis best explains all observations *jointly*?" Neyman–Pearson optimal.
- **Code:** `src/arbiter/detection/unified.py:35–150`

### Q: What does θ (attack strength) mean?
**A:** Fraction of rounds attacked. θ = 1 (every round), θ = 0.1 (10%). ARBITER searches over θ to find the maximum-likelihood explanation.
- **Code:** `src/arbiter/detection/unified.py:103`

### Q: Is ARBITER "optimal" in absolute terms?
**A:** No. Neyman–Pearson optimal *within its threat model* (i.i.d. attacks, known visibility). Explicitly does not defend against detector-blinding, PNS, Trojan-horse, side-channel.
- **Reference:** docs/threat-model.md

### Q: Why use e-values for sequential testing?
**A:** E-values allow checking evidence after every round without inflating false-alarm rate. Under Ville's inequality, stopping when E ≥ 1/α maintains α-level guarantees.
- **Code:** `src/arbiter/detection/sequential.py:56–105`

---

## Security & Attacks

### Q: What is the threat model?
**A:** 
| Attack | Sig Error | Fresh Error | CHSH |
|--------|-----------|-------------|------|
| Legitimate | 4% | 4% | 2.60 |
| Forgery | 50% | 4% | 2.60 |
| Impersonation | 50% | 50% | 2.00 |
| Replay | 4% | 50% | 2.60 |
| Channel | 4% | 4% | 1.50 |

Each attack has a unique fingerprint.
- **Code:** `src/arbiter/qds_simulation/model.py:112–177`

### Q: What attacks are out of scope?
**A:** Detector blinding, PNS, Trojan-horse, side-channel. These are named in the threat model with explanations.
- **Reference:** docs/threat-model.md:1–23

---

## Audit & Trust

### Q: Why dual-sign with ML-DSA and Merkle-Lamport?
**A:** ML-DSA-65 (NIST PQ) + Merkle-Lamport (hash-based, QR). Hedges against undiscovered vulnerabilities in either scheme.
- **Reference:** NIST FIPS 204; Merkle (1979)

### Q: Is the ledger a blockchain?
**A:** No. Local (one place), signed (crypto keys), not distributed/peer-verified. Tamper-evident but not tamper-tolerant.

---

## Business & Deployment

### Q: How would Egreen Quanta use this?
**A:** Deploy detector at Bob's station. Trapped-ion noise model means one-time per-device calibration, then no per-session tuning.
- **Code:** `src/arbiter/noise/trapped_ion.py:1–230`

### Q: Can it run on other hardware?
**A:** Yes. Only the noise model changes. Examples exist for IBM, Quantinuum, neutral-atom platforms.

---

## Reality Check

### Q: Is this tested on real hardware?
**A:** Not yet. All results from QisKit Aer simulation. Circuits are hardware-ready but not executed. Explicitly listed in honest-scope.
- **Reference:** docs/README.md:176 ("Simulation only")

### Q: How do I verify the numbers?
**A:** Every number is traceable. Run: `python examples/attack_sweep.py --sessions 200`

### Q: Why should judges care if it is simulated?
**A:** (1) Theory is rigorous, (2) Implementation is complete, (3) Hardware path is clear, (4) Results are reproducible.

---

## Comparison

### Q: How is this different from standard QKD?
**A:** QKD detects/corrects errors. ARBITER names the attack and measures its strength.

### Q: Why not machine learning?
**A:** ML needs training data, hyperparameter tuning. For security: (1) Generalization (v=0.92 vs. v=0.88?), (2) Auditability (judges cannot inspect neural network), (3) Optimality (statistical test has Neyman–Pearson guarantees; ML does not).

---

## Roadmap

### Q: What would you build next?
**A:** (1) Real hardware run (1 month), (2) Ledger key rotation (2–3 weeks), (3) Hybrid certificates (3 weeks), (4) Detector-blinding defense (1 month).

### Q: What does "v0.1" mean?
**A:** ARBITER is a v0.1 prototype. v1.0 includes real hardware calibration.
- **Roadmap:** docs/README.md:190–198

---

## Open Questions

### Q: What if visibility is unknown?
**A:** Future v0.2 will estimate visibility per-session.
- **Roadmap:** docs/README.md:192

### Q: Is "optimal" overclaiming?
**A:** Neyman–Pearson optimal *within the threat model*. Honest-scope is explicit.
- **Reference:** docs/README.md:176–180

