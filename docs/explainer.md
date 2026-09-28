# ARBITER, explained for a judge

This is a speaking guide, not a replacement for the formal model in [math derivations](math-derivations.md). Values below use the default visibility `v=0.92`; they come from `cell_probabilities`, the checked sweep in the README, or a stated formula. We deliberately do **not** claim real-hardware results.

## 1. QDS versus classical and PQC signatures

- **One-sentence answer:** QDS uses quantum states to make a message verifiable; it complements, rather than replaces, classical or post-quantum signatures.
- **Intuition:** A wax seal is useful because copying its appearance is not the same as possessing the seal; a quantum state similarly cannot be copied perfectly.
- **What the code does:** `src/arbiter/qds_simulation/protocol.py:91-139` creates verifier observations; `src/arbiter/audit_ledger/signatures.py:1-170` signs the audit record with ML-DSA and a hash-based scheme.
- **Worked number:** a default legitimate signature-round mismatch probability is `0.040` (`docs/math-derivations.md:45-51`).
- **Follow-up:** “Does this replace ML-DSA?” → No. ML-DSA signs the audit ledger; this simulation studies the QDS detection layer.

## 2. Teleportation, Bell pairs and corrections

- **One-sentence answer:** Teleportation transfers the state’s information using a shared Bell pair and two classical correction bits.
- **Intuition:** The Bell pair is a matched pair of gloves; the measurement tells Bob which way to turn his glove to match Alice’s state.
- **What the code does:** `src/arbiter/qds_simulation/model.py:114-131` implements teleportation; `src/arbiter/qds_simulation/circuits.py:40-101` implements its circuit.
- **Worked number:** ideal teleportation has visibility 1; the default noisy Bell resource has visibility `0.92`, producing a `4%` key-basis mismatch rate.
- **Follow-up:** “Why measure in the key basis?” → It is the measurement that distinguishes the expected Pauli eigenstate from a wrong one.

## 3. Signature, freshness and CHSH rounds

- **One-sentence answer:** Secretly mixing three round types stops one attack from looking harmless everywhere.
- **Intuition:** It is like checking a passport photo, today’s date, and a live liveness test rather than checking only a name.
- **What the code does:** `src/arbiter/qds_simulation/protocol.py:31-35,119-122` schedules the three types; `src/arbiter/qds_simulation/model.py:23-30` defines the six observation cells.
- **Worked number:** the default mix is `50%` signature, `25%` freshness and `25%` CHSH rounds.
- **Follow-up:** “Why keep the mix secret?” → An attacker cannot safely target only the kind of round that would expose them least.

## 4. Attack fingerprints

- **One-sentence answer:** Each modeled attack changes a different combination of signature errors, freshness errors, and Bell correlations.
- **Intuition:** A diagnosis uses a pattern of symptoms, not one thermometer reading.
- **What the code does:** `src/arbiter/qds_simulation/model.py:112-177` supplies per-cell probabilities; `docs/threat-model.md:24-31` states adversary capabilities.
- **Worked number:** at full strength forgery makes signature mismatch `0.500` while freshness remains `0.040`; replay makes freshness mismatch `0.500` (`docs/math-derivations.md:45-51`).
- **Follow-up:** “Why not just raise an alarm?” → The joint pattern is what lets ARBITER name the likely attack.

## 5. CHSH and entanglement

- **One-sentence answer:** A CHSH score above 2 is evidence of Bell correlations that a classical intercept-resend attack cannot reproduce.
- **Intuition:** Two separated dice can coordinate only so well without a shared quantum resource.
- **What the code does:** `src/arbiter/detection/chsh.py:1-91` estimates and checks `S`; `src/arbiter/qds_simulation/circuits.py:104-144` builds CHSH circuits.
- **Worked number:** `S=2√2v`, so at `v=0.92`, expected `S≈2.60`, above the classical bound `2`.
- **Follow-up:** “Is every S below 2 an attack?” → It is a channel-integrity alarm in this model; hardware calibration and finite-sample uncertainty still matter.

## 6. False alarms, misses and one joint test

- **One-sentence answer:** A false alarm rejects an honest session; a miss accepts an attack, and α sets the tolerated false-alarm probability.
- **Intuition:** A smoke alarm tuned too sensitively wakes everyone; too loosely it misses fires.
- **What the code does:** `src/arbiter/detection/unified.py:35-150` calibrates one GLRT threshold for the union of attacks.
- **Worked number:** default `α=0.01`; the README’s 1,000-session comparison observed `0.007` unified false alarms.
- **Follow-up:** “Why not four thresholds?” → Four isolated alarms lose the joint fingerprint and need error-budget bookkeeping; ARBITER calibrates one combined test.

## 7. GLRT and attack strength θ

- **One-sentence answer:** The GLRT asks which allowed attack pattern best explains all the observed cells, while θ is the attacked fraction of rounds.
- **Intuition:** It is a contest between several explanations for the same evidence, not a vote on one symptom.
- **What the code does:** `src/arbiter/detection/unified.py:37-49,101-150` enumerates hypotheses and θ values and calibrates the threshold conditional on the round counts.
- **Worked number:** θ is searched on 20 points from `0.05` to `1.00`; at θ=`0.1`, the README reports forgery detection `0.986`.
- **Follow-up:** “Is it universally optimal?” → No. The likelihood-ratio claim is relative to the stated model; the composite GLRT is not claimed uniformly most powerful.

## 8. Sequential e-values

- **One-sentence answer:** An e-value lets us look after every round without quietly increasing the stated false-alarm rate.
- **Intuition:** It is a pre-agreed evidence account: one may check its balance often, but it only trips at a fixed threshold.
- **What the code does:** `src/arbiter/detection/sequential.py:56-105` updates likelihood-ratio mixtures and stops when `E ≥ 1/α`.
- **Worked number:** with α=`0.01`, the alarm threshold is `1/α=100`; the README reports median full-strength forgery alarm at 13 rounds.
- **Follow-up:** “Why can we stop early?” → Ville’s inequality controls the chance that an honest-session e-process ever crosses that boundary.

## 9. Helstrom, Chernoff and efficiency

- **One-sentence answer:** Helstrom and quantum Chernoff bounds say what any measurement could achieve; ARBITER reports how close its chosen measurements get.
- **Intuition:** They are a speed limit, while detector efficiency says how much of that limit our route uses.
- **What the code does:** `src/arbiter/detection/bounds.py:1-181` computes quantum and measured exponents; `src/arbiter/quantum/info.py:1-170` contains the state-distance tools.
- **Worked number:** forgery measurement efficiency is `1.00`; replay is `0.49` in the checked default table in `README.md`.
- **Follow-up:** “Does 1.00 mean the system is perfect?” → No. It means the specified Pauli measurement is optimal for this modeled forgery discrimination task.

## 10. Why impersonation is all-or-nothing

- **One-sentence answer:** A partial impersonator is observationally the same kind of depolarization as channel manipulation, so the model assigns partial cases to channel manipulation.
- **Intuition:** If two causes leave exactly the same footprints, a fair detector must not pretend it can name one uniquely.
- **What the code does:** `src/arbiter/qds_simulation/model.py:17-22,112-177` enforces all-or-nothing hypotheses; `docs/threat-model.md:34-37` explains the identifiability result.
- **Worked number:** a partial substitution fraction θ is equivalent to intercept-resend at `1.5θ` for these observables.
- **Follow-up:** “Is that a limitation?” → Yes, and it is stated openly; distinguishing them needs extra observables or protocol rounds.

## 11. The audit ledger

- **One-sentence answer:** The ledger is a tamper-evident signed history, not a public blockchain.
- **Intuition:** Each page includes the fingerprint of the previous page and two independent seals; replacing a page exposes the break.
- **What the code does:** `src/arbiter/audit_ledger/ledger.py:1-183` chains and verifies entries; `src/arbiter/audit_ledger/signatures.py:1-170` provides ML-DSA and Merkle-Lamport signatures.
- **Worked number:** SHA3-512 gives a 512-bit hash output; the default Merkle-Lamport tree has height 10, supporting 1,024 signed entries.
- **Follow-up:** “Is a local hash chain a blockchain?” → No. It is local tamper evidence; external anchoring is separate future work.

## 12. Trapped-ion noise budget

- **One-sentence answer:** Hardware error sources are translated into an effective Bell visibility that the detector can use.
- **Intuition:** A recipe combines small losses from ingredients into the expected quality of the finished dish.
- **What the code does:** `src/arbiter/noise/trapped_ion.py:1-230` derives channel parameters; `docs/ion-trap-noise-model.md` states assumptions and presets.
- **Worked number:** the baseline detector model uses visibility `0.92`, hence expected legitimate CHSH `≈2.60`.
- **Follow-up:** “Is this calibrated to a customer device?” → No; it is a published-figure model until hardware data is supplied and reviewed.

## 13. PKI quantum risk

- **One-sentence answer:** PKI scoring estimates whether classical keys and certificates will outlive a cryptographically relevant quantum computer.
- **Intuition:** Mosca’s inequality asks whether a lock must protect a document longer than the time needed to replace the lock and break it.
- **What the code does:** `src/arbiter/pki_risk_scoring/scoring.py:1-240` estimates Shor resources and Mosca risk; `src/arbiter/pki_risk_scoring/certificates.py:1-150` parses certificates.
- **Worked number:** the API test scores RSA-2048 at `4,099` logical qubits (`tests/test_api.py:83-91`).
- **Follow-up:** “Does that predict a date?” → No. It is a transparent planning estimate with explicit assumptions, not a promise about a future machine.

## 14. What ARBITER does not claim

- **One-sentence answer:** ARBITER is a simulation-based detector for explicit i.i.d. attack models, not a proof of a deployed QDS system’s security.
- **Intuition:** A flight simulator can rigorously test a design without claiming the aircraft has flown in every storm.
- **What the code does:** `docs/threat-model.md:53-77` names excluded attacks; `README.md` “Honest scope” repeats the deployment limits.
- **Worked number:** default simulated sessions use 1,200 rounds (`src/arbiter/qds_simulation/protocol.py:38-41`), not device measurements.
- **Follow-up:** “What next?” → Hardware calibration, richer noise, adaptive-attack robustness and independently reviewed real-device results.

## Team self-test

Answer aloud before opening the details. These are prompts for team review; no review is claimed by this document.

<details><summary>1. What is the project’s single-sentence purpose?</summary>Attribute modeled QDS attacks with one calibrated statistical detector and keep an auditable verdict history.</details>
<details><summary>2. Does QDS replace ML-DSA?</summary>No. QDS is the simulated protocol layer; ML-DSA signs ledger entries.</details>
<details><summary>3. What does teleportation need?</summary>A Bell pair, a Bell measurement, two classical bits and the matching Pauli correction.</details>
<details><summary>4. Why are there three round types?</summary>They expose different attack footprints: key knowledge, freshness and entanglement.</details>
<details><summary>5. What changes under forgery?</summary>Signature mismatch rises to one half while freshness and CHSH stay legitimate in the model.</details>
<details><summary>6. What is the CHSH classical bound?</summary>2.</details>
<details><summary>7. What is expected S at v=0.92?</summary>About 2.60.</details>
<details><summary>8. What is a false alarm?</summary>Rejecting a legitimate session.</details>
<details><summary>9. What does α=0.01 control?</summary>The modeled false-alarm probability.</details>
<details><summary>10. Why one joint detector?</summary>The joint pattern supports both detection and attribution without four independent alarm rules.</details>
<details><summary>11. What does θ mean?</summary>The fraction of attacked rounds, except all-or-nothing impersonation.</details>
<details><summary>12. Why can the sequential test look repeatedly?</summary>Its likelihood-ratio mixture is an e-process controlled by Ville’s inequality.</details>
<details><summary>13. What is the sequential alarm boundary at α=0.01?</summary>100.</details>
<details><summary>14. What does efficiency 1.00 for forgery mean?</summary>The chosen measurement reaches the quantum Chernoff exponent for that modeled discrimination, not that all security is perfect.</details>
<details><summary>15. Why is partial impersonation not named separately?</summary>With these observations it is indistinguishable from an appropriate amount of channel depolarization.</details>
<details><summary>16. Is the ledger a blockchain?</summary>No; it is a local, dual-signed hash chain.</details>
<details><summary>17. Why two ledger signature schemes?</summary>They rely on different post-quantum assumptions and strengthen tamper evidence together.</details>
<details><summary>18. What does trapped-ion noise become in the model?</summary>An effective channel/Bell visibility and related error probabilities.</details>
<details><summary>19. What does PKI scoring estimate?</summary>Quantum migration urgency from key algorithms, sizes and protection lifetime assumptions.</details>
<details><summary>20. What is the most important honest limitation?</summary>No result here is a real-hardware deployment claim; guarantees are conditional on the stated simulation model.</details>
