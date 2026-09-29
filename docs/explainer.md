# ARBITER: Plain-Language Guide for Judges and Team

**Read this first.** This is a speaking guide—not a replacement for the formal model in [math-derivations.md](math-derivations.md), but your entry point if you're not steeped in quantum computing.

- Every section follows the same structure: one-sentence answer, intuition, code pointer, worked number from our results, and a likely follow-up.
- Every technical term is defined on first use.
- Values use the default simulated channel visibility `v = 0.92`; they come from `cell_probabilities`, the tables in [README.md](../README.md), or a stated formula.
- We do **not** claim real-hardware results.
- Use the **self-test** at the end to check your understanding.

---

## Part 1: What is ARBITER?

### The Big Picture

ARBITER is a **quantum digital signature (QDS) detector**: it watches a signature protocol run on quantum hardware and raises alarms if someone is forging messages, impersonating a signer, replaying old signatures, or tampering with the quantum channel.

**What makes it special:**
- It doesn't just say "accept" or "reject"—it also names the *likely attack* and its strength.
- It uses a single, mathematically principled test (not four hand-tuned alarm rules).
- It works with an explicit model of quantum states and measurements (not a black-box neural network).
- It records every decision in a tamper-evident, cryptographically signed ledger.

Think of ARBITER as a **fraud detective for quantum messages**: instead of just catching a forged check, it figures out whether the attacker was copying signatures, claiming to be the signer, using old signatures, or tampering with the phone line.

---

## Part 2: Quantum Digital Signatures vs. Classical and Post-Quantum Signatures

### The One-Sentence Answer
QDS uses quantum states to make signatures uncopyable; it complements, rather than replaces, classical or post-quantum signatures like ML-DSA.

### The Intuition

Imagine a wax seal on a letter:
- Copying the seal's appearance is easy—but possessing the *real* seal is the proof.
- A quantum state works similarly: you can't make a perfect copy of it, so it becomes evidence that you had access to the signer's equipment at a specific time.

A classical signature (like RSA) says: "I have a secret key, and only I could have computed this hash."
A quantum signature says: "I created a quantum state and sent it to you; only the signer's device could have made that state, and you can verify it by measuring."

**Together, they're stronger:**
- The audit ledger records each verdict and is signed with **post-quantum ML-DSA-65** (resistant to future quantum computers).
- The QDS layer itself detects live attacks on the *protocol session*, not just certificate forgery.

### What the Code Does

- `src/arbiter/qds_simulation/protocol.py:91-139` runs the verifier's measurement and records what they see.
- `src/arbiter/audit_ledger/signatures.py:1-170` signs each ledger entry with both ML-DSA and a Merkle-Lamport tree signature.
- `src/arbiter/pki_risk_scoring/scoring.py` assesses the quantum-migration risk of the certificates used to set up the channel.

### Worked Numbers

- Default legitimate signature-round **mismatch probability**: `0.040` (4%) when the channel has visibility `v = 0.92`.
- See [docs/math-derivations.md:45-51](math-derivations.md) for the derivation.
- In the 200-session full-strength attack sweep ([README.md](../README.md)), legitimate sessions show a 99% acceptance rate.

### Likely Follow-Up

**"Does this replace ML-DSA?"**

No. ML-DSA signs the *audit history* so that tampering with past verdicts is detectable. This explainer describes the *QDS protocol layer*—the quantum state exchange and verification. Both are needed.

---

## Part 3: The Protocol Flow (Teleportation and Bell Pairs)

### The One-Sentence Answer
The signer creates a quantum state, sends it to the verifier via a **Bell pair** (a shared quantum resource), and the verifier measures it in a secret basis to check the signature.

### The Intuition

Imagine two people have a pair of **magic gloves** that are always coordinated:
1. Alice (the signer) puts her message into her glove by doing a measurement.
2. She sends Bob two classical bits: "I measured in basis 1" and "I got outcome 0."
3. Bob, using his glove and those two bits, performs a **Pauli correction**—a simple rotation that transforms his glove's state into the signed message.
4. Bob then measures his glove in a secret key basis.
5. If he gets the expected outcome, the signature is good; if not, something attacked the channel.

This transfer of quantum information is called **quantum teleportation**. The Bell pair is the "magic glove" that makes it work.

### Technical Terms (First Use)

- **Bell pair**: a quantum state where two qubits are so correlated that measuring one instantly affects what's possible for the other, even if they're far apart. We use the Bell state `|Φ⁺⟩`.
- **Basis**: a choice of how to measure a qubit. There are infinitely many bases; the Pauli bases (X, Y, Z) are convenient.
- **Pauli correction**: a quantum gate (NOT, phase flip, or both) that adjusts the state based on measurement outcomes.
- **Visibility** `v`: a number from 0 to 1 measuring how "clean" the Bell pair is. `v = 1` is perfect; realistic trapped-ion systems have `v ≈ 0.92`.

### What the Code Does

- `src/arbiter/qds_simulation/model.py:114-131` performs the teleportation map.
- `src/arbiter/qds_simulation/circuits.py:40-101` builds the Qiskit circuit that simulates it.
- `src/arbiter/noise/trapped_ion.py` translates hardware error sources into the visibility parameter.

### Worked Numbers

- Ideal (noiseless) teleportation has `v = 1.0` and zero errors.
- Realistic with our default trapped-ion model: `v = 0.92`, producing a **4% legitimate mismatch rate** in signature measurements.
- See [docs/ion-trap-noise-model.md](ion-trap-noise-model.md) for how gate errors, dephasing, and heating combine into visibility.

### Protocol Flow Diagram

```
                    ALICE (Signer)              |              BOB (Verifier)
                                                |
[1] State creation                              |
    "I have message M"                          |
            |                                   |
            v                                   |
    Prepare state |ψ_M⟩                         |
                                                |
[2] Teleportation                               |
    Measure |ψ_M⟩ + Bell pair                   |
    Get two classical bits: a, b                |
                                                |
    Send (a, b, signature) =================>   |  Receive (a, b, signature)
                                                |
                                                v
                                        [3] Correction
                                        Apply Pauli(a,b)
                                        to my half of Bell pair
                                        State is now (ideally) |ψ_M⟩
                                                |
                                                v
                                        [4] Verification
                                        Measure in secret key basis k
                                        Expected outcome: k(M)
                                                |
                                                v
                                        [5] Decision
                                        Outcome = k(M) ? ACCEPT : REJECT
```

### Likely Follow-Up

**"Why measure in the key basis?"**

The key basis determines what we're checking. If the message was prepared in a known state, measuring in the *key basis* gives us the right answer only if the state arrived intact. A wrong basis gives a random result—so adversaries have to guess it, and wrong guesses expose the attack.

---

## Part 4: Three Round Types and the Mixed Strategy

### The One-Sentence Answer
ARBITER secretly mixes three kinds of rounds—**signature**, **freshness**, and **CHSH**—so no single attack can look harmless everywhere.

### The Intuition

A passport officer doesn't just check your name, your photo, *or* your expiration date—they check all three. An attacker who only forges names but leaves expiration dates alone is caught by the third check.

Similarly:
- **Signature rounds** ask: "Do you have the right quantum state?"
- **Freshness rounds** ask: "Is this a new state, not an old one replayed?"
- **CHSH rounds** ask: "Did the quantum channel survive intact? Do the Bell correlations prove it wasn't a classical intercept-resend?"

No attacker can pass all three without being strong, and the verifier switches between them in a *secret pattern* so the attacker can't prepare just one attack type.

### What the Code Does

- `src/arbiter/qds_simulation/protocol.py:31-35` defines the three round types.
- `src/arbiter/qds_simulation/protocol.py:119-122` schedules them in secret.
- `src/arbiter/qds_simulation/model.py:23-30` defines the six possible measurements (2 signature bases × 3 round types = 6 cells).

### Worked Numbers

- Default mix: **50% signature, 25% freshness, 25% CHSH** rounds.
- 1,200 rounds per session means roughly 600 signature, 300 freshness, 300 CHSH.
- The mix is determined by a QRNG seed known only to the verifier.

### Round Types in Detail

| Round Type | What it checks | Attack exposed if adversary... | Example cell |
|---|---|---|---|
| **Signature** | Is the quantum state the right message? | Can't produce the exact state | bit mismatch goes from 4% to 50% |
| **Freshness** | Is this a *new* state, not an old one from a past session? | Replays old states | error rate jumps from 4% to 50% |
| **CHSH** | Did the Bell pair survive? Is entanglement present? | Uses intercept-resend (classical-only) attack | Bell correlation S stays at ~2.6, drops below 2 for classical |

### Block Diagram: Round Scheduling

```
Verifier's QRNG seed
        |
        v
    Round schedule [S, F, C, S, F, S, C, S, F, ...]
        |
    (Kept secret until ledger entry is sealed)
        |
        v
    For each round i:
        |
        +-> Type? Signature, Freshness, or CHSH
        +-> Measurement basis?
        +-> Threshold for alarm?
        |
        v
    Record all observables
    Update joint likelihood
```

### Likely Follow-Ups

**"Why keep the mix secret?"**

An attacker who knows the schedule could prepare attacks that pass only the signature rounds (which won't be checked much) and fail the others—but hope the others aren't picked. By keeping the schedule secret, we force the attacker to pass *all* attacks simultaneously.

**"What if the schedule is exposed later?"**

The sequence is recorded in the final ledger entry, which is hashed and signed. Changing the sequence retroactively would break the hash chain, making tampering obvious.

---

## Part 5: The Five Attack Types and Their Fingerprints

### The One-Sentence Answer
Each attack leaves a distinct pattern of errors across the three round types; ARBITER diagnoses the attack by matching the observed pattern to the best model.

### The Intuition

A doctor diagnoses illness by a *pattern of symptoms*, not one reading:
- High fever + cough + throat pain → likely strep throat.
- High fever + chest pain + shortness of breath → likely pneumonia.

Similarly, each attack produces a recognizable error *profile*:
- **Forgery**: "I'll create a fake state without access to the signer's key" → fails signature rounds.
- **Impersonation**: "I'll replace the signer entirely" → fails freshness (can't match new states) and signature.
- **Replay**: "I'll re-use an old, valid signature" → fails freshness rounds (nonce checking).
- **Channel manipulation**: "I'll intercept and re-send the state" → fails CHSH (drops entanglement).

### Attack Fingerprints Table

| Attack | What adversary does | Signature errors | Freshness errors | CHSH S | Model file |
|---|---|---|---|---|---|
| **None (legit)** | Honest operation | 4% | 4% | ~2.60 | — |
| **Forgery** | Creates fake state without signer key | **50%** | 4% | ~2.60 | `model.py:112-123` |
| **Impersonation** | Replaces signer entirely | **50%** | **50%** | ~2.60 | `model.py:124-135` |
| **Replay** | Reuses old, valid state | 4% | **50%** | ~2.60 | `model.py:136-147` |
| **Channel manip.** | Intercepts state, re-sends classically | 4% | 4% | **< 2.00** | `model.py:148-177` |

### What the Code Does

- `src/arbiter/qds_simulation/model.py:112-177` specifies per-cell error probabilities for each attack.
- `src/arbiter/detection/unified.py:37-49` enumerates all hypotheses (legitimate + 4 attacks × 20 strength levels).
- `tests/test_fixture_verification.py` validates that simulated outcomes match the model predictions.

### Worked Numbers (from 200-session sweep with θ = 1.0, v = 0.92)

- **Forgery detection rate**: 100%; false attribution rate: 0%.
- **Impersonation detection rate**: 100%; false attribution: 0%.
- **Replay detection rate**: 100%; false attribution: 0%.
- **Channel manipulation detection rate**: 100%; false attribution: 0%.
- **Legitimate false-alarm rate**: ~1-2% (expected under α = 0.01).

See [README.md](../README.md) for the full confusion matrix.

### Likely Follow-Up

**"Why not just raise an alarm?"**

Because *naming* the attack lets the system respond appropriately:
- Forgery → revoke the signer's credentials.
- Impersonation → rotate the entire signer setup.
- Replay → check for message reuse.
- Channel manipulation → check hardware calibration.

A generic "alarm" is less actionable.

---

## Part 6: Hypothesis Testing and the Likelihood Ratio

### The One-Sentence Answer
A likelihood ratio compares how well each attack model explains the observed errors; the best match wins.

### The Intuition

Imagine you're a detective with five suspects and one crime scene. You test each suspect's fingerprints:
- Suspect A: 98% match.
- Suspect B: 2% match.
- Suspect C: 1% match.
- Etc.

The suspect with the highest match score is the most likely culprit. A **likelihood ratio** does the same for attacks: it calculates how probable the observed errors are *under each hypothesis*.

- **Hypothesis H₀**: The session is legitimate.
- **Hypothesis H₁**: Someone is forging (at strength θ).
- **Hypothesis H₂**: Someone is impersonating (at strength θ).
- Etc.

For each hypothesis, we compute: **"How likely would these observed errors be if this hypothesis were true?"**

The ratio of two likelihoods tells us which is more probable.

### Technical Terms

- **Likelihood function L(H | data)**: The probability of observing the data *if* hypothesis H is true.
- **Generalized Likelihood Ratio Test (GLRT)**: A method that compares the likelihoods of multiple hypotheses at once.
- **Neyman–Pearson lemma**: A mathematical result saying that if you want to catch an attack with the fewest false alarms, comparing likelihoods is optimal.
- **Threshold τ**: A cutoff value; if `L(attack) / L(legit) > τ`, we reject the session.

### What the Code Does

- `src/arbiter/detection/unified.py:37-49` sets up all hypotheses.
- `src/arbiter/detection/unified.py:101-150` computes likelihood ratios for all hypotheses and finds the best one.
- `src/arbiter/detection/unified.py:60-99` calibrates the threshold τ so that false alarms happen at the target rate α.

### Worked Numbers

- **α = 0.01**: We tolerate a 1% false-alarm rate (rejecting innocent sessions).
- In 1,000-session experiments (α = 0.01), observed false-alarm rate: **0.007** (0.7%)—better than promised.
- Threshold τ is computed per session based on its round counts and the background visibility.

### Why One Test Beats Four

| Approach | False-alarm control | Can name attack? | Notes |
|---|---|---|---|
| **Four independent alarms** | Bonferroni: α/4 per alarm; hard to tune fairly | No; just says "alarm" | Higher total error rate for same α |
| **ARBITER's joint test** | One α for all five hypotheses | Yes | Captures the correlations between error types |

### Likely Follow-Ups

**"What is θ?"**

Attack strength—the fraction of rounds the attacker controls. θ = 1 means all rounds are attacked; θ = 0.1 means 10% are attacked and 90% are honest. ARBITER searches over 20 values from 0.05 to 1.0 and picks the one with the highest likelihood.

**"Is it always right?"**

No. The detector is optimal *within the stated model*—that is, if the assumptions about per-cell error probabilities are correct. If the real channel behaves differently or the attacker uses a method not modeled, the detector's performance may differ. See "What ARBITER Does Not Claim" below.

---

## Part 7: Sequential Testing and Early Stopping

### The One-Sentence Answer
Instead of waiting for all 1,200 rounds, we check the likelihood ratio after each round and can stop early if the evidence is overwhelming—without cheating on our false-alarm rate.

### The Intuition

Imagine a poll that asks voters one at a time: "Do you support candidate A?"
- If after 100 voters, A has 98% support, you might stop early and declare them the winner.
- But if you keep peeking at partial results, you might accidentally declare victory too soon due to noise.
- An **e-process** is a bookkeeping trick that lets you peek as often as you want, as long as you agree on the final threshold *in advance*.

### Technical Terms

- **Sequential test**: A test that can stop after any number of samples, not just a fixed count.
- **E-value (evidence process)**: A running product of likelihood ratios designed so that it never crosses a threshold by accident.
- **Ville's inequality**: A mathematical result that guarantees: if you set a threshold 1/α and check it after every step, an honest session will cross it with probability at most α.

### What the Code Does

- `src/arbiter/detection/sequential.py:56-105` updates the e-value after each round.
- `src/arbiter/detection/sequential.py:1-55` initializes the mixture over attack strengths θ.
- The pipeline stops as soon as `E ≥ 1/α` or after 1,200 rounds, whichever comes first.

### Worked Numbers

- **Threshold**: At α = 0.01, we stop when `E ≥ 100`.
- **Full-strength forgery**: median alarm in **13 rounds** (out of 1,200 possible).
- **Full-strength impersonation**: median alarm in **7 rounds**.
- **Weak attack (θ = 0.1)**: may need more rounds; detection still >98%.

See the "alarm" column in [README.md](../README.md) for all attack types.

### Why This Works

1. **No peeking penalty**: Classical hypothesis testing penalizes you heavily for each peek (Bonferroni). E-processes don't.
2. **Always-valid**: The false-alarm rate stays at α no matter how many times you look.
3. **Safe stopping**: You can't fool the test by stopping early on a lucky streak.

### Likely Follow-Up

**"Can we set α differently per attack?"**

Yes, but it's more complex. ARBITER uses the same α for all five hypotheses (legit + 4 attacks) to keep the joint false-alarm rate controlled. You *could* allocate the error budget differently, but that's future work.

---

## Part 8: The CHSH Bell Test and Entanglement

### The One-Sentence Answer
The CHSH test (Clauser, Horne, Shimony, Holt) measures how "Bell-correlated" two qubits are; a classical intercept-resend attack can't exceed a score of 2, but an honest Bell pair scores ~2.6.

### The Intuition

Imagine two separated die rollers, Alice and Bob, who have a secret signal:
- **No signal (classical)**: They can coordinate at most so well. Over many rolls, their correlation score maxes out at 2.
- **Quantum signal (Bell pair)**: They can coordinate *better* than classically possible. The max is 2√2 ≈ 2.828.
- **Channel attack (intercept-resend)**: An attacker who captures the quantum state and re-sends a classical guess is just like two classical die rollers—score caps at 2.

A CHSH score of 2.60 (at visibility 0.92) strongly suggests a *real* Bell pair made it through, not a classical substitute.

### Technical Terms

- **CHSH inequality**: A mathematical inequality proven by Clauser et al. (1969) showing that quantum systems can violate it, but classical ones can't.
- **Bell violation**: A CHSH score above 2; evidence of entanglement.
- **Visibility**: How much of the ideal Bell-pair performance you actually achieve. `v = 1` gives S = 2√2 ≈ 2.828; `v = 0.92` gives `S ≈ 2.60`.

### What the Code Does

- `src/arbiter/qds_simulation/circuits.py:104-144` builds the CHSH test circuit.
- `src/arbiter/detection/chsh.py:1-91` estimates S and flags if S < 2 (no entanglement or strong noise).
- `src/arbiter/noise/trapped_ion.py` translates hardware errors into the visibility that determines S.

### Worked Numbers

**Expected CHSH score at visibility v = 0.92:**
```
S = 2√2 × v = 2.828 × 0.92 ≈ 2.60
```

- **Honest channel**: S ≈ 2.60 (well above the classical limit 2).
- **Intercept-resend attack**: Attacker measures and re-sends a classical guess → S ≈ 2 or lower.
- **Channel degradation (noise)**: S slightly lower, but still > 2 for honest sessions.

### CHSH Measurement Bases

ARBITER uses two measurement bases per qubit:
- Qubit A: basis 0 or basis 1 (basis angle = 0° or 22.5°).
- Qubit B: basis 0 or basis 1 (basis angle = 22.5° or 67.5°).

This gives four observable combinations. A classical strategy can coordinate to pass at most 3 of them on average; a quantum Bell pair can pass all 4 more often.

### Diagram: CHSH Measurement Outcomes

```
                       Alice                      Bob
                       (measures qubit A)         (measures qubit B)

                    Basis 0 | Basis 1          Basis 0 | Basis 1
                      0°    | 22.5°             22.5°  | 67.5°
                    --------|--------         --------|--------
Outcome +1           55%     | 85%              75%    | 20%
Outcome -1           45%     | 15%              25%    | 80%

Expected correlation:
classical:  E[A·B] ≤ 2  (four measurements, max 2 can be +1 together)
quantum:    E[A·B] ≤ 2√2 ≈ 2.828
```

### Likely Follow-Up

**"Is every S below 2 an attack?"**

Not automatically. A low S *could* mean:
- An attack (intercept-resend).
- Hardware degradation (low visibility).
- Statistical noise in a finite sample.

ARBITER flags low S as a channel-integrity alarm and counts it as evidence of channel manipulation. Real hardware would need calibration runs to distinguish genuine degradation from attacks.

---

## Part 9: Attack Strength θ and Partial Attacks

### The One-Sentence Answer
θ is the fraction of rounds the attacker controls; we search over θ = 0.05, 0.10, ..., 1.00 to find the strongest likelihood match.

### The Intuition

Imagine a factory quality-control inspector who finds defects:
- If 100% of widgets are defective, the supplier has a systemic problem (θ = 1.0).
- If 10% are defective, it's a minor glitch or a small attacker (θ = 0.1).
- If 1% are defective, it's almost working correctly (θ = 0.01).

The inspector estimates θ to decide whether to shut down production, request quality review, or accept the batch.

Similarly, ARBITER estimates θ to judge attack severity:
- θ = 1.0: Full-strength attack on every round.
- θ = 0.3: Attacker controls ~30% of rounds; honest channel runs the rest.
- θ = 0.1: Weak attack; mostly honest operation.

### What the Code Does

- `src/arbiter/detection/unified.py:37-49` sets up θ values from 0.05 to 1.00 (20 points).
- `src/arbiter/detection/unified.py:101-150` computes the best-fit θ for each attack hypothesis.
- `examples/attack_sweep.py:1-150` sweeps θ and reports detection rates.

### Worked Numbers

| θ | Forgery detection | Impersonation | Replay | Channel manip. |
|---|---|---|---|---|
| **1.0** | 1.00 | 1.00 | 1.00 | 1.00 |
| **0.3** | 1.00 | 1.00 | 0.999 | 1.00 |
| **0.1** | 0.986 | 1.00 | 0.868 | 0.959 |

At θ = 0.1, 90% of rounds are honest and only 10% are attacked; detection rates are still high for most attacks.

### Special Case: Impersonation is All-or-Nothing

Impersonation (replacing the signer entirely) cannot be done partially in our model. If the attacker controls *some* rounds, they either:
- Successfully replace the signer (θ = 1).
- Fail to impersonate and look like a channel attack instead (θ = 0).

This is because partial impersonation would produce the *exact same error pattern* as a partial channel attack—and no detector can distinguish causes with identical fingerprints.

See **Part 10** below for details.

### Likely Follow-Up

**"How do we know the real θ?"**

We don't, from data alone. What we report is: "The observed error pattern is most consistent with [attack type] at strength θ = [estimated value]." This is a *likelihood estimate*, not a certainty. If the true attack differs from our model, θ will be misestimated.

---

## Part 10: Why Impersonation is All-or-Nothing

### The One-Sentence Answer
Partial impersonation leaves the same error footprint as partial channel manipulation; ARBITER cannot distinguish them and therefore models impersonation as all-or-nothing.

### The Intuition

Two diseases can have identical symptoms even if the causes are different:
- Cold: sniffling, fever, cough.
- Flu: sniffling, fever, cough.

A doctor with only a thermometer and stethoscope cannot tell them apart. If you insist on naming one, you'll be wrong half the time.

Similarly:
- **Partial impersonation**: Attacker replaces the signer for some rounds → state is random → specific error rate.
- **Partial channel manipulation**: Attacker intercepts and re-sends a depolarized state → state is random → *same* error rate.

With the Pauli measurements we have, they're indistinguishable.

### The Math (Intuitive Version)

For the observables we measure (signature, freshness, CHSH), a partial impersonator at strength θ_imp produces the same cell probabilities as a channel attacker at strength `θ_ch ≈ 1.5 × θ_imp`.

| Impersonation θ_imp | Equivalent channel θ_ch |
|---|---|
| 0.5 | 0.75 |
| 0.1 | 0.15 |

So if ARBITER observes an error pattern consistent with "channel attack at θ_ch = 0.3," it *could* be an impersonator at θ_imp = 0.2, but it reports "channel attack" because that's the simplest explanation in the threat model.

### What the Code Does

- `src/arbiter/qds_simulation/model.py:17-22` defines impersonation as all-or-nothing.
- `src/arbiter/qds_simulation/model.py:124-135` specifies its cell probabilities (same as forgery when θ = 1).
- `docs/threat-model.md:34-37` explains the identifiability result.

### Worked Numbers

- Full-strength impersonation (θ = 1): detection rate **1.00**.
- Partial impersonation is not tested separately; equivalent channel attacks are tested and show good detection.

### Likely Follow-Up

**"Is that a limitation?"**

Yes. To distinguish partial impersonation from partial channel manipulation, you'd need extra observables (e.g., additional measurement bases or longer coherence checks). ARBITER is limited by the Pauli measurements inherent to the QDS protocol and states this openly.

---

## Part 11: The Audit Ledger and Cryptographic Signatures

### The One-Sentence Answer
Every verdict is recorded in a hash-chained ledger, and each entry is signed twice: once with post-quantum ML-DSA, once with a hash-based Merkle-Lamport signature.

### The Intuition

A traditional ledger in an old bank:
- Each page records transactions.
- The page is dated and signed.
- If someone changes page 5, page 6's "reference to page 5" breaks, exposing tampering.

ARBITER does the same, but digitally and with two signatures:
1. **ML-DSA-65 signature**: Strong against future quantum computers (post-quantum cryptography).
2. **Merkle-Lamport signature**: Also post-quantum, using only hash functions; backed by different math than ML-DSA.

Using two independent schemes means an attacker would need to break *both* to tamper undetected—a much higher bar.

### Technical Terms

- **Hash function**: A one-way function; easy to compute forward, hard to reverse. `SHA3-512` outputs a 512-bit fingerprint.
- **Hash chain**: Each entry includes the hash of the previous entry. Changing an old entry changes its hash, which breaks the next entry's reference.
- **ML-DSA-65**: A post-quantum digital signature scheme approved by NIST. It resists attacks from hypothetical quantum computers.
- **Merkle-Lamport**: A stateless hash-based signature; slower than ML-DSA but uses only hash functions.

### What the Code Does

- `src/arbiter/audit_ledger/ledger.py:1-183` chains entries and verifies the hash chain.
- `src/arbiter/audit_ledger/signatures.py:1-170` computes ML-DSA and Merkle-Lamport signatures.
- `src/arbiter/audit_ledger/keys.py` manages key material (keys are stored encrypted, see #30).
- The pipeline records verdict, signatures, and hash into the ledger after each session.

### Worked Numbers

- **Ledger entry hash**: SHA3-512 → 512 bits (64 bytes).
- **Merkle-Lamport signature**: XMSS tree of height 10 → supports 1,024 signatures per key, then keys rotate.
- **ML-DSA-65 signature**: ~4,595 bytes per signature.
- **Typical ledger entry size**: ~5 KB (hash + signatures + verdict data).

### Ledger Entry Structure

```
Ledger Entry i:
  ├─ session_id
  ├─ verdict: ACCEPT or REJECT
  ├─ attribution: legit | forgery | impersonation | replay | channel
  ├─ attack_strength: θ
  ├─ timestamp
  ├─ round_count
  ├─ round_schedule_hash
  ├─ hash_of_previous_entry (i-1)
  ├─ ml_dsa_signature
  ├─ merkle_lamport_signature
  └─ hash_of_this_entry

Entry i+1:
  ├─ ...
  ├─ hash_of_previous_entry = hash_of_entry(i)  ← links to i
  └─ ...

If anyone changes entry i, its hash changes.
Entry i+1's reference to entry i no longer matches.
Tampering is exposed.
```

### Ledger Verification Endpoint

- `GET /ledger/verify` walks the chain, checks both signatures, and reports any tampering.
- Returns: "Valid chain, all signatures checked" or "Entry N has broken hash reference" or "Signature on entry M is invalid."

### Likely Follow-Ups

**"Is the ledger a blockchain?"**

No. It's a *local* tamper-evident chain, not a distributed ledger. Each ARBITER deployment keeps its own ledger. External anchoring (e.g., committing hash roots to a public blockchain or a time-stamp service) is future work.

**"Why two signature schemes?"**

Diversity. If ML-DSA is later broken (very unlikely, but possible), Merkle-Lamport remains. Conversely, if hash functions are unexpectedly compromised, ML-DSA stays intact. Together, they're more robust than either alone.

**"Can I query the ledger?"**

Yes:
- `GET /ledger` lists all entries.
- `GET /ledger/{i}` retrieves entry i.
- `GET /ledger/verify` audits the chain.

---

## Part 12: Trapped-Ion Hardware Error Budget

### The One-Sentence Answer
Hardware errors (gate fidelity, qubit dephasing, heating, and measurement errors) combine into an effective "visibility" that describes how clean the Bell pair is.

### The Intuition

A recipe for bread:
- Use 100g flour (±2g error).
- Add 60ml water (±5ml error).
- Knead 10 minutes (±1 min error).
- Bake at 200°C (±5°C error).

Small errors in ingredients and timing add up to an "expected quality" of the finished loaf.

Similarly, quantum errors combine:
- **MS gate error**: ~0.2% per two-qubit gate.
- **T₂ dephasing**: Qubit loses coherence after ~5 ms (impacts CHSH rounds).
- **Heating**: Motional energy creeps up; slight frequency shifts.
- **SPAM** (state prep & measurement): ~0.3% prep error, ~0.5% measurement error.

Together, they reduce the Bell-pair visibility from 1.0 (ideal) to ~0.92 (realistic), which translates to ~4% legitimate error rates in signature measurements.

### What the Code Does

- `src/arbiter/noise/trapped_ion.py:1-230` models the error budget and derives visibility.
- `src/arbiter/qds_simulation/model.py` uses visibility to set per-cell probabilities.
- `examples/security_bounds.py` reports bounds for different hardware presets.

### Hardware Presets

| Preset | Visibility | P_error | Assumptions |
|---|---|---|---|
| **state_of_the_art_2025** | 0.9992 | 0.0002 | Best-in-class ion trap (e.g., IonQ) |
| **prototype** | 0.9945 | 0.0014 | Lab prototype (near-term hardware) |
| **conservative** | 0.8576 | 0.0356 | Deliberately pessimistic (worst-case) |

### Error Sources and Their Impact

```
Trapped-ion hardware:

  [SPAM]                 [Single-qubit gates]   [Two-qubit MS gate]
     0.3% prep              Negligible            0.2% error
     0.5% measurement                                  |
          |                                            v
          +-----------> Bell pair fidelity <----------+
                              |
                              v
                        Visibility v = 0.92
                              |
                              v
                    Expected CHSH score S = 2√2v ≈ 2.60
                    Expected sig mismatch ≈ 4%
```

### Why This Matters

- **Honest sessions** are designed to produce **4% error rate** at v = 0.92.
- An attacker who can't change the visibility is stuck with the same 4% error rate, making attacks hard to hide.
- If visibility drops (e.g., v = 0.5 due to hardware degradation), *all* error rates rise, and ARBITER raises alarms for *honest* sessions too—a sign of calibration issues.

### Worked Numbers (from `examples/security_bounds.py`)

For the state-of-the-art preset (v = 0.999187, p_err = 0.000203):
- **Minimum L (message length) for ε = 10⁻¹⁰**: 6,843 bits.
- At 1 kHz signaling rate, that's ~7 seconds per signature.
- At 10 kHz, ~0.7 seconds.

### Likely Follow-Up

**"Is this calibrated to a real device?"**

No. It's a *published-figure model* using realistic numbers from the literature (IonQ, Honeywell, etc.), not raw measurements from a specific device. When ARBITER is deployed on hardware, the visibility must be *experimentally measured* and configured via `ARBITER_NOISE_PRESET`.

---

## Part 13: Quantum Risk to Keys and Certificates (PKI Scoring)

### The One-Sentence Answer
A quantum computer with ~4,000 logical qubits could break RSA-2048 in hours; ARBITER estimates how long your keys are safe, given hardware progress assumptions.

### The Intuition

Imagine a bank vault that's safe for 10 years as long as the locks aren't cracked. But you hear rumors that someone might build a lock-breaking machine in 8 years. You have 2 years to change the locks before they become vulnerable.

**Mosca's inequality** formalizes this:
```
Safe if:  (migration_time + key_lifetime) < time_to_quantum_computer
```

If your RSA-2048 keys must remain secret for the next 20 years, and you estimate a quantum computer will arrive in 15 years, you're already in trouble—migrate now.

### Technical Terms

- **Shor's algorithm**: A quantum algorithm that factors large numbers exponentially faster than the best classical algorithm. It would break RSA, DSA, and elliptic-curve cryptography.
- **Logical qubits**: The "error-corrected" qubits available for computation, after accounting for error-correction overhead. A single logical qubit needs ~1,000–10,000 physical qubits.
- **NIST PQC**: NIST-approved post-quantum cryptography algorithms (e.g., ML-DSA, ML-KEM) designed to resist quantum attacks.
- **Mosca's inequality**: A planning rule: if breaking your key takes X quantum operations and you have Y years before a quantum computer arrives, migrate if `(key_lifetime + migration_effort) > Y`.

### What the Code Does

- `src/arbiter/pki_risk_scoring/scoring.py:1-240` estimates Shor resource counts.
- `src/arbiter/pki_risk_scoring/certificates.py:1-150` parses X.509 certificates.
- `POST /pki/assess` and `POST /pki/assess-key` endpoints score certificates and keys.

### Worked Numbers

RSA-2048:
- **Estimated logical qubits to factor**: ~4,099 (from Gidney & Ekera, 2021).
- **With error correction** (surface codes, magic states, etc.): ~20 million physical qubits.
- **Time to factor** (on such a machine): ~8 hours.
- **Risk score**: If a quantum computer arrives in 15 years and your RSA key must last 20 years, migrate *now*.

### Risk Assessment Flowchart

```
Input: RSA-2048 key, must remain secret until 2045
                |
                v
        Estimate: quantum computer in ~2035?
                |
                v
        Migration needed? 2045 - 2035 = 10 years
                |
                v
        Can we migrate all systems in 10 years?
                |
        YES → Medium risk (start planning now)
        NO  → High risk (migrate urgently)
```

### Likely Follow-Ups

**"Does this predict a date?"**

No. It's a *planning estimate* with explicit assumptions (Moore's law, error-correction overhead, etc.), not a crystal ball. The actual date depends on hardware breakthroughs we can't foresee.

**"Should we switch to ML-DSA-65 now?"**

Yes, if you're deploying new systems. If you have existing RSA infrastructure, a hybrid approach (both RSA and ML-DSA) buys time while you migrate.

**"What does ARBITER do about it?"**

ARBITER scores your TLS certificates and signing keys and reports risk. It doesn't auto-rotate keys (that's a deployment decision). The API endpoint `POST /pki/scan` optionally scans live TLS endpoints to assess the deployed PKI.

---

## Part 14: Quantum Chernoff Bounds and Measurement Efficiency

### The One-Sentence Answer
The quantum Chernoff bound is the *speed limit* for any detector; ARBITER's measurement efficiency tells you what fraction of that limit we actually achieve.

### The Intuition

A speed limit on a highway is the maximum safe speed. A car that goes 50 mph on a 70 mph highway is efficient at only 71% of the limit—it could go faster without violating physics.

Similarly:
- **Quantum Chernoff bound**: Theoretical maximum discrimination speed for any quantum measurement on a given attack.
- **ARBITER's efficiency**: How close our fixed Pauli measurements come to that maximum.
- **Why not 100%?** Because we use fixed bases; if we could *adapt* the measurement bases per round or use entangled measurements, we'd do better.

### Technical Terms

- **Chernoff exponent ξ**: The *rate* at which error probability drops with sample size N. Lower ξ is better (faster decay).
- **Helstrom measurement**: The theoretically optimal measurement for discriminating two quantum states.
- **Projective Pauli measurement**: A simple, practical measurement that we actually use.

### What the Code Does

- `src/arbiter/quantum/info.py:1-170` computes quantum Chernoff bounds via convex optimization (semidefinite program).
- `src/arbiter/detection/bounds.py:1-181` compares the quantum bound to our measured efficiency.
- `examples/security_bounds.py` and `GET /bounds` endpoint report efficiencies.

### Worked Numbers (from README)

| Attack | Quantum Chernoff ξ_Q | ARBITER ξ_M | Efficiency |
|---|---|---|---|
| Forgery | 0.0885 | 0.0885 | **1.00** ← Pauli meas. is optimal |
| Impersonation | 0.227 | 0.154 | 0.68 |
| Replay | 0.132 | 0.064 | 0.49 |
| Channel manip. | 0.114 | 0.080 | 0.70 |

### Why Forgery is 100% Efficient

Forgery detection asks: "Is the quantum state the one signed, or a random one?" Measuring in the signature basis (a Pauli measurement) *is* the optimal Helstrom measurement for this task. No adaptive or entangled measurement could do better.

### Why Others Are Below 100%

Impersonation, replay, and channel detection involve *multiple* signatures or composite attacks. Our fixed CHSH measurement bases are a compromise: they're good for all three attacks simultaneously, but not optimal for any single one. Adaptive (round-by-round) bases would help.

### Likely Follow-Ups

**"Does efficiency 1.00 mean the system is perfect?"**

No. It means our measurement is theoretically optimal *for that discrimination task*, assuming the noise model is correct. It does *not* mean:
- The protocol is unbreakable (other attacks not in our model might exist).
- The implementation is perfect (hardware always has bugs and misalignment).
- The noise model is right (real hardware might behave differently).

**"Can we improve efficiency for the other attacks?"**

Yes. The main avenue is adaptive CHSH bases—measuring in bases optimized per session after a pilot round. This is listed in the v0.2 roadmap.

---

## Part 15: What ARBITER Does Not Claim

### The Honest Scope

ARBITER is a **simulation-based detector for explicit, modeled attacks**. Here's what it explicitly *does not* claim:

### 1. Real-Hardware Results

- **Our claim**: We simulate QDS on Qiskit Aer (a classical simulator that implements quantum circuit semantics).
- **We don't claim**: These results hold on real trapped-ion hardware, photonics, superconducting qubits, or any other platform.
- **Why**: Hardware has measurement crosstalk, correlated errors, and calibration drifts that our model doesn't capture.
- **Next step**: Collaborate with hardware vendors to calibrate on real devices.

### 2. Robustness to Attacks Outside the Threat Model

- **Our claim**: ARBITER detects forgery, impersonation, replay, and channel manipulation *as modeled* in [docs/threat-model.md](threat-model.md).
- **We don't claim**: Robustness against:
  - **Detector blinding**: An attacker who measures ARBITER's hardware itself to learn secrets.
  - **Photon-number splitting (PNS)**: Attacks exploiting multi-photon pulses in optical systems.
  - **Trojan-horse attacks**: Attacker smuggles a probe qubit in alongside the legitimate state.
  - **Side channels**: Attacker learns secrets from power consumption, timing, electromagnetic leakage.
  - **Adaptive attacks**: Attacks that change strategy based on observed verdicts.
- **Why**: Modeling these requires assumptions about the specific hardware and adversary capabilities that we don't yet have.
- **Status**: [docs/threat-model.md:53-77](threat-model.md) names all excluded attacks explicitly.

### 3. Composable or Protocol-Level Proofs

- **Our claim**: ARBITER detects attacks on individual sessions with bounded false-alarm rate.
- **We don't claim**: 
  - The full protocol (including setup, key distribution, and ledger verification) is composably secure.
  - A multi-session attacker who adapts their strategy across sessions cannot break the system.
  - The honest-scope assumptions hold under a real adversary's manipulation.
- **Why**: Composability proofs require a formal model and security properties we haven't attempted.
- **Status**: This is appropriate for a simulation tool, not a proof-based system.

### 4. Quantum Advantage Over Classical Signatures

- **Our claim**: QDS is based on quantum states and Bell pairs.
- **We don't claim**: 
  - QDS is unconditionally secure (it's not; any quantum measurement can be eavesdropped in principle).
  - QDS replaces classical signatures (ML-DSA).
  - A real QDS system will be faster or cheaper than RSA or ML-DSA.
- **Why**: QDS shines in scenarios where public channels are untrusted and you have a *quantum* communication link already. Classical signatures are still essential for offline verification and ledger audit.
- **Status**: QDS is a *complement* to classical/post-quantum signatures, not a replacement.

### 5. Hardware Implementation Details

- **Our claim**: We provide an error budget model and validate protocols on simulators.
- **We don't claim**: 
  - Our noise model captures all trapped-ion error sources (e.g., no correlated errors, no coherent errors).
  - The presets match *any* specific device's actual performance.
  - Timing, geometric, or calibration details will transfer to a real experiment.
- **Why**: Each hardware platform has unique quirks; generic models are starting points, not blueprints.
- **Status**: Collaborate with hardware teams to calibrate on real systems.

### 6. Ledger as a Proof

- **Our claim**: The ledger is tamper-evident within a single ARBITER deployment.
- **We don't claim**: 
  - The ledger proves security to an external auditor (keys could be stolen; signatures forged).
  - The ledger solves Byzantine fault tolerance (a dishonest ARBITER operator can lie).
  - Anchoring the ledger to a public system (blockchain, time-stamp authority) is built-in.
- **Why**: Ledgers are useful for internal audit and forensics, not external proof.
- **Status**: External anchoring is future work.

### 7. Immunity to Quantum Advantage Curves

- **Our claim**: We report quantum Chernoff bounds and measurement efficiency.
- **We don't claim**: 
  - Future quantum computers can't break the protocol (Shor on the Bell pair preparation, for instance).
  - The system is immune to quantum attacks we haven't modeled.
- **Why**: Quantum advantage research is ongoing; future algorithms might apply.
- **Status**: ARBITER is designed around conservative threat assumptions; QDS itself remains an active research area.

### Table: What vs. What Not

| Claim | Status |
|---|---|
| Simulate QDS on Qiskit Aer | ✓ |
| Detect modeled attacks with controlled false-alarm rate | ✓ |
| Report attack attribution and strength | ✓ |
| Maintain an auditable ledger | ✓ |
| Assess PKI quantum migration urgency | ✓ |
| Work on real hardware without calibration | ✗ |
| Prove composable security | ✗ |
| Detect attacks outside threat model | ✗ |
| Replace classical signatures | ✗ |
| Resist detector blinding or Trojan-horse attacks | ✗ |
| Make the ledger a blockchain | ✗ |
| Guarantee safety even if keys are stolen | ✗ |

### How to Say It Confidently to a Judge

If a judge or auditor asks, "Is ARBITER production-ready?"

**Answer:**
> "ARBITER is a well-specified *simulation and detection framework* for teleportation-based QDS. We've validated it against explicit threat models and reported detailed performance metrics, including efficiency gaps. It is *not* a hardware-validated system; that requires real device data from collaborators. What we offer is a rigorous, reproducible testbed for QDS protocol design and a clear roadmap to hardware validation."

If they ask, "Does it replace classical signatures?"

**Answer:**
> "No. QDS is orthogonal to ML-DSA. ML-DSA signs the *audit ledger*; QDS is the *protocol layer* for live quantum sessions. Both are needed for a complete system."

If they ask, "What's the biggest limitation?"

**Answer:**
> "The noise model is a published-figure model, not hardware-calibrated. Before claiming security on a real system, we must measure the Bell pair visibility and protocol-relevant error rates on actual hardware and compare to our predictions."

---

## Team Self-Test (20 Questions)

Read each question aloud and answer without notes. These prompts are for team review; **no certification is claimed** by this document.

<details>
<summary>1. What is the project's single-sentence purpose?</summary>
Detect and attribute modeled QDS attacks (forgery, impersonation, replay, channel manipulation) with one calibrated statistical detector and record verdicts in a tamper-evident ledger.
</details>

<details>
<summary>2. Does QDS replace ML-DSA?</summary>
No. ML-DSA signs the audit ledger. QDS is the protocol layer for verifying live quantum signatures.
</details>

<details>
<summary>3. What does teleportation need?</summary>
A Bell pair, a Bell measurement, two classical correction bits, and the matching Pauli correction on the receiver's side.
</details>

<details>
<summary>4. What are the three round types?</summary>
Signature (check message), Freshness (check nonce), CHSH (check entanglement).
</details>

<details>
<summary>5. Why are there three round types?</summary>
They expose different attack signatures. An attacker can't safely target only one type if the verifier randomly switches.
</details>

<details>
<summary>6. What is the classical CHSH bound?</summary>
S ≤ 2. Quantum systems can achieve S ≤ 2√2 ≈ 2.828.
</details>

<details>
<summary>7. What is expected CHSH S at v = 0.92?</summary>
S = 2√2 × v ≈ 2.60.
</details>

<details>
<summary>8. What happens under forgery?</summary>
Signature mismatch rises to ~50%; freshness and CHSH remain at legitimate levels.
</details>

<details>
<summary>9. What happens under replay?</summary>
Freshness mismatch rises to ~50%; signature and CHSH remain legitimate.
</details>

<details>
<summary>10. What is a false alarm?</summary>
Rejecting an honest, unattacked session.
</details>

<details>
<summary>11. What does α control?</summary>
The maximum tolerated false-alarm probability. Default α = 0.01 means ≤1% of honest sessions are rejected.
</details>

<details>
<summary>12. Why one joint detector instead of four separate alarms?</summary>
The joint test leverages correlations between error types to both detect and attribute attacks. Four separate thresholds lose information and require error-budget sharing.
</details>

<details>
<summary>13. What is a likelihood ratio?</summary>
A comparison of how well each hypothesis (legit, forgery, impersonation, etc.) explains the observed data.
</details>

<details>
<summary>14. What is θ?</summary>
Attack strength—the fraction of rounds the attacker controls. θ = 1 means all rounds are attacked; θ = 0.1 means 10%.
</details>

<details>
<summary>15. Why can the sequential test check after every round?</summary>
The e-value is a special likelihood-ratio mixture designed so that an honest session's e-value crosses the threshold with probability at most α, no matter how many times you peek (Ville's inequality).
</details>

<details>
<summary>16. What is the sequential alarm threshold at α = 0.01?</summary>
1/α = 100.
</details>

<details>
<summary>17. What does efficiency 1.00 for forgery mean?</summary>
The Pauli measurement we use is theoretically optimal (Helstrom-optimal) for discriminating a forged state from a legitimate one, given the modeled attack.
</details>

<details>
<summary>18. Why is partial impersonation not modeled separately?</summary>
Partial impersonation leaves the same error pattern as partial channel manipulation; no detector can distinguish them without extra observables.
</details>

<details>
<summary>19. What does the audit ledger prove?</summary>
That verdicts haven't been changed after the fact (local tamper evidence). It does *not* prove security to an external auditor or constitute a distributed ledger.
</details>

<details>
<summary>20. Why two ledger signature schemes?</summary>
ML-DSA and Merkle-Lamport rely on different mathematical assumptions. If one is broken, the other remains. Together, they're more robust.
</details>

<details>
<summary>21. What is visibility?</summary>
A number from 0 to 1 measuring how "clean" the Bell pair is. It combines hardware errors (gate fidelity, decoherence, measurement errors) into one parameter.
</details>

<details>
<summary>22. What does ARBITER do if visibility drops (e.g., v = 0.5)?</summary>
All error rates rise, including for legitimate rounds. ARBITER raises alarms even for honest sessions—a sign of hardware degradation or miscalibration.
</details>

<details>
<summary>23. What are Mosca's inequality and quantum risk scoring?</summary>
Mosca's inequality: (migration_time + key_lifetime) must be less than time_to_quantum_computer. ARBITER estimates this to prioritize PKI updates.
</details>

<details>
<summary>24. How many logical qubits to break RSA-2048 with Shor?</summary>
Approximately 4,099 (from Gidney & Ekera, 2021). With error correction, you need ~20 million physical qubits.
</details>

<details>
<summary>25. What does ARBITER NOT claim?</summary>
Real-hardware results, robustness to detector blinding or Trojan-horse attacks, composable security, immunity to quantum advantage curves, or that the protocol is production-ready without calibration on actual devices.
</details>

---

## Key Takeaways for Judges

1. **ARBITER is a detector, not a proof.** It detects and attributes attacks in a *simulation* with specified threat assumptions. Real hardware requires calibration and validation.

2. **One test beats four.** The unified GLRT is mathematically principled, controls false alarms efficiently, and reports attack attribution—all without hand-tuned thresholds.

3. **Quantum states can't be copied.** That's the core insight behind QDS: an attacker who forges, impersonates, or manipulates leaves a detectable fingerprint in the error pattern.

4. **Every number in this guide is a *simulation result*.** It comes from:
   - Theoretical models (noise budget, Pauli measurement outcomes).
   - Qiskit Aer circuits (verified against the math).
   - 200-session sweeps under controlled attacks.

5. **The honest limitations are stated openly.** ARBITER works *as specified* in the threat model. Attacks outside that model, real hardware quirks, and composable security are explicitly out of scope.

6. **PKI quantum risk is urgent, but separate.** The QDS layer is independent from certificate security. Both matter; both are addressed.

---

## References and Further Reading

- **Quantum digital signatures overview**: Zeng & Keitel (2002), Wallden et al. (2015), Amiri et al. (2016).
- **Detection theory**: Helstrom (1976) (quantum hypothesis testing), Audenaert et al. (2007) (quantum Chernoff bounds), Ville (1939) (sequential testing).
- **CHSH inequality**: Clauser, Horne, Shimony, Holt (1969).
- **Post-quantum cryptography**: NIST PQC standards, including ML-DSA and ML-KEM.
- **Quantum threat timeline**: Mosca (2018), Gidney & Ekera (2021).

For code and reproducibility:
- [docs/math-derivations.md](math-derivations.md): Full formal model and proofs.
- [docs/threat-model.md](threat-model.md): Adversary capabilities and explicit exclusions.
- [docs/architecture.md](architecture.md): System design and integration points.
- [README.md](../README.md): Performance tables and quick-start.

---

**Version**: 1.0  
**Last updated**: 2026-09-29  
**Feedback**: Open an issue or reach out to the team at [CONTRIBUTING.md](../CONTRIBUTING.md).
