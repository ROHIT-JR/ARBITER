# Threat model and scope

ARBITER makes **statistical claims relative to an explicit model**. This page is that model. Anything not listed under "in scope" is not covered by the detector's guarantees.

## Parties and protocol

- **Signer (Alice)** holds a private signing key. The key and message deterministically select (via SHAKE-256) a Pauli eigenstate for each signature round.
- **Verifier (Bob)** issues a fresh 256-bit session nonce from the QRNG. He randomly chooses a type for each round, keeping the choice secret until measurement:
  - **Signature round**: Alice teleports her key-selected eigenstate. Bob applies the Pauli correction `X^m2 Z^m1` and measures projectively in that eigenstate's basis.
  - **Freshness round**: the same procedure, but the eigenstate comes from *today's nonce*.
  - **CHSH round**: Alice and Bob measure their halves of a Bell pair in random CHSH settings.
- **Legitimate channel**: Bell pairs with Werner visibility `v` (default 0.92). The induced teleportation channel is depolarizing with the same `v`, and the ideal CHSH value is `S = 2√2·v ≈ 2.60`.

## Adversaries (in scope)

Each attack is a replacement of the per-round quantum state. The primary
unified and sequential tests model a fraction `θ` of rounds independently
(the individual/collective-attack model). The change-point e-detector also
covers a single persistent late onset: it restarts likelihood-ratio evidence
at every candidate round and reports the most likely onset after an alarm.

| Attack | Adversary's capability | What it does to the rounds | Fingerprint |
|---|---|---|---|
| **Forgery** | Has legitimate network access and knows the public nonce, but not the key | Signature rounds carry a key-independent state. Any fixed guess mismatches a uniformly random Pauli key with probability exactly ½ (see `test_forger_best_guess_is_coin_flip`) | Signature errors → ½. Freshness and CHSH normal |
| **Impersonation** | Holds neither the key nor any of Alice's registered Bell halves | Correction bits and CHSH reports are uncorrelated with Bob's qubit | Everything → ½, S → 0 |
| **Replay** | Recorded a past session (states in quantum memory with storage visibility 0.85) and re-injects it under today's challenge | Signature rounds are valid but slightly decohered. Freshness rounds encode the *old* nonce. CHSH reports come from old settings | Freshness errors → ½, small rise in signature errors, S → 0 |
| **Channel manipulation** | Intercept-resend on Bob's half of the Bell pair in a random Pauli basis | Visibility drops to `v/3` on attacked rounds (measure-resend = depolarizing ⅓, see `test_measure_resend_is_depolarizing_one_third`) | Signature and freshness errors rise *together*; S drops in proportion |

A verbatim resubmission of an old transcript (a classical replay) is caught separately by the nonce registry.

### Two modelling decisions worth knowing

1. **Impersonation is all-or-nothing (θ = 1).** An impersonator holds none of the signer's entanglement, so they produce the whole session or none of it. There's also a deeper reason. A *partial* substitution of `I/2` on a fraction θ of rounds is observationally identical to intercept-resend on 1.5·θ of the rounds, because both are depolarizing. With these observables no detector could tell the two apart. ARBITER reports any such partial depolarization as channel manipulation.
2. **The forger has a legitimate channel.** This covers the canonical QDS forger: a dishonest recipient or insider who holds an authenticated link but not the signing key. An outsider without a link is an impersonator.

## Guarantees

- **False-alarm rate ≤ α** for both primary detectors under the legitimate model. For the unified GLRT this holds by exact Monte-Carlo calibration conditional on the observed round counts. For the sequential test it holds by Ville's inequality, even though it looks at the data after every round. Both are checked empirically in `test_false_alarm_rates_are_controlled`.
- **Late-onset coverage uses a separate ARL guarantee.** `ChangePointDetector` is a Shiryaev--Roberts-style mixture of likelihood-ratio e-processes, one started at every candidate onset. Its threshold is specified as an average-run-length (ARL) target in rounds (by default, `1 / α` 1200-round sessions), not as a one-session p-value. `tests/test_changepoint.py` checks the configured honest-stream operating point and the reproducible late-onset delay/onset estimates.
- **Optimality is relative to the model.** For any single alternative `(h, θ)`, the likelihood-ratio test is the most powerful level-α test (Neyman–Pearson). The union alternative is composite, so we use the generalized LRT, which is the standard, asymptotically optimal choice. It is not claimed to be uniformly most powerful.
- **Measurement optimality is partial, and we quantify it.** For forgery, the PS's projective Pauli measurement reaches the quantum Chernoff bound exactly (efficiency 1.00). For attacks that ARBITER sees mostly through CHSH rounds, the fixed CHSH settings reach 49–70% of the quantum exponent (see the `/bounds` endpoint and `examples/attack_sweep.py`). Closing that gap is listed as future work below.

## Out of scope (named, not ignored)

| Attack | Why out of scope | Standard countermeasure |
|---|---|---|
| Photon-number splitting | Applies to weak-coherent-pulse sources, not an entanglement-based simulation | Decoy states |
| Detector blinding / control (Lydersen et al. 2010) | Hardware attack that can extract the full key without raising the error rate | MDI architectures |
| Trojan horse, timing and power side channels | Physical layer | Optical isolation, constant-time hardware |
| Fully coherent attacks, asymptotic regime | Still an open research frontier | De Finetti reductions |
| Arbitrary adaptive, round-correlated attacks | The change-point detector covers one persistent onset and the simulator can model finite random bursts, but the likelihoods do not prove robustness to an adversary choosing round-by-round behavior from past outcomes, multiple changes, or coordinated quantum memory | Robust / minimax e-processes and correlated-noise calibration |
| Miscalibrated `v` | The detector assumes the legitimate visibility is known | Periodic recalibration. `arbiter.noise` derives `v` from hardware figures. Per-session estimation is on the roadmap |

## Future work that follows directly from this model

- Optimize the CHSH-round measurement: the SDP in `arbiter.quantum.info.optimal_povm` gives the target.
- Adaptive per-session estimation of `v` as a nuisance parameter.
- Extending the trapped-ion error budget ([ion-trap-noise-model.md](ion-trap-noise-model.md)) to coherent and correlated errors.
