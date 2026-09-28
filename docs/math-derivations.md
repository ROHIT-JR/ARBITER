# Mathematical modelling

Every equation here maps to code, cited in the right-hand notes. The tests check the non-trivial identities numerically.

## 1. States and channels

Pauli eigenstates: `Π_{b,s} = (I + (−1)^s σ_b)/2` for `b ∈ {X,Y,Z}` and `s ∈ {0,1}` (`quantum/states.py`).

Werner resource with visibility `v`:

```
τ_v = v |Φ⁺⟩⟨Φ⁺| + (1 − v) I/4 = (id ⊗ Δ_v)(|Φ⁺⟩⟨Φ⁺|),   Δ_v(ρ) = vρ + (1−v) I/2
```

**Teleportation.** The input is `ρ_C`, the resource is `τ_AB`, and the Bell measurement on CA is `CNOT(C→A)` followed by `H(C)`, giving outcomes `(m₁, m₂)`. Bob then applies `Z^{m₁} X^{m₂}`. The output is computed explicitly in `qds_simulation/model.py::teleport`, and the tests confirm two facts:

- teleporting through `|Φ⁺⟩` is the identity channel, and
- teleporting through `τ_v` is exactly `Δ_v`.

**Intercept-resend in a uniformly random Pauli basis** is

```
M(ρ) = ⅓ Σ_b Σ_s Π_{b,s} ρ Π_{b,s} = Δ_{1/3}(ρ)
```

because each dephasing keeps one Bloch component, and the average keeps ⅓ of each.

## 1.1 QDS distribution and messaging

The simulator supports two signature constructions.  The default `protocol="prf"`
keeps the original SHAKE-derived Pauli-eigenstate labels, so previous sessions
and detector tests stay bit-for-bit reproducible.  `protocol="qds"` models the
two-stage quantum-digital-signature construction below.

```mermaid
sequenceDiagram
    participant A as Alice (signer)
    participant B as Bob (recipient)
    A->>B: Distribution: teleport BB84 public-key state |ψᵢᵇ⟩
    B->>B: Random X/Z USE measurement; store one eliminated state eᵢᵇ
    Note over A,B: Repeat for i = 1…L and b ∈ {0,1}
    A->>B: Messaging: reveal message bit b and private key (ψ₁ᵇ,…,ψᴸᵇ)
    B->>B: Count mismatches: M = Σᵢ 1[eᵢᵇ = ψᵢᵇ]
```

The state set is BB84, `{|0⟩, |1⟩, |+⟩, |−⟩}`.  Bob selects a basis
`r ∈ {X,Z}` uniformly and obtains bit `s`.  He can unambiguously eliminate
`|r,1-s⟩`, because that state could not have produced `s` in basis `r`.
No attempt is made to identify the prepared state.  The signature cell is the
messaging mismatch statistic `M`.

For a teleported honest state over a Werner link of visibility `v`, a USE
mismatch needs both the matching basis (probability `1/2`) and a depolarizing
bit flip (probability `(1-v)/2`):

```
P_honest(M_i = 1) = (1-v)/4.
```

Thus it is exactly zero on a noiseless link.  During distribution, Eve's
intercept-resend attack is evaluated with the same Born-rule teleportation
state before this USE measurement.  During messaging, a forger without the
private key selects a BB84 reveal independent of Bob's eliminated label.  The
latter is uniform over four labels, hence the best achievable mismatch rate is
`P_forge(M_i = 1) = 1/4`; choosing a different fixed or randomized BB84 label
cannot improve it.  These identities are implemented by
`use_mismatch_probability` and `qds_forgery_mismatch_rate` and checked against
Aer in `test_qds_use_aer_matches_density_matrix_model`.

## 2. Observation model

The verifier's observations fall into six Bernoulli cells: signature mismatch, freshness mismatch, and four CHSH-setting cells. For hypothesis `h` at strength `θ`:

```
q_{h,θ}(c) = (1 − θ) q_0(c) + θ q_h(c)
q_h(sig/fresh) = Tr(Π_{b, 1−s} ρ_{h})            (mismatch probability)
q_h(chsh_ab)  = (1 − σ_ab Tr[(A_a ⊗ B_b) ρ_h]) / 2
```

The CHSH settings are `A ∈ {Z, X}` and `B ∈ {(Z+X)/√2, (Z−X)/√2}`, with signs `σ = (+,+,+,−)`, so that `S = Σ σ_ab E_ab = Σ (1 − 2 q(chsh_ab))`. See `cell_probabilities`.

With `v = 0.92`:

| hypothesis (θ=1) | sig | fresh | each CHSH cell | S |
|---|---|---|---|---|
| legitimate | 0.040 | 0.040 | 0.175 | 2.60 |
| forgery | 0.500 | 0.040 | 0.175 | 2.60 |
| impersonation | 0.500 | 0.500 | 0.500 | 0 |
| replay | 0.109 | 0.500 | 0.500 | 0 |
| channel manipulation | 0.347 | 0.347 | 0.392 | 0.87 |

## 3. Unified detector (GLRT)

Write `n_c` and `k_c` for the rounds and outcome-1 counts in cell `c`. Then

```
ℓ(h, θ) = Σ_c k_c log q_{h,θ}(c) + (n_c − k_c) log(1 − q_{h,θ}(c))
Λ = max_{h ∈ attacks, θ ∈ Θ_h} ℓ(h, θ) − ℓ(legit)
reject H₀  ⇔  Λ > τ_α(n),   τ_α(n) = (1−α)-quantile of Λ under H₀ given n
```

`Θ_h` is a 20-point grid on [0.05, 1], except for impersonation, where `Θ = {1}`. `τ_α` is recomputed for every session by exact Monte-Carlo, drawing `k ~ Binomial(n, q₀)`.

**Attribution** is the maximum-marginal-likelihood attack. The posterior uses a uniform prior over the five hypotheses and over `Θ_h`. See `detection/unified.py`.

**Why this is the right test.** For a simple alternative `(h, θ)`, the Neyman–Pearson lemma makes the likelihood-ratio test the most powerful test at level α. Maximizing over `(h, θ)` gives the generalized LRT for the composite union. By Wilks-type asymptotics it is optimal, and it needs no per-attack thresholds.

## 4. Anytime-valid sequential test

For each component `j = (h, θ)`, `L_t^j = Π_{i≤t} q_j(x_i | c_i) / q_0(x_i | c_i)` is a nonnegative martingale with mean 1 under H₀. The prior-weighted mixture `E_t = Σ_j w_j L_t^j` is one too. **Ville's inequality** then gives

```
P_H₀(∃ t ≥ 1 : E_t ≥ 1/α) ≤ α
```

So the verifier may stop at the first `t` with `E_t ≥ 1/α`, which is the *alarm time*. After the alarm, rounds keep being read until the attack posterior reaches 0.99, the *attribution time*. See `detection/sequential.py`.

## 5. CHSH pre-check

`Ŝ = Σ σ_ab (1 − 2k_ab/n_ab)`. Each `Ê_ab` is a mean of ±1 variables. Hoeffding plus a union bound over the four settings gives the half-width

```
|Ŝ − S| ≤ Σ_ab √(2 ln(8/δ) / n_ab)    with probability ≥ 1 − δ
```

Two decisions follow:

- **Flag** the session if `Ŝ < 2`, the local bound. Intercept-resend cannot exceed it.
- **Certify** a Bell violation if `Ŝ − halfwidth > 2`.

## 6. Information-theoretic limits

The verifier knows each round's type, so the per-round state is block-diagonal (classical-quantum):

```
ρ_h = ⊕_t p_t ((1 − θ) ρ_{0,t} + θ ρ_{h,t})
```

The single-round **Helstrom** error is `½ − ¼‖ρ_0 − ρ_h‖₁`. The **quantum Chernoff** exponent is

```
ξ_Q = −log min_{0≤s≤1} Tr(ρ_0^s ρ_h^{1−s})
```

The best achievable error over `N` rounds decays as `exp(−N ξ_Q)`. The classical Chernoff information `ξ_M` of ARBITER's actual measurement outcomes satisfies `ξ_M ≤ ξ_Q`. The ratio `ξ_M/ξ_Q` is reported as the measurement efficiency (`detection/bounds.py`).

**Result:** the forgery efficiency is exactly 1. The legitimate and forged signature states commute, since `Δ_v(Π_s)` and `I/2` are both diagonal in the key basis, so the PS's projective Pauli measurement is Helstrom-optimal. `test_projective_pauli_measurement_is_helstrom_optimal` confirms this against the min-error SDP.

## 7. Audit ledger

```
signed_i = canonical_json(index, timestamp, prev_hash, payload)
hash_i   = SHA3-512(hash_{i−1} ‖ signed_i ‖ σ_ML-DSA ‖ σ_HBS)
```

`σ_HBS` is a Lamport one-time signature on `SHA3-256(signed_i)`. Its leaf key is authenticated by a Merkle path to the root published in genesis, the stateful hash-based construction of NIST SP 800-208. Forging an entry requires breaking **both** module-lattice (ML-DSA) and hash (SHA3) assumptions.
