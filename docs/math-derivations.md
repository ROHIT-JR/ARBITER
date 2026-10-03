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

### 1.2 Finite-size protocol security

The detector's false-alarm control is not a QDS signature-security parameter.
For `protocol="qds"`, `detection/security.py` reports separate, conservative
stand-alone upper bounds for a signature of length `L`. Let `p_err` be the
honest USE mismatch probability computed above, and let `p_f = 1/4` be the
keyless-forger mismatch probability. Direct authentication accepts below
`s_a L` mismatches and forwarded verification accepts below `s_v L`, with

```
p_err < s_a < s_v < p_f.
```

Using the one-sided Hoeffding tail, the forger's chance of passing verification
is

```
P_forge <= exp[-2 (p_f - s_v)^2 L].
```

This is Eq. (5) of Wallden, Dunjko, Kent and Andersson, *Phys. Rev. A* **91**,
042304 (2015), at its no-abort parameter `r = 0`: their exponent reduces to
`-2 L (1/4-s_v)^2`. Robustness is the two-sided honest tail,

```
P_rob <= 2 exp[-2 (s_a-p_err)^2 L].
```

For repudiation ARBITER uses the ideal random half-exchange symmetrisation
model analytically, because the explicit exchange workflow is not yet in this
repository. The BB84 USE success probability is `p_USD=1/2`, so Eq. (2) of
Dunjko, Wallden and Andersson, *Phys. Rev. Lett.* **112**, 040502 (2014)
gives

```
P_rep <= exp[-p_USD^2 (s_v-s_a)^2 L / 2]
       = exp[-(s_v-s_a)^2 L / 8].
```

The implementation searches the admissible threshold interval and solves the
three exponential inequalities for the smallest integer `L` with
`max(P_forge, P_rep, P_rob) <= epsilon`. This is only a finite-size Hoeffding,
collective-attack, stationary-channel, one-bit **stand-alone** calculation. It
is not a composable proof, does not cover coherent attacks, and does not claim
that an unimplemented recipient-exchange protocol has been executed. The API
returns these assumptions with every result.

## 2. Observation model

The verifier's observations fall into nine Bernoulli cells: signature mismatch, freshness mismatch, four CHSH-setting cells, and three Bell-fidelity cells. For hypothesis `h` at strength `θ`:

```
q_{h,θ}(c) = (1 − θ) q_0(c) + θ q_h(c)
q_h(sig/fresh) = Tr(Π_{b, 1−s} ρ_{h})            (mismatch probability)
q_h(chsh_ab)   = (1 − σ_ab Tr[(A_a ⊗ B_b) ρ_h]) / 2
q_h(bell_PP)   = (1 − τ_P Tr[(P ⊗ P) ρ_h]) / 2
```

The CHSH settings are `A ∈ {Z, X}` and `B ∈ {(Z+X)/√2, (Z−X)/√2}`, with signs `σ = (+,+,+,−)`, so that `S = Σ σ_ab E_ab = Σ (1 − 2 q(chsh_ab))`.

The Bell-fidelity settings are *aligned*: both parties measure the same `P ∈ {Z, X, Y}`, with signs `τ = (+,+,−)` — the `|Φ⁺⟩` stabiliser eigenvalues `⟨ZZ⟩ = ⟨XX⟩ = +1`, `⟨YY⟩ = −1`. The three signed means give the fidelity `F = (1 + ⟨ZZ⟩ + ⟨XX⟩ − ⟨YY⟩)/4`, so an ideal pair gives `F = 1` and a Werner pair `F = (1+3v)/4`. See `cell_probabilities`.

Every cell records a **mismatch** bit `(1 − sign · correlator)/2`. The ideal correlator already carries the cell's sign, so `sign · correlator` is positive in every cell — applying the sign a second time is what used to invert the `chsh11` cell and bias `estimate_visibility` low by ≈0.024.

With `v = 0.92`:

| hypothesis (θ=1) | sig | fresh | each CHSH cell | each Bell cell | S | F |
|---|---|---|---|---|---|---|
| legitimate | 0.040 | 0.040 | 0.175 | 0.040 | 2.60 | 0.94 |
| forgery | 0.500 | 0.040 | 0.175 | 0.040 | 2.60 | 0.94 |
| impersonation | 0.500 | 0.500 | 0.500 | 0.500 | 0 | 0.25 |
| replay | 0.109 | 0.500 | 0.500 | 0.500 | 0 | 0.25 |
| channel manipulation | 0.347 | 0.347 | 0.392 | 0.347 | 0.87 | 0.48 |

Why keep both shared-pair types: a Werner pair has `|⟨P ⊗ P⟩| = v` for every aligned `P`, but only `v/√2` for the ±45° CHSH settings. The aligned measurement therefore separates the hypotheses further per round (honest mismatch `(1−v)/2 = 0.04` against `(1−v/√2)/2 = 0.175`), while the ±45° settings are precisely the ones that maximise the Bell *violation* and so are the ones that can certify non-locality. `SessionConfig.round_mix` sets the split.

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

`Ŝ = Σ σ_ab (1 − 2k_ab/n_ab)`. Rather than bounding each `Ê_ab` separately and adding four half-widths under a union bound, note that `Ŝ − S` is a *single* sum of independent zero-mean terms — one per sampled round, each of the form `(σ_ab/n_ab)(X_i − E X_i)` with `X_i ∈ {−1,+1}` and hence of range `2/n_ab`. One application of Hoeffding to the whole linear combination gives

```
P(|Ŝ − S| ≥ t) ≤ 2 exp(−t² / (2 Σ_ab 1/n_ab))
⇒  halfwidth(δ) = √(2 ln(2/δ) · Σ_ab 1/n_ab)
```

At equal counts this is ≈2.35× tighter than the union-bound form `Σ_ab √(2 ln(8/δ)/n_ab)`. Half-widths scale as `1/√m`, so the saving in *rounds* is the square, ≈5.5×: certifying at `v = 0.92, δ = 0.05` needs ≈328 CHSH rounds instead of ≈1792. `tests/test_chsh_bound.py` verifies the coverage by Monte Carlo (realised miss rate ≈0.002 against the 0.05 budget — Hoeffding remains conservative here because it ignores the binomial variance).

Two decisions follow:

- **Flag** the session if `Ŝ < 2`, the local bound. Intercept-resend cannot exceed it. This uses the point estimate, so it needs enough rounds to be quiet on an honest channel: below ≈140 CHSH rounds the false-alarm rate exceeds 1%, which is the floor on the CHSH weight in `round_mix`.
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

Because the blocks are diagonal, `ρ^s = ⊕_t p_t^s ρ_{h,t}^s` and therefore

```
Tr(ρ_0^s ρ_h^{1−s}) = Σ_t p_t Tr(ρ_{0,t}^s ρ_{h,t}^{1−s})
```

so both exponents decompose per round type over a *shared* `s`. Decomposing that way localises the whole efficiency deficit: the signature and freshness blocks are exactly 100% efficient, and all of the loss sits in the shared-pair block.

### 6.1 Why ξ_Q is the wrong yardstick, and ξ_L is the right one

Both hypotheses' shared-pair states are Bell-diagonal, so they share the Bell basis as a common eigenbasis and a **Bell-basis measurement attains `ξ_Q` exactly** (verified numerically to ratio 1.0000). That measurement is non-local: it requires the signer's half and the verifier's half in the same place. A distributed signature protocol cannot do it, so `ξ_Q` is unreachable by construction and `ξ_M/ξ_Q` is pessimistic by a constant factor no design choice can recover.

Restricting to **local** (product) measurements plus classical comparison, a Werner pair gives `⟨σ_a ⊗ σ_b⟩ = v(a_x b_x − a_y b_y + a_z b_z)`, whose magnitude is maximised at `v` by any aligned pair — i.e. exactly the Bell-fidelity settings. A 40-restart numerical search over all local directions `(a, b)` finds nothing better, and recording both outcome bits instead of their parity adds no information (for Bell-diagonal states the parity is a sufficient statistic, since the marginals are uniform). So:

```
ξ_L = exponent of the best local measurement   (achievable)
ξ_M ≤ ξ_L ≤ ξ_Q
```

`local_efficiency = ξ_M/ξ_L` is the actionable number, and it reaches 1.0 when the shared-pair budget is spent on Bell-fidelity rather than CHSH rounds. At `v = 0.92` the local-vs-non-local separation is `ξ_L/ξ_Q ≈ 0.51` for impersonation/replay and `≈0.58` for channel manipulation — the irreducible cost of keeping the parties apart.

Note that `ξ_Q` is invariant to how the shared-pair budget splits between CHSH and Bell-fidelity rounds, since both hold the same physical pair; only `ξ_M` moves. That keeps the comparison fair.

**Result:** the forgery efficiency is exactly 1 against *both* yardsticks. The legitimate and forged signature states commute, since `Δ_v(Π_s)` and `I/2` are both diagonal in the key basis, so the PS's projective Pauli measurement is Helstrom-optimal. `test_projective_pauli_measurement_is_helstrom_optimal` confirms this against the min-error SDP.

## 7. Audit ledger

```
signed_i = canonical_json(index, timestamp, prev_hash, payload)
hash_i   = SHA3-512(hash_{i−1} ‖ signed_i ‖ σ_ML-DSA ‖ σ_HBS)
```

`σ_HBS` is a Lamport one-time signature on `SHA3-256(signed_i)`. Its leaf key is authenticated by a Merkle path to the root published in genesis, the stateful hash-based construction of NIST SP 800-208. Forging an entry requires breaking **both** module-lattice (ML-DSA) and hash (SHA3) assumptions.
