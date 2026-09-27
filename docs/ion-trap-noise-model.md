# Trapped-ion noise model

Everything ARBITER computes (likelihoods, thresholds, Chernoff bounds) is derived from two numbers in `ChannelParams`:

- the Werner **visibility** `v` of the distributed Bell pairs, and
- the **storage visibility** of a replay attacker's quantum memory.

`arbiter.noise.TrappedIonParams` computes both from trapped-ion hardware figures. A hardware team can drop in calibration data and every downstream quantity updates automatically.

```python
from arbiter.noise import PRESETS, TrappedIonParams
from arbiter.pipeline import Arbiter

params = TrappedIonParams(two_qubit_gate_fidelity=0.9985, t2_seconds=2.5).channel_params()
arbiter = Arbiter(params)  # or: ARBITER_NOISE_PRESET=prototype uvicorn --factory ...
PRESETS["prototype"].visibility_budget()
```

## Error budget

The link visibility is the product of independent Bloch-vector / Werner shrink factors:

| factor | parameter | formula | why |
|---|---|---|---|
| Mølmer–Sørensen gate | average fidelity `F₂` | `1 − (4/3)(1 − F₂)` | Two-qubit depolarizing with parameter `p` has average fidelity `1 − 3p/4` |
| Idle dephasing | `T₂`, idle time `t` | `(4F − 1)/3` with `F = (1 + e^{−2t/T₂})/2` | Dephasing both halves of \|Φ⁺⟩. Bilateral Pauli twirling makes the state exactly Werner with the same fidelity. Laser phase noise and magnetic-field noise are folded into `T₂` |
| Motional heating | residual 2-qubit error per link `ε_h` | `1 − (4/3)ε_h` | Heating during transport or shuttling degrades the entangling operation like a gate error |
| Single-qubit gates | fidelity `F₁`, `k` gates per round | `(1 − 2(1 − F₁))^k` | Single-qubit depolarizing (d = 2) |
| SPAM | error `e` | `1 − 2e` | An outcome flip with probability `e` equals depolarizing with `v = 1 − 2e` for the mismatch statistic |

The replay attacker's memory dephases for its storage time `t_s`. Twirled, this gives `v_s = (1 + 2e^{−t_s/T₂})/3`.

Each identity is checked numerically in `tests/test_noise.py`.

## Presets

| preset | F₂ | F₁ | SPAM | T₂ | idle | → v | → CHSH S |
|---|---|---|---|---|---|---|---|
| `state_of_the_art_2025` | 0.9999 | 0.99999 | 2e-4 | 10 s | 1 ms | 0.9992 | 2.826 |
| `prototype` (default) | 0.999 | 0.99995 | 5e-4 | 1 s | 2 ms | 0.9945 | 2.813 |
| `conservative` | 0.99 | 0.9995 | 3e-3 | 50 ms | 5 ms | 0.8576 | 2.426 |

The presets describe *a* trapped-ion link with these component figures, not any particular vendor's device.

Sources for the ranges:

- Two-qubit gate fidelities of 99.9–99.99% are reported for Mølmer–Sørensen gates (IonQ 2025; Quantinuum Helios 2025, 99.921% across all pairs; *J. Phys. B* 2024).
- Hyperfine-qubit coherence ranges from seconds without decoupling to more than an hour with it (*Nature Communications* 2020), and more than 10 hours in a decoherence-free clock qubit (arXiv:2603.19631).
- Raman spontaneous-emission error of ~4–5.7 × 10⁻⁴ per gate (arXiv:2212.03367) is folded into `F₂`.

## Limitations and next steps

- Every error is modelled as Pauli/depolarizing after twirling. Coherent over-rotation errors and correlated crosstalk are not captured.
- The idle time and `T₂` are single numbers. A real network would use a distribution.
- **We invite ion-trap teams to contribute measured parameters**: gate fidelities by pair, `T₂` with and without dynamical decoupling, heating rates and SPAM. Open an issue labelled `noise-model`.
