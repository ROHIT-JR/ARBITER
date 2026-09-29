# Collaborating with hardware teams on quantum digital signatures

This one-page guide explains what ARBITER can do for your hardware team, what data it needs, and how to contribute.

## What ARBITER does

ARBITER performs **unified attack attribution** for quantum digital signatures based on teleportation. It answers:

- **Can your hardware run QDS?** By comparing measured noise levels against a threshold, ARBITER computes whether the quantum channel is strong enough to support unbreakable signatures.
- **How many rounds does an attacker need?** Given your hardware parameters, ARBITER calculates how many protocol rounds an attacker must forge to break the signature.
- **What's your security margin?** ARBITER outputs the CHSH inequality violation S-value and security bounds.

In short: **your measured noise parameters + ARBITER = device-specific security bounds**.

## What data you need to share

### Minimal dataset (5 numbers)

1. **MS gate fidelity** (~99.9–99.99%): Average two-qubit gate fidelity
2. **Single-qubit gate fidelity** (~99.99%): Average single-qubit gate fidelity
3. **T₂ coherence time** (seconds): How long qubit superposition lasts
4. **T₁ relaxation time** (seconds): How long qubit population lasts
5. **SPAM error** (~10⁻⁴–10⁻³): State preparation and measurement error

## Privacy: your data stays yours

- **You control the data.** ARBITER only needs aggregate parameters.
- **No logging.** The data is not stored, shared, or logged by default.
- **You decide what to publish.** If you want to contribute a preset, choose exactly what goes public.

## How to use ARBITER with your data

### Step 1: Create a JSON calibration file

Write a JSON file following the schema in `src/arbiter/noise/calibration.schema.json`:

```json
{
  "device_id": "My-Device",
  "date": "2025-01-15T10:30:00Z",
  "qubit_count": 10,
  "two_qubit_gate_fidelity": 0.999,
  "single_qubit_gate_fidelity": 0.99995,
  "spam_error": 5e-4,
  "t2_seconds": 1.0,
  "t1_seconds": 0.1
}
```

### Step 2: Import into ARBITER

```python
from arbiter.noise import TrappedIonParams
from arbiter.pipeline import Arbiter

params = TrappedIonParams.from_calibration_file("path/to/calibration.json")
arbiter = Arbiter(params.channel_params())
```

### Step 3: Review results

ARBITER outputs:
- Visibility budget breakdown (which error sources dominate?)
- Link Werner visibility (how entangled are your Bell pairs?)
- Security bounds (rounds to attack, security margin)

## Contributing your device (optional)

If you'd like to add your parameters to the public preset library:

1. Prepare a calibration JSON with your measurements
2. Open a GitHub issue labeled `noise-model`
3. Include a summary of your platform (e.g., "11-qubit hyperfine-qubit system")
4. We'll validate and consider adding a preset

Contributing is optional; ARBITER works great with private calibrations too.

## For more information

- **Detailed calibration guide**: `docs/hardware-calibration-format.md`
- **Noise model internals**: `docs/ion-trap-noise-model.md`
- **ARBITER usage**: `README.md`

**Summary:** Provide your measured gate fidelities and coherence times → ARBITER predicts whether your hardware can run secure QDS and how many rounds are needed to break an attack.
