# Hardware calibration data format for ARBITER

This document describes how to measure, export, and import ion-trap hardware calibration data into ARBITER for accurate, device-specific noise modeling of quantum digital signature verification.

## Overview

ARBITER's security analysis depends on two key noise parameters:
- **Link Werner visibility** `v`: determines how well the distributed Bell pairs are entangled after all error sources
- **Storage visibility** `v_s`: determines how long an attacker can maintain quantum memory

Both are computed from calibrated hardware figures. Rather than using generic presets, you can provide your own measurements to get predictions tailored to your device.

## JSON schema

Calibration data is provided as a JSON file conforming to the `calibration.schema.json` schema (located in `src/arbiter/noise/calibration.schema.json`). The schema is self-documenting; this section highlights the key fields.

### Required fields

| field | type | range | notes |
|-------|------|-------|-------|
| `device_id` | string | — | Unique identifier for your hardware (e.g., `"IonQ-Aria-1"`, `"Quantinuum-H12"`) |
| `date` | ISO 8601 datetime | — | When the calibration was measured (e.g., `"2025-01-15T10:30:00Z"`) |
| `qubit_count` | integer | ≥ 2 | Total number of qubits in your device |
| `two_qubit_gate_fidelity` | float | (0.5, 1.0] | Average Mølmer–Sørensen MS gate fidelity (typically 0.99–0.9999) |
| `single_qubit_gate_fidelity` | float | (0.5, 1.0] | Average single-qubit gate fidelity (typically 0.999–0.99999) |
| `spam_error` | float | [0, 0.5] | State preparation and measurement error probability per qubit |
| `t2_seconds` | float | > 0 | Coherence time T₂ (dephasing) in seconds. Includes laser phase noise and magnetic field effects. |
| `t1_seconds` | float | > 0 | Relaxation time T₁ (amplitude damping) in seconds |

### Optional fields

| field | type | default | notes |
|-------|------|---------|-------|
| `link_idle_seconds` | float | 0.002 | Typical idle time between MS gates (2 ms) |
| `heating_error_per_link` | float | 0.0001 | Residual error from motional heating / ion shuttling (0.01%) |
| `single_qubit_gates_per_round` | integer | 4 | Number of single-qubit ops per QDS protocol round |
| `ms_overrotation_rad` | float | 0.0 | Systematic phase error in MS gates (coherent error, not twirled away) |
| `crosstalk_error` | float | 0.0 | Neighboring-qubit crosstalk (fractional fidelity loss) |
| `attacker_storage_seconds` | float | 0.2 | How long an attacker can hold quantum memory (200 ms) |

## Importing calibration data

### Python API

```python
from arbiter.noise import TrappedIonParams

# Load from JSON file
params = TrappedIonParams.from_calibration_file("path/to/calibration.json")

# Validate and print summary
print(params.visibility_budget())
print(f"Link visibility: {params.visibility():.6f}")
print(f"Storage visibility: {params.storage_visibility():.6f}")

# Get channel parameters for ARBITER
channel_params = params.channel_params()
```

### Command-line interface

```bash
arbiter noise import path/to/calibration.json
```

## Example calibrations

See `examples/calibrations/` for sample files:
- `ionq_aria_inspired.json`: State-of-the-art 11-qubit system
- `quantinuum_h_series_inspired.json`: 20-qubit system with per-pair measurements
- `generic_trapped_ion_defaults.json`: Minimal required fields

## Data privacy

Calibration data can stay **private to your organization**:
- Only aggregate parameters (average fidelities, T₂ ranges, etc.) are shared
- Raw hardware figures are not logged or exported by ARBITER
- You control what goes in the JSON file; the schema is a guideline

For more information, see `docs/collaborating-with-hardware-teams.md`.
