"""Regenerate the README's trapped-ion QDS security table."""

from arbiter.detection.security import minimum_signature_parameters
from arbiter.noise import PRESETS


def main() -> None:
    print("| trapped-ion preset | visibility | p_err | minimum L for ε = 10⁻¹⁰ |")
    print("|---|---:|---:|---:|")
    for name, preset in PRESETS.items():
        result = minimum_signature_parameters(1e-10, preset.channel_params()).bounds
        print(f"| {name} | {preset.visibility():.6f} | {result.p_err:.6f} | {result.length:,} |")


if __name__ == "__main__":
    main()
