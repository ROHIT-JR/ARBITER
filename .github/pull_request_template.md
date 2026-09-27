## Summary

<!-- What changes and why. Link the issue if there is one. -->

## Checklist

- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `pytest` passes (including `-m slow`)
- [ ] New detection logic has a false-alarm test under H₀ and a per-attack detection test
- [ ] Physics changes are in `model.py` first and mirrored in `circuits.py` (the circuit-vs-model test passes)
- [ ] `docs/threat-model.md` updated if the adversary model or scope changed
- [ ] Frontend: `npm run build` passes (if touched)
