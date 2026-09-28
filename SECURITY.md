# Security policy

ARBITER is research and demonstration software. It simulates quantum protocols and is **not** a production signing or key-management system.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through [GitHub security advisories](https://github.com/ROHIT-JR/ARBITER/security/advisories/new), not as public issues. Include steps to reproduce and the affected commit. We aim to acknowledge reports within 7 days.

Examples of what's in scope:

- A way to make the audit ledger accept a modified, reordered or forged entry.
- Signature verification bugs in the ML-DSA or Merkle-Lamport code paths.
- Reuse of a Merkle-Lamport one-time key.
- A transcript that makes the detector exceed its stated false-alarm rate α under the documented model.

## Known limitations (not vulnerabilities)

- The QRNG and the quantum channel are simulated. See [docs/threat-model.md](docs/threat-model.md).
- Ledger keys are stored unencrypted in `$ARBITER_DATA_DIR/ledger_keys.json`. Protect that directory.
- The Merkle-Lamport key has a fixed capacity: 2^10 entries by default. Once it is exhausted, the API returns HTTP 409 and the keys must be rotated.
- The API has no authentication. Don't expose it beyond localhost.
- `POST /pki/scan` is disabled unless `ARBITER_PKI_SCAN=1` and a hostname suffix allowlist is supplied through `ARBITER_PKI_SCAN_ALLOW`. Keep that allowlist narrow; the scanner refuses non-public DNS results, but it still makes outbound connections to approved services.
