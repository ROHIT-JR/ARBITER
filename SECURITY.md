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
- Ledger key storage and rotations require the operator to retain the passphrase and a consistent backup; see the lifecycle below.
- Without `ARBITER_API_KEYS`, the API is intended for localhost-only use. Set a comma-separated key list and send `X-API-Key` to protect expensive endpoints. `ARBITER_RATE_LIMIT` and `ARBITER_RATE_WINDOW` tune the per-key/IP in-process rate limiter; `ARBITER_CORS_ORIGINS` is empty by default.
- `POST /pki/scan` is disabled unless `ARBITER_PKI_SCAN=1` and a hostname suffix allowlist is supplied through `ARBITER_PKI_SCAN_ALLOW`. Keep that allowlist narrow; the scanner refuses non-public DNS results, but it still makes outbound connections to approved services.

## Ledger key lifecycle

Set `ARBITER_KEY_PASSPHRASE` before the first API start. The service derives an
AES-256-GCM key with Argon2id and stores encrypted signing keys in
`$ARBITER_DATA_DIR/ledger_keys.json`. A wrong passphrase fails startup. For an
isolated local development instance only, set `ARBITER_ALLOW_PLAINTEXT_KEYS=1`
to opt into plaintext keys; do not use that setting for a shared service.
Existing plaintext key files must be migrated explicitly before starting in
encrypted mode: load them in a trusted offline environment, call
`LedgerKeys.save_encrypted()` with the new passphrase, replace the file, and
verify the ledger from its published genesis hash.

The Merkle-Lamport tree has 1024 one-time leaves by default. At 90% use, or
when `POST /ledger/rotate` is called, the service prepares new encrypted keys
in `ledger_keys.json.next`, appends a transition signed by both epochs, then
atomically replaces `ledger_keys.json`. On startup, a valid `.next` file is
used only if it matches the active keys in the verified ledger. The retired
epoch's secret keys are no longer needed for verification and are removed from
the active key file. Filesystem snapshots or earlier backups may still contain
them; apply your normal secret-retention policy to those copies.

Back up `ledger.jsonl`, `ledger_keys.json`, any `ledger_keys.json.next`, and
the independently published genesis hash together. Restore the files as a
set, supply the same passphrase, then call `GET /ledger/verify` and compare the
genesis hash with the published value before accepting new entries. Do not
restore an older key file beside a newer ledger: it can reuse a one-time leaf
or leave the active epoch without its secret key.
