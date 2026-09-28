# PKI quantum-risk scoring

`arbiter.pki_risk_scoring` answers a practical question that doesn't need quantum hardware: **which of our classical keys and certificates does a future quantum computer threaten, and how urgently?**

```python
from arbiter.pki_risk_scoring import assess_certificates, assess_chains, assess_key

assess_key("RSA", 2048, expires=some_datetime).to_dict()
for r in assess_certificates(open("bundle.pem", "rb").read()):
    print(r.subject, r.public_key.level, r.public_key.recommendation)

for chain in assess_chains(open("bundle.pem", "rb").read()):
    print(chain.weakest_link.subject, chain.level, chain.recommendation)
```

It is also available over the API as `POST /pki/assess` (a PEM bundle) and `POST /pki/assess-key`. A linked bundle returns `{"chains": [...]}`; a standalone certificate keeps the original list response. Certificate parsing needs `pip install -e ".[pki]"`.

## Scan public TLS endpoints

The local CLI fetches the certificates offered by public TLS services, records the negotiated TLS version and cipher, then applies the same scoring model:

```bash
arbiter pki scan example.com:443 api.example.com --json
arbiter pki scan --hosts-file hosts.txt
```

The scanner resolves targets once, rejects loopback, private, link-local, multicast, reserved and otherwise non-global addresses, and connects to the resolved IP to prevent DNS rebinding. It intentionally does not validate the TLS chain: expired and self-signed certificates are still useful inventory findings. Python's `ssl` interface does not reliably expose the negotiated key-exchange group, so reports mark it as `unknown`; use an audited `openssl s_client` workflow when that field is essential.

`POST /pki/scan` is disabled by default because it makes outbound connections. Enable it only for a controlled deployment and always set a hostname allowlist:

```bash
ARBITER_PKI_SCAN=1 ARBITER_PKI_SCAN_ALLOW=example.com,corp.example.com \
  uvicorn --factory arbiter.api.app:create_app
```

The allowlist accepts an exact hostname or a subdomain of each suffix. The API returns HTTP 403 when scanning is disabled, no allowlist is configured, a target is outside the allowlist, or DNS resolves to a non-public address.

## Model

**Shor resources (logical qubits):**

- RSA-n needs `2n + 3` (Beauregard 2003).
- ECC over an n-bit field needs `9n + 2⌈log₂ n⌉ + 10` (Roetteler et al., ASIACRYPT 2017).
- Finite-field DSA/DH scale like RSA.

Physical-qubit counts depend on the error-correction overhead and aren't reported. For scale, Gidney & Ekerå (2019) estimated RSA-2048 at ~20 million noisy qubits, and Gidney (2025) brought that below 1 million.

**Mosca's inequality.** A key is at risk when *x + y > z*:

- *x*: the key's remaining lifetime,
- *y*: how long whatever it protects must stay trustworthy after expiry (`protection_years_after_expiry`, for example archived signed documents or harvest-now-decrypt-later), and
- *z*: the years until a cryptographically relevant quantum computer exists (`crqc_year`, default 2035, a planning assumption to set by your own policy).

**Score (0–100) and level:**

- Every Shor-breakable key starts at 60.
- Keys already below NIST's 112-bit classical floor, such as RSA-1024, are forced to ≥ 95, which is **critical**.
- A Mosca violation adds 25.
- Slack before the CRQC year removes up to 20.

| score | level |
|---|---|
| ≥ 90 | critical |
| 70–89 | high |
| 40–69 | medium |
| < 40 | low |

FIPS 203/204/205 and SP 800-208 algorithms score as low risk.

## Chains and certificate signatures

`assess_chains` orders a PEM bundle leaf → intermediate → root using issuer and
subject names, preferring authority/subject key identifier matches when they
are available.  Unrelated certificate trees are returned as separate chain
reports.

Each link contains its subject-key assessment and a signature assessment.  The
latter uses the *issuer* certificate's key size for the Shor estimate, then
adds a hash assessment. MD5 and SHA-1 are always critical. SHA-256 and stronger
retain a substantial Grover pre-image margin, which is reported rather than
mistaken for a Shor break.

The chain score is the maximum link score. Its Mosca calculation uses the
longest-lived certificate in the path, because a long-lived root can keep the
whole chain exposed after a short-lived leaf has been replaced. If an issuer
key dominates, the recommendation explicitly calls out that migrating only the
leaf does not repair the trust path.

## Limitations

- `crqc_year` is an assumption, not a prediction. Run the numbers under several values.
- Hybrid (composite) certificates are not yet recognized.
