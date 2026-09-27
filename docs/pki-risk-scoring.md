# PKI quantum-risk scoring

`arbiter.pki_risk_scoring` answers a practical question that doesn't need quantum hardware: **which of our classical keys and certificates does a future quantum computer threaten, and how urgently?**

```python
from arbiter.pki_risk_scoring import assess_certificates, assess_key

assess_key("RSA", 2048, expires=some_datetime).to_dict()
for r in assess_certificates(open("bundle.pem", "rb").read()):
    print(r.subject, r.public_key.level, r.public_key.recommendation)
```

It is also available over the API as `POST /pki/assess` (a PEM bundle) and `POST /pki/assess-key`. Certificate parsing needs `pip install -e ".[pki]"`.

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

## Limitations

- `crqc_year` is an assumption, not a prediction. Run the numbers under several values.
- Only the subject public key is scored. The issuer's signature algorithm is reported but not yet scored separately.
- Hybrid (composite) certificates are not yet recognized.
