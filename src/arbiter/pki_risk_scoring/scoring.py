"""Quantum-risk scoring for classical public-key material.

For each key we estimate the resources a fault-tolerant quantum computer
would need to break it, and turn that plus the certificate lifetime into a
risk level via **Mosca's inequality**: a signature or key is at risk if

    (years it must stay trustworthy) > (years until a cryptographically
                                        relevant quantum computer, CRQC)

Resource estimates (logical qubits for Shor's algorithm):

* RSA-n:  2n + 3              (Beauregard 2003, circuit for Shor factoring)
* ECC over an n-bit prime field:
          9n + 2*ceil(log2 n) + 10   (Roetteler et al., ASIACRYPT 2017)
* Symmetric / hash: Grover's algorithm halves the security level; no Shor break.

For scale: Gidney & Ekera (2019) estimated RSA-2048 at ~20 million noisy
qubits and 8 hours, and Gidney (2025) brought that below 1 million noisy
qubits. These are *physical* counts and depend on the error-correction
overhead. We report logical counts, which are hardware-independent.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum

DEFAULT_CRQC_YEAR = 2035  # planning assumption; override per policy

# Algorithms standardised as quantum-resistant (FIPS 203/204/205, SP 800-208).
PQC_ALGORITHMS = {
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA",
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
    "FN-DSA",
    "FALCON",
    "XMSS",
    "LMS",
}

# Composite ML-DSA prototype OIDs from draft-ietf-lamps-pq-composite-sigs-07,
# Table 1.  These are draft-specific and must not be mistaken for final IANA OIDs.
COMPOSITE_OID_DRAFT = "draft-ietf-lamps-pq-composite-sigs-07"
COMPOSITE_OID_MAP = {
    "2.16.840.1.114027.80.9.1.0": ("ML-DSA-44", "RSA-2048-PSS", "SHA256"),
    "2.16.840.1.114027.80.9.1.1": ("ML-DSA-44", "RSA-2048-PKCS15", "SHA256"),
    "2.16.840.1.114027.80.9.1.2": ("ML-DSA-44", "Ed25519", "SHA512"),
    "2.16.840.1.114027.80.9.1.3": ("ML-DSA-44", "ECDSA-P256", "SHA256"),
    "2.16.840.1.114027.80.9.1.4": ("ML-DSA-65", "RSA-3072-PSS", "SHA512"),
    "2.16.840.1.114027.80.9.1.5": ("ML-DSA-65", "RSA-3072-PKCS15", "SHA512"),
    "2.16.840.1.114027.80.9.1.6": ("ML-DSA-65", "RSA-4096-PSS", "SHA512"),
    "2.16.840.1.114027.80.9.1.7": ("ML-DSA-65", "RSA-4096-PKCS15", "SHA512"),
    "2.16.840.1.114027.80.9.1.8": ("ML-DSA-65", "ECDSA-P256", "SHA512"),
    "2.16.840.1.114027.80.9.1.9": ("ML-DSA-65", "ECDSA-P384", "SHA512"),
    "2.16.840.1.114027.80.9.1.10": ("ML-DSA-65", "ECDSA-brainpoolP256r1", "SHA512"),
    "2.16.840.1.114027.80.9.1.11": ("ML-DSA-65", "Ed25519", "SHA512"),
    "2.16.840.1.114027.80.9.1.12": ("ML-DSA-87", "ECDSA-P384", "SHA512"),
    "2.16.840.1.114027.80.9.1.13": ("ML-DSA-87", "ECDSA-brainpoolP384r1", "SHA512"),
    "2.16.840.1.114027.80.9.1.14": ("ML-DSA-87", "Ed448", "SHAKE256"),
    "2.16.840.1.114027.80.9.1.15": ("ML-DSA-87", "RSA-3072-PSS", "SHA512"),
    "2.16.840.1.114027.80.9.1.16": ("ML-DSA-87", "RSA-4096-PSS", "SHA512"),
    "2.16.840.1.114027.80.9.1.17": ("ML-DSA-87", "ECDSA-P521", "SHA512"),
}

# Pure ML-DSA OIDs from RFC 9881
PURE_MLDSA_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}

# Pure SLH-DSA public-key/signature OIDs, RFC 9909 section 2.
_SLH_PARAMETERS = (
    "SHA2-128s",
    "SHA2-128f",
    "SHA2-192s",
    "SHA2-192f",
    "SHA2-256s",
    "SHA2-256f",
    "SHAKE-128s",
    "SHAKE-128f",
    "SHAKE-192s",
    "SHAKE-192f",
    "SHAKE-256s",
    "SHAKE-256f",
)
PURE_SLHDSA_OIDS = {
    f"2.16.840.1.101.3.4.3.{number}": f"SLH-DSA-{name}" for number, name in enumerate(_SLH_PARAMETERS, start=20)
}


def parse_composite_oid(oid_dotted: str) -> tuple[str, str, str] | None:
    """Parse a composite algorithm OID and return (pqc_alg, trad_alg, hash_alg).

    Returns None if the OID is not a recognised composite ML-DSA OID.
    """
    return COMPOSITE_OID_MAP.get(oid_dotted)


def is_composite_oid(oid_dotted: str) -> bool:
    """Check if an OID is a recognised composite ML-DSA OID."""
    return oid_dotted in COMPOSITE_OID_MAP


def is_pure_mldsa_oid(oid_dotted: str) -> str | None:
    """Check if an OID is a pure ML-DSA OID (RFC 9881). Returns algorithm name or None."""
    return PURE_MLDSA_OIDS.get(oid_dotted)


def assess_composite_key(
    pqc_algorithm: str,
    traditional_algorithm: str,
    *,
    pqc_key_bits: int | None = None,
    trad_key_bits: int | None = None,
    expires: datetime | None = None,
    protection_years_after_expiry: float = 0.0,
    crqc_year: int = DEFAULT_CRQC_YEAR,
    now: datetime | None = None,
) -> RiskAssessment:
    """Assess both components; either surviving component protects the hybrid."""
    now = now or datetime.now(timezone.utc)

    trad_assessment_alg = traditional_algorithm
    if traditional_algorithm.startswith("RSA-"):
        trad_assessment_alg = "RSA"
        if trad_key_bits is None:
            trad_key_bits = int(traditional_algorithm.split("-")[1])
    elif traditional_algorithm.startswith("ECDSA-"):
        trad_assessment_alg = "ECDSA"
        if trad_key_bits is None:
            suffix = traditional_algorithm.split("-", 1)[1]
            trad_key_bits = int(suffix[1:]) if suffix.startswith("P") else curve_bits(suffix)

    pqc_assessment = assess_key(
        pqc_algorithm,
        pqc_key_bits,
        expires=expires,
        protection_years_after_expiry=protection_years_after_expiry,
        crqc_year=crqc_year,
        now=now,
    )
    trad_assessment = assess_key(
        trad_assessment_alg,
        trad_key_bits,
        expires=expires,
        protection_years_after_expiry=protection_years_after_expiry,
        crqc_year=crqc_year,
        now=now,
    )

    # The lower risk component can retain security after the other fails.
    if pqc_assessment.score <= trad_assessment.score:
        weaker = pqc_assessment
    else:
        weaker = trad_assessment

    return RiskAssessment(
        algorithm=f"{pqc_algorithm}+{traditional_algorithm} (hybrid)",
        key_bits=None,
        family="hybrid",
        classical_security_bits=None,
        quantum_security_bits=None,
        shor_logical_qubits=None,
        expires=expires.isoformat() if expires else None,
        years_protection_needed=weaker.years_protection_needed,
        crqc_year=crqc_year,
        mosca_violated=weaker.mosca_violated,
        score=weaker.score,
        level=weaker.level,
        recommendation=(
            f"Hybrid certificate with {pqc_algorithm} (PQC) and {traditional_algorithm} (traditional). "
            f"The stronger surviving component ({weaker.algorithm}) governs overall risk; "
            f"the classical component has quantum exposure: {trad_assessment.recommendation}"
        ),
    )


# Classical security (bits) of RSA moduli, NIST SP 800-57 Part 1.
_RSA_CLASSICAL = [(1024, 80), (2048, 112), (3072, 128), (7680, 192), (15360, 256)]

_CURVE_BITS = {
    "secp256r1": 256,
    "prime256v1": 256,
    "p-256": 256,
    "secp384r1": 384,
    "p-384": 384,
    "secp521r1": 521,
    "p-521": 521,
    "secp256k1": 256,
    "ed25519": 255,
    "x25519": 255,
    "ed448": 448,
    "x448": 448,
    "brainpoolp256r1": 256,
    "brainpoolp384r1": 384,
    "brainpoolp512r1": 512,
}


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskAssessment:
    algorithm: str
    key_bits: int | None
    family: str  # rsa | ecc | ffdlp | pqc | unknown
    classical_security_bits: int | None
    quantum_security_bits: int | None  # 0 when Shor breaks it outright
    shor_logical_qubits: int | None
    expires: str | None
    years_protection_needed: float | None
    crqc_year: int
    mosca_violated: bool
    score: int  # 0 (safe) .. 100 (break it today)
    level: RiskLevel
    recommendation: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["level"] = self.level.value
        return d


def _rsa_classical_bits(n: int) -> int:
    bits = 0
    for size, sec in _RSA_CLASSICAL:
        if n >= size:
            bits = sec
    return bits if bits else max(1, n // 16)


def _years_until(when: datetime | None, now: datetime) -> float | None:
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (when - now).total_seconds() / (365.25 * 86400)


def curve_bits(curve: str) -> int | None:
    return _CURVE_BITS.get(curve.lower())


def assess_key(
    algorithm: str,
    key_bits: int | None = None,
    *,
    expires: datetime | None = None,
    protection_years_after_expiry: float = 0.0,
    crqc_year: int = DEFAULT_CRQC_YEAR,
    now: datetime | None = None,
) -> RiskAssessment:
    """Score one public key.

    ``algorithm`` is e.g. ``"RSA"``, ``"ECDSA"``, ``"Ed25519"``, ``"ML-DSA-65"``.
    ``key_bits`` is the modulus size for RSA and the field size for ECC.
    ``protection_years_after_expiry`` covers data or signatures that must
    remain trustworthy after the certificate expires (e.g. archived signed
    documents, or harvest-now-decrypt-later for key exchange).
    """
    now = now or datetime.now(timezone.utc)
    alg = algorithm.upper().replace("_", "-")
    years_left = _years_until(expires, now)
    needed = None if years_left is None else max(0.0, years_left) + protection_years_after_expiry
    years_to_crqc = crqc_year - (now.year + (now.timetuple().tm_yday - 1) / 365.25)

    if any(alg.startswith(p) for p in PQC_ALGORITHMS):
        return RiskAssessment(
            algorithm,
            key_bits,
            "pqc",
            None,
            None,
            None,
            expires.isoformat() if expires else None,
            needed,
            crqc_year,
            False,
            5,
            RiskLevel.LOW,
            "Quantum-resistant algorithm; keep monitoring NIST guidance.",
        )

    if alg in ("RSA", "RSA-PSS", "RSAES-OAEP"):
        family = "rsa"
        n = key_bits or 2048
        classical = _rsa_classical_bits(n)
        qubits = 2 * n + 3
    elif alg in ("EC", "ECDSA", "ECDH", "ED25519", "ED448", "X25519", "X448", "EDDSA", "DSA", "DH"):
        family = "ffdlp" if alg in ("DSA", "DH") else "ecc"  # finite-field DLP scales like RSA under Shor
        if alg in ("ED25519", "X25519"):
            key_bits = key_bits or 255
        if alg in ("ED448", "X448"):
            key_bits = key_bits or 448
        n = key_bits if key_bits is not None and key_bits > 0 else 256
        if family == "ecc":
            classical = n // 2
            qubits = 9 * n + 2 * math.ceil(math.log2(n)) + 10
        else:
            classical = _rsa_classical_bits(n)
            qubits = 2 * n + 3
    else:
        return RiskAssessment(
            algorithm,
            key_bits,
            "unknown",
            None,
            None,
            None,
            expires.isoformat() if expires else None,
            needed,
            crqc_year,
            False,
            50,
            RiskLevel.MEDIUM,
            "Unrecognised algorithm; review manually.",
        )

    mosca = needed is not None and needed > years_to_crqc
    # Base score: every Shor-breakable key starts high; weak classical keys
    # and Mosca violations push it higher; distant expiry within the safe
    # window pulls it down a little.
    score = 60
    if classical < 112:
        score += 30  # already below NIST's 2030 minimum, even classically
    if mosca:
        score += 25
    elif needed is not None:
        slack = years_to_crqc - needed
        score -= int(min(20, max(0, slack) * 2))
    if classical < 112:
        score = max(score, 95)  # classically weak: no lifetime credit
    score = max(0, min(100, score))
    level = (
        RiskLevel.CRITICAL
        if score >= 90
        else RiskLevel.HIGH
        if score >= 70
        else RiskLevel.MEDIUM
        if score >= 40
        else RiskLevel.LOW
    )

    target = "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
    if classical < 112:
        rec = f"Replace now: below the classical security floor. Migrate to {target}."
    elif mosca:
        rec = f"Lifetime extends past the assumed CRQC year {crqc_year}; migrate to {target} or a hybrid certificate."
    else:
        rec = f"Shor-vulnerable; plan migration to {target} before {crqc_year}."
    return RiskAssessment(
        algorithm,
        n,
        family,
        classical,
        0,
        qubits,
        expires.isoformat() if expires else None,
        needed,
        crqc_year,
        mosca,
        score,
        level,
        rec,
    )
