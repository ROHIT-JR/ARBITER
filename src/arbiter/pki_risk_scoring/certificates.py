"""Parse X.509 certificates (PEM or DER) and score their quantum risk.

Needs the optional ``cryptography`` dependency (``pip install arbiter-qds[pki]``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from arbiter.pki_risk_scoring.scoring import (
    DEFAULT_CRQC_YEAR,
    RiskAssessment,
    assess_composite_key,
    assess_key,
    curve_bits,
    is_pure_mldsa_oid,
    parse_composite_oid,
)

_PEM_BLOCK = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


@dataclass
class CertificateReport:
    subject: str
    issuer: str
    serial: str
    not_after: str
    signature_algorithm: str
    public_key: RiskAssessment
    composite_info: dict | None = None

    def to_dict(self) -> dict:
        d = {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "not_after": self.not_after,
            "signature_algorithm": self.signature_algorithm,
            "public_key": self.public_key.to_dict(),
        }
        if self.composite_info is not None:
            d["composite_info"] = self.composite_info
        return d


def _key_info(public_key) -> tuple[str, int | None]:
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519

    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", curve_bits(public_key.curve.name) or public_key.curve.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 255
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    if isinstance(public_key, x25519.X25519PublicKey):
        return "X25519", 255
    if isinstance(public_key, x448.X448PublicKey):
        return "X448", 448
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    return type(public_key).__name__, None


def load_certificates(data: bytes) -> list:
    from cryptography import x509

    blocks = _PEM_BLOCK.findall(data)
    if blocks:
        return [x509.load_pem_x509_certificate(b) for b in blocks]
    return [x509.load_der_x509_certificate(data)]


def assess_certificates(
    data: bytes,
    *,
    protection_years_after_expiry: float = 0.0,
    crqc_year: int = DEFAULT_CRQC_YEAR,
    now: datetime | None = None,
) -> list[CertificateReport]:
    """Assess every certificate in a PEM bundle, or a single DER certificate."""
    reports = []
    for cert in load_certificates(data):
        alg, bits = _key_info(cert.public_key())
        not_after = cert.not_valid_after_utc
        sig_oid = cert.signature_algorithm_oid
        sig_oid_dotted = sig_oid.dotted_string
        sig_alg_name = getattr(sig_oid, "_name", None) or sig_oid_dotted

        composite_info = None
        composite_assessment = None

        # Check for hybrid/composite signature algorithm OID (draft-ietf-lamps-pq-composite-sigs)
        composite = parse_composite_oid(sig_oid_dotted)
        if composite:
            pqc_alg, trad_alg, hash_alg = composite
            composite_info = {
                "type": "hybrid_signature",
                "draft_version": "draft-ietf-lamps-pq-composite-sigs-07",
                "pqc_algorithm": pqc_alg,
                "traditional_algorithm": trad_alg,
                "hash_algorithm": hash_alg,
                "signature_oid": sig_oid_dotted,
            }
            composite_assessment = assess_composite_key(
                pqc_alg,
                trad_alg,
                expires=not_after,
                protection_years_after_expiry=protection_years_after_expiry,
                crqc_year=crqc_year,
                now=now,
            )
        # Check for pure ML-DSA signature algorithm OID (RFC 9881)
        elif mldsa_alg := is_pure_mldsa_oid(sig_oid_dotted):
            composite_info = {
                "type": "pure_mldsa_signature",
                "algorithm": mldsa_alg,
                "signature_oid": sig_oid_dotted,
            }
        # Unknown OID: attempt ASN.1 parsing for algorithm identifier fallback
        else:
            composite_info = {
                "type": "unknown_algorithm",
                "signature_oid": sig_oid_dotted,
                "signature_algorithm_name": sig_alg_name,
            }

        # Use composite assessment if available, otherwise fall back to public key assessment
        if composite_assessment:
            public_key_assessment = composite_assessment
        else:
            public_key_assessment = assess_key(
                alg,
                bits,
                expires=not_after,
                protection_years_after_expiry=protection_years_after_expiry,
                crqc_year=crqc_year,
                now=now,
            )

        reports.append(
            CertificateReport(
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                serial=format(cert.serial_number, "x"),
                not_after=not_after.isoformat(),
                signature_algorithm=sig_alg_name,
                public_key=public_key_assessment,
                composite_info=composite_info,
            )
        )
    return reports
