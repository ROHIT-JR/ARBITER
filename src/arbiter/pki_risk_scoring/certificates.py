"""Parse X.509 certificates (PEM or DER) and score their quantum risk.

Needs the optional ``cryptography`` dependency (``pip install arbiter-qds[pki]``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from arbiter.pki_risk_scoring.scoring import DEFAULT_CRQC_YEAR, RiskAssessment, assess_key, curve_bits

_PEM_BLOCK = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


@dataclass
class CertificateReport:
    subject: str
    issuer: str
    serial: str
    not_after: str
    signature_algorithm: str
    public_key: RiskAssessment

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "not_after": self.not_after,
            "signature_algorithm": self.signature_algorithm,
            "public_key": self.public_key.to_dict(),
        }


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
        reports.append(
            CertificateReport(
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                serial=format(cert.serial_number, "x"),
                not_after=not_after.isoformat(),
                signature_algorithm=getattr(sig_oid, "_name", None) or sig_oid.dotted_string,
                public_key=assess_key(
                    alg,
                    bits,
                    expires=not_after,
                    protection_years_after_expiry=protection_years_after_expiry,
                    crqc_year=crqc_year,
                    now=now,
                ),
            )
        )
    return reports
