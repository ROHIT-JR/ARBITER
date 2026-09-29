"""Parse X.509 certificates (PEM or DER) and score their quantum risk.

Needs the optional ``cryptography`` dependency (``pip install arbiter-qds[pki]``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from arbiter.pki_risk_scoring.scoring import (
    COMPOSITE_OID_DRAFT,
    DEFAULT_CRQC_YEAR,
    PURE_SLHDSA_OIDS,
    RiskAssessment,
    assess_composite_key,
    assess_key,
    curve_bits,
    is_pure_mldsa_oid,
    parse_composite_oid,
)

_PEM_BLOCK = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def _der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one bounded DER tag/length/value without decoding key material."""
    if offset + 2 > len(data):
        raise ValueError("truncated DER value")
    tag = data[offset]
    length_byte = data[offset + 1]
    offset += 2
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    else:
        length = length_byte
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, data[offset:end], end


def _decode_oid(value: bytes) -> str:
    if not value:
        raise ValueError("empty DER OID")
    first = value[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    current = 0
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(current)
            current = 0
    if current:
        raise ValueError("truncated DER OID")
    return ".".join(str(part) for part in parts)


def _public_key_oid(cert) -> str:
    """Read SubjectPublicKeyInfo's OID even when cryptography cannot load its key."""
    tag, tbs, _ = _der_tlv(cert.tbs_certificate_bytes, 0)
    if tag != 0x30:
        raise ValueError("certificate TBS is not a DER sequence")
    offset = 0
    tag, _, end = _der_tlv(tbs, offset)
    if tag == 0xA0:  # optional explicit version
        offset = end
    for _ in range(5):  # serial, signature, issuer, validity, subject
        _, _, offset = _der_tlv(tbs, offset)
    tag, spki, _ = _der_tlv(tbs, offset)
    if tag != 0x30:
        raise ValueError("missing SubjectPublicKeyInfo")
    return _algorithm_oid(spki)


def _algorithm_oid(value: bytes) -> str:
    """Extract the first AlgorithmIdentifier OID from DER sequence content."""
    tag, algorithm, _ = _der_tlv(value, 0)
    if tag != 0x30:
        raise ValueError("missing public-key AlgorithmIdentifier")
    tag, oid, _ = _der_tlv(algorithm, 0)
    if tag != 0x06:
        raise ValueError("missing public-key algorithm OID")
    return _decode_oid(oid)


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

    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa

        for level in (44, 65, 87):
            if isinstance(public_key, getattr(mldsa, f"MLDSA{level}PublicKey")):
                return f"ML-DSA-{level}", None
    except ImportError:
        pass

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
        from cryptography.exceptions import UnsupportedAlgorithm

        key_oid = _public_key_oid(cert)
        try:
            alg, bits = _key_info(cert.public_key())
        except (UnsupportedAlgorithm, ValueError):
            alg, bits = is_pure_mldsa_oid(key_oid) or PURE_SLHDSA_OIDS.get(key_oid) or key_oid, None
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
                "draft_version": COMPOSITE_OID_DRAFT,
                "pqc_algorithm": pqc_alg,
                "traditional_algorithm": trad_alg,
                "hash_algorithm": hash_alg,
                "signature_oid": sig_oid_dotted,
                "public_key_oid": key_oid,
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
        elif slh_alg := PURE_SLHDSA_OIDS.get(sig_oid_dotted):
            composite_info = {
                "type": "pure_slh_dsa_signature",
                "algorithm": slh_alg,
                "signature_oid": sig_oid_dotted,
            }
        elif alg == key_oid:
            composite_info = {
                "type": "unknown_algorithm",
                "signature_oid": sig_oid_dotted,
                "signature_algorithm_name": sig_alg_name,
                "public_key_oid": key_oid,
            }

        # ITU-T X.509 (2019) alternative public-key/signature extensions.
        # This reports their structure and algorithm IDs; signature validity
        # remains the responsibility of a certificate-chain verifier.
        extensions = {ext.oid.dotted_string: ext.value for ext in cert.extensions}
        if all(oid in extensions for oid in ("2.5.29.72", "2.5.29.73", "2.5.29.74")):
            alt_spki = extensions["2.5.29.72"].value
            tag, alt_spki_content, _ = _der_tlv(alt_spki, 0)
            if tag != 0x30:
                raise ValueError("malformed alternative SubjectPublicKeyInfo")
            alt_key_oid = _algorithm_oid(alt_spki_content)
            tag, alt_alg_content, _ = _der_tlv(extensions["2.5.29.73"].value, 0)
            if tag != 0x30:
                raise ValueError("malformed alternative signature AlgorithmIdentifier")
            alt_sig_oid = _decode_oid(_der_tlv(alt_alg_content, 0)[1])
            alt_alg = is_pure_mldsa_oid(alt_key_oid) or PURE_SLHDSA_OIDS.get(alt_key_oid)
            composite_info = {
                "type": "alternative_signature",
                "public_key_oid": key_oid,
                "alternative_public_key_oid": alt_key_oid,
                "alternative_signature_oid": alt_sig_oid,
                "alternative_signature_algorithm": alt_alg,
            }
            if alt_alg:
                composite_assessment = assess_composite_key(
                    alt_alg,
                    alg,
                    trad_key_bits=bits,
                    expires=not_after,
                    protection_years_after_expiry=protection_years_after_expiry,
                    crqc_year=crqc_year,
                    now=now,
                )

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
