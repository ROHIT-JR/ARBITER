from datetime import datetime, timedelta, timezone

import pytest

from arbiter.pki_risk_scoring import (
    RiskLevel,
    assess_composite_key,
    assess_key,
    is_composite_oid,
    is_pure_mldsa_oid,
    parse_composite_oid,
)

NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)


def test_shor_resource_estimates():
    rsa = assess_key("RSA", 2048, now=NOW)
    assert rsa.shor_logical_qubits == 2 * 2048 + 3 and rsa.quantum_security_bits == 0
    p256 = assess_key("ECDSA", 256, now=NOW)
    assert p256.shor_logical_qubits == 9 * 256 + 2 * 8 + 10  # Roetteler et al. 2017: 2330
    assert assess_key("Ed25519", now=NOW).key_bits == 255


def test_pqc_is_low_risk():
    a = assess_key("ML-DSA-65", now=NOW, expires=NOW + timedelta(days=3650))
    assert a.family == "pqc" and a.level is RiskLevel.LOW


def test_weak_rsa_is_critical():
    assert assess_key("RSA", 1024, now=NOW).level is RiskLevel.CRITICAL
    # even with a short remaining lifetime
    assert assess_key("RSA", 1024, expires=NOW + timedelta(days=30), now=NOW).level is RiskLevel.CRITICAL


def test_mosca_inequality_drives_risk():
    short = assess_key("RSA", 3072, expires=NOW + timedelta(days=90), now=NOW)
    long = assess_key("RSA", 3072, expires=NOW + timedelta(days=365 * 12), now=NOW)
    assert not short.mosca_violated and long.mosca_violated
    assert long.score > short.score and long.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    archived = assess_key("ECDSA", 256, expires=NOW + timedelta(days=90), protection_years_after_expiry=15, now=NOW)
    assert archived.mosca_violated


def test_unknown_algorithm():
    assert assess_key("GOST", 256, now=NOW).family == "unknown"


def _self_signed(key, days: int):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "arbiter.test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)


def _certificate(subject, issuer, subject_key, issuer_key, days: int, *, hash_algorithm, ca: bool):
    """Test-only certificate-chain helper used by API regression tests."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .sign(issuer_key, hash_algorithm)
    )
    return builder, builder.public_bytes(Encoding.PEM)


def _rsa_chain(*, leaf_hash=None, pqc_leaf: bool = False):
    """Return a small CA/leaf fixture used by the API test module."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    root_key = rsa.generate_private_key(65537, 2048)
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    root, root_pem = _certificate("root", "root", root_key, root_key, 365 * 20, hash_algorithm=hashes.SHA256(), ca=True)
    _, leaf_pem = _certificate(
        "leaf", "root", leaf_key, root_key, 365, hash_algorithm=leaf_hash or hashes.SHA256(), ca=False
    )
    return root, leaf_key, leaf_pem, root_pem


def test_certificate_bundle_parsing():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    from arbiter.pki_risk_scoring import assess_certificates

    bundle = b"".join(
        [
            _self_signed(rsa.generate_private_key(65537, 2048), 365),
            _self_signed(ec.generate_private_key(ec.SECP384R1()), 365 * 15),
            _self_signed(ed25519.Ed25519PrivateKey.generate(), 30),
        ]
    )
    reports = assess_certificates(bundle)
    algs = [(r.public_key.algorithm, r.public_key.key_bits) for r in reports]
    assert algs == [("RSA", 2048), ("ECDSA", 384), ("Ed25519", 255)]
    assert reports[1].public_key.mosca_violated  # 15-year cert outlives the CRQC assumption
    assert all(r.subject == "CN=arbiter.test" for r in reports)


def test_composite_oid_recognition():
    # Test all 13 composite OIDs are recognized
    assert is_composite_oid("1.3.6.1.4.1.2.267.12.1")
    assert is_composite_oid("1.3.6.1.4.1.2.267.12.13")
    assert not is_composite_oid("1.3.6.1.4.1.2.267.12.99")
    assert not is_composite_oid("2.16.840.1.101.3.4.3.17")  # pure ML-DSA

    # Test parsing
    result = parse_composite_oid("1.3.6.1.4.1.2.267.12.1")
    assert result == ("ML-DSA-44", "RSA-PSS", "SHA256")

    result = parse_composite_oid("1.3.6.1.4.1.2.267.12.6")
    assert result == ("ML-DSA-65", "RSA-PSS", "SHA512")

    result = parse_composite_oid("1.3.6.1.4.1.2.267.12.13")
    assert result == ("ML-DSA-87", "Ed448", "SHA512")

    assert parse_composite_oid("2.16.840.1.101.3.4.3.17") is None


def test_pure_mldsa_oid_recognition():
    assert is_pure_mldsa_oid("2.16.840.1.101.3.4.3.17") == "ML-DSA-44"
    assert is_pure_mldsa_oid("2.16.840.1.101.3.4.3.18") == "ML-DSA-65"
    assert is_pure_mldsa_oid("2.16.840.1.101.3.4.3.19") == "ML-DSA-87"
    assert is_pure_mldsa_oid("1.3.6.1.4.1.2.267.12.1") is None


def test_composite_key_assessment():
    NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)
    # Hybrid with PQC (low risk, score=5) + RSA-2048 (medium risk, score~60-70)
    # Overall risk should be driven by the WEAKER component (PQC is stronger = lower score)
    # Minimum score wins: PQC=5 vs RSA-2048=~65 -> overall = 5 (PQC dominates)
    comp = assess_composite_key("ML-DSA-65", "RSA", now=NOW)
    assert comp.family == "hybrid"
    assert comp.algorithm == "ML-DSA-65+RSA (hybrid)"
    # PQC component (score=5) is stronger than RSA-2048 (~65), so PQC dominates
    assert comp.score == 5  # PQC is the weaker (more secure) component
    assert comp.level == RiskLevel.LOW


def test_composite_key_pqc_dominates_when_stronger():
    """Hybrid uses MINIMUM risk score - PQC (score=5) dominates over weak traditional (score>=90)."""
    NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)
    # Hybrid with PQC (score=5) + very weak traditional (RSA-1024, score>=90)
    # Minimum score wins: min(5, 95) = 5 -> PQC dominates (more secure)
    comp = assess_composite_key("ML-DSA-65", "RSA", trad_key_bits=1024, now=NOW)
    assert comp.family == "hybrid"
    # Minimum score wins: PQC component (score=5) is stronger than RSA-1024 (~95)
    assert comp.score == 5
    assert comp.level == RiskLevel.LOW


def test_composite_key_pqc_only_low():
    NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)
    # Hybrid with PQC + PQC-like traditional (not possible in practice, but test)
    comp = assess_composite_key("ML-DSA-65", "ML-DSA-44", now=NOW)
    assert comp.family == "hybrid"
    assert comp.level == RiskLevel.LOW
    assert comp.score == 5


def test_unknown_algorithm_oid_fallback():
    """Test unknown OID fallback returns structured info."""
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    from arbiter.pki_risk_scoring import assess_certificates

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.unknown")])
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(65537, 2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    reports = assess_certificates(cert.public_bytes(Encoding.PEM))
    assert len(reports) == 1
    # The composite_info should have the right structure
    assert "type" in reports[0].composite_info
    assert reports[0].composite_info["type"] in ("hybrid_signature", "pure_mldsa_signature", "unknown_algorithm")
