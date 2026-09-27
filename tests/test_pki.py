from datetime import datetime, timedelta, timezone

import pytest

from arbiter.pki_risk_scoring import RiskLevel, assess_key

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
