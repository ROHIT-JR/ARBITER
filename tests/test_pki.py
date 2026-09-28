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


def test_mldsa_public_key_class_is_recognised_when_backend_supports_it():
    pytest.importorskip("cryptography")
    mldsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")

    from arbiter.pki_risk_scoring.certificates import _key_info

    key = mldsa.MLDSA65PrivateKey.generate().public_key()
    assert _key_info(key) == ("ML-DSA-65", None)


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


def _certificate(subject, issuer, subject_key, issuer_key, days: int, *, hash_algorithm, ca: bool):
    """Test-only chain fixture, signed by the supplied issuer key."""
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
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    root_key = rsa.generate_private_key(65537, 2048)
    if pqc_leaf:
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa

            leaf_key = mldsa.MLDSA65PrivateKey.generate()
        except ImportError:
            # Older cryptography releases cannot encode ML-DSA X.509 keys;
            # the chain test below uses an explicit scoring-only stub then.
            leaf_key = ec.generate_private_key(ec.SECP384R1())
    else:
        leaf_key = ec.generate_private_key(ec.SECP384R1())
    root, root_pem = _certificate("root", "root", root_key, root_key, 365 * 20, hash_algorithm=hashes.SHA256(), ca=True)
    _, leaf_pem = _certificate(
        "leaf",
        "root",
        leaf_key,
        root_key,
        365,
        hash_algorithm=leaf_hash or hashes.SHA256(),
        ca=False,
    )
    return root, leaf_key, leaf_pem, root_pem


def test_chain_orders_out_of_order_and_identifies_ca_bottleneck(monkeypatch):
    pytest.importorskip("cryptography")
    from arbiter.pki_risk_scoring import assess_chains
    from arbiter.pki_risk_scoring import chain as chain_module

    root, leaf_key, leaf_pem, root_pem = _rsa_chain(pqc_leaf=True)
    original_key_info = chain_module._key_info

    if original_key_info(leaf_key.public_key()) != ("ML-DSA-65", None):
        # Honest compatibility fixture: only the scoring adapter is changed;
        # no unsupported ML-DSA X.509 key is represented as a real key.
        leaf_numbers = leaf_key.public_key().public_numbers()

        def pqc_leaf_stub(key):
            if key.public_numbers() == leaf_numbers:
                return "ML-DSA-65", None
            return original_key_info(key)

        monkeypatch.setattr(chain_module, "_key_info", pqc_leaf_stub)
    report = assess_chains(leaf_pem + root_pem, now=NOW)[0]
    assert [link.subject for link in report.links] == ["CN=leaf", "CN=root"]
    assert report.weakest_link.subject == "CN=root"
    assert report.weakest_link.role == "CA key"
    assert report.level is RiskLevel.HIGH
    assert "migrating the leaf alone" in report.recommendation.lower()
    assert report.links[0].public_key.algorithm == "ML-DSA-65"
    assert root.subject.rfc4514_string() == "CN=root"


def test_sha1_signature_is_critical_regardless_of_key_strength(monkeypatch):
    pytest.importorskip("cryptography")

    from arbiter.pki_risk_scoring import assess_chains
    from arbiter.pki_risk_scoring import chain as chain_module

    _, _, leaf_pem, root_pem = _rsa_chain()
    # Recent cryptography versions intentionally refuse to create SHA-1
    # certificates. The parser's OID mapping is deterministic, so this is an
    # explicit fixture stub for the legacy SHA-1 certificate we must flag.
    monkeypatch.setattr(chain_module, "_signature_info", lambda cert: ("RSA", "SHA-1"))
    report = assess_chains(root_pem + leaf_pem, now=NOW)[0]
    leaf = report.links[0]
    assert leaf.signature.hash.algorithm == "SHA-1"
    assert leaf.signature.hash.level is RiskLevel.CRITICAL
    assert leaf.signature.level is RiskLevel.CRITICAL


def test_unrelated_certificates_are_separate_chains():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    from arbiter.pki_risk_scoring import assess_chains

    first = _self_signed(rsa.generate_private_key(65537, 2048), 365)
    second = _self_signed(rsa.generate_private_key(65537, 2048), 365)
    bundle = first + second
    chains = assess_chains(bundle, now=NOW)
    assert len(chains) == 2
    assert all(len(chain.links) == 1 for chain in chains)
