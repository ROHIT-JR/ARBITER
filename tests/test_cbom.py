"""Tests for CycloneDX 1.6 CBOM export functionality."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from arbiter.pki_risk_scoring import (
    RiskLevel,
    assess_certificates,
    certificates_to_cbom,
    cbom_to_json,
)

NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)


def _self_signed(key, days: int):
    """Generate a self-signed test certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "arbiter.test.cbom")])
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


def test_cbom_structure_matches_cyclonedx_16():
    """Verify CBOM document structure conforms to CycloneDX 1.6."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_pem = _self_signed(rsa.generate_private_key(65537, 2048), 365)
    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    # Verify required top-level fields
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert "serialNumber" in bom
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["version"] == 1
    assert "metadata" in bom
    assert "components" in bom

    # Verify metadata structure
    assert "timestamp" in bom["metadata"]
    assert "tools" in bom["metadata"]
    assert len(bom["metadata"]["tools"]) > 0
    assert bom["metadata"]["tools"][0]["vendor"] == "Anthropic"
    assert "ARBITER" in bom["metadata"]["tools"][0]["name"]


def test_cbom_contains_certificate_component():
    """Verify CBOM includes cryptographic-asset component for certificate."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_pem = _self_signed(rsa.generate_private_key(65537, 2048), 365)
    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    # Find certificate component
    cert_comps = [c for c in bom["components"] if c["type"] == "cryptographic-asset"]
    assert len(cert_comps) > 0

    cert_comp = cert_comps[0]
    assert "cryptoProperties" in cert_comp
    assert cert_comp["cryptoProperties"]["assetType"] == "certificate"
    assert "certificateProperties" in cert_comp["cryptoProperties"]

    # Verify certificate details
    cert_props = cert_comp["cryptoProperties"]["certificateProperties"]
    assert cert_props["certificateFormat"] == "X.509"
    assert "subjectDN" in cert_props
    assert "issuerDN" in cert_props
    assert "serialNumber" in cert_props
    assert "expirationDate" in cert_props


def test_cbom_contains_algorithm_component():
    """Verify CBOM includes cryptographic-algorithm component."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_pem = _self_signed(rsa.generate_private_key(65537, 2048), 365)
    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    # Find algorithm component
    alg_comps = [c for c in bom["components"] if c["type"] == "cryptographic-algorithm"]
    assert len(alg_comps) > 0

    alg_comp = alg_comps[0]
    assert "RSA" in alg_comp["name"]
    assert "properties" in alg_comp

    # Verify properties include NIST quantum security level
    prop_names = [p["name"] for p in alg_comp["properties"]]
    assert "nistQuantumSecurityLevel" in prop_names
    assert "arbiter:primitive-type" in prop_names
    assert "arbiter:risk-score" in prop_names


def test_cbom_contains_key_component():
    """Verify CBOM includes related-crypto-material component for public key."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_pem = _self_signed(rsa.generate_private_key(65537, 2048), 365)
    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    # Find key component
    key_comps = [c for c in bom["components"] if c["type"] == "related-crypto-material"]
    assert len(key_comps) > 0

    key_comp = key_comps[0]
    assert "cryptoProperties" in key_comp
    assert key_comp["cryptoProperties"]["assetType"] == "key"
    assert "keyProperties" in key_comp["cryptoProperties"]

    # Verify key details
    key_props = key_comp["cryptoProperties"]["keyProperties"]
    assert key_props["keyFormat"] == "X.509-SubjectPublicKeyInfo"
    assert "keySize" in key_props
    assert "keyAlgorithm" in key_props


def test_cbom_dependencies_link_certificate_to_algorithm_and_key():
    """Verify CBOM dependencies correctly link certificate->algorithm->key."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_pem = _self_signed(rsa.generate_private_key(65537, 2048), 365)
    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    assert "dependencies" in bom
    assert len(bom["dependencies"]) > 0

    # Find certificate dependency
    cert_deps = [d for d in bom["dependencies"] if d["ref"].startswith("cert-")]
    assert len(cert_deps) > 0

    cert_dep = cert_deps[0]
    assert "dependsOn" in cert_dep
    assert len(cert_dep["dependsOn"]) >= 2  # should depend on algorithm and key

    # Find key dependency
    key_deps = [d for d in bom["dependencies"] if d["ref"].startswith("key-")]
    assert len(key_deps) > 0
    key_dep = key_deps[0]
    assert "dependsOn" in key_dep
    assert any("algorithm" in dep for dep in key_dep["dependsOn"])


def test_cbom_nist_quantum_security_level_for_rsa():
    """Verify RSA gets NIST quantum security level 0 (Shor-breakable)."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_pem = _self_signed(rsa.generate_private_key(65537, 2048), 365)
    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    alg_comp = [c for c in bom["components"] if c["type"] == "cryptographic-algorithm"][0]
    nist_prop = next((p for p in alg_comp["properties"] if p["name"] == "nistQuantumSecurityLevel"), None)
    assert nist_prop is not None
    assert nist_prop["value"] == "0"  # RSA is Shor-breakable


def test_cbom_nist_quantum_security_level_for_pqc():
    """Verify PQC algorithms get NIST quantum security level 3."""
    pytest.importorskip("cryptography")
    pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")

    from cryptography.hazmat.primitives.asymmetric import mldsa
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    # Generate a PQC certificate
    key = mldsa.MLDSA65PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pqc.test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, None)
    )
    cert_pem = cert.public_bytes(Encoding.PEM)

    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    alg_comp = [c for c in bom["components"] if c["type"] == "cryptographic-algorithm"][0]
    nist_prop = next((p for p in alg_comp["properties"] if p["name"] == "nistQuantumSecurityLevel"), None)
    assert nist_prop is not None
    assert nist_prop["value"] == "3"  # PQC gets level 3


def test_cbom_includes_arbiter_risk_properties():
    """Verify CBOM includes ARBITER-specific risk assessment properties."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_pem = _self_signed(rsa.generate_private_key(65537, 2048), 365)
    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    # Check algorithm component for risk properties
    alg_comp = [c for c in bom["components"] if c["type"] == "cryptographic-algorithm"][0]
    prop_names = [p["name"] for p in alg_comp["properties"]]
    assert "arbiter:risk-score" in prop_names
    assert "arbiter:risk-level" in prop_names
    assert "arbiter:family" in prop_names

    # Check certificate component for risk properties
    cert_comp = [c for c in bom["components"] if c["type"] == "cryptographic-asset"][0]
    cert_prop_names = [p["name"] for p in cert_comp["properties"]]
    assert "arbiter:risk-score" in cert_prop_names
    assert "arbiter:risk-level" in cert_prop_names
    assert "arbiter:recommendation" in cert_prop_names


def test_cbom_includes_shor_logical_qubits_for_classical_algorithms():
    """Verify CBOM includes Shor logical qubit estimates for RSA/ECC."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_pem = _self_signed(rsa.generate_private_key(65537, 2048), 365)
    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    alg_comp = [c for c in bom["components"] if c["type"] == "cryptographic-algorithm"][0]
    prop_names = [p["name"] for p in alg_comp["properties"]]
    assert "arbiter:shor-logical-qubits" in prop_names

    # RSA-2048: 2n + 3 = 4099 qubits
    qubit_prop = next((p for p in alg_comp["properties"] if p["name"] == "arbiter:shor-logical-qubits"), None)
    assert qubit_prop is not None
    assert int(qubit_prop["value"]) == 4099


def test_cbom_marks_mosca_violated():
    """Verify CBOM marks when Mosca inequality is violated."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import ec

    # Create a long-lived ECC certificate (will violate Mosca)
    cert_pem = _self_signed(ec.generate_private_key(ec.SECP384R1()), 365 * 15)
    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    alg_comp = [c for c in bom["components"] if c["type"] == "cryptographic-algorithm"][0]
    prop_names = [p["name"] for p in alg_comp["properties"]]
    # Long-lived cert should trigger Mosca
    if certs[0].public_key.mosca_violated:
        assert "arbiter:mosca-violated" in prop_names


def test_cbom_handles_multiple_certificates():
    """Verify CBOM correctly handles multiple certificates in a bundle."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

    # Create a bundle with 3 different certificates
    certs_pem = b"".join(
        [
            _self_signed(rsa.generate_private_key(65537, 2048), 365),
            _self_signed(ec.generate_private_key(ec.SECP256R1()), 365),
            _self_signed(ed25519.Ed25519PrivateKey.generate(), 30),
        ]
    )

    certs = assess_certificates(certs_pem, now=NOW)
    assert len(certs) == 3

    bom = certificates_to_cbom(certs)

    # Should have 3 certificate components
    cert_comps = [c for c in bom["components"] if c["type"] == "cryptographic-asset"]
    assert len(cert_comps) == 3

    # Should have 3 key components
    key_comps = [c for c in bom["components"] if c["type"] == "related-crypto-material"]
    assert len(key_comps) == 3

    # Should have 3 algorithm components (one per unique algorithm)
    alg_comps = [c for c in bom["components"] if c["type"] == "cryptographic-algorithm"]
    assert len(alg_comps) == 3


def test_cbom_deduplicates_repeated_algorithms():
    """Verify CBOM does not duplicate algorithm components for repeated algorithms."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Create two RSA-2048 certificates
    cert_pem = b"".join(
        [
            _self_signed(rsa.generate_private_key(65537, 2048), 365),
            _self_signed(rsa.generate_private_key(65537, 2048), 365),
        ]
    )

    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    # Should have 2 certificate components
    cert_comps = [c for c in bom["components"] if c["type"] == "cryptographic-asset"]
    assert len(cert_comps) == 2

    # Should have only 1 algorithm component (RSA is deduplicated)
    alg_comps = [c for c in bom["components"] if c["type"] == "cryptographic-algorithm"]
    assert len(alg_comps) == 1
    assert "RSA" in alg_comps[0]["name"]


def test_cbom_json_serialization():
    """Verify CBOM can be serialized to valid JSON."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_pem = _self_signed(rsa.generate_private_key(65537, 2048), 365)
    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    # Test JSON serialization
    json_str = cbom_to_json(bom)
    assert isinstance(json_str, str)
    assert json_str.startswith("{")
    assert json_str.endswith("}")

    # Verify it's valid JSON by re-parsing
    import json

    parsed = json.loads(json_str)
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.6"


def test_cbom_round_trip_all_findings_preserved():
    """Verify round-trip: all certificate findings appear in CBOM."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_pem = _self_signed(rsa.generate_private_key(65537, 2048), 365)
    certs = assess_certificates(cert_pem, now=NOW)
    bom = certificates_to_cbom(certs)

    # Extract all subjects from original certificates
    original_subjects = {c.subject for c in certs}

    # Extract all subjects from CBOM certificate components
    cert_comps = [c for c in bom["components"] if c["type"] == "cryptographic-asset"]
    cbom_subjects = set()
    for comp in cert_comps:
        cert_props = comp["cryptoProperties"]["certificateProperties"]
        cbom_subjects.add(cert_props["subjectDN"])

    # Verify all certificates are represented
    assert original_subjects == cbom_subjects


def test_cbom_real_composite_certificate():
    """Verify CBOM exports composite (hybrid) certificate correctly."""
    fixture = Path(__file__).parent / "fixtures" / "lamps_composite_mldsa65_rsa3072_pss_draft07.pem"
    if not fixture.exists():
        pytest.skip("Composite certificate fixture not available")

    certs = assess_certificates(fixture.read_bytes(), now=NOW)
    assert len(certs) > 0
    assert certs[0].composite_info is not None

    bom = certificates_to_cbom(certs)
    assert bom["bomFormat"] == "CycloneDX"

    # Verify hybrid/composite info appears in CBOM
    cert_comp = [c for c in bom["components"] if c["type"] == "cryptographic-asset"][0]
    cert_props = [p["name"] for p in cert_comp["properties"]]
    assert "arbiter:composite-type" in cert_props
