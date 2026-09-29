"""Export PKI findings as CycloneDX 1.6 Cryptography Bill of Materials (CBOM).

CycloneDX 1.6 introduces the Cryptography Bill of Materials (CBOM) format,
which standardizes the representation of cryptographic assets for inventory,
compliance, and migration workflows.

Reference: https://cyclonedx.org/docs/1.6/json/

This module converts ARBITER's PKI risk assessments (certificates, algorithms,
keys) into CycloneDX 1.6 components with proper cryptographic dependencies.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from arbiter.pki_risk_scoring.certificates import CertificateReport
from arbiter.pki_risk_scoring.scoring import RiskAssessment


def _nist_quantum_security_level(risk_assessment: RiskAssessment) -> int:
    """Map ARBITER risk assessment to NIST quantum security level (0-5).

    NIST SP 800-208 defines levels:
    - 1: AES-128, SHA-256 equivalent (256-bit post-quantum)
    - 2: AES-192, SHA-384 equivalent (384-bit post-quantum)
    - 3: AES-256, SHA-512 equivalent (512-bit post-quantum)
    - 4: Reserved for future use
    - 5: Reserved for future use

    For Shor-breakable algorithms, return 0 (no quantum resistance).
    For PQC algorithms (ML-DSA, SLH-DSA, etc.), return 3.
    """
    if risk_assessment.family == "pqc":
        return 3  # PQC algorithms meet level 3 (512-bit post-quantum)
    if risk_assessment.family in ("rsa", "ecc", "ffdlp"):
        return 0  # Shor-breakable (no quantum resistance)
    return 0  # Unknown/unsupported


def _algorithm_to_cbom_component(algorithm: str, key_bits: int | None) -> dict[str, Any]:
    """Create a CycloneDX cryptographic algorithm component.

    Maps the ARBITER algorithm name to a CycloneDX component with:
    - name: algorithm name
    - type: "cryptographic-algorithm"
    - assetType: "algorithm"
    - version: key size (for parameterized algorithms)
    - properties: nistQuantumSecurityLevel, primitive type
    """
    # Map algorithm to NIST primitive type
    if algorithm.startswith("RSA"):
        primitive = "asymmetric-encryption"
    elif algorithm.startswith("ECDSA"):
        primitive = "asymmetric-signature"
    elif algorithm in ("Ed25519", "Ed448"):
        primitive = "asymmetric-signature"
    elif algorithm.startswith("ML-DSA"):
        primitive = "asymmetric-signature"
    elif algorithm.startswith("ML-KEM"):
        primitive = "asymmetric-encryption"
    elif algorithm.startswith("SLH-DSA"):
        primitive = "asymmetric-signature"
    elif "DSA" in algorithm or algorithm == "DH":
        primitive = "asymmetric-encryption" if algorithm == "DH" else "asymmetric-signature"
    elif algorithm.startswith("SHA") or algorithm.startswith("SHAKE"):
        primitive = "hash"
    else:
        primitive = "unknown"

    component = {
        "type": "cryptographic-algorithm",
        "bom-ref": f"algorithm-{algorithm.replace(' ', '_').replace('+', '_')}",
        "name": algorithm,
        "properties": [
            {
                "name": "arbiter:primitive-type",
                "value": primitive,
            }
        ],
    }

    # Add key size as parameterSetIdentifier for algorithms that support it
    if key_bits is not None:
        component["properties"].append(
            {
                "name": "arbiter:key-bits",
                "value": str(key_bits),
            }
        )

    return component


def _create_certificate_component(cert: CertificateReport, bom_ref_prefix: str = "") -> dict[str, Any]:
    """Create a CycloneDX cryptographic-asset component for an X.509 certificate."""
    ref = f"{bom_ref_prefix}cert-{cert.serial[:16]}"

    # Build the component
    component: dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": f"Certificate: {cert.subject}",
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {
                "certificateFormat": "X.509",
                "subjectDN": cert.subject,
                "issuerDN": cert.issuer,
                "serialNumber": cert.serial,
                "signature": {
                    "algorithmName": cert.signature_algorithm,
                },
                "issueDate": cert.not_after[:10] if cert.not_after else None,
                "expirationDate": cert.not_after,
            },
        },
        "properties": [
            {
                "name": "arbiter:risk-score",
                "value": str(cert.public_key.score),
            },
            {
                "name": "arbiter:risk-level",
                "value": cert.public_key.level.value,
            },
            {
                "name": "arbiter:recommendation",
                "value": cert.public_key.recommendation,
            },
        ],
    }

    if cert.composite_info:
        component["properties"].append(
            {
                "name": "arbiter:composite-type",
                "value": cert.composite_info.get("type", "unknown"),
            }
        )
        if "pqc_algorithm" in cert.composite_info:
            component["properties"].append(
                {
                    "name": "arbiter:pqc-algorithm",
                    "value": cert.composite_info["pqc_algorithm"],
                }
            )
        if "traditional_algorithm" in cert.composite_info:
            component["properties"].append(
                {
                    "name": "arbiter:traditional-algorithm",
                    "value": cert.composite_info["traditional_algorithm"],
                }
            )

    return component


def _create_algorithm_component(
    algorithm: str, key_bits: int | None, risk_assessment: RiskAssessment
) -> dict[str, Any]:
    """Create a CycloneDX cryptographic-algorithm component with risk properties."""
    base = _algorithm_to_cbom_component(algorithm, key_bits)

    # Add NIST quantum security level
    nist_level = _nist_quantum_security_level(risk_assessment)
    base["properties"].append(
        {
            "name": "nistQuantumSecurityLevel",
            "value": str(nist_level),
        }
    )

    # Add ARBITER risk assessment properties
    base["properties"].extend(
        [
            {
                "name": "arbiter:risk-score",
                "value": str(risk_assessment.score),
            },
            {
                "name": "arbiter:risk-level",
                "value": risk_assessment.level.value,
            },
            {
                "name": "arbiter:family",
                "value": risk_assessment.family,
            },
        ]
    )

    if risk_assessment.classical_security_bits is not None:
        base["properties"].append(
            {
                "name": "arbiter:classical-security-bits",
                "value": str(risk_assessment.classical_security_bits),
            }
        )

    if risk_assessment.shor_logical_qubits is not None:
        base["properties"].append(
            {
                "name": "arbiter:shor-logical-qubits",
                "value": str(risk_assessment.shor_logical_qubits),
            }
        )

    if risk_assessment.mosca_violated:
        base["properties"].append(
            {
                "name": "arbiter:mosca-violated",
                "value": "true",
            }
        )

    return base


def _create_key_component(cert: CertificateReport, bom_ref_prefix: str = "") -> dict[str, Any]:
    """Create a CycloneDX related-crypto-material component for the public key."""
    ref = f"{bom_ref_prefix}key-{cert.serial[:16]}"
    alg = cert.public_key.algorithm
    bits = cert.public_key.key_bits

    component = {
        "type": "related-crypto-material",
        "bom-ref": ref,
        "name": f"Public Key: {alg}",
        "cryptoProperties": {
            "assetType": "key",
            "keyProperties": {
                "keyFormat": "X.509-SubjectPublicKeyInfo",
                "keySize": bits,
                "keyAlgorithm": alg,
            },
        },
        "properties": [
            {
                "name": "arbiter:risk-score",
                "value": str(cert.public_key.score),
            },
            {
                "name": "arbiter:risk-level",
                "value": cert.public_key.level.value,
            },
        ],
    }

    if cert.public_key.expires:
        component["cryptoProperties"]["keyProperties"]["expirationDate"] = cert.public_key.expires

    return component


def certificates_to_cbom(
    certificates: list[CertificateReport],
    metadata_component: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert PKI certificate assessments to a CycloneDX 1.6 CBOM document.

    Args:
        certificates: List of CertificateReport objects from assess_certificates()
        metadata_component: Optional custom metadata component for the BOM

    Returns:
        A complete CycloneDX 1.6 JSON object that can be serialized with json.dumps()
    """
    components = []
    dependencies = []

    # Track unique algorithms to avoid duplication
    seen_algorithms = set()

    for cert in certificates:
        cert_ref = f"cert-{cert.serial[:16]}"
        key_ref = f"key-{cert.serial[:16]}"
        alg_ref = f"algorithm-{cert.public_key.algorithm.replace(' ', '_').replace('+', '_')}"

        # Add certificate component
        cert_component = _create_certificate_component(cert)
        components.append(cert_component)

        # Add algorithm component (if not seen before)
        if alg_ref not in seen_algorithms:
            alg_component = _create_algorithm_component(
                cert.public_key.algorithm, cert.public_key.key_bits, cert.public_key
            )
            components.append(alg_component)
            seen_algorithms.add(alg_ref)

        # Add key component
        key_component = _create_key_component(cert)
        components.append(key_component)

        # Add dependencies: certificate -> algorithm <- key
        dependencies.append(
            {
                "ref": cert_ref,
                "dependsOn": [alg_ref, key_ref],
            }
        )
        dependencies.append(
            {
                "ref": key_ref,
                "dependsOn": [alg_ref],
            }
        )

    # Build the BOM metadata
    metadata = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tools": [
            {
                "vendor": "Anthropic",
                "name": "ARBITER PKI Risk Scoring",
                "version": "1.0.0",
                "hashes": [],
            }
        ],
    }

    if metadata_component:
        metadata["component"] = metadata_component

    # Build the complete BOM document
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }

    if dependencies:
        bom["dependencies"] = dependencies

    return bom


def cbom_to_json(bom: dict[str, Any], indent: int = 2) -> str:
    """Serialize a CBOM dictionary to JSON string.

    Args:
        bom: CBOM dictionary from certificates_to_cbom()
        indent: JSON indentation level (2 for readability, None for compact)

    Returns:
        JSON string
    """
    return json.dumps(bom, indent=indent, sort_keys=True)
