"""PKI metadata registry for key inventory.

This module provides a user-friendly way to inventory SSH keys and code-signing
certificates by accepting key metadata (not the keys themselves) from users.
The metadata is used to assess quantum risk via Mosca's inequality.

The registry avoids filesystem scanning for security reasons and instead relies
on users providing their own key information through a JSON file or API.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from .scoring import RiskAssessment, assess_key


class KeyType(str, Enum):
    """SSH and cryptographic key types."""

    RSA = "RSA"
    ECDSA = "ECDSA"
    ED25519 = "Ed25519"
    ED448 = "Ed448"
    DSA = "DSA"
    OPENSSH_SK_ECDSA = "sk-ecdsa-sha2-nistp256"
    OPENSSH_SK_ED25519 = "sk-ed25519"
    ML_DSA_44 = "ML-DSA-44"
    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"
    ML_KEM_512 = "ML-KEM-512"
    ML_KEM_768 = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"


class KeySource(str, Enum):
    """Where the key is used or stored."""

    SSH_AUTHORIZED_KEYS = "ssh_authorized_keys"
    SSH_KNOWN_HOSTS = "ssh_known_hosts"
    SSH_HOST_KEY = "ssh_host_key"
    SSH_PUB_FILE = "ssh_pub_file"
    CODE_SIGNING_CERT = "code_signing_cert"
    TLS_CERTIFICATE = "tls_certificate"
    OTHER = "other"


@dataclass
class KeyMetadata:
    """Metadata describing a single public key for risk assessment."""

    key_id: str
    """Unique identifier for this key (e.g. fingerprint, hash, or name)."""

    key_type: KeyType
    """Algorithm type of the key."""

    key_size: int
    """Key size in bits (e.g., 2048 for RSA-2048, 256 for ECDSA-P256)."""

    source: KeySource
    """Where the key is used (SSH authorized_keys, code-signing cert, etc.)."""

    source_description: str
    """Human-readable description of the key's location/purpose."""

    created_date: Optional[datetime] = None
    """When the key was created (optional)."""

    expiry_date: Optional[datetime] = None
    """When the key expires (optional, especially important for code-signing)."""

    protection_years_after_expiry: float = field(default=0.0)
    """For archived signatures/documents, how long they must stay trustworthy
    after the signing certificate expires (e.g., 10 years for code-signing)."""

    metadata: dict = field(default_factory=dict)
    """Optional extra metadata (e.g., comment, owner, environment)."""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        d = asdict(self)
        d["key_type"] = self.key_type.value
        d["source"] = self.source.value
        if self.created_date:
            d["created_date"] = self.created_date.isoformat()
        if self.expiry_date:
            d["expiry_date"] = self.expiry_date.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> KeyMetadata:
        """Load from a dictionary (e.g., from JSON)."""
        data = data.copy()
        data["key_type"] = KeyType(data["key_type"])
        data["source"] = KeySource(data["source"])
        if data.get("created_date") and isinstance(data["created_date"], str):
            data["created_date"] = datetime.fromisoformat(data["created_date"])
        if data.get("expiry_date") and isinstance(data["expiry_date"], str):
            data["expiry_date"] = datetime.fromisoformat(data["expiry_date"])
        return cls(**data)


@dataclass
class RegistryEntry:
    """A key's metadata plus its quantum risk assessment."""

    metadata: KeyMetadata
    assessment: RiskAssessment


class KeyMetadataRegistry:
    """Registry for managing key metadata and computing risk assessments."""

    def __init__(self, crqc_year: int = 2035, now: Optional[datetime] = None):
        """Initialize the registry.

        Args:
            crqc_year: Assumed year of cryptographically-relevant quantum computer.
            now: Current time for testing (defaults to now).
        """
        self.crqc_year = crqc_year
        self.now = now or datetime.now(timezone.utc)
        self._entries: dict[str, RegistryEntry] = {}

    def add_key(self, metadata: KeyMetadata) -> RiskAssessment:
        """Add a key to the registry and assess its risk.

        Args:
            metadata: Key metadata to add.

        Returns:
            The risk assessment for this key.
        """
        assessment = self._assess_metadata(metadata)
        self._entries[metadata.key_id] = RegistryEntry(metadata, assessment)
        return assessment

    def _assess_metadata(self, metadata: KeyMetadata) -> RiskAssessment:
        """Convert key metadata to a risk assessment using scoring.py."""
        # Map KeyType enum to algorithm name for assess_key
        algorithm = metadata.key_type.value
        key_bits = metadata.key_size

        assessment = assess_key(
            algorithm,
            key_bits,
            expires=metadata.expiry_date,
            protection_years_after_expiry=metadata.protection_years_after_expiry,
            crqc_year=self.crqc_year,
            now=self.now,
        )
        return assessment

    def get_key(self, key_id: str) -> Optional[RegistryEntry]:
        """Retrieve a key's metadata and assessment.

        Args:
            key_id: The key identifier.

        Returns:
            The registry entry, or None if not found.
        """
        return self._entries.get(key_id)

    def query_by_algorithm(self, algorithm: KeyType) -> list[RegistryEntry]:
        """Find all keys of a specific algorithm type.

        Args:
            algorithm: The key type to search for.

        Returns:
            List of matching entries.
        """
        return [entry for entry in self._entries.values() if entry.metadata.key_type == algorithm]

    def query_by_size(self, key_size: int) -> list[RegistryEntry]:
        """Find all keys of a specific size in bits.

        Args:
            key_size: The key size to search for.

        Returns:
            List of matching entries.
        """
        return [entry for entry in self._entries.values() if entry.metadata.key_size == key_size]

    def query_by_risk_level(self, risk_level: str) -> list[RegistryEntry]:
        """Find all keys with a specific risk level.

        Args:
            risk_level: The risk level ('low', 'medium', 'high', 'critical').

        Returns:
            List of matching entries.
        """
        return [entry for entry in self._entries.values() if entry.assessment.level.value == risk_level]

    def query_by_source(self, source: KeySource) -> list[RegistryEntry]:
        """Find all keys from a specific source/use case.

        Args:
            source: The key source to search for.

        Returns:
            List of matching entries.
        """
        return [entry for entry in self._entries.values() if entry.metadata.source == source]

    def all_entries(self) -> list[RegistryEntry]:
        """Get all entries in the registry.

        Returns:
            List of all registry entries.
        """
        return list(self._entries.values())

    def import_from_json(self, json_file: Path | str) -> list[RiskAssessment]:
        """Load key metadata from a JSON file and add to registry.

        Expected JSON format:
        {
          "keys": [
            {
              "key_id": "...",
              "key_type": "RSA",
              "key_size": 2048,
              "source": "ssh_authorized_keys",
              "source_description": "...",
              "created_date": "2023-01-01T00:00:00Z",
              "expiry_date": "2026-01-01T00:00:00Z",
              "protection_years_after_expiry": 10.0,
              "metadata": {...}
            }
          ]
        }

        Args:
            json_file: Path to the JSON file.

        Returns:
            List of risk assessments for the imported keys.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            ValueError: If the JSON format is invalid.
        """
        json_path = Path(json_file)
        if not json_path.exists():
            raise FileNotFoundError(f"JSON file not found: {json_file}")

        with open(json_path, "r") as f:
            data = json.load(f)

        if not isinstance(data, dict) or "keys" not in data:
            raise ValueError("JSON must have a 'keys' array at the root level")

        assessments = []
        for key_data in data["keys"]:
            try:
                metadata = KeyMetadata.from_dict(key_data)
                assessment = self.add_key(metadata)
                assessments.append(assessment)
            except (ValueError, KeyError, TypeError) as e:
                raise ValueError(f"Invalid key metadata: {key_data}") from e

        return assessments

    def export_to_json(self, json_file: Path | str, include_assessments: bool = True) -> None:
        """Export registry to a JSON file.

        Args:
            json_file: Path where to write the JSON file.
            include_assessments: If True, include risk assessments in the output.
        """
        json_path = Path(json_file)

        data = {"keys": []}
        for entry in self._entries.values():
            key_dict = entry.metadata.to_dict()
            if include_assessments:
                key_dict["assessment"] = entry.assessment.to_dict()
            data["keys"].append(key_dict)

        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)

    def summary_report(self) -> dict:
        """Generate a summary report of all keys and their risk levels.

        Returns:
            A dictionary with statistics and risk breakdown.
        """
        from .scoring import RiskLevel

        entries = self._entries.values()
        if not entries:
            return {
                "total_keys": 0,
                "by_algorithm": {},
                "by_source": {},
                "by_risk_level": {},
            }

        risk_counts = {level.value: 0 for level in RiskLevel}
        algo_counts = {}
        source_counts = {}

        for entry in entries:
            risk_counts[entry.assessment.level.value] += 1
            algo = entry.metadata.key_type.value
            algo_counts[algo] = algo_counts.get(algo, 0) + 1
            source = entry.metadata.source.value
            source_counts[source] = source_counts.get(source, 0) + 1

        return {
            "total_keys": len(self._entries),
            "by_algorithm": algo_counts,
            "by_source": source_counts,
            "by_risk_level": risk_counts,
        }
