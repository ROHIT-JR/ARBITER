"""Deterministic unit tests for the PKI key-metadata registry (Issue #38).

The registry accepts user-supplied key *metadata* (never key material),
assesses quantum risk via Mosca's inequality, and supports JSON
import/export plus risk/source/algorithm queries.
"""

from datetime import datetime, timezone

import pytest

from arbiter.pki_risk_scoring.key_metadata_registry import (
    KeyMetadata,
    KeyMetadataRegistry,
    KeySource,
    KeyType,
)

NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)


def _rsa_key(key_id="host-key-1", **overrides):
    fields = {
        "key_id": key_id,
        "key_type": KeyType.RSA,
        "key_size": 2048,
        "source": KeySource.SSH_AUTHORIZED_KEYS,
        "source_description": "test host authorized_keys",
    }
    fields.update(overrides)
    return KeyMetadata(**fields)


def test_metadata_roundtrip_with_dates():
    meta = KeyMetadata(
        key_id="sig-cert-1",
        key_type=KeyType.ECDSA,
        key_size=256,
        source=KeySource.CODE_SIGNING_CERT,
        source_description="release signer",
        created_date=datetime(2023, 1, 1, tzinfo=timezone.utc),
        expiry_date=datetime(2028, 1, 1, tzinfo=timezone.utc),
        protection_years_after_expiry=10.0,
    )
    restored = KeyMetadata.from_dict(meta.to_dict())
    assert restored == meta


def test_metadata_roundtrip_without_dates():
    meta = _rsa_key()
    assert KeyMetadata.from_dict(meta.to_dict()) == meta


def test_add_and_get_key():
    registry = KeyMetadataRegistry(now=NOW)
    assessment = registry.add_key(_rsa_key())
    assert assessment.algorithm == "RSA"
    entry = registry.get_key("host-key-1")
    assert entry is not None
    assert entry.metadata.key_id == "host-key-1"
    assert entry.assessment is assessment
    assert registry.get_key("missing") is None


def test_weak_key_scores_critical():
    registry = KeyMetadataRegistry(now=NOW)
    assessment = registry.add_key(_rsa_key("weak-rsa", key_size=1024))
    assert assessment.level.value == "critical"


def test_pqc_key_scores_low():
    registry = KeyMetadataRegistry(now=NOW)
    assessment = registry.add_key(
        _rsa_key(
            "pqc-key",
            key_type=KeyType.ML_DSA_65,
            key_size=0,
            source=KeySource.TLS_CERTIFICATE,
            source_description="pqc endpoint",
            expiry_date=datetime(2036, 1, 1, tzinfo=timezone.utc),
        )
    )
    assert assessment.level.value == "low"


def test_query_filters():
    registry = KeyMetadataRegistry(now=NOW)
    registry.add_key(_rsa_key("rsa-1", key_size=2048))
    registry.add_key(_rsa_key("rsa-2", key_size=1024))
    registry.add_key(
        _rsa_key(
            "ec-1",
            key_type=KeyType.ECDSA,
            key_size=256,
            source=KeySource.SSH_KNOWN_HOSTS,
            source_description="known host",
        )
    )

    assert {e.metadata.key_id for e in registry.query_by_algorithm(KeyType.RSA)} == {"rsa-1", "rsa-2"}
    assert [e.metadata.key_id for e in registry.query_by_size(1024)] == ["rsa-2"]
    assert {e.metadata.key_id for e in registry.query_by_source(KeySource.SSH_KNOWN_HOSTS)} == {"ec-1"}
    assert [e.metadata.key_id for e in registry.query_by_risk_level("critical")] == ["rsa-2"]
    assert len(registry.all_entries()) == 3


def test_import_export_roundtrip(tmp_path):
    registry = KeyMetadataRegistry(now=NOW)
    registry.add_key(_rsa_key("rsa-1"))
    registry.add_key(
        _rsa_key(
            "ec-1",
            key_type=KeyType.ECDSA,
            key_size=256,
            source=KeySource.SSH_KNOWN_HOSTS,
            source_description="known host",
        )
    )

    path = tmp_path / "inventory.json"
    registry.export_to_json(path)
    assert path.is_file()

    fresh = KeyMetadataRegistry(now=NOW)
    assessments = fresh.import_from_json(path)
    assert len(assessments) == 2
    assert fresh.get_key("rsa-1") is not None
    assert fresh.get_key("ec-1") is not None


def test_export_without_assessments(tmp_path):
    registry = KeyMetadataRegistry(now=NOW)
    registry.add_key(_rsa_key("rsa-1"))
    path = tmp_path / "inventory.json"
    registry.export_to_json(path, include_assessments=False)

    import json

    data = json.loads(path.read_text())
    assert "assessment" not in data["keys"][0]

    fresh = KeyMetadataRegistry(now=NOW)
    assert len(fresh.import_from_json(path)) == 1


def test_import_errors(tmp_path):
    registry = KeyMetadataRegistry(now=NOW)
    with pytest.raises(FileNotFoundError):
        registry.import_from_json(tmp_path / "does-not-exist.json")

    bad = tmp_path / "bad.json"
    bad.write_text('{"nope": []}')
    with pytest.raises(ValueError):
        registry.import_from_json(bad)

    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"keys": [{"key_id": "x"}]}')
    with pytest.raises(ValueError):
        registry.import_from_json(invalid)


def test_summary_report_empty_and_populated():
    registry = KeyMetadataRegistry(now=NOW)
    empty = registry.summary_report()
    assert empty == {"total_keys": 0, "by_algorithm": {}, "by_source": {}, "by_risk_level": {}}

    registry.add_key(_rsa_key("rsa-1", key_size=2048))
    registry.add_key(_rsa_key("rsa-2", key_size=1024))
    report = registry.summary_report()
    assert report["total_keys"] == 2
    assert report["by_algorithm"] == {"RSA": 2}
    assert report["by_source"] == {"ssh_authorized_keys": 2}
    assert report["by_risk_level"]["critical"] == 1
    assert sum(report["by_risk_level"].values()) == 2
