import copy
import json

import pytest

from arbiter.audit_ledger import AuditLedger, LedgerKeys, MerkleLamport, verify_entries
from arbiter.audit_ledger.signatures import MLDSA


@pytest.fixture(scope="module")
def keys():
    return LedgerKeys.generate(hbs_height=4)


@pytest.fixture
def ledger(keys):
    led = AuditLedger(keys)
    for i in range(4):
        led.append({"type": "verdict", "decision": "ACCEPT", "i": i})
    return led


def test_merkle_lamport_roundtrip():
    hbs = MerkleLamport(b"\x01" * 32, height=3)
    sig = hbs.sign(b"hello", leaf=5)
    assert MerkleLamport.verify(hbs.root, b"hello", sig)
    assert not MerkleLamport.verify(hbs.root, b"hellp", sig)
    with pytest.raises(ValueError):
        hbs.sign(b"x", leaf=8)


def test_mldsa_roundtrip():
    k = MLDSA()
    s = k.sign(b"msg")
    assert MLDSA.verify(k.public_key, b"msg", s)
    assert not MLDSA.verify(k.public_key, b"msh", s)


def test_clean_ledger_verifies(ledger):
    report = ledger.verify()
    assert report.ok and report.entries == 5


@pytest.mark.parametrize(
    "tamper, expected",
    [
        (lambda e: e[2]["payload"].update(decision="REJECT"), "content altered"),
        (lambda e: e.pop(2), "index out of sequence"),
        (lambda e: e[3].update(prev_hash=e[1]["hash"]), "chain broken"),
        (lambda e: e[1]["signatures"]["hbs"].update(leaf=1), "entry hash mismatch"),
    ],
)
def test_tampering_is_detected(ledger, tamper, expected):
    entries = copy.deepcopy(ledger.entries)
    tamper(entries)
    report = verify_entries(entries)
    assert not report.ok
    assert expected in report.problems[0]


def test_rewriting_with_recomputed_hash_still_fails_signatures(ledger):
    """An attacker who edits a verdict and recomputes the hash chain still
    cannot produce valid signatures."""
    from arbiter.audit_ledger.ledger import _entry_hash, canonical

    entries = copy.deepcopy(ledger.entries)
    e = entries[2]
    e["payload"]["decision"] = "REJECT"
    header = {k: e[k] for k in ("index", "timestamp", "prev_hash", "payload")}
    e["hash"] = _entry_hash(e["prev_hash"], canonical(header), e["signatures"]["mldsa"], e["signatures"]["hbs"])
    report = verify_entries(entries)
    assert not report.ok and "ML-DSA" in report.problems[0]


def test_genesis_trust_anchor(ledger, keys):
    other = AuditLedger(LedgerKeys.generate(hbs_height=2))
    assert not verify_entries(other.entries, expected_genesis_hash=ledger.genesis_hash).ok


def test_malformed_signature_encoding_returns_failed_report(ledger):
    """Regression: a corrupt base64 byte must not crash verification."""
    entries = copy.deepcopy(ledger.entries)
    entries[1]["signatures"]["mldsa"] = "!"
    assert not verify_entries(entries).ok


def test_genesis_signature_placeholder_is_integrity_checked(ledger):
    """Regression: unsigned genesis entries cannot carry arbitrary metadata."""
    entries = copy.deepcopy(ledger.entries)
    entries[0]["signatures"]["mldsa"] = "unexpected"
    assert not verify_entries(entries).ok


def test_persistence(tmp_path, keys):
    path = tmp_path / "ledger.jsonl"
    led = AuditLedger(keys, path)
    led.append({"a": 1})
    reopened = AuditLedger(keys, path)
    reopened.append({"a": 2})
    assert reopened.verify().ok and len(reopened.entries) == 3
    assert len(path.read_text().splitlines()) == 3
    json.loads(path.read_text().splitlines()[-1])
    with pytest.raises(ValueError):
        AuditLedger(LedgerKeys.generate(hbs_height=2), path)
