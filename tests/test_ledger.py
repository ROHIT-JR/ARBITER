import copy
import json

import pytest
from cryptography.exceptions import InvalidTag

from arbiter.audit_ledger import (
    AuditLedger,
    EncryptedKeyStore,
    EpochManager,
    LedgerKeys,
    MerkleLamport,
    verify_entries,
)
from arbiter.audit_ledger.signatures import MLDSA


@pytest.fixture
def keys():
    return LedgerKeys.generate(hbs_height=10)


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
    from arbiter.audit_ledger.common import canonical, entry_hash

    entries = copy.deepcopy(ledger.entries)
    e = entries[2]
    e["payload"]["decision"] = "REJECT"
    header = {k: e[k] for k in ("index", "timestamp", "prev_hash", "payload")}
    e["hash"] = entry_hash(e["prev_hash"], canonical(header), e["signatures"]["mldsa"], e["signatures"]["hbs"])
    report = verify_entries(entries)
    assert not report.ok and "ML-DSA" in report.problems[0]


def test_genesis_trust_anchor(ledger, keys):
    other = AuditLedger(LedgerKeys.generate(hbs_height=2))
    assert not verify_entries(other.entries, expected_genesis_hash=ledger.genesis_hash).ok


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


def test_encrypted_key_storage(tmp_path):
    """Test encrypted key storage round-trip."""
    keys = LedgerKeys.generate(hbs_height=4)
    path = tmp_path / "keys.enc.json"
    passphrase = "test-passphrase-123"

    # Save encrypted
    keys.save_encrypted(path, passphrase)

    # Load encrypted
    loaded = LedgerKeys.load_encrypted(path, passphrase)

    # Verify keys match
    assert loaded.mldsa.public_key == keys.mldsa.public_key
    assert loaded.mldsa.secret_key == keys.mldsa.secret_key
    assert loaded.hbs.seed == keys.hbs.seed
    assert loaded.hbs.height == keys.hbs.height
    assert loaded.epoch_id == keys.epoch_id


def test_encrypted_key_storage_wrong_passphrase(tmp_path):
    """Test that wrong passphrase fails to decrypt."""
    keys = LedgerKeys.generate(hbs_height=4)
    path = tmp_path / "keys.enc.json"

    keys.save_encrypted(path, "correct-passphrase")

    with pytest.raises(InvalidTag):
        LedgerKeys.load_encrypted(path, "wrong-passphrase")


def test_encrypted_key_store_direct(tmp_path):
    """Test EncryptedKeyStore directly."""
    store = EncryptedKeyStore(tmp_path / "store.json")
    data = {"test": "data", "number": 42}
    passphrase = "passphrase"

    store.save(data, passphrase)
    assert store.exists()

    loaded = store.load(passphrase)
    assert loaded == data

    with pytest.raises(InvalidTag):
        store.load("wrong-passphrase")


def test_epoch_manager_initialization():
    """Test epoch manager genesis creation."""
    mgr = EpochManager(hbs_height=4)
    epoch0 = mgr.initialize_genesis()

    assert epoch0.epoch_id == 0
    assert epoch0.mldsa is not None
    assert epoch0.hbs is not None
    assert epoch0.genesis_hash is not None
    assert len(mgr.epochs) == 1
    assert mgr.epochs[0].epoch_id == 0
    assert mgr.epochs[0].status == "active"


def test_epoch_rotation(tmp_path):
    """Test epoch key rotation with cross-signing."""
    keys = LedgerKeys.generate(hbs_height=3)  # 8 leaves
    mgr = EpochManager(hbs_height=3, max_hbs_usage_ratio=0.5)  # rotate at 4 leaves
    mgr.initialize_genesis()  # Initialize epoch 0
    ledger = AuditLedger(keys, epoch_manager=mgr)

    # Append entries until rotation triggers (at 4 leaves used)
    for i in range(5):
        ledger.append({"type": "verdict", "i": i})

    # Should have rotated to epoch 1
    assert ledger.keys.epoch_id == 1
    assert len(mgr.epochs) == 2
    assert mgr.epochs[0].status == "retired"
    assert mgr.epochs[1].status == "active"
    # Cross-signature is on the new epoch's keys, accessible via epoch manager
    assert mgr.current_epoch is not None
    assert mgr.current_epoch.cross_signature is not None
    # start_index is global index where epoch 1 starts (after rotation at index 4)
    assert mgr.epochs[1].start_index == 4

    # Verify entries: genesis + 4 regular + 1 key_transition + 1 after rotation = 7 entries
    assert len(ledger.entries) == 7
    # Check that a key_transition entry was written
    transition_entries = [e for e in ledger.entries if e.get("payload", {}).get("type") == "key_transition"]
    assert len(transition_entries) == 1
    transition = transition_entries[0]
    assert transition["payload"]["type"] == "key_transition"
    assert "cross_signature" in transition["payload"]

    # Verify individual epoch 1 entries can be verified with epoch 1 keys
    # (Full cross-epoch verification requires storing epoch keys, which is a separate feature)


def test_epoch_cross_signature_verification():
    """Test that cross-signatures can be verified."""
    mgr = EpochManager(hbs_height=4)
    epoch0 = mgr.initialize_genesis()

    # Create epoch 1 and cross-sign
    epoch1 = mgr.rotate_keys(global_index=10)

    # Verify cross-signature
    cross_sig = epoch1.cross_signature
    assert cross_sig is not None

    # Verify using epoch0's keys
    ok = epoch1.verify_cross_signature(
        cross_sig,
        epoch0.mldsa.public_key,
        epoch0.hbs.root,
        epoch0.hbs_leaf,
    )
    assert ok


def test_ledger_with_encrypted_storage(tmp_path):
    """Test full ledger with encrypted key storage."""
    keys = LedgerKeys.generate(hbs_height=4)
    key_path = tmp_path / "keys.enc.json"
    ledger_path = tmp_path / "ledger.jsonl"
    passphrase = "test-passphrase"

    # Save keys encrypted
    keys.save_encrypted(key_path, passphrase)

    # Create ledger with encrypted keys
    loaded_keys = LedgerKeys.load_encrypted(key_path, passphrase)
    ledger = AuditLedger(loaded_keys, ledger_path)

    ledger.append({"type": "verdict", "decision": "ACCEPT"})
    report = ledger.verify()
    assert report.ok

    # Reopen ledger
    loaded_keys2 = LedgerKeys.load_encrypted(key_path, passphrase)
    reopened = AuditLedger(loaded_keys2, ledger_path)
    assert reopened.verify().ok
