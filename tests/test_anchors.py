"""Tests for external timestamp anchoring (audit_ledger/anchors.py)."""

from arbiter.audit_ledger.anchors import (
    AnchorReceipt,
    NoAnchor,
    OpenTimestampsAnchor,
    RFC3161Anchor,
    get_anchor,
)

HEAD_HASH = "ab" * 32


def test_anchor_receipt_round_trips_through_dict():
    receipt = AnchorReceipt(
        receipt_type="ots", proof="deadbeef", timestamp=123, status="confirmed", anchor_url="https://example.org"
    )
    restored = AnchorReceipt.from_dict(receipt.to_dict())
    assert restored == receipt


def test_no_anchor_submit_and_verify():
    anchor = NoAnchor()
    receipt = anchor.submit(HEAD_HASH)
    assert receipt.receipt_type == "none"
    assert receipt.status == "disabled"
    assert anchor.verify(HEAD_HASH, receipt) is True
    assert anchor.upgrade(receipt) is None


def test_open_timestamps_anchor_submit_and_verify():
    anchor = OpenTimestampsAnchor()
    receipt = anchor.submit(HEAD_HASH)
    assert receipt.receipt_type == "ots"
    assert receipt.status == "pending"
    assert anchor.verify(HEAD_HASH, receipt) is True


def test_open_timestamps_anchor_verify_rejects_wrong_type():
    anchor = OpenTimestampsAnchor()
    receipt = RFC3161Anchor("http://tsa.example").submit(HEAD_HASH)
    assert anchor.verify(HEAD_HASH, receipt) is False


def test_open_timestamps_anchor_verify_rejects_tampered_proof():
    anchor = OpenTimestampsAnchor()
    receipt = anchor.submit(HEAD_HASH)
    receipt.proof = "not-valid-base64!!"
    assert anchor.verify(HEAD_HASH, receipt) is False


def test_open_timestamps_anchor_upgrade_confirms_pending_receipt():
    anchor = OpenTimestampsAnchor()
    receipt = anchor.submit(HEAD_HASH)
    upgraded = anchor.upgrade(receipt)
    assert upgraded is not None
    assert upgraded.status == "confirmed"
    assert upgraded.timestamp is not None


def test_open_timestamps_anchor_upgrade_returns_none_if_already_confirmed():
    anchor = OpenTimestampsAnchor()
    receipt = anchor.submit(HEAD_HASH)
    confirmed = anchor.upgrade(receipt)
    assert anchor.upgrade(confirmed) is None


def test_open_timestamps_anchor_custom_server_urls():
    anchor = OpenTimestampsAnchor(server_urls=["https://custom.example"], timeout=5)
    assert anchor.server_urls == ["https://custom.example"]
    assert anchor.timeout == 5


def test_rfc3161_anchor_submit_and_verify():
    anchor = RFC3161Anchor("http://freetsa.org/tst")
    receipt = anchor.submit(HEAD_HASH)
    assert receipt.receipt_type == "tsa"
    assert receipt.status == "confirmed"
    assert receipt.anchor_url == "http://freetsa.org/tst"
    assert anchor.verify(HEAD_HASH, receipt) is True


def test_rfc3161_anchor_verify_rejects_wrong_type():
    anchor = RFC3161Anchor("http://freetsa.org/tst")
    receipt = OpenTimestampsAnchor().submit(HEAD_HASH)
    assert anchor.verify(HEAD_HASH, receipt) is False


def test_rfc3161_anchor_verify_rejects_tampered_proof():
    anchor = RFC3161Anchor("http://freetsa.org/tst")
    receipt = anchor.submit(HEAD_HASH)
    receipt.proof = "not-valid-base64!!"
    assert anchor.verify(HEAD_HASH, receipt) is False


def test_rfc3161_anchor_upgrade_is_always_noop():
    anchor = RFC3161Anchor("http://freetsa.org/tst")
    receipt = anchor.submit(HEAD_HASH)
    assert anchor.upgrade(receipt) is None


def test_get_anchor_defaults_to_no_anchor(monkeypatch):
    monkeypatch.delenv("ARBITER_ANCHOR", raising=False)
    assert isinstance(get_anchor(), NoAnchor)


def test_get_anchor_explicit_none():
    assert isinstance(get_anchor("none"), NoAnchor)


def test_get_anchor_ots():
    assert isinstance(get_anchor("ots"), OpenTimestampsAnchor)


def test_get_anchor_tsa_requires_url():
    anchor = get_anchor("tsa", tsa_url="http://tsa.example")
    assert isinstance(anchor, RFC3161Anchor)
    assert anchor.tsa_url == "http://tsa.example"


def test_get_anchor_tsa_falls_back_to_env_url(monkeypatch):
    monkeypatch.setenv("ARBITER_TSA_URL", "http://env-tsa.example")
    anchor = get_anchor("tsa")
    assert isinstance(anchor, RFC3161Anchor)
    assert anchor.tsa_url == "http://env-tsa.example"


def test_get_anchor_reads_env_var(monkeypatch):
    monkeypatch.setenv("ARBITER_ANCHOR", "ots")
    assert isinstance(get_anchor(), OpenTimestampsAnchor)


def test_get_anchor_picks_first_of_multiple():
    anchor = get_anchor("ots,tsa", tsa_url="http://tsa.example")
    assert isinstance(anchor, OpenTimestampsAnchor)


def test_get_anchor_unknown_type_falls_back_to_no_anchor():
    assert isinstance(get_anchor("bogus"), NoAnchor)
