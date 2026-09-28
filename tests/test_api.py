import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from arbiter.api.app import create_app  # noqa: E402


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    return TestClient(create_app(tmp_path_factory.mktemp("arbiter")))


def test_health_and_model(client):
    assert client.get("/health").json()["status"] == "ok"
    m = client.get("/model").json()
    assert set(m["hypotheses"]) == {"legitimate", "forgery", "impersonation", "replay", "channel_manipulation"}
    assert len(client.get("/bounds").json()) == 4


def test_compare_endpoint(client):
    response = client.get("/compare", params={"theta": 0.3, "sessions": 5, "seed": 11})
    assert response.status_code == 200
    body = response.json()
    assert body["metadata"]["theta"] == 0.3
    assert set(body["detectors"]) == {"unified", "baseline", "baseline_bonferroni"}
    for detector in body["detectors"].values():
        assert sum(detector["confusion_matrix"]["forgery"].values()) == 5
        assert 0 <= detector["attacks"]["forgery"]["detection_rate"] <= 1
    assert client.get("/compare", params={"theta": 0, "sessions": 5}).status_code == 422


def test_session_verdicts_land_in_ledger(client):
    ok = client.post("/sessions", json={"seed": 1}).json()
    assert ok["decision"] == "ACCEPT" and ok["attribution"] == "legitimate"
    bad = client.post("/sessions", json={"hypothesis": "forgery", "seed": 2}).json()
    assert bad["decision"] == "REJECT" and bad["attribution"] == "forgery"
    entries = client.get("/ledger").json()["entries"]
    assert [e.get("session_id") for e in entries[-2:]] == [ok["session"]["id"], bad["session"]["id"]]
    assert client.get("/ledger/verify").json()["ok"]
    full = client.get(f"/ledger/{bad['ledger']['index']}").json()
    assert full["signatures"]["mldsa"] and full["signatures"]["hbs"]


def test_shared_seed_across_scenarios_is_not_mistaken_for_replay(client):
    for h in ("legitimate", "forgery", "impersonation", "replay", "channel_manipulation"):
        r = client.post("/sessions", json={"hypothesis": h, "seed": 42}).json()
        assert r["layers"]["nonce_fresh"] and r["attribution"] == h


def test_verbatim_resubmission_is_flagged_as_replay(client):
    first = client.post("/sessions", json={"seed": 3}).json()
    again = client.post(f"/sessions/{first['session']['id']}/resubmit?trajectory=true").json()
    assert len(again["layers"]["sequential"]["log_evidence"]) == first["session"]["rounds"]
    assert again["decision"] == "REJECT" and again["attribution"] == "replay"
    assert not again["layers"]["nonce_fresh"]


def test_sessions_persist_across_app_restarts(tmp_path):
    data_dir = tmp_path / "persistent"
    first_app = TestClient(create_app(data_dir))
    first = first_app.post("/sessions", json={"seed": 31}).json()
    session_id = first["session"]["id"]

    restarted = TestClient(create_app(data_dir))
    listed = restarted.get("/sessions").json()["sessions"]
    assert listed[0]["id"] == session_id
    details = restarted.get(f"/sessions/{session_id}")
    assert details.status_code == 200
    assert details.json()["transcript_digest"] == first["session"]["transcript_digest"]

    replay = restarted.post(f"/sessions/{session_id}/resubmit").json()
    assert replay["decision"] == "REJECT"
    assert replay["attribution"] == "replay"
    assert not replay["layers"]["nonce_fresh"]


def test_unknown_session_is_not_found(client):
    assert client.get("/sessions/not-a-session").status_code == 404


@pytest.mark.slow
def test_qiskit_backend_through_api(client):
    r = client.post("/sessions", json={"hypothesis": "channel_manipulation", "backend": "qiskit", "seed": 4}).json()
    assert r["session"]["backend"] == "qiskit"
    assert r["decision"] == "REJECT" and r["layers"]["chsh"]["flagged"]


def test_noise_presets(client):
    presets = client.get("/noise/presets").json()
    assert "state_of_the_art_2025" in presets
    assert 0.9 < presets["prototype"]["visibility"] < 1


def test_pki_endpoints(client):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa
    from test_pki import _self_signed

    pem = _self_signed(rsa.generate_private_key(65537, 2048), 400).decode()
    r = client.post("/pki/assess", json={"pem": pem}).json()
    assert r[0]["public_key"]["algorithm"] == "RSA" and r[0]["public_key"]["shor_logical_qubits"] == 4099
    assert client.post("/pki/assess", json={"pem": "garbage"}).status_code == 422
    k = client.post("/pki/assess-key", json={"algorithm": "ML-DSA-65"}).json()
    assert k["level"] == "low"


def test_pki_assess_returns_chain_report_for_linked_bundle(client):
    pytest.importorskip("cryptography")
    from test_pki import _rsa_chain

    _, _, leaf_pem, root_pem = _rsa_chain()
    response = client.post("/pki/assess", json={"pem": (root_pem + leaf_pem).decode()})
    assert response.status_code == 200
    payload = response.json()
    assert [link["subject"] for link in payload["chains"][0]["links"]] == ["CN=leaf", "CN=root"]
    assert payload["chains"][0]["weakest_link"]["subject"] == "CN=root"


def test_noise_preset_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ARBITER_NOISE_PRESET", "conservative")
    c = TestClient(create_app(tmp_path))
    assert c.get("/health").json()["noise_preset"] == "conservative"
    monkeypatch.setenv("ARBITER_NOISE_PRESET", "nope")
    with pytest.raises(ValueError):
        create_app(tmp_path / "x")


def test_demo_ledger_tampering_is_disabled_by_default(client):
    assert client.get("/health").json()["demo_mode"] is False
    assert client.post("/ledger/0/tamper", json={"field": "timestamp", "value": "altered"}).status_code == 403
    assert client.post("/ledger/restore").status_code == 403


def test_demo_tamper_behaviors_are_memory_only_and_signature_checked(tmp_path, monkeypatch):
    monkeypatch.setenv("ARBITER_DEMO_MODE", "1")
    c = TestClient(create_app(tmp_path))
    verdict = c.post("/sessions", json={"seed": 21}).json()
    index = verdict["ledger"]["index"]
    ledger_path = tmp_path / "ledger.jsonl"
    persisted = ledger_path.read_text()

    changed = c.post(f"/ledger/{index}/tamper", json={"field": "decision", "value": "REJECT"})
    assert changed.status_code == 200
    assert changed.json()["ok"] is False
    assert changed.json()["first_bad_index"] == index
    assert "content altered" in changed.json()["problems"][0]
    assert ledger_path.read_text() == persisted

    restored = c.post("/ledger/restore")
    assert restored.status_code == 200 and restored.json()["ok"] is True
    assert c.get("/ledger/verify").json()["ok"] is True
    assert ledger_path.read_text() == persisted

    verdict = c.post("/sessions", json={"seed": 22}).json()
    index = verdict["ledger"]["index"]
    changed = c.post(
        f"/ledger/{index}/tamper",
        json={"field": "attribution", "value": "replay", "recompute_hashes": True},
    )
    assert changed.status_code == 200
    assert changed.json()["ok"] is False
    assert changed.json()["first_bad_index"] == index
    assert "ML-DSA-65 signature invalid" in changed.json()["problems"][0]
