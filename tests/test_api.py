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


def test_noise_preset_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ARBITER_NOISE_PRESET", "conservative")
    c = TestClient(create_app(tmp_path))
    assert c.get("/health").json()["noise_preset"] == "conservative"
    monkeypatch.setenv("ARBITER_NOISE_PRESET", "nope")
    with pytest.raises(ValueError):
        create_app(tmp_path / "x")
