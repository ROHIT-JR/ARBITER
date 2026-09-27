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


def test_verbatim_resubmission_is_flagged_as_replay(client):
    first = client.post("/sessions", json={"seed": 3}).json()
    again = client.post(f"/sessions/{first['session']['id']}/resubmit").json()
    assert again["decision"] == "REJECT" and again["attribution"] == "replay"
    assert not again["layers"]["nonce_fresh"]


@pytest.mark.slow
def test_qiskit_backend_through_api(client):
    r = client.post("/sessions", json={"hypothesis": "channel_manipulation", "backend": "qiskit", "seed": 4}).json()
    assert r["session"]["backend"] == "qiskit"
    assert r["decision"] == "REJECT" and r["layers"]["chsh"]["flagged"]
