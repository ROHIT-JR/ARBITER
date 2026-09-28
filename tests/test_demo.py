import asyncio

import httpx
import pytest

pytest.importorskip("fastapi")

from arbiter.api.app import create_app
from arbiter.cli import main
from arbiter.demo import dashboard_is_offline, demo_catalog, run_preflight


def test_demo_catalog_covers_the_walkthrough_and_has_a_cached_accuracy_result():
    catalogue = demo_catalog()
    scenarios = {scenario["id"]: scenario for scenario in catalogue["scenarios"]}
    assert list(scenarios) == ["legitimate", "forgery", "replay_qiskit", "resubmit", "tamper", "accuracy", "hardware"]
    assert scenarios["forgery"]["expected"]["layers.sequential.stopped_at"]["at_most"] == 20
    assert scenarios["accuracy"]["cached_result"]["metadata"]["seed"] == 26141
    assert scenarios["hardware"]["optional"] is True


def test_demo_preflight_runs_seeded_presets_without_a_tcp_server(tmp_path, monkeypatch):
    monkeypatch.setenv("ARBITER_DEMO_MODE", "1")
    results = run_preflight(create_app(tmp_path))
    assert [(result.scenario_id, result.status) for result in results] == [
        ("legitimate", "passed"),
        ("forgery", "passed"),
        ("replay_qiskit", "passed"),
        ("resubmit", "passed"),
        ("tamper", "passed"),
        ("accuracy", "passed"),
        ("hardware", "skipped"),
    ]


def test_static_dashboard_and_api_prefix_are_served_by_one_app(tmp_path, monkeypatch):
    static_dir = tmp_path / "dist"
    static_dir.mkdir()
    (static_dir / "index.html").write_text("<!doctype html><title>ARBITER</title>")
    monkeypatch.setenv("ARBITER_DASHBOARD_DIR", str(static_dir))

    async def check() -> None:
        transport = httpx.ASGITransport(app=create_app(tmp_path / "data"))
        async with httpx.AsyncClient(transport=transport, base_url="http://arbiter.local") as client:
            assert (await client.get("/")).status_code == 200
            assert (await client.get("/api/health")).json()["status"] == "ok"

    asyncio.run(check())


def test_built_index_rejects_external_urls(tmp_path):
    (tmp_path / "index.html").write_text('<script src="https://cdn.example.test/app.js"></script>')
    assert dashboard_is_offline(tmp_path) is False
    (tmp_path / "index.html").write_text('<script src="/assets/app.js"></script>')
    assert dashboard_is_offline(tmp_path) is True


def test_demo_check_uses_a_fresh_throwaway_data_directory(monkeypatch):
    observed = {}

    def fake_create_app():
        observed["data_dir"] = __import__("os").environ["ARBITER_DATA_DIR"]
        observed["demo_mode"] = __import__("os").environ["ARBITER_DEMO_MODE"]
        return object()

    def fake_preflight(app):
        assert app is not None
        from arbiter.demo import DemoCheckResult

        return [DemoCheckResult("legitimate", "passed", "ok")]

    monkeypatch.setattr("arbiter.api.app.create_app", fake_create_app)
    monkeypatch.setattr("arbiter.demo.run_preflight", fake_preflight)
    assert main(["demo", "--check"]) == 0
    assert observed["demo_mode"] == "1"
    assert not __import__("pathlib").Path(observed["data_dir"]).exists()
