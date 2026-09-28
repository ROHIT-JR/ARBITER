"""Offline demo presets and their headless pre-flight runner.

The web UI consumes the same JSON catalogue as the CLI.  Keeping the actions
here rather than in either transport adapter makes the morning-of-demo check
cheap to run and easy to test without opening a socket or browser.
"""

from __future__ import annotations

import json
import re
from asyncio import run
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any


class DemoCheckError(RuntimeError):
    """A seeded preset did not produce the promised result."""


@dataclass(frozen=True)
class DemoCheckResult:
    scenario_id: str
    status: str
    detail: str


_EXTERNAL_URL = re.compile(r"(?:https?:)?//(?!127\.0\.0\.1(?::\d+)?(?:/|$)|localhost(?::\d+)?(?:/|$))", re.IGNORECASE)


def dashboard_is_offline(static_dir: str | Path) -> bool:
    """Return whether a built dashboard avoids CDN and other external URLs."""
    index = Path(static_dir) / "index.html"
    return index.is_file() and _EXTERNAL_URL.search(index.read_text(encoding="utf-8")) is None


def demo_catalog() -> dict[str, Any]:
    """Load the versioned, package-owned demo catalogue."""
    raw = files("arbiter").joinpath("demo_scenarios.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("scenarios"), list):
        raise DemoCheckError("demo_scenarios.json must contain a scenarios list")
    return data


def _at_path(value: Mapping[str, Any], path: str) -> Any:
    current: Any = value
    for key in path.split("."):
        if not isinstance(current, Mapping) or key not in current:
            raise DemoCheckError(f"response has no {path!r}")
        current = current[key]
    return current


def _assert_expected(response: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    for path, wanted in expected.items():
        actual = _at_path(response, path)
        if isinstance(wanted, Mapping):
            if "at_most" in wanted and not actual <= wanted["at_most"]:
                raise DemoCheckError(f"{path}: expected at most {wanted['at_most']}, got {actual}")
            if "at_least" in wanted and not actual >= wanted["at_least"]:
                raise DemoCheckError(f"{path}: expected at least {wanted['at_least']}, got {actual}")
        elif actual != wanted:
            raise DemoCheckError(f"{path}: expected {wanted!r}, got {actual!r}")


def run_preflight(app: Any) -> list[DemoCheckResult]:
    """Exercise every available preset through the ASGI app, without a network.

    An ASGI transport keeps the check faithful to the dashboard's HTTP
    contract while avoiding a real TCP listener. Results are retained by
    scenario id for the deliberate replay and tamper follow-up actions.
    """
    import httpx

    async def check() -> list[DemoCheckResult]:
        catalogue = demo_catalog()
        responses: dict[str, Mapping[str, Any]] = {}
        results: list[DemoCheckResult] = []
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://arbiter.local") as client:
            for scenario in catalogue["scenarios"]:
                scenario_id = scenario["id"]
                kind = scenario["kind"]
                if scenario.get("optional") and not scenario.get("cached_result"):
                    results.append(DemoCheckResult(scenario_id, "skipped", "no cached hardware result bundled"))
                    continue

                if kind == "session":
                    response = await client.post("/sessions", json=scenario["request"])
                elif kind == "resubmit":
                    source = responses[scenario["source"]]
                    response = await client.post(f"/sessions/{_at_path(source, 'session.id')}/resubmit?trajectory=true")
                elif kind == "tamper":
                    source = responses[scenario["source"]]
                    response = await client.post(
                        f"/ledger/{_at_path(source, 'ledger.index')}/tamper",
                        json=scenario["request"],
                    )
                elif kind == "accuracy":
                    cached = scenario.get("cached_result")
                    if not isinstance(cached, Mapping):
                        raise DemoCheckError(f"{scenario_id}: cached comparison is missing")
                    _assert_expected(cached, scenario["expected"])
                    responses[scenario_id] = cached
                    results.append(DemoCheckResult(scenario_id, "passed", "cached comparison is internally consistent"))
                    continue
                else:
                    raise DemoCheckError(f"{scenario_id}: unknown scenario kind {kind!r}")

                if response.status_code >= 400:
                    raise DemoCheckError(f"{scenario_id}: API returned {response.status_code}: {response.text[:200]}")
                payload = response.json()
                if not isinstance(payload, Mapping):
                    raise DemoCheckError(f"{scenario_id}: API did not return an object")
                _assert_expected(payload, scenario["expected"])
                responses[scenario_id] = payload
                results.append(DemoCheckResult(scenario_id, "passed", scenario["title"]))
        return results

    return run(check())
