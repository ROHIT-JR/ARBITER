"""FastAPI service: run attack simulations, get verdicts, inspect the ledger.

Run with ``uvicorn --factory arbiter.api.app:create_app`` and open /docs.
State lives in ``$ARBITER_DATA_DIR`` (default ``./.arbiter``): the ledger
keys and the JSON-lines ledger itself.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from importlib.resources import files
from pathlib import Path
from threading import Lock
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from arbiter import __version__
from arbiter.api.jobs import JobRunner
from arbiter.api.security import Security
from arbiter.audit_ledger import AuditLedger, LedgerKeys
from arbiter.detection import attack_bounds, compare_detectors
from arbiter.noise import PRESETS
from arbiter.pipeline import Arbiter
from arbiter.qds_simulation import (
    CELLS,
    ChannelParams,
    Hypothesis,
    SessionConfig,
    Transcript,
    cell_probabilities,
    expected_chsh,
    simulate_session,
)
from arbiter.storage import SQLiteStorage


def dashboard_dist() -> Path:
    """Return the installed dashboard resource directory, with a test override."""
    configured = os.environ.get("ARBITER_DASHBOARD_DIR")
    if configured:
        return Path(configured)
    return Path(str(files("arbiter").joinpath("dashboard")))


class ApiPrefixMiddleware:
    """Let the static dashboard keep its stable ``/api`` development contract.

    Existing API consumers continue using unprefixed paths; only the dashboard
    alias is rewritten before FastAPI performs its normal route matching.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"].startswith("/api/"):
            scope = dict(scope)
            scope["path"] = scope["path"][4:]
            scope["raw_path"] = scope["path"].encode()
        await self.app(scope, receive, send)


class SessionRequest(BaseModel):
    hypothesis: Hypothesis = Hypothesis.LEGITIMATE
    theta: float = Field(1.0, gt=0, le=1, description="fraction of rounds attacked (impersonation is always 1)")
    n_rounds: int = Field(1200, ge=40, le=20000)
    backend: Literal["analytic", "qiskit"] = "analytic"
    protocol: Literal["prf", "qds"] = "prf"
    seed: int | None = None
    message: str = "transfer 100 units to account 42"
    trajectory: bool = Field(False, description="include the sequential log-evidence trajectory")


class CertificateRequest(BaseModel):
    pem: str = Field(..., description="one or more PEM certificates")
    protection_years_after_expiry: float = Field(0.0, ge=0, le=100)
    crqc_year: int = Field(2035, ge=2025, le=2100)


class KeyRequest(BaseModel):
    algorithm: str = Field(..., examples=["RSA", "ECDSA", "Ed25519", "ML-DSA-65"])
    key_bits: int | None = Field(None, ge=1, le=65536)
    expires: datetime | None = None
    protection_years_after_expiry: float = Field(0.0, ge=0, le=100)
    crqc_year: int = Field(2035, ge=2025, le=2100)


class LedgerTamperRequest(BaseModel):
    field: Literal["decision", "attribution", "timestamp"]
    value: str = Field(min_length=1, max_length=500)
    recompute_hashes: bool = False


class TlsScanRequest(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=32, description="host, host:port, or [ipv6]:port")
    timeout: float = Field(5.0, gt=0, le=60)
    protection_years_after_expiry: float = Field(0.0, ge=0, le=100)
    crqc_year: int = Field(2035, ge=2025, le=2100)


class JobRequest(BaseModel):
    kind: Literal["session", "compare", "hardware"]
    params: dict = Field(default_factory=dict)


def _summarise_entry(e: dict) -> dict:
    p = e["payload"]
    out = {"index": e["index"], "timestamp": e["timestamp"], "hash": e["hash"], "prev_hash": e["prev_hash"]}
    if p.get("type") == "verdict":
        out |= {
            "session_id": p["session"]["id"],
            "decision": p["decision"],
            "attribution": p["attribution"],
            "signed": {"mldsa": bool(e["signatures"]["mldsa"]), "hbs_leaf": e["signatures"]["hbs"]["leaf"]},
        }
    else:
        out["type"] = p.get("type")
    return out


def create_app(data_dir: Path | None = None, params: ChannelParams | None = None) -> FastAPI:
    """Build the app. ``$ARBITER_NOISE_PRESET`` (a key of ``arbiter.noise.PRESETS``)
    calibrates the legitimate channel from a trapped-ion noise model."""
    data_dir = Path(data_dir or os.environ.get("ARBITER_DATA_DIR", ".arbiter"))
    preset = os.environ.get("ARBITER_NOISE_PRESET")
    if params is None and preset:
        if preset not in PRESETS:
            raise ValueError(f"unknown ARBITER_NOISE_PRESET {preset!r}; choose from {sorted(PRESETS)}")
        params = PRESETS[preset].channel_params()
    key_path = data_dir / "ledger_keys.json"
    if key_path.exists():
        keys = LedgerKeys.load(key_path)
    else:
        keys = LedgerKeys.generate()
        keys.save(key_path)
    ledger = AuditLedger(keys, data_dir / "ledger.jsonl")
    storage = SQLiteStorage(data_dir / "arbiter.db")
    arbiter = Arbiter(params, ledger=ledger, nonces=storage.nonce_registry())
    arbiters = {
        "prf": arbiter,
        "qds": Arbiter(params, ledger=ledger, nonces=storage.nonce_registry(), protocol="qds"),
    }
    ledger_lock = Lock()
    demo_mode = os.environ.get("ARBITER_DEMO_MODE") == "1"
    if demo_mode:
        logging.getLogger(__name__).warning(
            "ARBITER DEMO MODE IS ENABLED: in-memory ledger tampering endpoints are available. "
            "Do not expose this server outside a controlled demo."
        )
    scan_enabled = os.environ.get("ARBITER_PKI_SCAN") == "1"
    scan_allowlist = tuple(
        item.strip() for item in os.environ.get("ARBITER_PKI_SCAN_ALLOW", "").split(",") if item.strip()
    )
    security = Security()

    app = FastAPI(
        title="ARBITER",
        version=__version__,
        description="Unified attack attribution for teleportation-based quantum digital signatures.",
    )
    origins = [value for value in os.environ.get("ARBITER_CORS_ORIGINS", "").split(",") if value]
    app.add_middleware(
        CORSMiddleware, allow_origins=origins, allow_methods=["*"], allow_headers=["*"], allow_credentials=False
    )
    app.add_middleware(ApiPrefixMiddleware)

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "version": __version__,
            "ledger_entries": len(ledger.entries),
            "ledger_capacity": keys.hbs.capacity,
            "noise_preset": preset,
            "demo_mode": demo_mode,
        }

    @app.get("/demo/scenarios")
    def demo_scenarios():
        """Named, seeded local-demo actions plus an instant cached accuracy view."""
        from arbiter.demo import demo_catalog

        return demo_catalog()

    @app.get("/model")
    def model(theta: float = Query(1.0, gt=0, le=1)):
        """Per-cell outcome probabilities each hypothesis induces (the detector's likelihoods)."""
        return {
            "params": arbiter.params.__dict__,
            "cells": CELLS,
            "hypotheses": {
                h.value: {
                    "cell_probabilities": cell_probabilities(h, theta, arbiter.params).round(6).tolist(),
                    "expected_chsh": round(expected_chsh(h, theta, arbiter.params), 4),
                }
                for h in Hypothesis
            },
        }

    @app.get("/bounds")
    def bounds(theta: float = Query(1.0, gt=0, le=1), epsilon: float = Query(1e-6, gt=0, lt=1)):
        """Helstrom / quantum-Chernoff limits vs what ARBITER's measurements achieve."""
        return attack_bounds(theta, SessionConfig(params=arbiter.params), epsilon)

    @app.get("/compare")
    def compare(  # noqa: B008
        theta: float = Query(1.0, gt=0, le=1),
        sessions: int = Query(100, ge=1, le=1000),
        seed: int = Query(26141, ge=0, le=2**32 - 1),
        _=Depends(security.expensive),  # noqa: B008
    ):
        """Unified GLRT vs equally calibrated fixed-threshold baselines."""
        return compare_detectors(theta, sessions, seed, params=arbiter.params)

    def _run_session(req: SessionRequest):
        config = SessionConfig(n_rounds=req.n_rounds, params=arbiter.params, protocol=req.protocol)
        t = simulate_session(req.hypothesis, req.theta, config, req.message, seed=req.seed, backend=req.backend)
        storage.save_session(t, seed=req.seed)
        return _verify(t, req.trajectory)

    @app.post("/sessions")
    def run_session(req: SessionRequest, _=Depends(security.expensive)):  # noqa: B008
        if req.backend == "qiskit" and req.n_rounds > 5000:
            raise HTTPException(422, "use POST /jobs for Qiskit sessions above 5000 rounds")
        return _run_session(req)

    def _verify(t: Transcript, trajectory: bool = False) -> dict:
        try:
            with ledger_lock:
                result = arbiters[t.protocol].verify(t).to_dict(trajectory=trajectory)
            storage.save_verdict(t.session_id, result)
            return result
        except ValueError as exc:  # hash-based one-time keys exhausted
            raise HTTPException(409, f"audit ledger cannot sign: {exc}; rotate keys") from exc

    def _run_job(kind: str, job_params: dict) -> dict:
        if kind == "session":
            return _run_session(SessionRequest.model_validate(job_params))
        if kind == "compare":
            return compare_detectors(
                float(job_params.get("theta", 1)),
                int(job_params.get("sessions", 100)),
                int(job_params.get("seed", 26141)),
                params=arbiter.params,
            )
        raise ValueError("hardware jobs require the optional hardware backend")

    jobs = JobRunner(storage, _run_job)

    @app.on_event("shutdown")
    def shutdown_jobs() -> None:
        """Release worker threads when an application instance is discarded."""
        jobs.pool.shutdown(wait=False, cancel_futures=True)

    @app.post("/jobs", status_code=status.HTTP_202_ACCEPTED)
    def create_job(req: JobRequest, request: Request, _=Depends(security.expensive)):  # noqa: B008
        return {"job_id": jobs.submit(req.kind, req.params, security.identity(request))}

    @app.get("/jobs/{job_id}")
    def get_job(job_id: str, request: Request, _=Depends(security.expensive)):  # noqa: B008
        job = storage.job(job_id)
        if job is None:
            raise HTTPException(404, "unknown job id")
        if job["owner"] != security.identity(request):
            raise HTTPException(403, "job belongs to another API identity")
        job.pop("owner")
        return job

    @app.post("/sessions/{session_id}/resubmit")
    def resubmit(session_id: str, trajectory: bool = Query(False)):
        """Replay a previously verified transcript verbatim (classical replay demo)."""
        t = storage.load_session(session_id)
        if t is None:
            raise HTTPException(404, "unknown session id")
        return _verify(t, trajectory)

    @app.get("/sessions")
    def sessions(limit: int = Query(50, ge=1, le=1000)):
        return {"sessions": storage.list_sessions(limit)}

    @app.get("/sessions/{session_id}")
    def session(session_id: str):
        details = storage.session_details(session_id)
        if details is None:
            raise HTTPException(404, "unknown session id")
        return details

    @app.get("/ledger")
    def ledger_entries(limit: int = Query(50, ge=1, le=1000)):
        return {"genesis_hash": ledger.genesis_hash, "entries": [_summarise_entry(e) for e in ledger.entries[-limit:]]}

    @app.get("/ledger/verify")
    def ledger_verify():
        with ledger_lock:
            return ledger.verify().to_dict()

    @app.get("/ledger/{index}")
    def ledger_entry(index: int):
        if not 0 <= index < len(ledger.entries):
            raise HTTPException(404, "no such entry")
        return ledger.entries[index]

    def _require_demo_mode() -> None:
        if not demo_mode:
            raise HTTPException(403, "ledger tampering is available only when ARBITER_DEMO_MODE=1")

    @app.post("/ledger/{index}/tamper")
    def ledger_tamper(index: int, req: LedgerTamperRequest):
        """Alter an in-memory entry for the controlled, visual tamper demo."""
        _require_demo_mode()
        if not 1 <= index < len(ledger.entries):
            raise HTTPException(422, "choose a signed ledger entry; the genesis entry cannot be tampered")
        entry = ledger.entries[index]
        if req.field == "timestamp":
            entry["timestamp"] = req.value
        else:
            payload = entry.get("payload", {})
            if payload.get("type") != "verdict":
                raise HTTPException(422, "only verdict entries have decision and attribution fields")
            payload[req.field] = req.value
        if req.recompute_hashes:
            ledger.recompute_hashes_from(index)
        return ledger.verify().to_dict()

    @app.post("/ledger/restore")
    def ledger_restore():
        """Restore the in-memory demo ledger from its untouched persisted file."""
        _require_demo_mode()
        try:
            ledger.restore()
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return ledger.verify().to_dict()

    @app.get("/noise/presets")
    def noise_presets():
        """Trapped-ion noise presets and the channel parameters they induce."""
        return {name: p.to_dict() for name, p in PRESETS.items()}

    @app.post("/pki/assess")
    def pki_assess(req: CertificateRequest):
        """Quantum-risk score for certificates, with a chain report for linked bundles."""
        try:
            from arbiter.pki_risk_scoring import assess_certificates, assess_chains
        except ImportError as exc:  # pragma: no cover
            raise HTTPException(501, "install arbiter-qds[pki] for certificate parsing") from exc
        try:
            reports = assess_certificates(
                req.pem.encode(),
                protection_years_after_expiry=req.protection_years_after_expiry,
                crqc_year=req.crqc_year,
            )
            chains = assess_chains(
                req.pem.encode(),
                protection_years_after_expiry=req.protection_years_after_expiry,
                crqc_year=req.crqc_year,
            )
        except ValueError as exc:
            raise HTTPException(422, f"could not parse certificate: {exc}") from exc
        # Keep the original list response for a standalone certificate or a
        # bag of unrelated certificates.  A linked path gains the richer
        # chain result without breaking existing API users.
        if any(len(chain.links) > 1 for chain in chains):
            return {"chains": [chain.to_dict() for chain in chains]}
        return [r.to_dict() for r in reports]

    @app.post("/pki/assess-key")
    def pki_assess_key(req: KeyRequest):
        from arbiter.pki_risk_scoring import assess_key

        return assess_key(
            req.algorithm,
            req.key_bits,
            expires=req.expires,
            protection_years_after_expiry=req.protection_years_after_expiry,
            crqc_year=req.crqc_year,
        ).to_dict()

    @app.post("/pki/scan")
    def pki_scan(req: TlsScanRequest):
        """Scan allowlisted public TLS endpoints when explicitly enabled."""
        if not scan_enabled:
            raise HTTPException(403, "TLS scanning is disabled; set ARBITER_PKI_SCAN=1 to enable it")
        if not scan_allowlist:
            raise HTTPException(403, "TLS scanning requires ARBITER_PKI_SCAN_ALLOW with allowed hostname suffixes")
        try:
            from arbiter.pki_risk_scoring.scan import (
                ScanBlockedError,
                ScanError,
                host_is_allowed,
                parse_target,
                scan_tls,
            )
        except ImportError as exc:  # pragma: no cover
            raise HTTPException(501, "install arbiter-qds[pki] for TLS certificate scanning") from exc
        reports = []
        for target in req.targets:
            try:
                host, port = parse_target(target)
                if not host_is_allowed(host, scan_allowlist):
                    raise ScanBlockedError(f"target {host!r} is outside the configured allowlist")
                reports.append(
                    scan_tls(
                        host,
                        port,
                        timeout=req.timeout,
                        protection_years_after_expiry=req.protection_years_after_expiry,
                        crqc_year=req.crqc_year,
                    ).to_dict()
                )
            except ScanBlockedError as exc:
                raise HTTPException(403, str(exc)) from exc
            except ScanError as exc:
                raise HTTPException(422, str(exc)) from exc
        return reports

    static_dir = dashboard_dist()
    if (static_dir / "index.html").is_file():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="dashboard")
    return app
