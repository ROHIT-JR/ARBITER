"""FastAPI service: run attack simulations, get verdicts, inspect the ledger.

Run with ``uvicorn --factory arbiter.api.app:create_app`` and open /docs.
State lives in ``$ARBITER_DATA_DIR`` (default ``./.arbiter``): the ledger
keys and the JSON-lines ledger itself.
"""

from __future__ import annotations

import os
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from arbiter import __version__
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


class SessionRequest(BaseModel):
    hypothesis: Hypothesis = Hypothesis.LEGITIMATE
    theta: float = Field(1.0, gt=0, le=1, description="fraction of rounds attacked (impersonation is always 1)")
    n_rounds: int = Field(1200, ge=40, le=20000)
    backend: Literal["analytic", "qiskit"] = "analytic"
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
    arbiter = Arbiter(params, ledger=ledger)
    transcripts: OrderedDict[str, Transcript] = OrderedDict()

    app = FastAPI(
        title="ARBITER",
        version=__version__,
        description="Unified attack attribution for teleportation-based quantum digital signatures.",
    )

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "version": __version__,
            "ledger_entries": len(ledger.entries),
            "ledger_capacity": keys.hbs.capacity,
            "noise_preset": preset,
        }

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
    def compare(
        theta: float = Query(1.0, gt=0, le=1),
        sessions: int = Query(100, ge=1, le=1000),
        seed: int = Query(26141, ge=0, le=2**32 - 1),
    ):
        """Unified GLRT vs equally calibrated fixed-threshold baselines."""
        return compare_detectors(theta, sessions, seed, params=arbiter.params)

    @app.post("/sessions")
    def run_session(req: SessionRequest):
        config = SessionConfig(n_rounds=req.n_rounds, params=arbiter.params)
        t = simulate_session(req.hypothesis, req.theta, config, req.message, seed=req.seed, backend=req.backend)
        transcripts[t.session_id] = t
        while len(transcripts) > 256:
            transcripts.popitem(last=False)
        return _verify(t, req.trajectory)

    def _verify(t: Transcript, trajectory: bool = False) -> dict:
        try:
            return arbiter.verify(t).to_dict(trajectory=trajectory)
        except ValueError as exc:  # hash-based one-time keys exhausted
            raise HTTPException(409, f"audit ledger cannot sign: {exc}; rotate keys") from exc

    @app.post("/sessions/{session_id}/resubmit")
    def resubmit(session_id: str, trajectory: bool = Query(False)):
        """Replay a previously verified transcript verbatim (classical replay demo)."""
        t = transcripts.get(session_id)
        if t is None:
            raise HTTPException(404, "unknown or expired session id")
        return _verify(t, trajectory)

    @app.get("/ledger")
    def ledger_entries(limit: int = Query(50, ge=1, le=1000)):
        return {"genesis_hash": ledger.genesis_hash, "entries": [_summarise_entry(e) for e in ledger.entries[-limit:]]}

    @app.get("/ledger/verify")
    def ledger_verify():
        return ledger.verify().to_dict()

    @app.get("/ledger/{index}")
    def ledger_entry(index: int):
        if not 0 <= index < len(ledger.entries):
            raise HTTPException(404, "no such entry")
        return ledger.entries[index]

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

    return app
