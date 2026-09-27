"""FastAPI service: run attack simulations, get verdicts, inspect the ledger.

Run with ``uvicorn --factory arbiter.api.app:create_app`` and open /docs.
State lives in ``$ARBITER_DATA_DIR`` (default ``./.arbiter``): the ledger
keys and the JSON-lines ledger itself.
"""

from __future__ import annotations

import os
from collections import OrderedDict
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from arbiter import __version__
from arbiter.audit_ledger import AuditLedger, LedgerKeys
from arbiter.detection import attack_bounds
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
    data_dir = Path(data_dir or os.environ.get("ARBITER_DATA_DIR", ".arbiter"))
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
        return {"status": "ok", "version": __version__, "ledger_entries": len(ledger.entries)}

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

    @app.post("/sessions")
    def run_session(req: SessionRequest):
        config = SessionConfig(n_rounds=req.n_rounds, params=arbiter.params)
        t = simulate_session(req.hypothesis, req.theta, config, req.message, seed=req.seed, backend=req.backend)
        transcripts[t.session_id] = t
        while len(transcripts) > 256:
            transcripts.popitem(last=False)
        return arbiter.verify(t).to_dict(trajectory=req.trajectory)

    @app.post("/sessions/{session_id}/resubmit")
    def resubmit(session_id: str):
        """Replay a previously verified transcript verbatim (classical replay demo)."""
        t = transcripts.get(session_id)
        if t is None:
            raise HTTPException(404, "unknown or expired session id")
        return arbiter.verify(t).to_dict()

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

    return app

