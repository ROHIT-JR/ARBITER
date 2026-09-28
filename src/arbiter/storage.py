"""SQLite persistence for API sessions, verdicts, and replay nonces.

The application intentionally keeps this module separate from the simulation
and detection code: :class:`arbiter.pipeline.Arbiter` still uses the in-memory
``NonceRegistry`` by default.  The FastAPI application opts into this store so
a nonce cannot become valid again just because the server restarted.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from arbiter.qds_simulation.model import Hypothesis
from arbiter.qds_simulation.protocol import Transcript


class SQLiteNonceRegistry:
    """A nonce registry backed by a UNIQUE constraint.

    Each call uses its own connection, so the insert remains safe when API
    requests are handled by separate threads.  ``INSERT OR IGNORE`` is both
    the freshness check and the registration operation.
    """

    def __init__(self, storage: SQLiteStorage):
        self.storage = storage

    def check_and_register(self, nonce: str) -> bool:
        with self.storage._connect() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO nonces (nonce, first_seen) VALUES (?, ?)",
                (nonce, _utc_now()),
            )
            return cursor.rowcount == 1


class SQLiteStorage:
    """Persistent API state stored in one portable SQLite database."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    hypothesis TEXT NOT NULL,
                    theta REAL NOT NULL,
                    backend TEXT NOT NULL,
                    seed INTEGER,
                    nonce TEXT NOT NULL,
                    cells BLOB NOT NULL,
                    outcomes BLOB NOT NULL,
                    digest TEXT NOT NULL,
                    message TEXT NOT NULL,
                    attacked BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS nonces (
                    nonce TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS verdicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id),
                    decision TEXT NOT NULL,
                    attribution TEXT NOT NULL,
                    ledger_index INTEGER,
                    json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS verdicts_session_id_id ON verdicts(session_id, id DESC);
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL, params TEXT NOT NULL,
                    status TEXT NOT NULL, progress REAL NOT NULL, result TEXT,
                    error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                """
            )
            connection.execute(
                "UPDATE jobs SET status='failed', progress=1, error='interrupted by server restart', updated_at=? "
                "WHERE status IN ('queued', 'running')",
                (_utc_now(),),
            )

    def nonce_registry(self) -> SQLiteNonceRegistry:
        return SQLiteNonceRegistry(self)

    def save_session(self, transcript: Transcript, seed: int | None = None) -> None:
        """Store a simulated transcript before it is verified.

        ``attacked`` and ``message`` are retained as reconstruction metadata.
        They are not detector inputs, but preserve the public ``Transcript``
        object and make its digest round-trip exactly.
        """
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO sessions (
                    id, created_at, hypothesis, theta, backend, seed, nonce,
                    cells, outcomes, digest, message, attacked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transcript.session_id,
                    _utc_now(),
                    transcript.truth.value,
                    transcript.theta,
                    transcript.backend,
                    seed,
                    transcript.nonce,
                    _array_bytes(transcript.cells, np.int64),
                    _array_bytes(transcript.outcomes, np.int8),
                    transcript.digest(),
                    transcript.message,
                    _array_bytes(transcript.attacked, np.bool_),
                ),
            )

    def load_session(self, session_id: str) -> Transcript | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if row is None:
            return None
        transcript = Transcript(
            session_id=row["id"],
            message=row["message"],
            nonce=row["nonce"],
            cells=_array_from_bytes(row["cells"], np.int64),
            outcomes=_array_from_bytes(row["outcomes"], np.int8),
            truth=Hypothesis(row["hypothesis"]),
            theta=float(row["theta"]),
            attacked=_array_from_bytes(row["attacked"], np.bool_),
            backend=row["backend"],
        )
        if transcript.digest() != row["digest"]:
            raise ValueError(f"stored transcript {session_id} failed its digest check")
        return transcript

    def save_verdict(self, session_id: str, verdict: dict[str, Any]) -> None:
        ledger = verdict.get("ledger") or {}
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO verdicts (session_id, decision, attribution, ledger_index, json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    verdict["decision"],
                    verdict["attribution"],
                    ledger.get("index"),
                    json.dumps(verdict, sort_keys=True, separators=(",", ":")),
                    _utc_now(),
                ),
            )

    def create_job(self, job_id: str, kind: str, params: dict[str, Any]) -> None:
        with self._connect() as connection:
            now = _utc_now()
            connection.execute(
                "INSERT INTO jobs VALUES (?, ?, ?, 'queued', 0, NULL, NULL, ?, ?)",
                (job_id, kind, json.dumps(params), now, now),
            )

    def update_job(self, job_id: str, *, status: str, progress: float, result=None, error=None) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE jobs SET status=?, progress=?, result=?, error=?, updated_at=? WHERE id=?",
                (status, progress, json.dumps(result) if result is not None else None, error, _utc_now(), job_id),
            )

    def job(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            return None
        return {
            "job_id": row["id"],
            "kind": row["kind"],
            "status": row["status"],
            "progress": row["progress"],
            "result": json.loads(row["result"]) if row["result"] else None,
            "error": row["error"],
        }

    def list_sessions(self, limit: int) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT s.id, s.created_at, s.hypothesis, s.theta, s.backend, s.nonce, s.digest,
                       v.decision, v.attribution, v.ledger_index
                FROM sessions AS s
                LEFT JOIN verdicts AS v ON v.id = (
                    SELECT id FROM verdicts WHERE session_id = s.id ORDER BY id DESC LIMIT 1
                )
                ORDER BY s.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._session_summary(row) for row in rows]

    def session_details(self, session_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT s.id, s.created_at, s.hypothesis, s.theta, s.backend, s.seed, s.nonce, s.digest,
                       v.json AS verdict
                FROM sessions AS s
                LEFT JOIN verdicts AS v ON v.id = (
                    SELECT id FROM verdicts WHERE session_id = s.id ORDER BY id DESC LIMIT 1
                )
                WHERE s.id = ?
                """,
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        details = self._session_summary(row)
        details["seed"] = row["seed"]
        details["verdict"] = json.loads(row["verdict"]) if row["verdict"] else None
        return details

    @staticmethod
    def _session_summary(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "hypothesis": row["hypothesis"],
            "theta": row["theta"],
            "backend": row["backend"],
            "nonce": row["nonce"],
            "transcript_digest": row["digest"],
            "decision": row["decision"] if "decision" in row.keys() else None,
            "attribution": row["attribution"] if "attribution" in row.keys() else None,
            "ledger_index": row["ledger_index"] if "ledger_index" in row.keys() else None,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _array_bytes(values: np.ndarray, dtype: np.dtype) -> bytes:
    return np.asarray(values, dtype=dtype).tobytes()


def _array_from_bytes(values: bytes, dtype: np.dtype) -> np.ndarray:
    return np.frombuffer(values, dtype=dtype).copy()
