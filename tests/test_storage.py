import sqlite3
from concurrent.futures import ThreadPoolExecutor

from arbiter.detection import NonceRegistry
from arbiter.pipeline import Arbiter
from arbiter.qds_simulation import Hypothesis, SessionConfig, simulate_session
from arbiter.storage import SQLiteStorage


def test_transcript_round_trips_with_its_digest(tmp_path):
    storage = SQLiteStorage(tmp_path / "arbiter.db")
    transcript = simulate_session(Hypothesis.FORGERY, seed=81)

    storage.save_session(transcript, seed=81)
    restored = storage.load_session(transcript.session_id)

    assert restored is not None
    assert restored.digest() == transcript.digest()
    assert restored.cells.tolist() == transcript.cells.tolist()
    assert restored.outcomes.tolist() == transcript.outcomes.tolist()


def test_sqlite_nonce_registry_is_atomic_and_survives_reopen(tmp_path):
    database = tmp_path / "arbiter.db"
    registry = SQLiteStorage(database).nonce_registry()

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(registry.check_and_register, ["same-nonce"] * 8))

    assert results.count(True) == 1
    assert SQLiteStorage(database).nonce_registry().check_and_register("same-nonce") is False


def test_legacy_arbiter_positional_nonce_registry_is_preserved():
    registry = NonceRegistry()
    arbiter = Arbiter(None, 0.01, None, 2.0, registry)
    assert arbiter.nonces is registry
    assert arbiter.protocol == "prf"


def test_qds_transcript_round_trips_with_protocol_and_digest(tmp_path):
    storage = SQLiteStorage(tmp_path / "arbiter.db")
    transcript = simulate_session(config=SessionConfig(n_rounds=100, protocol="qds"), seed=82)

    storage.save_session(transcript, seed=82)
    restored = storage.load_session(transcript.session_id)

    assert restored is not None
    assert restored.protocol == "qds"
    assert restored.digest() == transcript.digest()


def test_existing_sqlite_sessions_migrate_to_prf_protocol(tmp_path):
    database = tmp_path / "legacy.db"
    transcript = simulate_session(seed=83)
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE sessions (
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL, hypothesis TEXT NOT NULL,
                theta REAL NOT NULL, backend TEXT NOT NULL, seed INTEGER, nonce TEXT NOT NULL,
                cells BLOB NOT NULL, outcomes BLOB NOT NULL, digest TEXT NOT NULL,
                message TEXT NOT NULL, attacked BLOB NOT NULL
            );
            """
        )
        connection.execute(
            """
            INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transcript.session_id,
                "2026-01-01T00:00:00+00:00",
                transcript.truth.value,
                transcript.theta,
                transcript.backend,
                83,
                transcript.nonce,
                transcript.cells.astype("int64").tobytes(),
                transcript.outcomes.astype("int8").tobytes(),
                transcript.digest(),
                transcript.message,
                transcript.attacked.astype("bool").tobytes(),
            ),
        )

    restored = SQLiteStorage(database).load_session(transcript.session_id)
    assert restored is not None
    assert restored.protocol == "prf"
    assert restored.digest() == transcript.digest()
