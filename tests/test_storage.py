from concurrent.futures import ThreadPoolExecutor

from arbiter.qds_simulation import Hypothesis, simulate_session
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
