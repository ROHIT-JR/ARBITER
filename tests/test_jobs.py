from threading import Event

from arbiter.api.jobs import JobRunner
from arbiter.storage import SQLiteStorage


def test_job_result_persists_across_storage_reopen(tmp_path):
    done = Event()

    def run(kind, params):
        done.set()
        return {"kind": kind, "value": params["value"]}

    storage = SQLiteStorage(tmp_path / "arbiter.db")
    runner = JobRunner(storage, run)
    job_id = runner.submit("compare", {"value": 7})
    assert done.wait(2)
    assert SQLiteStorage(tmp_path / "arbiter.db").job(job_id) == {
        "job_id": job_id,
        "owner": "anonymous:local",
        "kind": "compare",
        "status": "done",
        "progress": 1,
        "result": {"kind": "compare", "value": 7},
        "error": None,
    }
    runner.pool.shutdown(wait=True)


def test_job_failure_is_persisted(tmp_path):
    done = Event()

    def fail(kind, params):
        done.set()
        raise RuntimeError("deliberate worker failure")

    storage = SQLiteStorage(tmp_path / "arbiter.db")
    runner = JobRunner(storage, fail)
    job_id = runner.submit("session", {})
    assert done.wait(2)
    runner.pool.shutdown(wait=True)
    job = storage.job(job_id)
    assert job["status"] == "failed"
    assert job["error"] == "deliberate worker failure"


def test_interrupted_jobs_are_marked_failed_on_restart(tmp_path):
    path = tmp_path / "arbiter.db"
    storage = SQLiteStorage(path)
    storage.create_job("interrupted", "compare", {})
    storage.update_job("interrupted", status="running", progress=0.4)
    job = SQLiteStorage(path).job("interrupted")
    assert job["status"] == "failed"
    assert job["error"] == "interrupted by server restart"
