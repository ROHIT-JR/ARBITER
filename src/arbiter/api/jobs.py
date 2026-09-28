"""Persistent, in-process background jobs for expensive API work."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4


class JobRunner:
    def __init__(self, storage, run):
        self.storage, self.run = storage, run
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="arbiter-job")

    def submit(self, kind: str, params: dict) -> str:
        job_id = str(uuid4())
        self.storage.create_job(job_id, kind, params)
        self.pool.submit(self._work, job_id, kind, params)
        return job_id

    def _work(self, job_id: str, kind: str, params: dict) -> None:
        self.storage.update_job(job_id, status="running", progress=0.05)
        try:
            result = self.run(kind, params)
            self.storage.update_job(job_id, status="done", progress=1, result=result)
        except Exception as exc:  # worker failures must remain observable
            self.storage.update_job(job_id, status="failed", progress=1, error=str(exc))
