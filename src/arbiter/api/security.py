"""Optional API-key authentication and small in-process rate limiter."""

from __future__ import annotations

import os
import time
from hashlib import sha256
from collections import defaultdict
from threading import Lock

from fastapi import HTTPException, Request


class Security:
    def __init__(self) -> None:
        self.keys = {key for key in os.environ.get("ARBITER_API_KEYS", "").split(",") if key}
        self.capacity = int(os.environ.get("ARBITER_RATE_LIMIT", "30"))
        self.window = float(os.environ.get("ARBITER_RATE_WINDOW", "60"))
        self.calls: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def expensive(self, request: Request) -> None:
        key = request.headers.get("X-API-Key")
        if self.keys and key not in self.keys:
            raise HTTPException(401, "valid X-API-Key required")
        identity = key or (request.client.host if request.client else "local")
        now = time.monotonic()
        with self._lock:
            calls = self.calls[identity]
            calls[:] = [then for then in calls if now - then < self.window]
            if len(calls) >= self.capacity:
                retry = max(1, int(self.window - (now - calls[0])))
                raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(retry)})
            calls.append(now)

    def identity(self, request: Request) -> str:
        key = request.headers.get("X-API-Key")
        return f"key:{sha256(key.encode()).hexdigest()}" if key else f"anonymous:{request.client.host if request.client else 'local'}"
