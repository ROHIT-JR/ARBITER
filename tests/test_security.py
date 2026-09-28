from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from arbiter.api.app import create_app
from arbiter.api.security import Security


def _request(key: str | None = None, host: str = "127.0.0.1") -> Request:
    headers = [(b"x-api-key", key.encode())] if key else []
    return Request({"type": "http", "headers": headers, "client": (host, 1234)})


def test_api_key_auth(monkeypatch):
    monkeypatch.setenv("ARBITER_API_KEYS", "correct")
    security = Security()
    with pytest.raises(HTTPException, match="valid X-API-Key") as error:
        security.expensive(_request())
    assert error.value.status_code == 401
    security.expensive(_request("correct"))


def test_rate_limit_has_retry_after(monkeypatch):
    monkeypatch.setenv("ARBITER_RATE_LIMIT", "1")
    monkeypatch.setenv("ARBITER_RATE_WINDOW", "60")
    security = Security()
    security.expensive(_request())
    with pytest.raises(HTTPException) as error:
        security.expensive(_request())
    assert error.value.status_code == 429
    assert error.value.headers["Retry-After"] == "59"


def test_rate_limit_is_atomic_under_concurrency(monkeypatch):
    monkeypatch.setenv("ARBITER_RATE_LIMIT", "1")
    security = Security()
    def allowed():
        try:
            security.expensive(_request(host="same"))
            return True
        except HTTPException:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(lambda _: allowed(), range(8))).count(True) == 1


def test_cors_configuration_is_opt_in(tmp_path, monkeypatch):
    monkeypatch.setenv("ARBITER_CORS_ORIGINS", "https://dashboard.example")
    app = create_app(tmp_path)
    middleware = next(item for item in app.user_middleware if item.cls.__name__ == "CORSMiddleware")
    assert middleware.kwargs["allow_origins"] == ["https://dashboard.example"]
