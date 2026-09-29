"""Uvicorn server entry point for ARBITER API.

This module provides a direct FastAPI app instance for Uvicorn.
Usage: uvicorn arbiter.api.server:app
"""

from arbiter.api.app import create_app

app = create_app()
