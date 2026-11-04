"""Shared bounded Groq client configuration."""

from __future__ import annotations

import httpx
from groq import Groq


def create_groq_client(api_key: str, *, timeout: float) -> Groq:
    """Create an SDK client with bounded timeout, no retries, and no redirects."""
    transport = httpx.Client(timeout=timeout, follow_redirects=False)
    try:
        return Groq(api_key=api_key, timeout=timeout, max_retries=0, http_client=transport)
    except Exception:
        transport.close()
        raise
