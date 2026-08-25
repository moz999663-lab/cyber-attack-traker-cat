"""Authenticated CAT telemetry sender.

The client only sends normalized telemetry to a configured CAT endpoint. The
server cannot send executable instructions through this client.
"""
from __future__ import annotations

import os
from typing import Any, Iterable

import httpx


def send_events(events: Iterable[dict[str, Any]], endpoint: str | None = None, api_key: str | None = None) -> int:
    endpoint = endpoint or os.environ.get("CAT_ENDPOINT", "http://127.0.0.1:8000/api/v1/events")
    api_key = api_key or os.environ.get("CAT_API_KEY", "")
    if not api_key:
        raise ValueError("CAT_API_KEY is required")
    sent = 0
    with httpx.Client(timeout=10.0, follow_redirects=False) as client:
        for event in events:
            response = client.post(endpoint, json=event, headers={"X-API-Key": api_key})
            response.raise_for_status()
            sent += 1
    return sent
