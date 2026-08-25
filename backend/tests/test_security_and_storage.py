import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.storage import EventStore
from app.models import SecurityEvent


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.delenv("CAT_API_KEY", raising=False)
    # Import-time STORE uses the process environment, so tests for the store
    # use an explicit URL and endpoint tests remain focused on API behavior.
    return TestClient(app)


def test_security_headers(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_api_key_required_when_configured(monkeypatch):
    monkeypatch.setenv("CAT_API_KEY", "test-secret")
    local_client = TestClient(app)
    response = local_client.post("/api/v1/demo")
    assert response.status_code == 401
    response = local_client.post("/api/v1/demo", headers={"X-API-Key": "test-secret"})
    assert response.status_code == 200


def test_event_store_round_trip(tmp_path):
    store = EventStore(f"sqlite:///{tmp_path / 'events.db'}")
    event = SecurityEvent(
        event_id=uuid4(),
        timestamp="2026-08-25T18:00:00Z",
        event_type="process",
        source="simulator",
        host_id="test-host",
    )
    store.add(event)
    assert store.exists(event.event_id)
    assert store.count() == 1
