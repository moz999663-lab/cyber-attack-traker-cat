import json
import os
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import DateTime, MetaData, String, Table, create_engine, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON

from .models import SecurityEvent

metadata = MetaData()

events_table = Table(
    "security_events",
    metadata,
    # String keeps the UUID portable across SQLite and PostgreSQL.
    __import__("sqlalchemy").Column("event_id", String(36), primary_key=True),
    __import__("sqlalchemy").Column("host_id", String(128), nullable=False, index=True),
    __import__("sqlalchemy").Column("event_type", String(32), nullable=False),
    __import__("sqlalchemy").Column("timestamp", DateTime(timezone=True), nullable=False, index=True),
    __import__("sqlalchemy").Column("payload", JSON().with_variant(JSONB, "postgresql"), nullable=False),
)


def database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///./cat.db")


class EventStore:
    def __init__(self, url: str | None = None):
        self.engine = create_engine(url or database_url(), future=True)
        metadata.create_all(self.engine)

    def add(self, event: SecurityEvent) -> None:
        payload = event.model_dump(mode="json")
        with self.engine.begin() as connection:
            connection.execute(events_table.insert().values(
                event_id=str(event.event_id),
                host_id=event.host_id,
                event_type=event.event_type.value,
                timestamp=event.timestamp.astimezone(timezone.utc),
                payload=payload,
            ))

    def exists(self, event_id: UUID) -> bool:
        with self.engine.connect() as connection:
            return connection.execute(
                select(events_table.c.event_id).where(events_table.c.event_id == str(event_id)).limit(1)
            ).first() is not None

    def count(self) -> int:
        with self.engine.connect() as connection:
            return len(connection.execute(select(events_table.c.event_id)).all())
