from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator

class EventType(str, Enum):
    process = "process"
    file = "file"
    network = "network"
    auth = "auth"
    system = "system"

class ProcessInfo(BaseModel):
    pid: int | None = Field(default=None, ge=0)
    parent_pid: int | None = Field(default=None, ge=0)
    name: str | None = Field(default=None, max_length=255)
    executable: str | None = Field(default=None, max_length=1024)
    hash_sha256: str | None = Field(default=None, min_length=64, max_length=64)

    @field_validator("hash_sha256")
    @classmethod
    def valid_hash(cls, value: str | None):
        if value is not None and any(c not in "0123456789abcdefABCDEF" for c in value):
            raise ValueError("hash_sha256 must be hexadecimal")
        return value

class NetworkInfo(BaseModel):
    direction: Literal["inbound", "outbound"] | None = None
    remote_ip: str | None = Field(default=None, max_length=64)
    remote_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = Field(default=None, max_length=32)

class FileInfo(BaseModel):
    path: str | None = Field(default=None, max_length=2048)
    operation: Literal["create", "modify", "delete", "rename"] | None = None
    hash_sha256: str | None = Field(default=None, min_length=64, max_length=64)

class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: UUID
    timestamp: datetime
    event_type: EventType
    source: Literal["agent", "simulator", "integration"]
    host_id: str = Field(min_length=1, max_length=128)
    user_id: str | None = Field(default=None, max_length=128)
    process: ProcessInfo | None = None
    network: NetworkInfo | None = None
    file: FileInfo | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    schema_version: Literal["1.0"] = "1.0"

    @field_validator("timestamp")
    @classmethod
    def utc_timestamp(cls, value: datetime):
        if value.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        return value.astimezone(timezone.utc)
