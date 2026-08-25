"""CAT endpoint telemetry agent.

Collects process and network metadata only. It never executes commands received
from the server and does not collect credentials, file contents, or keystrokes.
"""
from __future__ import annotations

import hashlib
import os
import platform
import socket
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import psutil
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("Install psutil to run the CAT agent") from exc


@dataclass(frozen=True)
class AgentConfig:
    host_id: str
    interval_seconds: float = 10.0
    max_processes: int = 500


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: str, max_bytes: int = 4 * 1024 * 1024) -> str | None:
    """Hash a readable executable only, with a strict size/read limit."""
    try:
        p = Path(path)
        if not p.is_file() or p.stat().st_size > max_bytes:
            return None
        digest = hashlib.sha256()
        with p.open("rb") as handle:
            remaining = max_bytes
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


def collect_process_events(config: AgentConfig) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "username"]):
        if len(events) >= config.max_processes:
            break
        info = proc.info
        exe = info.get("exe")
        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": _utc_now(),
            "event_type": "process",
            "source": "agent",
            "host_id": config.host_id,
            "user_id": info.get("username"),
            "process": {
                "pid": info.get("pid"),
                "parent_pid": info.get("ppid"),
                "name": info.get("name"),
                "executable": exe,
                "hash_sha256": _sha256_file(exe) if exe else None,
            },
            "attributes": {"platform": platform.system()},
            "schema_version": "1.0",
        })
    return events


def collect_network_events(config: AgentConfig) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for conn in psutil.net_connections(kind="inet"):
        remote = conn.raddr
        if not remote:
            continue
        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": _utc_now(),
            "event_type": "network",
            "source": "agent",
            "host_id": config.host_id,
            "user_id": None,
            "network": {
                "direction": "outbound",
                "remote_ip": remote.ip,
                "remote_port": remote.port,
                "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
            },
            "process": {"pid": conn.pid},
            "attributes": {"status": conn.status},
            "schema_version": "1.0",
        })
    return events


def collect_once(config: AgentConfig) -> list[dict[str, Any]]:
    return collect_process_events(config) + collect_network_events(config)


def run_forever(config: AgentConfig):
    while True:
        yield collect_once(config)
        time.sleep(max(1.0, config.interval_seconds))


if __name__ == "__main__":
    host = socket.gethostname()
    config = AgentConfig(host_id=host)
    for batch in run_forever(config):
        print(f"collected {len(batch)} events for {host}")
