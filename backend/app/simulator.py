from datetime import datetime, timedelta, timezone
from uuid import uuid4
from .models import SecurityEvent

def sample_events() -> list[SecurityEvent]:
    t = datetime.now(timezone.utc)
    host = "demo-host-01"
    return [
        SecurityEvent(event_id=uuid4(), timestamp=t, event_type="process", source="simulator", host_id=host,
            process={"pid": 100, "name": "launcher", "executable": "/demo/launcher"}),
        SecurityEvent(event_id=uuid4(), timestamp=t + timedelta(seconds=2), event_type="process", source="simulator", host_id=host,
            process={"pid": 101, "parent_pid": 100, "name": "suspicious-child", "executable": "/demo/suspicious-child"}),
        SecurityEvent(event_id=uuid4(), timestamp=t + timedelta(seconds=5), event_type="network", source="simulator", host_id=host,
            network={"direction": "outbound", "remote_ip": "203.0.113.20", "remote_port": 4444, "protocol": "tcp"}),
        SecurityEvent(event_id=uuid4(), timestamp=t + timedelta(seconds=7), event_type="file", source="simulator", host_id=host,
            file={"path": "/demo/example.dat", "operation": "modify"}),
    ]
