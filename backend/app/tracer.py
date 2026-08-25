from dataclasses import dataclass
from .models import SecurityEvent
from .correlation import Incident

@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    label: str
    observed: bool = True

@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    relation: str
    evidence_event_id: str

class AttackTracer:
    def build(self, incident: Incident) -> dict:
        nodes: dict[str, GraphNode] = {}
        edges: list[GraphEdge] = []
        events = sorted(incident.events, key=lambda e: e.timestamp)
        for e in events:
            if e.process and e.process.pid is not None:
                pid = f"proc:{e.host_id}:{e.process.pid}"
                nodes[pid] = GraphNode(pid, "process", e.process.name or str(e.process.pid))
                if e.process.parent_pid is not None:
                    parent = f"proc:{e.host_id}:{e.process.parent_pid}"
                    nodes.setdefault(parent, GraphNode(parent, "process", str(e.process.parent_pid), observed=False))
                    edges.append(GraphEdge(parent, pid, "spawned", str(e.event_id)))
            if e.network and e.network.remote_ip:
                src = f"host:{e.host_id}"
                dst = f"net:{e.network.remote_ip}:{e.network.remote_port or 0}"
                nodes.setdefault(src, GraphNode(src, "host", e.host_id))
                nodes.setdefault(dst, GraphNode(dst, "network", e.network.remote_ip))
                edges.append(GraphEdge(src, dst, "connected_to", str(e.event_id)))
            if e.file and e.file.path:
                src = f"host:{e.host_id}"
                dst = f"file:{e.file.path}"
                nodes.setdefault(src, GraphNode(src, "host", e.host_id))
                nodes.setdefault(dst, GraphNode(dst, "file", e.file.path))
                edges.append(GraphEdge(src, dst, e.file.operation or "touched", str(e.event_id)))
        timeline = [{"event_id": str(e.event_id), "timestamp": e.timestamp.isoformat(), "type": e.event_type.value} for e in events]
        return {"nodes": [n.__dict__ for n in nodes.values()], "edges": [x.__dict__ for x in edges], "timeline": timeline}
