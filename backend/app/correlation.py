from dataclasses import dataclass, field
from .detection import DetectionResult
from .models import SecurityEvent

@dataclass
class Incident:
    incident_id: str
    host_id: str
    events: list[SecurityEvent] = field(default_factory=list)
    detections: list[DetectionResult] = field(default_factory=list)

class Correlator:
    def correlate(self, events: list[SecurityEvent], detections: list[DetectionResult]) -> list[Incident]:
        grouped: dict[str, Incident] = {}
        for event in events:
            grouped.setdefault(event.host_id, Incident("INC-" + event.host_id, event.host_id)).events.append(event)
        for detection in detections:
            ids = set(detection.evidence_event_ids)
            for incident in grouped.values():
                if any(str(e.event_id) in ids for e in incident.events):
                    incident.detections.append(detection)
        return [i for i in grouped.values() if i.detections]
