from dataclasses import dataclass
from .models import SecurityEvent

@dataclass(frozen=True)
class DetectionResult:
    detection_id: str
    rule_id: str
    severity: int
    confidence: float
    title: str
    explanation: str
    evidence_event_ids: tuple[str, ...]

class Detector:
    def detect(self, event: SecurityEvent) -> list[DetectionResult]:
        raise NotImplementedError

class SuspiciousParentDetector(Detector):
    """Synthetic-data-friendly behavioral detector; no command execution."""
    rule_id = "PROC-001"
    def detect(self, event: SecurityEvent) -> list[DetectionResult]:
        p = event.process
        if event.event_type.value == "process" and p and p.parent_pid is not None and p.name:
            suspicious = p.name.lower() in {"unknown-child", "suspicious-child"}
            if suspicious:
                return [DetectionResult(str(event.event_id)+":PROC-001", self.rule_id, 70, 0.82,
                    "Unexpected process relationship",
                    "The synthetic telemetry contains a process name explicitly marked suspicious; investigate its parent chain.",
                    (str(event.event_id),))]
        return []

class ExternalConnectionDetector(Detector):
    rule_id = "NET-001"
    def detect(self, event: SecurityEvent) -> list[DetectionResult]:
        n = event.network
        if event.event_type.value == "network" and n and n.direction == "outbound" and n.remote_port in {4444, 8080}:
            return [DetectionResult(str(event.event_id)+":NET-001", self.rule_id, 55, 0.65,
                "Unusual outbound connection metadata",
                "The synthetic telemetry uses a configurable unusual destination port. This is an investigation signal, not proof of compromise.",
                (str(event.event_id),))]
        return []

def run_detectors(event: SecurityEvent) -> list[DetectionResult]:
    results: list[DetectionResult] = []
    for detector in (SuspiciousParentDetector(), ExternalConnectionDetector()):
        results.extend(detector.detect(event))
    return results
