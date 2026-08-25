from dataclasses import dataclass
from .correlation import Incident

@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    factors: list[str]
    confidence: float

def assess(incident: Incident) -> RiskAssessment:
    if not incident.detections:
        return RiskAssessment(0, "none", [], 0.0)
    severity = max(d.severity for d in incident.detections)
    confidence = sum(d.confidence for d in incident.detections) / len(incident.detections)
    diversity = len({d.rule_id for d in incident.detections})
    score = min(100, round(severity * 0.65 + confidence * 25 + max(0, diversity - 1) * 8))
    level = "critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 45 else "low"
    factors = [f"max_detection_severity={severity}", f"mean_detection_confidence={confidence:.2f}", f"distinct_rules={diversity}"]
    return RiskAssessment(score, level, factors, round(confidence, 2))
