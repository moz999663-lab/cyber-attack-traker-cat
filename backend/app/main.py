from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .models import SecurityEvent
from .detection import run_detectors
from .correlation import Correlator
from .tracer import AttackTracer
from .risk import assess
from .simulator import sample_events

app = FastAPI(title="Cyber Attack Tracker", version="0.1.0")
EVENTS: list[SecurityEvent] = []

class AnalysisRequest(BaseModel):
    events: list[SecurityEvent]

@app.get("/health")
def health():
    return {"status": "ok", "service": "cat-backend", "version": "0.1.0"}

@app.post("/api/v1/events")
def ingest(event: SecurityEvent):
    if any(x.event_id == event.event_id for x in EVENTS):
        raise HTTPException(status_code=409, detail="duplicate event_id")
    if len(EVENTS) >= 10000:
        raise HTTPException(status_code=429, detail="event buffer limit reached")
    EVENTS.append(event)
    return {"accepted": True, "event_id": str(event.event_id)}

@app.post("/api/v1/analyze")
def analyze(request: AnalysisRequest):
    detections = [d for event in request.events for d in run_detectors(event)]
    incidents = Correlator().correlate(request.events, detections)
    results = []
    tracer = AttackTracer()
    for incident in incidents:
        risk = assess(incident)
        results.append({
            "incident_id": incident.incident_id,
            "host_id": incident.host_id,
            "detections": [d.__dict__ for d in incident.detections],
            "risk": risk.__dict__,
            "attack_graph": tracer.build(incident),
        })
    return {"incidents": results, "events_analyzed": len(request.events)}

@app.post("/api/v1/demo")
def demo():
    events = sample_events()
    return analyze(AnalysisRequest(events=events))
