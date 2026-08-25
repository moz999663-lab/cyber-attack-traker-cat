from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .models import SecurityEvent
from .detection import run_detectors
from .correlation import Correlator
from .tracer import AttackTracer
from .risk import assess
from .simulator import sample_events
from .security import require_api_key

app = FastAPI(title="Cyber Attack Tracker", version="0.2.0")
EVENTS: list[SecurityEvent] = []
MAX_REQUEST_BYTES = 1_000_000

class AnalysisRequest(BaseModel):
    events: list[SecurityEvent]

@app.middleware("http")
async def security_headers(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(status_code=413, content={"detail": "request too large"})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "invalid content-length"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/health")
def health():
    return {"status": "ok", "service": "cat-backend", "version": "0.2.0"}

@app.post("/api/v1/events", dependencies=[Depends(require_api_key)])
def ingest(event: SecurityEvent):
    if any(x.event_id == event.event_id for x in EVENTS):
        raise HTTPException(status_code=409, detail="duplicate event_id")
    if len(EVENTS) >= 10000:
        raise HTTPException(status_code=429, detail="event buffer limit reached")
    EVENTS.append(event)
    return {"accepted": True, "event_id": str(event.event_id)}

@app.post("/api/v1/analyze", dependencies=[Depends(require_api_key)])
def analyze(request: AnalysisRequest):
    if len(request.events) > 5000:
        raise HTTPException(status_code=413, detail="too many events")
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

@app.post("/api/v1/demo", dependencies=[Depends(require_api_key)])
def demo():
    events = sample_events()
    return analyze(AnalysisRequest(events=events))
