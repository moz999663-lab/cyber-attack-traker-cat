# Attack Tracer

The attack tracer reconstructs an evidence-backed incident timeline and graph from normalized events and detections.

## Graph model

Nodes may represent:

- host
- user
- process
- file
- network endpoint
- authentication event
- detection

Edges represent observed relationships such as `spawned`, `modified`, `connected_to`, `authenticated`, or `triggered`.

## Rules

- Every graph relationship must reference evidence event IDs.
- Do not infer certainty from missing telemetry.
- Distinguish observed facts from hypotheses.
- Preserve timestamps and ordering information.
- Handle cycles and duplicate events safely.
- Bound graph size per incident to prevent resource exhaustion.

The first implementation should produce a deterministic timeline and graph from synthetic events.