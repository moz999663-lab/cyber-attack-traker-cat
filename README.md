# Cyber Attack Tracker (CAT)

Defensive security telemetry and incident-tracing platform designed to detect suspicious behavior, correlate events, reconstruct attack timelines, and support safe incident response.

## Vision

CAT is designed as a modular EDR-style platform:

- **Agent** — collects security telemetry with data minimization.
- **Detection Engine** — evaluates rules and behavioral indicators.
- **Correlation Engine** — links related events into incidents.
- **Attack Tracer** — reconstructs an attack timeline/graph.
- **Risk Engine** — produces explainable risk scores.
- **Backend API** — stores and serves normalized security events.
- **Dashboard** — visualizes incidents, timelines, and recommendations.

## Security boundary

This project is defensive. It focuses on detection, investigation, evidence preservation, and safe response. It must not contain malware, exploit payloads, credential theft, persistence mechanisms for unauthorized access, or offensive automation.

## Initial development phases

1. Repository foundation and architecture.
2. Event schema and local telemetry simulator.
3. Detection and correlation engine.
4. Attack graph/timeline reconstruction.
5. Risk scoring and explainable alerts.
6. API and dashboard.
7. Controlled response actions and audit logging.
8. Testing, hardening, documentation, and deployment.

## Development principles

- Secure by default.
- Least privilege.
- Explicit, explainable decisions.
- Immutable/auditable incident records where practical.
- No secrets committed to source control.
- Unit, integration, and security tests for every major component.
- Prefer deterministic rules before adding ML.
- Treat external telemetry as untrusted input.

## Status

Early foundation. Implementation should proceed incrementally with small, reviewable commits.