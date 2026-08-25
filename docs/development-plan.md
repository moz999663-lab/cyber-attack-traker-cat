# Development Plan

## Phase 1 — Foundation

- Canonical event model.
- Python backend skeleton.
- Synthetic agent/event generator.
- Event validation.
- In-memory repository plus PostgreSQL adapter.
- Basic health and ingestion APIs.

## Phase 2 — Detection

- Rule interface.
- Versioned deterministic rules.
- Detection result model.
- Correlation service.
- Incident lifecycle.

## Phase 3 — Attack tracing

- Evidence graph model.
- Timeline builder.
- Graph traversal and root-cause hypotheses.
- Uncertainty representation.

## Phase 4 — Risk

- Explainable scoring.
- Asset criticality.
- Confidence calibration.
- Alert prioritization.

## Phase 5 — Dashboard

- Incident list.
- Timeline and graph visualization.
- Evidence explorer.
- Risk explanation.

## Phase 6 — Safe response

- Dry-run response actions.
- Explicit authorization.
- Idempotency.
- Audit log.
- Rollback where technically possible.

## Phase 7 — Hardening

- Threat model review.
- Security test suite.
- Dependency scanning.
- Container hardening.
- Documentation.
- Deployment configuration.
