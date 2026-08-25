# Testing Strategy

Every component should have automated tests before production integration.

## Required layers

- Unit tests for schemas, detectors, correlation, graph construction, and risk scoring.
- Integration tests for event ingestion and persistence.
- Security tests for authentication, authorization, validation, rate limits, replay handling, and oversized input.
- End-to-end tests using synthetic telemetry.
- Regression tests for every confirmed detection bug.

Tests must use synthetic data and must never require real malware or real attack payloads.