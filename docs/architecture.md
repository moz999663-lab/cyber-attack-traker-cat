# CAT Architecture

## 1. Purpose

Cyber Attack Tracker (CAT) is a defensive security platform for collecting security telemetry, detecting suspicious behavior, correlating related events, reconstructing attack timelines, and producing explainable risk assessments.

## 2. High-level flow

```text
[Endpoint / Server]
       |
       v
     Agent
       |
       v
 Event Normalizer
       |
       v
 Ingestion API ---> Event Store
       |
       v
 Detection Engine
       |
       v
 Correlation Engine
       |
       v
 Attack Tracer ---> Attack Graph / Timeline
       |
       v
 Risk Engine
       |
       +----> Alert / Incident API ----> Dashboard
       |
       +----> Safe Response Controller
                    |
                    v
               Audit Log
```

## 3. Components

### Agent

Collects narrowly scoped security telemetry such as process lifecycle, file metadata changes, authentication events, and network connection metadata. Collection must be configurable and least-privileged.

### Event Normalizer

Converts source-specific records into the canonical CAT event schema. It validates timestamps, identifiers, types, and required fields. Invalid input is rejected or quarantined.

### Ingestion API

Accepts authenticated telemetry from agents and other approved sources. It must implement authentication, authorization, input validation, rate limiting, request-size limits, and structured audit logging.

### Event Store

Stores normalized events and incident relationships. Retention must be configurable. Sensitive data should be minimized and protected at rest.

### Detection Engine

Starts with deterministic rules and behavioral indicators. Each detection produces an explanation, evidence references, confidence, and severity rather than an opaque verdict.

### Correlation Engine

Groups related detections/events using host, process, user, time-window, network, and other trusted identifiers. Correlation decisions must be explainable.

### Attack Tracer

Builds a directed graph from correlated events. Nodes represent entities/events and edges represent observed relationships. The tracer reconstructs a timeline and identifies likely entry points, execution chains, persistence indicators, lateral movement indicators, and impact indicators when evidence supports them.

### Risk Engine

Calculates a bounded risk score from severity, confidence, evidence quality, asset criticality, propagation indicators, and uncertainty. Every score must expose contributing factors.

### Dashboard

Provides incident list, incident details, event timeline, attack graph, evidence, risk explanation, and response recommendations.

### Safe Response Controller

Provides controlled defensive actions. High-impact actions must support explicit authorization, dry-run mode, idempotency, and complete audit records.

## 4. Trust boundaries

1. Endpoint telemetry is untrusted input.
2. API clients must authenticate before ingestion.
3. External indicators must be treated as data, never executable instructions.
4. Dashboard users require role-based authorization.
5. Response actions must not execute arbitrary commands supplied by telemetry.

## 5. Security principles

- Least privilege.
- Secure defaults.
- Defense in depth.
- Explicit authorization for disruptive response.
- No secrets in source control.
- Structured audit trail.
- Deterministic behavior before ML.
- Fail closed on authorization errors.
- Validate at every trust boundary.
- Protect against replay, injection, oversized events, and malformed graph relationships.

## 6. Initial technology direction

The first implementation should favor a simple, maintainable stack. Python is suitable for the backend and detection engine; PostgreSQL can be used for persistent data; Redis may be introduced for queues/caching; Docker Compose can provide local development. The agent should initially support a simulator before privileged OS-specific collection is added.

Technology choices remain replaceable behind clear interfaces.

## 7. Non-goals

CAT is not an offensive framework, malware builder, exploit platform, credential theft tool, persistence toolkit, or autonomous attack system.