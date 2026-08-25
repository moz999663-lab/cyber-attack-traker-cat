# Threat Model

## Assets

- Security telemetry
- Incident records
- Host and user identifiers
- Detection rules
- Response authorization

## Threats

- Spoofed telemetry
- Replay or duplicate events
- Malformed/oversized payloads
- Unauthorized incident access
- Tampering with evidence
- Abuse of response controls
- Credential leakage
- Supply-chain compromise

## Controls in MVP

- Strict Pydantic validation
- Duplicate event detection
- Payload and collection bounds
- Explicit response-action allowlist
- Human approval requirement in response planning
- No secrets in repository
- Synthetic-only testing

## Next hardening

- Mutual authentication for agents
- Per-tenant authorization
- Durable append-only audit storage
- Signed agent packages and update verification
- Key rotation
- Encryption in transit and at rest
- Dependency/SBOM scanning
- Container runtime hardening
