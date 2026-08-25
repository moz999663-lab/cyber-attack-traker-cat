# Production Security Baseline

Before exposing CAT to a real environment:

## Authentication

Set `CAT_API_KEY` through a secret manager. Do not place secrets in GitHub, Docker images, compose files, or client-side code. For larger deployments, replace the shared key with an identity provider and short-lived tokens.

## Network

- Put the API behind TLS termination.
- Restrict inbound traffic to trusted collectors and administrators.
- Do not expose PostgreSQL publicly.
- Use a private network between the API and database.

## Data

- Use PostgreSQL for production persistence.
- Encrypt storage and backups according to organizational policy.
- Define retention periods for telemetry and incidents.
- Minimize collection of personal data and never store credentials or secrets as telemetry.

## Application

- Keep request-size limits enabled.
- Keep authentication enabled for all non-health endpoints.
- Run the container as a non-root user where supported.
- Pin and regularly update dependencies.
- Review CI security findings before release.

## Response safety

Response actions must be allow-listed, authorized, logged, and idempotent. CAT must never execute arbitrary commands supplied by telemetry, detections, or external intelligence.

## Monitoring

Monitor API authentication failures, ingestion errors, database health, queue/backlog size, detector error rates, and unusual administrative actions.
