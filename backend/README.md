# Backend

The backend owns authenticated event ingestion, normalization, persistence, detection orchestration, incident APIs, and audit logging.

## Planned modules

```text
backend/
├── app/
│   ├── api/
│   ├── domain/
│   ├── services/
│   ├── storage/
│   └── security/
└── tests/
```

## API principles

- Version APIs (`/api/v1/...`).
- Authenticate every ingestion client.
- Authorize every management operation.
- Validate JSON against explicit schemas.
- Apply request and payload limits.
- Return safe error messages without internal secrets.
- Generate correlation/request IDs.
- Log security-relevant actions.

The first implementation should expose a health endpoint and a validated event-ingestion endpoint backed by an in-memory repository or PostgreSQL adapter behind an interface.