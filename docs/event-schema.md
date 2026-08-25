# Canonical Security Event Schema

CAT events are normalized before detection. The schema is intentionally small for the foundation phase.

```json
{
  "event_id": "uuid",
  "timestamp": "RFC3339 UTC",
  "event_type": "process|file|network|auth|system",
  "source": "agent|simulator|integration",
  "host_id": "string",
  "user_id": "string|null",
  "process": {
    "pid": "integer|null",
    "parent_pid": "integer|null",
    "name": "string|null",
    "executable": "string|null",
    "hash_sha256": "string|null"
  },
  "network": {
    "direction": "inbound|outbound|null",
    "remote_ip": "string|null",
    "remote_port": "integer|null",
    "protocol": "string|null"
  },
  "file": {
    "path": "string|null",
    "operation": "create|modify|delete|rename|null",
    "hash_sha256": "string|null"
  },
  "attributes": {},
  "schema_version": "1.0"
}
```

## Validation requirements

- `event_id` must be unique within the accepted event stream.
- `timestamp` must be normalized to UTC and checked for unreasonable clock skew.
- `event_type` must be from the controlled vocabulary.
- Strings require maximum lengths.
- Ports must be 1-65535 when present.
- Hashes must be validated as hexadecimal SHA-256 when present.
- Arbitrary `attributes` must have bounded size and must never be interpreted as executable instructions.
- Unknown fields may be rejected in strict mode or retained only in a controlled extension mechanism.

## Evidence references

Detections should reference original `event_id` values rather than duplicating entire events. This keeps incidents traceable and reduces inconsistent copies.

## Privacy

Do not collect message contents, passwords, authentication secrets, or unrelated personal data. Prefer metadata required for security analysis.