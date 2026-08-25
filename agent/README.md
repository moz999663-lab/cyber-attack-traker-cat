# Agent

The CAT Agent is a defensive telemetry collector. The initial milestone uses a simulator so the rest of the system can be developed and tested without privileged host access.

## Responsibilities

1. Collect approved telemetry sources.
2. Normalize records into the canonical event schema.
3. Buffer events safely when the backend is unavailable.
4. Authenticate to the ingestion API.
5. Apply local collection limits and configuration.
6. Never execute commands received from the backend or from telemetry.

## Future platform adapters

Platform-specific collectors should live behind interfaces and be enabled explicitly. They must use least privilege and document exactly what data they collect.