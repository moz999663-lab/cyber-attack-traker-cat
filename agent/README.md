# CAT Agent

The CAT Agent is a defensive endpoint telemetry collector. It now includes a cross-platform Python collector for process and network metadata while retaining the simulator for development.

## Responsibilities

1. Collect approved telemetry sources.
2. Normalize records into the canonical event schema.
3. Buffer events safely when the backend is unavailable.
4. Authenticate to the ingestion API when transport is enabled.
5. Apply local collection limits and configuration.
6. Never execute commands received from the backend or from telemetry.
7. Never collect passwords, keystrokes, file contents, or unrelated personal data.

## Running the collector

Install the agent dependency with `pip install psutil`, then run:

```text
python agent/cat_agent.py
```

The collector currently emits process and outbound network metadata to stdout. A transport adapter should be added only after authentication, batching, retry limits, TLS verification, and local buffering are tested.

## Safety boundary

The agent is intentionally read-only. It does not terminate processes, delete files, modify persistence, execute remote commands, or change firewall configuration. Defensive response actions belong to a separately authorized controller.
