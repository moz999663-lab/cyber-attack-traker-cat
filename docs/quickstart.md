# CAT MVP Quickstart

## Local

```bash
cd backend
python -m venv .venv
# activate the environment using your platform's normal command
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `/docs` for the FastAPI API explorer. Use `POST /api/v1/demo` to run the synthetic end-to-end analysis.

## Docker

From the repository root:

```bash
docker compose -f docker/docker-compose.yml up --build
```

## What the demo proves

The synthetic scenario passes through event validation, deterministic detections, correlation, attack-graph construction, and explainable risk scoring. It intentionally uses documentation-only network addresses and synthetic process names.

## Production warning

This MVP is not a production EDR. It lacks OS-specific privileged telemetry, durable event storage, identity infrastructure, signed agent updates, fleet management, mature authentication, and a production-grade response controller. Those must be implemented and security-reviewed before deployment to real endpoints.
