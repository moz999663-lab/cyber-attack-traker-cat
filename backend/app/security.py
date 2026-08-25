import os
import secrets
from typing import Optional

from fastapi import Header, HTTPException


API_KEY_ENV = "CAT_API_KEY"
MAX_BODY_BYTES = 1_000_000


def configured_api_key() -> Optional[str]:
    value = os.getenv(API_KEY_ENV)
    return value.strip() if value else None


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Require a shared API key when CAT_API_KEY is configured.

    Local development remains usable without credentials, while production
    deployments should always set CAT_API_KEY through a secret manager.
    """
    expected = configured_api_key()
    if expected is None:
        return
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="authentication required")
