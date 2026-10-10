"""API authentication fails closed; never store keys in code or browser storage."""

import hmac
import os

from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader

header = APIKeyHeader(name="X-API-Key", auto_error=False)


def authenticate(key: str | None = Depends(header)) -> str:
    expected = os.getenv("CTIG_API_KEY")
    if not expected:
        raise HTTPException(503, "API key is not configured")
    if not key or not hmac.compare_digest(key.encode(), expected.encode()):
        raise HTTPException(401, "Invalid API key")
    return "authenticated-local-user"
