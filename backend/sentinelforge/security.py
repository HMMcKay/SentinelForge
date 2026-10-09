from __future__ import annotations

import hashlib
import hmac
import secrets

from fastapi import Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Sensor


def issue_ingestion_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str, pepper: str) -> str:
    return hmac.new(pepper.encode(), token.encode(), hashlib.sha256).hexdigest()


def require_enrollment_key(request: Request, x_enrollment_key: str | None = Header(None)) -> None:
    expected = request.app.state.settings.enrollment_key
    if not x_enrollment_key or not hmac.compare_digest(x_enrollment_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid enrollment key"
        )


def require_admin_key(request: Request, x_admin_key: str | None = Header(None)) -> None:
    expected = request.app.state.settings.admin_key
    if not x_admin_key or not hmac.compare_digest(x_admin_key, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid admin key")


def authenticate_sensor(request: Request, session: Session, authorization: str | None) -> Sensor:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required"
        )
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required"
        )
    digest = hash_token(token, request.app.state.settings.token_pepper)
    sensor = session.scalar(
        select(Sensor).where(Sensor.token_hash == digest, Sensor.status == "active")
    )
    if sensor is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid sensor token")
    return sensor
