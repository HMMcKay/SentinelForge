from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _env(*names: str, default: str) -> str:
    return next((os.environ[name] for name in names if os.getenv(name)), default)


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _weak_secret(value: str) -> bool:
    lowered = value.lower()
    return len(value) < 32 or lowered.startswith(("development-", "change-this-"))


def _rules_path() -> Path:
    configured = _env("SENTINELFORGE_RULES_PATH", "RULES_PATH", default="")
    if configured:
        return Path(configured)
    repository_path = Path(__file__).resolve().parents[2] / "detections" / "rules"
    return repository_path


@dataclass(slots=True)
class Settings:
    environment: str = field(
        default_factory=lambda: _env("SENTINELFORGE_ENV", default="development").lower()
    )
    database_url: str = field(
        default_factory=lambda: _env(
            "SENTINELFORGE_DATABASE_URL", "DATABASE_URL", default="sqlite:///./sentinelforge.db"
        ).replace("postgres://", "postgresql+psycopg://", 1)
    )
    rules_path: Path = field(default_factory=_rules_path)
    enrollment_key: str = field(
        default_factory=lambda: _env(
            "SENTINELFORGE_ENROLLMENT_KEY",
            "ENROLLMENT_SECRET",
            default="development-enroll-key",
        )
    )
    admin_key: str = field(
        default_factory=lambda: os.getenv("SENTINELFORGE_ADMIN_KEY", "development-admin-key")
    )
    token_pepper: str = field(
        default_factory=lambda: os.getenv("SENTINELFORGE_TOKEN_PEPPER", "development-only-pepper")
    )
    log_level: str = field(
        default_factory=lambda: os.getenv("SENTINELFORGE_LOG_LEVEL", "INFO").upper()
    )
    lab_mode: bool = field(default_factory=lambda: _bool("SENTINELFORGE_LAB_MODE"))
    auto_create_schema: bool = field(
        default_factory=lambda: _bool("SENTINELFORGE_AUTO_CREATE_SCHEMA", True)
    )
    max_request_bytes: int = field(
        default_factory=lambda: _int_env("SENTINELFORGE_MAX_REQUEST_BYTES", 2_097_152)
    )
    max_batch_events: int = field(
        default_factory=lambda: _int_env("SENTINELFORGE_MAX_BATCH_EVENTS", 500)
    )
    retention_days: int = field(
        default_factory=lambda: _int_env("SENTINELFORGE_RETENTION_DAYS", 30)
    )
    cors_origins: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            item.strip()
            for item in os.getenv(
                "SENTINELFORGE_CORS_ORIGINS", "http://localhost:3000,http://localhost:8080"
            ).split(",")
            if item.strip()
        )
    )

    @property
    def development_secrets(self) -> bool:
        return any(
            _weak_secret(value)
            for value in (self.enrollment_key, self.admin_key, self.token_pepper)
        )

    def __post_init__(self) -> None:
        if self.environment not in {"development", "test", "production"}:
            raise ValueError("SENTINELFORGE_ENV must be development, test, or production")
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(
                "SENTINELFORGE_LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR, or CRITICAL"
            )
        if not 1 <= self.max_request_bytes <= 100 * 1024 * 1024:
            raise ValueError("SENTINELFORGE_MAX_REQUEST_BYTES must be between 1 and 104857600")
        if not 1 <= self.max_batch_events <= 500:
            raise ValueError("SENTINELFORGE_MAX_BATCH_EVENTS must be between 1 and 500")
        if not 1 <= self.retention_days <= 3650:
            raise ValueError("SENTINELFORGE_RETENTION_DAYS must be between 1 and 3650")
        if self.environment == "production" and self.development_secrets:
            raise ValueError(
                "production mode requires enrollment, admin, and token-pepper secrets of at least "
                "32 characters and refuses development/change-this placeholders"
            )
