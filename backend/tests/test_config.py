from __future__ import annotations

from pathlib import Path

import pytest

from sentinelforge.config import Settings


def _production(**overrides) -> Settings:
    values = {
        "environment": "production",
        "database_url": "sqlite://",
        "rules_path": Path("rules"),
        "enrollment_key": "e" * 32,
        "admin_key": "a" * 32,
        "token_pepper": "p" * 32,
    }
    values.update(overrides)
    return Settings(**values)


def test_production_accepts_independent_strong_secrets() -> None:
    settings = _production()
    assert settings.development_secrets is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("enrollment_key", "short"),
        ("admin_key", "change-this-admin-secret-xxxxxxxx"),
        ("token_pepper", "development-pepper-xxxxxxxxxxxx"),
    ],
)
def test_production_rejects_weak_or_placeholder_secrets(field: str, value: str) -> None:
    with pytest.raises(ValueError, match="production mode requires"):
        _production(**{field: value})


def test_invalid_integer_environment_has_clear_error(monkeypatch) -> None:
    monkeypatch.setenv("SENTINELFORGE_RETENTION_DAYS", "thirty")
    with pytest.raises(ValueError, match="SENTINELFORGE_RETENTION_DAYS must be an integer"):
        Settings()
