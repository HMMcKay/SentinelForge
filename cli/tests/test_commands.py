from __future__ import annotations

import json

from typer.testing import CliRunner

from sentinelctl import main

runner = CliRunner()


def test_mutating_command_fails_clearly_without_admin_key(monkeypatch) -> None:
    monkeypatch.delenv("SENTINELFORGE_ADMIN_KEY", raising=False)
    result = runner.invoke(main.app, ["purge"])
    assert result.exit_code == 2
    assert "Admin key required" in result.output


def test_export_dash_writes_json_to_stdout(monkeypatch) -> None:
    bundle = {"schema_version": "1.0", "events": [], "alerts": []}
    monkeypatch.setattr(main, "_request", lambda *args, **kwargs: bundle)
    result = runner.invoke(
        main.app,
        ["--admin-key", "test-admin-key", "export", "investigation", "--output", "-"],
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == bundle
