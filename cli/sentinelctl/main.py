from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

import httpx
import typer
import yaml

app = typer.Typer(
    name="sentinelctl",
    help="Operate a local SentinelForge deployment.",
    no_args_is_help=True,
)
sensors_app = typer.Typer(help="Inspect enrolled sensors.")
scenarios_app = typer.Typer(help="Request safe simulation scenarios.")
demo_app = typer.Typer(help="Manage deterministic demo data.")
rules_app = typer.Typer(help="Validate and reload detection rules.")
export_app = typer.Typer(help="Export investigation data.")
app.add_typer(sensors_app, name="sensors")
app.add_typer(scenarios_app, name="scenarios")
app.add_typer(demo_app, name="demo")
app.add_typer(rules_app, name="rules")
app.add_typer(export_app, name="export")

ALLOWED_TOP = {
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "modified",
    "version",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "tags",
    "references",
    "investigation",
    "sentinelforge",
}
ALLOWED_MODIFIERS = {"contains", "startswith", "endswith", "exists", "all"}


class State:
    url: str
    admin_key: str
    timeout: float


state = State()


@app.callback()
def configure(
    url: str = typer.Option(
        lambda: os.getenv("SENTINELFORGE_URL", "http://localhost:8000"),
        "--url",
        help="Backend base URL.",
    ),
    admin_key: str = typer.Option(
        lambda: os.getenv("SENTINELFORGE_ADMIN_KEY", ""),
        "--admin-key",
        help="Admin key for mutating operations (or SENTINELFORGE_ADMIN_KEY).",
        show_default=False,
    ),
    timeout: float = typer.Option(10.0, min=0.1, max=300.0),
) -> None:
    state.url = url.rstrip("/")
    state.admin_key = admin_key
    state.timeout = timeout


def _request(method: str, path: str, *, admin: bool = False, **kwargs: Any) -> Any:
    headers = kwargs.pop("headers", {})
    if admin:
        if not state.admin_key:
            typer.echo(
                "Admin key required; set SENTINELFORGE_ADMIN_KEY or pass --admin-key.", err=True
            )
            raise typer.Exit(2)
        headers["X-Admin-Key"] = state.admin_key
    try:
        response = httpx.request(
            method,
            f"{state.url}{path}",
            headers=headers,
            timeout=state.timeout,
            **kwargs,
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json().get("detail", exc.response.text)
        except ValueError:
            detail = exc.response.text
        typer.echo(f"API error ({exc.response.status_code}): {detail}", err=True)
        raise typer.Exit(1) from exc
    except httpx.RequestError as exc:
        typer.echo(f"Cannot reach SentinelForge at {state.url}: {exc}", err=True)
        raise typer.Exit(1) from exc


def _print(value: Any) -> None:
    typer.echo(json.dumps(value, indent=2, sort_keys=True))


@app.command()
def health() -> None:
    """Check backend and database health."""
    _print(_request("GET", "/health"))


@sensors_app.command("list")
def sensors_list() -> None:
    """List enrolled endpoint sensors."""
    _print(_request("GET", "/api/v1/sensors"))


@scenarios_app.command("run")
def scenarios_run(
    scenario_id: str = typer.Argument(..., help="Scenario ID from `scenarios list`."),
    sensor_id: str | None = typer.Option(None, help="Target enrolled sensor ID."),
    execute: bool = typer.Option(
        False, "--execute", help="Request real lab execution; defaults to a safe dry run."
    ),
) -> None:
    """Validate or request a lab-gated scenario run."""
    payload = {"sensor_id": sensor_id, "dry_run": not execute, "parameters": {}}
    _print(_request("POST", f"/api/v1/scenarios/{scenario_id}/runs", admin=True, json=payload))


@scenarios_app.command("list")
def scenarios_list() -> None:
    """List available safe simulations."""
    _print(_request("GET", "/api/v1/scenarios"))


@demo_app.command("seed")
def demo_seed(
    seed: int = typer.Option(1337, min=0, max=2_147_483_647),
    reset: bool = typer.Option(False, "--reset", help="Replace prior data for this demo seed."),
) -> None:
    """Load deterministic positive and near-miss telemetry."""
    _print(
        _request(
            "POST",
            "/api/v1/demo/seed",
            admin=True,
            json={"seed": seed, "reset_demo": reset},
        )
    )


def validate_rule_document(document: Any, source: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return [f"{source}: document must be a YAML mapping"]
    unknown = sorted(set(document) - ALLOWED_TOP)
    if unknown:
        errors.append(f"{source}: unsupported fields: {', '.join(unknown)}")
    for key in ("title", "id", "description", "logsource", "detection", "level"):
        if key not in document:
            errors.append(f"{source}: missing {key}")
    if "id" in document and not re.fullmatch(r"SF-[A-Z0-9-]{3,64}", str(document["id"])):
        errors.append(f"{source}: invalid rule ID format")
    detection = document.get("detection")
    if not isinstance(detection, dict):
        errors.append(f"{source}: detection must be a mapping")
        return errors
    if "timeframe" in detection:
        errors.append(f"{source}: native Sigma timeframe is unsupported")
    if not isinstance(detection.get("condition"), str):
        errors.append(f"{source}: detection.condition must be a string")
    selections = {name for name in detection if name not in {"condition", "timeframe"}}
    for name in selections:
        selection = detection[name]
        if not isinstance(selection, dict) or not selection:
            errors.append(f"{source}: selection {name} must be a non-empty mapping")
            continue
        for expression in selection:
            modifiers = str(expression).split("|")[1:]
            unsupported = sorted(set(modifiers) - ALLOWED_MODIFIERS)
            if unsupported:
                errors.append(
                    f"{source}: unsupported modifiers on {expression}: {', '.join(unsupported)}"
                )
    condition = detection.get("condition", "")
    if isinstance(condition, str):
        referenced = set(re.findall(r"\bselection[A-Za-z0-9_]*\b", condition))
        missing = sorted(referenced - selections)
        if missing:
            errors.append(
                f"{source}: condition references missing selections: {', '.join(missing)}"
            )
    correlation = document.get("sentinelforge", {}).get("correlation")
    if correlation is not None:
        if not isinstance(correlation, dict) or correlation.get("type") not in {
            "threshold",
            "sequence",
        }:
            errors.append(f"{source}: correlation type must be threshold or sequence")
        elif not re.fullmatch(r"[1-9]\d*[smh]", str(correlation.get("within", ""))):
            errors.append(f"{source}: correlation.within must use a positive s/m/h duration")
    return errors


@rules_app.command("validate")
def rules_validate(path: Path = typer.Argument(Path("/rules"))) -> None:
    """Validate SentinelForge's supported Sigma subset without loading rules."""
    if not path.exists() or not path.is_dir() and not path.is_file():
        typer.echo(f"Rule path does not exist: {path}", err=True)
        raise typer.Exit(1)
    files = sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")) if path.is_dir() else [path]
    if not files:
        typer.echo(f"No YAML rules found beneath {path}", err=True)
        raise typer.Exit(1)
    errors: list[str] = []
    identifiers: dict[str, Path] = {}
    for rule_path in files:
        try:
            document = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{rule_path}: {exc}")
            continue
        errors.extend(validate_rule_document(document, str(rule_path)))
        if isinstance(document, dict) and isinstance(document.get("id"), str):
            prior = identifiers.get(document["id"])
            if prior:
                errors.append(f"{rule_path}: duplicate ID also used by {prior}")
            identifiers[document["id"]] = rule_path
    if errors:
        typer.echo("Rule validation failed:", err=True)
        for error in errors:
            typer.echo(f"- {error}", err=True)
        raise typer.Exit(1)
    typer.echo(f"Validated {len(files)} rule(s); no unsupported features found.")


@rules_app.command("reload")
def rules_reload() -> None:
    """Atomically reload valid backend detection rules."""
    _print(_request("POST", "/api/v1/rules/reload", admin=True))


@export_app.command("investigation")
def export_investigation(
    output: Path = typer.Option(Path("sentinelforge-investigation.json"), "--output", "-o"),
    scenario_run_id: str | None = typer.Option(None),
) -> None:
    """Write a bounded JSON investigation bundle using an atomic replace."""
    params = {"scenario_run_id": scenario_run_id} if scenario_run_id else None
    data = _request("GET", "/api/v1/investigations/export", admin=True, params=params)
    if str(output) == "-":
        _print(data)
        return
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=output.parent, delete=False, suffix=".tmp"
    ) as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(output)
    typer.echo(f"Wrote {output}")


@app.command()
def purge(
    days: int = typer.Option(30, min=1, max=3650),
    execute: bool = typer.Option(
        False, "--execute", help="Delete matching data; default only reports candidates."
    ),
) -> None:
    """Preview or execute retention cleanup."""
    _print(
        _request(
            "POST",
            "/api/v1/maintenance/purge",
            admin=True,
            json={"retention_days": days, "dry_run": not execute},
        )
    )


if __name__ == "__main__":
    app()
