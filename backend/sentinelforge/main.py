from __future__ import annotations

import logging
import re
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import cast, func, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from .config import Settings
from .database import Database
from .demo import seed_demo
from .detection import DetectionEngine, load_rules
from .models import (
    Alert,
    AttackTechnique,
    DetectionRule,
    Host,
    NormalizedEvent,
    Scenario,
    ScenarioRun,
    Sensor,
    SensorHealth,
)
from .schemas import (
    DemoSeedIn,
    EventBatchIn,
    PurgeIn,
    ScenarioRunIn,
    ScenarioRunStatusIn,
    SensorEnrollIn,
    SensorHeartbeatIn,
)
from .security import (
    authenticate_sensor,
    hash_token,
    issue_ingestion_token,
    require_admin_key,
    require_enrollment_key,
)
from .services import (
    build_timeline,
    ingest_batch,
    purge_old_events,
    seed_catalog,
    serialize_alert,
    serialize_event,
)

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
)
logger = structlog.get_logger()


class LiveHub:
    def __init__(self) -> None:
        self.connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.connections.discard(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        stale: list[WebSocket] = []
        for connection in tuple(self.connections):
            try:
                await connection.send_json(message)
            except Exception:  # pragma: no cover - transport-specific failure
                stale.append(connection)
        for connection in stale:
            self.disconnect(connection)


def _session(request: Request) -> Iterator[Session]:
    yield from request.app.state.database.sessions()


def _rule_response(rule: DetectionRule) -> dict[str, Any]:
    logsource = rule.definition_json.get("logsource", {})
    log_source_label = ":".join(
        str(logsource[key]) for key in ("product", "category") if logsource.get(key)
    )
    investigation = rule.definition_json.get("investigation")
    return {
        "id": rule.id,
        "title": rule.title,
        "description": rule.description,
        "version": rule.version,
        "status": rule.status,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "enabled": rule.enabled,
        "source": "sigma",
        "attack_tags": rule.attack_tags,
        "techniques": rule.attack_tags,
        "attack_techniques": rule.attack_tags,
        "logsource": logsource,
        "log_sources": [log_source_label] if log_source_label else [],
        "false_positives": rule.definition_json.get("falsepositives", []),
        "investigation": investigation,
        "investigation_guidance": investigation,
        "guidance": [investigation] if investigation else [],
        "correlation": rule.definition_json.get("sentinelforge", {}).get("correlation"),
        "definition": rule.definition_json,
    }


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, settings.log_level))
    )
    database = Database(settings.database_url)
    live_hub = LiveHub()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if settings.auto_create_schema:
            database.create_schema()
        rules, errors = load_rules(settings.rules_path)
        if errors:
            raise RuntimeError("detection rule validation failed:\n" + "\n".join(errors))
        engine = DetectionEngine(rules)
        with database.session_factory() as session:
            seed_catalog(session)
            engine.sync_catalog(session)
            session.commit()
        app.state.detection_engine = engine
        log_method = logger.warning if settings.development_secrets else logger.info
        log_method(
            "service_started",
            rules=len(rules),
            lab_mode=settings.lab_mode,
            development_secrets=settings.development_secrets,
        )
        yield
        database.close()

    app = FastAPI(
        title="SentinelForge API",
        version="0.1.0",
        description="Controlled endpoint-telemetry ingestion and explainable detection evaluation.",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.live_hub = live_hub
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Admin-Key", "X-Enrollment-Key"],
    )

    @app.middleware("http")
    async def request_controls(request: Request, call_next):  # type: ignore[no-untyped-def]
        supplied_request_id = request.headers.get("x-request-id", "")
        request_id = (
            supplied_request_id
            if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", supplied_request_id)
            else str(uuid.uuid4())
        )
        length = request.headers.get("content-length")
        if length:
            try:
                if int(length) > settings.max_request_bytes:
                    return JSONResponse(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        content={"detail": "request body exceeds configured limit"},
                    )
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "invalid Content-Length"})
        if request.method in {"POST", "PUT", "PATCH"}:
            chunks: list[bytes] = []
            actual_length = 0
            async for chunk in request.stream():
                actual_length += len(chunk)
                if actual_length > settings.max_request_bytes:
                    return JSONResponse(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        content={"detail": "request body exceeds configured limit"},
                    )
                chunks.append(chunk)
            # Starlette reuses this cached body when FastAPI parses the request downstream.
            request._body = b"".join(chunks)  # type: ignore[attr-defined]
        structlog.contextvars.bind_contextvars(request_id=request_id)
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        structlog.contextvars.clear_contextvars()
        return response

    router = APIRouter(prefix="/api/v1")

    @app.get("/health")
    def health(session: Session = Depends(_session)) -> dict[str, Any]:
        session.execute(text("SELECT 1"))
        rule_count = session.scalar(select(func.count()).select_from(DetectionRule)) or 0
        return {
            "status": "ok",
            "service": "sentinelforge-api",
            "version": "0.1.0",
            "database": "ok",
            "rules_loaded": rule_count,
            "lab_mode": settings.lab_mode,
            "development_secrets": settings.development_secrets,
            "security_status": "degraded" if settings.development_secrets else "configured",
            "retention_days": settings.retention_days,
            "time": datetime.now(UTC).isoformat(),
        }

    @router.post(
        "/sensors/enroll",
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_enrollment_key)],
    )
    def enroll_sensor(
        payload: SensorEnrollIn, session: Session = Depends(_session)
    ) -> dict[str, Any]:
        if session.scalar(
            select(Sensor.id).where(Sensor.host_identifier == payload.host_identifier)
        ):
            raise HTTPException(status_code=409, detail="host_identifier is already enrolled")
        token = issue_ingestion_token()
        sensor = Sensor(
            name=payload.name,
            host_identifier=payload.host_identifier,
            token_hash=hash_token(token, settings.token_pepper),
            metadata_json=payload.metadata,
        )
        session.add(sensor)
        session.flush()
        session.add(
            Host(
                sensor_id=sensor.id,
                hostname=payload.hostname,
                os_name=payload.os_name,
                os_version=payload.os_version,
            )
        )
        session.commit()
        logger.info("sensor_enrolled", sensor_id=sensor.id)
        return {"sensor_id": sensor.id, "ingestion_token": token, "token_type": "Bearer"}

    @router.get("/sensors")
    def list_sensors(session: Session = Depends(_session)) -> dict[str, Any]:
        sensors = session.scalars(select(Sensor).order_by(Sensor.enrolled_at.desc())).all()
        items: list[dict[str, Any]] = []
        for sensor in sensors:
            host = session.scalar(
                select(Host)
                .where(Host.sensor_id == sensor.id)
                .order_by(Host.first_seen_at)
                .limit(1)
            )
            health = session.get(SensorHealth, sensor.id)
            health_record = (
                {
                    "status": health.status,
                    "received_at": health.received_at.isoformat(),
                    "agent_version": health.agent_version,
                    "service_mode": health.service_mode,
                    "last_event_time": health.last_event_time.isoformat()
                    if health.last_event_time
                    else None,
                    "spool_event_count": health.spool_event_count,
                    "spool_bytes": health.spool_bytes,
                    "error_codes": health.error_codes,
                }
                if health
                else None
            )
            items.append(
                {
                    "id": sensor.id,
                    "name": sensor.name,
                    "hostname": host.hostname if host else sensor.name,
                    "host_identifier": sensor.host_identifier,
                    "status": health.status if health else sensor.status,
                    "enrolled_at": sensor.enrolled_at.isoformat(),
                    "last_seen_at": sensor.last_seen_at.isoformat()
                    if sensor.last_seen_at
                    else None,
                    "last_seen": sensor.last_seen_at.isoformat() if sensor.last_seen_at else None,
                    "agent_version": health.agent_version if health else None,
                    "queue_depth": health.spool_event_count if health else None,
                    "metadata": sensor.metadata_json,
                    "health": health_record,
                }
            )
        return {"items": items, "total": len(items)}

    @router.post("/sensors/{sensor_id}/heartbeat")
    def sensor_heartbeat(
        sensor_id: str,
        payload: SensorHeartbeatIn,
        request: Request,
        authorization: str | None = Header(None),
        session: Session = Depends(_session),
    ) -> dict[str, Any]:
        sensor = authenticate_sensor(request, session, authorization)
        if sensor.id != sensor_id:
            raise HTTPException(status_code=404, detail="sensor not found")
        now = datetime.now(UTC)
        health = session.get(SensorHealth, sensor.id)
        values = payload.model_dump()
        values["received_at"] = now
        if health is None:
            health = SensorHealth(sensor_id=sensor.id, **values)
            session.add(health)
        else:
            for key, value in values.items():
                setattr(health, key, value)
        sensor.last_seen_at = now
        session.commit()
        return {"sensor_id": sensor.id, "accepted": True, "received_at": now.isoformat()}

    async def _ingest(
        request: Request,
        payload: EventBatchIn,
        authorization: str | None,
        session: Session,
    ) -> dict[str, Any]:
        if len(payload.events) > settings.max_batch_events:
            raise HTTPException(
                status_code=413,
                detail=f"batch exceeds configured maximum of {settings.max_batch_events} events",
            )
        sensor = authenticate_sensor(request, session, authorization)
        result, alerts = ingest_batch(session, sensor, payload, request.app.state.detection_engine)
        session.commit()
        if not result["idempotent_replay"]:
            await live_hub.broadcast(
                {
                    "type": "ingest",
                    "sensor_id": sensor.id,
                    "batch_id": payload.batch_id,
                    "accepted": result["accepted"],
                    "alerts": [serialize_alert(session, alert, False) for alert in alerts],
                }
            )
        return result

    @router.post("/events/batch")
    async def ingest_events_batch(
        request: Request,
        payload: EventBatchIn,
        authorization: str | None = Header(None),
        session: Session = Depends(_session),
    ) -> dict[str, Any]:
        return await _ingest(request, payload, authorization, session)

    @router.post("/events/ingest", include_in_schema=False)
    async def ingest_events_alias(
        request: Request,
        payload: EventBatchIn,
        authorization: str | None = Header(None),
        session: Session = Depends(_session),
    ) -> dict[str, Any]:
        return await _ingest(request, payload, authorization, session)

    @router.get("/events")
    def list_events(
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0, le=1_000_000),
        host_id: str | None = None,
        event_type: str | None = None,
        scenario_run_id: str | None = None,
        session: Session = Depends(_session),
    ) -> dict[str, Any]:
        query = select(NormalizedEvent)
        count_query = select(func.count()).select_from(NormalizedEvent)
        predicates = []
        if host_id:
            predicates.append(NormalizedEvent.host_id == host_id)
        if event_type:
            predicates.append(NormalizedEvent.event_type == event_type)
        if scenario_run_id:
            predicates.append(NormalizedEvent.scenario_run_id == scenario_run_id)
        if predicates:
            query = query.where(*predicates)
            count_query = count_query.where(*predicates)
        items = session.scalars(
            query.order_by(NormalizedEvent.event_time.desc()).offset(offset).limit(limit)
        ).all()
        return {
            "items": [serialize_event(item) for item in items],
            "total": session.scalar(count_query) or 0,
            "limit": limit,
            "offset": offset,
        }

    @router.get("/alerts")
    def list_alerts(
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0, le=1_000_000),
        severity: str | None = None,
        rule_id: str | None = None,
        scenario_run_id: str | None = None,
        session: Session = Depends(_session),
    ) -> dict[str, Any]:
        query = select(Alert)
        count_query = select(func.count()).select_from(Alert)
        predicates = []
        if severity:
            predicates.append(Alert.severity == severity)
        if rule_id:
            predicates.append(Alert.rule_id == rule_id)
        if scenario_run_id:
            predicates.append(Alert.scenario_run_id == scenario_run_id)
        if predicates:
            query = query.where(*predicates)
            count_query = count_query.where(*predicates)
        alerts = session.scalars(
            query.order_by(Alert.created_at.desc()).offset(offset).limit(limit)
        ).all()
        return {
            "items": [serialize_alert(session, item, include_evidence=False) for item in alerts],
            "total": session.scalar(count_query) or 0,
            "limit": limit,
            "offset": offset,
        }

    @router.get("/alerts/{alert_id}")
    def alert_detail(alert_id: str, session: Session = Depends(_session)) -> dict[str, Any]:
        alert = session.get(Alert, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return serialize_alert(session, alert)

    @router.get("/rules")
    def list_detection_rules(session: Session = Depends(_session)) -> dict[str, Any]:
        rules = session.scalars(select(DetectionRule).order_by(DetectionRule.title)).all()
        return {"items": [_rule_response(rule) for rule in rules], "total": len(rules)}

    @router.post("/rules/reload", dependencies=[Depends(require_admin_key)])
    def reload_detection_rules(
        request: Request, session: Session = Depends(_session)
    ) -> dict[str, Any]:
        rules, errors = load_rules(settings.rules_path)
        if errors:
            raise HTTPException(status_code=422, detail={"errors": errors})
        engine = DetectionEngine(rules)
        engine.sync_catalog(session)
        session.commit()
        request.app.state.detection_engine = engine
        return {"loaded": len(rules), "errors": []}

    @router.get("/scenarios")
    def list_scenarios(session: Session = Depends(_session)) -> dict[str, Any]:
        scenarios = session.scalars(select(Scenario).order_by(Scenario.name)).all()
        return {
            "items": [
                {
                    "id": item.id,
                    "name": item.name,
                    "description": item.description,
                    "technique_ids": item.technique_ids,
                    "supported_platforms": item.supported_platforms,
                    "platform": item.supported_platforms[0] if item.supported_platforms else None,
                    "safety_notes": item.safety_notes,
                    "safety": " ".join(item.safety_notes),
                    "reversible": True,
                    "supports_dry_run": True,
                    "lab_mode_required": True,
                    "enabled": item.enabled,
                }
                for item in scenarios
            ],
            "lab_mode": settings.lab_mode,
            "total": len(scenarios),
        }

    @router.get("/scenario-runs")
    def list_scenario_runs(
        limit: int = Query(100, ge=1, le=1000), session: Session = Depends(_session)
    ) -> dict[str, Any]:
        runs = session.scalars(
            select(ScenarioRun).order_by(ScenarioRun.requested_at.desc()).limit(limit)
        ).all()
        return {
            "items": [
                {
                    "id": run.id,
                    "scenario_id": run.scenario_id,
                    "sensor_id": run.sensor_id,
                    "status": run.status,
                    "dry_run": run.dry_run,
                    "requested_at": run.requested_at.isoformat(),
                    "cleanup_verified": run.cleanup_verified,
                    "error_summary": run.error_summary,
                    "parameters": run.parameters_json,
                }
                for run in runs
            ]
        }

    @router.get("/scenario-runs/pending")
    def pending_scenario_run(
        request: Request,
        authorization: str | None = Header(None),
        session: Session = Depends(_session),
    ) -> dict[str, Any]:
        sensor = authenticate_sensor(request, session, authorization)
        run = session.scalar(
            select(ScenarioRun)
            .where(
                ScenarioRun.sensor_id == sensor.id,
                ScenarioRun.status == "requested",
                ScenarioRun.dry_run.is_(False),
            )
            .order_by(ScenarioRun.requested_at, ScenarioRun.id)
            .limit(1)
        )
        if run is None:
            return {"run": None}
        # Parameters are intentionally not dispatched. The allowlisted Windows lab runner maps
        # this vetted catalog ID to a local implementation and never receives an arbitrary command.
        return {
            "run": {
                "run_id": run.id,
                "scenario_id": run.scenario_id,
                "sensor_id": sensor.id,
                "dry_run": run.dry_run,
            }
        }

    @router.post("/scenario-runs/{run_id}/status")
    def update_scenario_run_status(
        run_id: str,
        payload: ScenarioRunStatusIn,
        request: Request,
        authorization: str | None = Header(None),
        session: Session = Depends(_session),
    ) -> dict[str, Any]:
        sensor = authenticate_sensor(request, session, authorization)
        run = session.scalar(select(ScenarioRun).where(ScenarioRun.id == run_id).with_for_update())
        if run is None or run.sensor_id != sensor.id:
            # Do not disclose whether another sensor owns a run ID.
            raise HTTPException(status_code=404, detail="scenario run not found")
        allowed_transitions = {
            "requested": {"running", "failed"},
            "running": {"completed", "failed"},
        }
        if payload.status not in allowed_transitions.get(run.status, set()):
            raise HTTPException(
                status_code=409,
                detail=f"invalid scenario run transition: {run.status} -> {payload.status}",
            )
        now = datetime.now(UTC)
        run.status = payload.status
        if payload.status == "running":
            run.started_at = now
        else:
            run.completed_at = now
            run.cleanup_verified = payload.cleanup_verified
        if payload.error_summary:
            run.error_summary = payload.error_summary
        session.commit()
        return {
            "run_id": run.id,
            "scenario_id": run.scenario_id,
            "status": run.status,
            "cleanup_verified": run.cleanup_verified,
        }

    @router.post(
        "/scenarios/{scenario_id}/runs",
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=[Depends(require_admin_key)],
    )
    def request_scenario_run(
        scenario_id: str, payload: ScenarioRunIn, session: Session = Depends(_session)
    ) -> dict[str, Any]:
        scenario = session.get(Scenario, scenario_id)
        if scenario is None or not scenario.enabled:
            raise HTTPException(status_code=404, detail="scenario not found or disabled")
        if not payload.dry_run and not settings.lab_mode:
            raise HTTPException(
                status_code=403,
                detail="non-dry scenario runs require SENTINELFORGE_LAB_MODE=1",
            )
        if not payload.dry_run and payload.sensor_id is None:
            raise HTTPException(status_code=422, detail="non-dry scenario runs require sensor_id")
        if payload.sensor_id and session.get(Sensor, payload.sensor_id) is None:
            raise HTTPException(status_code=422, detail="unknown sensor_id")
        run = ScenarioRun(
            scenario_id=scenario.id,
            sensor_id=payload.sensor_id,
            status="validated" if payload.dry_run else "requested",
            dry_run=payload.dry_run,
            parameters_json=payload.parameters,
            cleanup_verified=True if payload.dry_run else None,
        )
        session.add(run)
        session.commit()
        return {
            "id": run.id,
            "scenario_id": run.scenario_id,
            "sensor_id": run.sensor_id,
            "status": run.status,
            "dry_run": run.dry_run,
            "lab_mode": settings.lab_mode,
            "cleanup_verified": run.cleanup_verified,
        }

    @router.get("/attack/coverage")
    def attack_coverage(session: Session = Depends(_session)) -> dict[str, Any]:
        rules = session.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))).all()
        techniques = session.scalars(select(AttackTechnique).order_by(AttackTechnique.id)).all()
        postgres = session.get_bind().dialect.name == "postgresql"

        def tag_count(model, column, technique_id: str) -> int:  # type: ignore[no-untyped-def]
            if postgres:
                return (
                    session.scalar(
                        select(func.count())
                        .select_from(model)
                        .where(cast(column, JSONB).contains([technique_id]))
                    )
                    or 0
                )
            # SQLite lacks JSONB containment and is only the bounded local demo/test path.
            return sum(technique_id in tags for tags in session.scalars(select(column)))

        items = []
        for technique in techniques:
            mapped_rules = [rule.id for rule in rules if technique.id in rule.attack_tags]
            items.append(
                {
                    "technique_id": technique.id,
                    "name": technique.name,
                    "tactic": technique.tactic,
                    "url": technique.url,
                    "rule_ids": mapped_rules,
                    "rule_count": len(mapped_rules),
                    "alert_count": tag_count(Alert, Alert.attack_tags, technique.id),
                    "event_count": tag_count(
                        NormalizedEvent, NormalizedEvent.attack_tags, technique.id
                    ),
                    "covered": bool(mapped_rules),
                }
            )
        return {
            "items": items,
            "summary": {
                "techniques_cataloged": len(items),
                "techniques_covered": sum(item["covered"] for item in items),
                "total_techniques": len(items),
                "covered_techniques": sum(item["covered"] for item in items),
                "enabled_rules": len(rules),
                "rule_count": len(rules),
            },
        }

    @router.get("/timeline")
    def timeline(
        limit: int = Query(500, ge=1, le=5000),
        host_id: str | None = None,
        rule_id: str | None = None,
        technique: str | None = None,
        severity: str | None = None,
        scenario_run_id: str | None = None,
        session: Session = Depends(_session),
    ) -> dict[str, Any]:
        return build_timeline(
            session,
            limit=limit,
            host_id=host_id,
            rule_id=rule_id,
            technique=technique,
            severity=severity,
            scenario_run_id=scenario_run_id,
        )

    @router.get("/overview")
    def overview(session: Session = Depends(_session)) -> dict[str, Any]:
        severities = dict(
            session.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all()
        )
        return {
            "sensors": session.scalar(select(func.count()).select_from(Sensor)) or 0,
            "events": session.scalar(select(func.count()).select_from(NormalizedEvent)) or 0,
            "alerts": session.scalar(select(func.count()).select_from(Alert)) or 0,
            "rules": session.scalar(select(func.count()).select_from(DetectionRule)) or 0,
            "alerts_by_severity": severities,
            "lab_mode": settings.lab_mode,
        }

    @router.post("/demo/seed", dependencies=[Depends(require_admin_key)])
    async def demo_seed(
        request: Request, payload: DemoSeedIn, session: Session = Depends(_session)
    ) -> dict[str, Any]:
        result = seed_demo(
            session,
            request.app.state.detection_engine,
            seed=payload.seed,
            token_pepper=settings.token_pepper,
            reset_demo=payload.reset_demo,
        )
        session.commit()
        await live_hub.broadcast({"type": "demo_seed", **result})
        return result

    @router.post("/maintenance/purge", dependencies=[Depends(require_admin_key)])
    def purge(payload: PurgeIn, session: Session = Depends(_session)) -> dict[str, Any]:
        retention_days = payload.retention_days or settings.retention_days
        result = purge_old_events(session, retention_days, payload.dry_run)
        session.commit()
        return result

    @router.get("/investigations/export", dependencies=[Depends(require_admin_key)])
    def export_investigation(
        scenario_run_id: str | None = None,
        limit: int = Query(5000, ge=1, le=10000),
        session: Session = Depends(_session),
    ) -> dict[str, Any]:
        event_query = select(NormalizedEvent).order_by(NormalizedEvent.event_time).limit(limit)
        alert_query = select(Alert).order_by(Alert.created_at).limit(limit)
        if scenario_run_id:
            event_query = event_query.where(NormalizedEvent.scenario_run_id == scenario_run_id)
            alert_query = alert_query.where(Alert.scenario_run_id == scenario_run_id)
        events = session.scalars(event_query).all()
        alerts = session.scalars(alert_query).all()
        return {
            "schema_version": "1.0",
            "generated_at": datetime.now(UTC).isoformat(),
            "filters": {"scenario_run_id": scenario_run_id},
            "events": [serialize_event(event) for event in events],
            "alerts": [serialize_alert(session, alert) for alert in alerts],
            "truncated": len(events) >= limit or len(alerts) >= limit,
        }

    @app.websocket("/api/v1/live")
    async def live(websocket: WebSocket) -> None:
        await live_hub.connect(websocket)
        try:
            await websocket.send_json({"type": "connected", "schema_version": "1.0"})
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            live_hub.disconnect(websocket)

    app.include_router(router)
    return app


app = create_app()
