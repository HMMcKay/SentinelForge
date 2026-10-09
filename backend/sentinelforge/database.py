from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


class Database:
    def __init__(self, url: str) -> None:
        engine_args: dict[str, object] = {"pool_pre_ping": True}
        if url.startswith("sqlite"):
            engine_args["connect_args"] = {"check_same_thread": False}
            if url in {"sqlite://", "sqlite:///:memory:"}:
                engine_args["poolclass"] = StaticPool
        self.engine = create_engine(url, **engine_args)
        if url.startswith("sqlite"):
            event.listen(self.engine, "connect", self._enable_sqlite_foreign_keys)
        self.session_factory = sessionmaker(
            bind=self.engine, autoflush=False, expire_on_commit=False, class_=Session
        )

    @staticmethod
    def _enable_sqlite_foreign_keys(connection, _record) -> None:  # type: ignore[no-untyped-def]
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    def create_schema(self) -> None:
        from . import models  # noqa: F401

        Base.metadata.create_all(self.engine)

    def sessions(self) -> Iterator[Session]:
        session = self.session_factory()
        try:
            yield session
        finally:
            session.close()

    def close(self) -> None:
        self.engine.dispose()
