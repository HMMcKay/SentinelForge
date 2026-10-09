"""Create the SentinelForge normalized telemetry schema.

Revision ID: 20260727_0001
Revises:
Create Date: 2026-07-27

The complete table, constraint, and index definitions live in the SQLAlchemy metadata
used by both Alembic autogeneration and SQLite test initialization. Binding this initial
migration to that metadata prevents the migration and application bootstrap paths from
silently diverging while the schema is still at its first public version.
"""

from collections.abc import Sequence

from alembic import op
from sentinelforge import models  # noqa: F401
from sentinelforge.database import Base

revision: str = "20260727_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind(), checkfirst=False)


def downgrade() -> None:
    bind = op.get_bind()
    for table in reversed(Base.metadata.sorted_tables):
        table.drop(bind=bind, checkfirst=True)
