FROM postgres:17.10-alpine3.23

LABEL org.opencontainers.image.title="SentinelForge PostgreSQL" \
      org.opencontainers.image.description="Pinned PostgreSQL runtime for the local SentinelForge lab"

# Schema evolution is owned by Alembic in the backend image. This image intentionally
# adds no initialization scripts, extensions, or host-facing configuration.
