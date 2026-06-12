"""Async SQLAlchemy engine + session factory.

Two engines are maintained when ``SENTINEL_POSTGRES_REPLICA_URL`` is set:
- Primary engine  — used for writes and the ``get_db()`` dependency.
- Replica engine  — used for read-only queries via ``get_read_db()``.
  Falls back to the primary when no replica URL is configured.
"""
from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings
from app.models.db import Base

_engine = None
_session_factory = None

# Read-replica engine (optional HA)
_read_engine = None
_read_session_factory = None


def get_engine():
    """Return the shared async engine, creating it on first use."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            settings.postgres_url,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
        )
    return _engine


def get_session_factory() -> async_sessionmaker:
    """Return the shared session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(), expire_on_commit=False, class_=AsyncSession
        )
    return _session_factory


async def create_tables() -> None:
    """Create all ORM tables (idempotent — safe to call on every startup)."""
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_engine() -> None:
    """Dispose the engine on shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


def get_read_engine():
    """Return the replica async engine (or primary when no replica is configured)."""
    global _read_engine
    if _read_engine is None:
        url = settings.postgres_replica_url or settings.postgres_url
        _read_engine = create_async_engine(
            url,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
        )
    return _read_engine


def get_read_session_factory() -> async_sessionmaker:
    """Return the read-replica session factory."""
    global _read_session_factory
    if _read_session_factory is None:
        _read_session_factory = async_sessionmaker(
            get_read_engine(), expire_on_commit=False, class_=AsyncSession
        )
    return _read_session_factory


async def close_read_engine() -> None:
    """Dispose the read-replica engine on shutdown."""
    global _read_engine, _read_session_factory
    if _read_engine is not None:
        await _read_engine.dispose()
        _read_engine = None
        _read_session_factory = None


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a session and commits/rolls back on exit."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_read_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for read-only queries.

    Uses the Postgres read replica when ``SENTINEL_POSTGRES_REPLICA_URL`` is
    set; otherwise falls back to the primary engine (safe for non-HA mode).
    """
    factory = get_read_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            raise
