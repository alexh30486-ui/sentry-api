from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()

engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """
    FastAPI dependency exposing the session *factory* rather than a session.

    Background tasks (e.g. scan execution) run after the request/response
    cycle has ended, so they can't reuse the request-scoped session from
    `get_db` -- they need to open their own. Routes that schedule a
    background task should depend on this and pass the factory through
    explicitly, rather than the task importing `AsyncSessionLocal` directly.
    Importing it directly silently bypasses `dependency_overrides`, which
    means tests that override `get_db` would still have the background
    task hit the real production database.
    """
    return AsyncSessionLocal
