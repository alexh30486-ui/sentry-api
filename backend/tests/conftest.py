"""
Shared fixtures for the integration test suite.

Uses an in-memory SQLite database (via a shared StaticPool connection so
every session sees the same tables) instead of a real Postgres instance.
This works because the models use the portable `GUID` type decorator
(app/core/types.py) rather than a Postgres-only UUID column -- the same
models run against both engines.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.rate_limit import limiter
from app.database import Base, get_db, get_sessionmaker
from app.factory import create_app


@pytest_asyncio.fixture
async def test_engine():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def app(test_engine):
    fastapi_app = create_app()
    session_maker = async_sessionmaker(bind=test_engine, expire_on_commit=False)

    async def _get_test_db():
        async with session_maker() as session:
            yield session

    def _get_test_sessionmaker():
        return session_maker

    fastapi_app.dependency_overrides[get_db] = _get_test_db
    fastapi_app.dependency_overrides[get_sessionmaker] = _get_test_sessionmaker
    yield fastapi_app
    fastapi_app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Each test gets a clean rate-limit window regardless of run order."""
    limiter.reset()
    yield
    limiter.reset()


async def register_and_login(client: AsyncClient, email: str, password: str = "supersecret1") -> str:
    """Test helper: register + log in, return a bearer token string."""
    await client.post("/api/auth/register", json={"email": email, "password": password})
    resp = await client.post("/api/auth/login", json={"email": email, "password": password})
    return resp.json()["access_token"]
