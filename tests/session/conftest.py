"""Shared fixtures for session tests."""

import pytest
import valkey.asyncio as valkey

from app.shared.session.repository import SessionRepository
from app.shared.session.service import SessionService


VALKEY_TEST_URL = "valkey://localhost:6379/1"


@pytest.fixture
async def valkey_client():
    """Create Valkey client for tests."""
    client = await valkey.from_url(
        VALKEY_TEST_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    yield client
    await client.flushdb()
    await client.aclose()


@pytest.fixture
async def repository(valkey_client):
    """Create session repository."""
    repo = SessionRepository(VALKEY_TEST_URL)
    await repo.connect()
    yield repo
    await repo.close()


@pytest.fixture
async def session_service(repository):
    """Create session service."""
    return SessionService()
