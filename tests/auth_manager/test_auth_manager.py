"""Tests para AuthManager — flujo de autenticación."""
import base64
import pytest
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

from app.shared.middleware.auth.auth_manager.manager import AuthManager


# ── Fakes ───────────────────────────────────────────────────────────

FAKE_ID = uuid4()


@dataclass
class FakeEntity:
    id: UUID = field(default_factory=lambda: FAKE_ID)
    is_active: bool = True
    name: str = "Fake Entity"


class FakeRepository:
    def __init__(self, session, entity=None):
        self._entity = entity

    def get_by_id(self, entity_id):
        if self._entity and str(self._entity.id) == str(entity_id):
            return self._entity
        return None


class FakeAuthSuccess:
    def authenticate(self, entity, request_data) -> dict:
        return {"valid": True}

    def get_auth_type(self) -> str:
        return "fake_success"


class FakeAuthFail:
    def authenticate(self, entity, request_data) -> dict:
        return {"valid": False, "error": "Authentication failed"}

    def get_auth_type(self) -> str:
        return "fake_fail"


class FakeRequest:
    def __init__(self, entity_id: UUID = FAKE_ID):
        self.entity_id = entity_id


class StubAuthManager(AuthManager[FakeEntity]):
    repository_class = FakeRepository
    _auth_methods = {
        "success": FakeAuthSuccess,
        "fail": FakeAuthFail,
    }

    def _get_entity_id(self, request_data) -> UUID:
        return request_data.entity_id


# ── Fixtures ────────────────────────────────────────────────────────

@pytest.fixture
def mock_session_service():
    service = AsyncMock()
    service.get_session.return_value = None
    service.create_entity_session.return_value = MagicMock(
        session_id="test-session-id",
        encrypted_token="test-encrypted-token",
    )
    return service


@pytest.fixture
def active_entity():
    return FakeEntity(id=FAKE_ID, is_active=True)


@pytest.fixture
def inactive_entity():
    return FakeEntity(id=FAKE_ID, is_active=False)


@pytest.fixture
def request_info():
    return {"ip_address": "127.0.0.1", "user_agent": "test-agent"}


def patch_repository(entity):
    """Patchear FakeRepository para retornar la entidad dada."""
    original = FakeRepository.__init__
    def patched(self, session, e=None):
        original(self, session, entity=entity)
    FakeRepository.__init__ = patched
    return original


# ── Tests: flujo exitoso ────────────────────────────────────────────

class TestAuthManagerSuccess:

    @pytest.mark.asyncio
    async def test_valid_auth_returns_valid(self, mock_session_service, active_entity, request_info):
        original = patch_repository(active_entity)
        manager = StubAuthManager(None, mock_session_service, auth_type="success")
        result = await manager.authenticate(FakeRequest(), request_info)
        assert result["valid"] is True
        assert "session_id" in result
        assert "encrypted_token" in result
        assert "key_session" in result
        FakeRepository.__init__ = original

    @pytest.mark.asyncio
    async def test_session_key_is_base64_32_bytes(self, mock_session_service, active_entity, request_info):
        original = patch_repository(active_entity)
        manager = StubAuthManager(None, mock_session_service, auth_type="success")
        result = await manager.authenticate(FakeRequest(), request_info)
        key_bytes = base64.urlsafe_b64decode(result["key_session"])
        assert len(key_bytes) == 32
        FakeRepository.__init__ = original

    @pytest.mark.asyncio
    async def test_create_session_called_with_ip_and_user_agent(self, mock_session_service, active_entity, request_info):
        original = patch_repository(active_entity)
        manager = StubAuthManager(None, mock_session_service, auth_type="success")
        await manager.authenticate(FakeRequest(), request_info)
        mock_session_service.create_entity_session.assert_called_once()
        call_kwargs = mock_session_service.create_entity_session.call_args[1]
        assert call_kwargs["entity_id"] == str(FAKE_ID)
        assert call_kwargs["ip"] == "127.0.0.1"
        assert call_kwargs["user_agent"] == "test-agent"
        assert "key_session" in call_kwargs
        FakeRepository.__init__ = original


# ── Tests: entidad no encontrada ────────────────────────────────────

class TestAuthManagerEntityNotFound:

    @pytest.mark.asyncio
    async def test_nonexistent_entity_fails(self, mock_session_service, request_info):
        manager = StubAuthManager(None, mock_session_service, auth_type="success")
        result = await manager.authenticate(FakeRequest(entity_id=uuid4()), request_info)
        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


# ── Tests: entidad inactiva ─────────────────────────────────────────

class TestAuthManagerEntityInactive:

    @pytest.mark.asyncio
    async def test_inactive_entity_fails(self, mock_session_service, inactive_entity, request_info):
        original = patch_repository(inactive_entity)
        manager = StubAuthManager(None, mock_session_service, auth_type="success")
        result = await manager.authenticate(FakeRequest(), request_info)
        assert result["valid"] is False
        assert result["error"] == "Authentication failed"
        FakeRepository.__init__ = original


# ── Tests: sesión activa ────────────────────────────────────────────

class TestAuthManagerSessionActive:

    @pytest.mark.asyncio
    async def test_active_session_fails(self, mock_session_service, active_entity, request_info):
        mock_session_service.get_session.return_value = MagicMock()
        original = patch_repository(active_entity)
        manager = StubAuthManager(None, mock_session_service, auth_type="success")
        result = await manager.authenticate(FakeRequest(), request_info)
        assert result["valid"] is False
        assert result["error"] == "Authentication failed"
        FakeRepository.__init__ = original


# ── Tests: autenticación falla ──────────────────────────────────────

class TestAuthManagerAuthFails:

    @pytest.mark.asyncio
    async def test_auth_method_fails(self, mock_session_service, active_entity, request_info):
        original = patch_repository(active_entity)
        manager = StubAuthManager(None, mock_session_service, auth_type="fail")
        result = await manager.authenticate(FakeRequest(), request_info)
        assert result["valid"] is False
        assert result["error"] == "Authentication failed"
        FakeRepository.__init__ = original


# ── Tests: tipo inválido ────────────────────────────────────────────

class TestAuthManagerInvalidType:

    def test_invalid_auth_type_raises(self, mock_session_service):
        with pytest.raises(ValueError, match="no disponible"):
            StubAuthManager(None, mock_session_service, auth_type="xyz")


# ── Tests: llave de sesión ──────────────────────────────────────────

class TestAuthManagerSessionKey:

    def test_session_key_is_32_bytes(self):
        manager = StubAuthManager.__new__(StubAuthManager)
        key = manager._generate_session_key()
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_session_keys_are_unique(self):
        manager = StubAuthManager.__new__(StubAuthManager)
        assert manager._generate_session_key() != manager._generate_session_key()
