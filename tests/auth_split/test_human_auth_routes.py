from fastapi.testclient import TestClient

from app.main import app
from app.shared.auth.service import get_shared_auth_service


class StubAuthService:
    def __init__(self):
        self.calls: list[tuple[str, object, bool | None]] = []

    def login_human_rc(self, payload, expected_is_master=None):
        self.calls.append(("login_human_rc", payload, expected_is_master))
        return {
            "access_token": "token",
            "token_type": "bearer",
            "account_type": payload.entity_type,
            "auth_method": "auth_rc",
            "is_master": expected_is_master is True,
        }

    def create_xmss_challenge(self, payload, expected_is_master=None):
        self.calls.append(("create_xmss_challenge", payload, expected_is_master))
        return {
            "auth_method": "auth_xmss",
            "entity_type": payload.entity_type,
            "identifier": payload.identifier,
            "challenge": "challenge",
            "leaf_index": 0,
            "expires_at": 1234567890,
            "public_root": "root",
            "canonical_message": {"identifier": payload.identifier},
            "client_material_compact": None,
        }

    def verify_xmss(self, payload, expected_is_master=None):
        self.calls.append(("verify_xmss", payload, expected_is_master))
        return {
            "access_token": "token",
            "token_type": "bearer",
            "account_type": payload.entity_type,
            "auth_method": "auth_xmss",
            "is_master": expected_is_master is True,
        }


def _override_service():
    service = StubAuthService()
    app.dependency_overrides[get_shared_auth_service] = lambda: service
    return service


def _clear_override():
    app.dependency_overrides.pop(get_shared_auth_service, None)


class TestHumanAuthSplitRoutes:
    def test_auth_rc_master_login_sets_administrator_and_master_flag(self, client: TestClient):
        service = _override_service()

        try:
            response = client.post(
                "/api/v1/auth-rc/master/login",
                json={
                    "email": "MASTER_ADMIN@TEST.COM",
                    "password": "MasterPassword123!",
                },
            )
        finally:
            _clear_override()

        assert response.status_code == 200
        call_name, payload, expected_is_master = service.calls[-1]
        assert call_name == "login_human_rc"
        assert payload.entity_type == "administrator"
        assert payload.email == "master_admin@test.com"
        assert expected_is_master is True

    def test_auth_rc_admin_login_sets_administrator_and_non_master_flag(self, client: TestClient):
        service = _override_service()

        try:
            response = client.post(
                "/api/v1/auth-rc/admin/login",
                json={
                    "email": "regular_admin@test.com",
                    "password": "RegularAdmin123!",
                },
            )
        finally:
            _clear_override()

        assert response.status_code == 200
        call_name, payload, expected_is_master = service.calls[-1]
        assert call_name == "login_human_rc"
        assert payload.entity_type == "administrator"
        assert expected_is_master is False

    def test_auth_rc_user_login_sets_user_entity(self, client: TestClient):
        service = _override_service()

        try:
            response = client.post(
                "/api/v1/auth-rc/user/login",
                json={
                    "email": "USER@TEST.COM",
                    "password": "UserPassword123!",
                },
            )
        finally:
            _clear_override()

        assert response.status_code == 200
        call_name, payload, expected_is_master = service.calls[-1]
        assert call_name == "login_human_rc"
        assert payload.entity_type == "user"
        assert payload.email == "user@test.com"
        assert expected_is_master is None

    def test_auth_xmss_manager_challenge_sets_manager_entity(self, client: TestClient):
        service = _override_service()

        try:
            response = client.post(
                "/api/v1/auth-xmss/manager/challenge",
                json={
                    "identifier": "MANAGER@TEST.COM",
                    "tree_height": 6,
                },
            )
        finally:
            _clear_override()

        assert response.status_code == 200
        call_name, payload, expected_is_master = service.calls[-1]
        assert call_name == "create_xmss_challenge"
        assert payload.entity_type == "manager"
        assert payload.identifier == "manager@test.com"
        assert payload.tree_height == 6
        assert expected_is_master is None

    def test_auth_xmss_master_verify_sets_administrator_and_master_flag(self, client: TestClient):
        service = _override_service()

        try:
            response = client.post(
                "/api/v1/auth-xmss/master/verify",
                json={
                    "identifier": "MASTER_ADMIN@TEST.COM",
                    "challenge": "challenge",
                    "leaf_index": 0,
                    "message": {"challenge": "challenge"},
                    "signature": {},
                    "auth_path": [],
                },
            )
        finally:
            _clear_override()

        assert response.status_code == 200
        call_name, payload, expected_is_master = service.calls[-1]
        assert call_name == "verify_xmss"
        assert payload.entity_type == "administrator"
        assert payload.identifier == "master_admin@test.com"
        assert expected_is_master is True