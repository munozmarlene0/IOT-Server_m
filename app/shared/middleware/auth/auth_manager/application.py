"""Auth manager para applications."""

from uuid import UUID

from app.database.model import Application
from app.domain.application.repository import ApplicationRepository
from app.shared.middleware.auth.auth_rc.application import ApplicationAuth
from app.shared.middleware.auth.auth_manager.manager import AuthManager


class ApplicationAuthManager(AuthManager[Application]):

    repository_class = ApplicationRepository
    _auth_methods = {
        "rc": ApplicationAuth,
        # "up": ApplicationAuthUP,  ← agregar aquí cuando exista
    }

    def _get_entity_id(self, request_data) -> UUID:
        return request_data.application_id
