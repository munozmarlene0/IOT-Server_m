"""Auth manager para dispositivos."""

from uuid import UUID

from app.database.model import Device
from app.domain.device.repository import DeviceRepository
from app.shared.middleware.auth.auth_rc.device import DeviceAuth
from app.shared.middleware.auth.auth_manager.manager import AuthManager


class DeviceAuthManager(AuthManager[Device]):

    repository_class = DeviceRepository
    _auth_methods = {
        "rc": DeviceAuth,
        # "up": DeviceAuthUP,  ← agregar aquí cuando exista
    }

    def _get_entity_id(self, request_data) -> UUID:
        return request_data.device_id
