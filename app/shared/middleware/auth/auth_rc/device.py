"""Adaptador de puzzle criptográfico para dispositivos."""

from app.database.model import Device
from app.shared.middleware.auth.interface import IAuthMethod
from app.shared.middleware.auth.auth_rc.puzzle import PuzzleVerifier


class DeviceAuth(IAuthMethod[Device]):
    """Extrae encryption_key del Device y delega al PuzzleVerifier."""

    def __init__(self):
        self.verifier = PuzzleVerifier()

    def authenticate(self, device: Device, puzzle) -> dict:
        if not device.encryption_key:
            return {"valid": False, "error": "Authentication failed"}
        key = bytes.fromhex(device.encryption_key)
        return self.verifier.verify(key, puzzle, str(device.id))

    def get_auth_type(self) -> str:
        return "rc"
