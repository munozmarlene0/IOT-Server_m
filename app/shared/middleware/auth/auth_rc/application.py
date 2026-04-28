"""Adaptador de puzzle criptográfico para applications."""

from app.database.model import Application
from app.shared.middleware.auth.interface import IAuthMethod
from app.shared.middleware.auth.auth_rc.puzzle import PuzzleVerifier


class ApplicationAuth(IAuthMethod[Application]):
    """Extrae api_key de la Application y delega al PuzzleVerifier."""

    def __init__(self):
        self.verifier = PuzzleVerifier()

    def authenticate(self, application: Application, puzzle) -> dict:
        if not application.api_key:
            return {"valid": False, "error": "Authentication failed"}
        key = bytes.fromhex(application.api_key)
        return self.verifier.verify(key, puzzle, str(application.id))

    def get_auth_type(self) -> str:
        return "rc"
