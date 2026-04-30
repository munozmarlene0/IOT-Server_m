from app.shared.middleware.auth.humans import HumanPasswordAuth
from app.shared.middleware.auth.interface import IAuthMethod


class HumanAuth(IAuthMethod):
    """
    Adaptador auth_rc para humanos.

    Mantiene separado el login humano de:
    - dispositivos
    - aplicaciones

    Atiende administrator, manager y user usando HumanPasswordAuth.
    """

    def __init__(self):
        self.human_auth = HumanPasswordAuth()

    def authenticate(self, human_entity, request_data) -> dict:
        return self.human_auth.authenticate(human_entity, request_data)

    def get_auth_type(self) -> str:
        return "auth_rc"