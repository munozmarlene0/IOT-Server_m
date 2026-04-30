"""
IAuthMethod — interfaz base para todos los métodos de autenticación.

Cualquier método (RC, UP, bio, etc.) debe heredar de IAuthMethod
e implementar todos sus métodos abstractos.

Usa Generic[T] para tipar la entidad (Device, Application, User, etc.)
"""

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Generic, TypeVar

from app.shared.base_domain.model import BaseTable


T = TypeVar("T", bound=BaseTable)


class AuthType(StrEnum):
    AUTH_RC = "auth_rc"
    AUTH_XMSS = "auth_xmss"


class IAuthMethod(ABC, Generic[T]):
    """
    Contrato base para cualquier método de autenticación.

    Ejemplos:
    - auth_rc para puzzle criptográfico.
    - auth_xmss para autenticación basada en XMSS.
    """

    @abstractmethod
    def authenticate(self, entity: T, request_data) -> dict:
        ...

    @abstractmethod
    def get_auth_type(self) -> str:
        ...


class AuthMethodSelector:
    """
    Selector central para escoger el método de autenticación.

    Permite registrar handlers por:
    - tipo de auth: auth_rc / auth_xmss
    - tipo de entidad: user / manager / administrator / device / application
    """

    def __init__(self):
        self._methods: dict[tuple[str, str], IAuthMethod] = {}

    def register(
        self,
        *,
        auth_type: str,
        entity_type: str,
        method: IAuthMethod,
    ) -> None:
        self._methods[(auth_type, entity_type)] = method

    def resolve(
        self,
        *,
        auth_type: str,
        entity_type: str,
    ) -> IAuthMethod:
        method = self._methods.get((auth_type, entity_type))

        if method is None:
            raise ValueError(
                f"Authentication method not configured: {auth_type} for {entity_type}"
            )

        return method