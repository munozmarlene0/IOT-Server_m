"""
IAuthMethod — interfaz base para todos los métodos de autenticación.

Cualquier método (RC, UP, bio, etc.) debe heredar de IAuthMethod
e implementar todos sus métodos abstractos.

Usa Generic[T] para tipar la entidad (Device, Application, User, etc.)
"""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from app.shared.base_domain.model import BaseTable

T = TypeVar("T", bound=BaseTable)


class IAuthMethod(ABC, Generic[T]):
    """
    Contrato que todo método de autenticación debe cumplir.

    Uso:
        class DeviceAuth(IAuthMethod[Device]):
            def authenticate(self, entity: Device, request_data) -> dict: ...
            def get_auth_type(self) -> str: ...
    """

    @abstractmethod
    def authenticate(self, entity: T, request_data) -> dict:
        """
        Ejecutar la autenticación.

        Args:
            entity: la entidad ya validada (Device, Application, etc.)
            request_data: datos del request (puzzle, credenciales, etc.)

        Returns:
            {"valid": True} si exitosa
            {"valid": False, "error": "..."} si falla
        """
        ...

    @abstractmethod
    def get_auth_type(self) -> str:
        """
        Retornar identificador del tipo de autenticación.
        Ej: 'rc', 'up', 'bio', etc.
        """
        ...
