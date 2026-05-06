from contextvars import ContextVar
from typing import TypeVar, Annotated
from fastapi import Depends, HTTPException, status

from app.shared.authorization.oso_config import get_oso
from app.shared.authorization.models import CurrentUser
from app.domain.auth.service import CurrentAccountDep


_current_user_ctx: ContextVar[CurrentUser | None] = ContextVar(
    "current_user", default=None
)

T = TypeVar("T")


def get_current_user_from_context() -> CurrentUser | None:
    return _current_user_ctx.get()


def require_oso_permission(action: str, resource_type: type[T]):
    def check_permission(current: CurrentAccountDep) -> CurrentUser:
        user = CurrentUser.from_state_dict(current.__dict__)
        oso = get_oso()
        allowed = oso.is_allowed(user, action, resource_type)

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {action} on {resource_type.__name__}",
            )

        _current_user_ctx.set(user)
        return user

    return Depends(check_permission)


def require_read(resource_type: type[T]):
    return require_oso_permission("read", resource_type)


def require_write(resource_type: type[T]):
    return require_oso_permission("write", resource_type)


def require_delete(resource_type: type[T]):
    return require_oso_permission("delete", resource_type)


def require_administer(resource_type: type[T]):
    return require_oso_permission("administer", resource_type)

