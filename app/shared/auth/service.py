from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
from sqlmodel import Session

from app.config import settings
from app.database import SessionDep
from app.shared.auth.repository import AuthRepository
from app.shared.auth.schemas import (
    ChangePasswordRequest,
    EntityPuzzleLoginRequest,
    HumanLoginRequest,
    MessageResponse,
    TokenResponse,
    XMSSChallengeRequest,
    XMSSChallengeResponse,
    XMSSVerifyRequest,
)
from app.shared.auth.security import (
    create_access_token,
    get_token_ttl_seconds,
    verify_password,
)
from app.shared.exceptions import BadRequestException, NotFoundException
from app.shared.middleware.auth.auth_rc.application import ApplicationAuth
from app.shared.middleware.auth.auth_rc.device import DeviceAuth
from app.shared.middleware.auth.auth_rc.human import HumanAuth
from app.shared.middleware.auth.auth_xmss.application import ApplicationXMSSAuth
from app.shared.middleware.auth.auth_xmss.challenge import XMSSChallengeFactory
from app.shared.middleware.auth.auth_xmss.device import DeviceXMSSAuth
from app.shared.middleware.auth.auth_xmss.human import HumanXMSSAuth
from app.shared.middleware.auth.interface import AuthMethodSelector
from app.shared.session.repository import SessionRepository


AccountType = Literal["administrator", "manager", "user", "device", "application"]

bearer_scheme = HTTPBearer()


@dataclass
class CurrentAccount:
    account_id: UUID
    sensitive_data_id: UUID | None
    account_type: AccountType
    email: str | None
    is_master: bool = False
    auth_method: str | None = None


class SharedAuthService:
    def __init__(self, session: Session):
        self.session = session
        self.repository = AuthRepository(session)
        self.xmss_factory = XMSSChallengeFactory()

        self.selector = AuthMethodSelector()

        for human_type in ["administrator", "manager", "user"]:
            self.selector.register(
                auth_type="auth_rc",
                entity_type=human_type,
                method=HumanAuth(),
            )
            self.selector.register(
                auth_type="auth_xmss",
                entity_type=human_type,
                method=HumanXMSSAuth(),
            )

        self.selector.register(
            auth_type="auth_rc",
            entity_type="device",
            method=DeviceAuth(),
        )
        self.selector.register(
            auth_type="auth_rc",
            entity_type="application",
            method=ApplicationAuth(),
        )
        self.selector.register(
            auth_type="auth_xmss",
            entity_type="device",
            method=DeviceXMSSAuth(),
        )
        self.selector.register(
            auth_type="auth_xmss",
            entity_type="application",
            method=ApplicationXMSSAuth(),
        )

    def login_human_rc(
        self,
        payload: HumanLoginRequest,
        expected_is_master: bool | None = None,
    ) -> TokenResponse:
        resolved = self.repository.get_human_by_email(
            email=payload.email,
            entity_type=payload.entity_type,
        )

        if resolved is None:
            raise BadRequestException("Invalid credentials")

        self._validate_expected_admin_scope(
            entity_type=payload.entity_type,
            is_master=resolved.is_master,
            expected_is_master=expected_is_master,
        )

        method = self.selector.resolve(
            auth_type="auth_rc",
            entity_type=payload.entity_type,
        )

        result = method.authenticate(
            resolved.account,
            {
                "account_type": resolved.account_type,
                "sensitive_data": resolved.sensitive_data,
                "password": payload.password,
            },
        )

        if not result.get("valid"):
            raise BadRequestException(result.get("error", "Authentication failed"))

        return self._issue_token(
            account_id=resolved.account.id,
            account_type=resolved.account_type,
            auth_method="auth_rc",
            email=resolved.sensitive_data.email,
            is_master=resolved.is_master,
        )

    def login_device_rc(self, payload: EntityPuzzleLoginRequest) -> TokenResponse:
        device = self.repository.get_device_by_identifier(payload.identifier)

        if device is None:
            raise BadRequestException("Invalid device credentials")

        method = self.selector.resolve(
            auth_type="auth_rc",
            entity_type="device",
        )

        result = method.authenticate(device, payload)

        if not result.get("valid"):
            raise BadRequestException(result.get("error", "Authentication failed"))

        return self._issue_token(
            account_id=device.id,
            account_type="device",
            auth_method="auth_rc",
            email=None,
            is_master=False,
        )

    def login_application_rc(self, payload: EntityPuzzleLoginRequest) -> TokenResponse:
        application = self.repository.get_application_by_identifier(payload.identifier)

        if application is None:
            raise BadRequestException("Invalid application credentials")

        method = self.selector.resolve(
            auth_type="auth_rc",
            entity_type="application",
        )

        result = method.authenticate(application, payload)

        if not result.get("valid"):
            raise BadRequestException(result.get("error", "Authentication failed"))

        return self._issue_token(
            account_id=application.id,
            account_type="application",
            auth_method="auth_rc",
            email=None,
            is_master=False,
        )

    def create_xmss_challenge(
        self,
        payload: XMSSChallengeRequest,
        expected_is_master: bool | None = None,
    ) -> XMSSChallengeResponse:
        entity = self._get_entity_for_xmss(
            entity_type=payload.entity_type,
            identifier=payload.identifier,
            expected_is_master=expected_is_master,
        )

        if entity is None:
            raise NotFoundException(payload.entity_type, payload.identifier)

        state = self.repository.get_xmss_state(entity)

        challenge_data = self.xmss_factory.create_challenge(
            entity_type=payload.entity_type,
            identifier=payload.identifier,
            leaf_index=state["current_index"],
            tree_height=payload.tree_height,
            public_root=state["public_root"],
        )

        if not state["public_root"]:
            self.repository.set_xmss_initial_state(
                entity=entity,
                public_root=challenge_data["public_root"],
                tree_height=payload.tree_height,
            )

        return XMSSChallengeResponse(**challenge_data)

    def verify_xmss(
        self,
        payload: XMSSVerifyRequest,
        expected_is_master: bool | None = None,
    ) -> TokenResponse:
        entity = self._get_entity_for_xmss(
            entity_type=payload.entity_type,
            identifier=payload.identifier,
            expected_is_master=expected_is_master,
        )

        if entity is None:
            raise NotFoundException(payload.entity_type, payload.identifier)

        state = self.repository.get_xmss_state(entity)

        if state["public_root"] is None:
            raise BadRequestException("XMSS is not configured for this entity")

        if payload.leaf_index != state["current_index"]:
            raise BadRequestException("Invalid XMSS leaf index")

        method = self.selector.resolve(
            auth_type="auth_xmss",
            entity_type=payload.entity_type,
        )

        result = method.authenticate(
            entity,
            {
                "payload": payload,
                "public_root": state["public_root"],
            },
        )

        if not result.get("valid"):
            raise BadRequestException(result.get("error", "Authentication failed"))

        self.repository.increment_xmss_index(entity)

        email = None
        is_master = False

        if payload.entity_type in {"administrator", "manager", "user"}:
            resolved = self.repository.get_human_for_xmss(
                entity_type=payload.entity_type,
                identifier=payload.identifier,
            )
            if resolved:
                email = resolved.sensitive_data.email
                is_master = resolved.is_master

        return self._issue_token(
            account_id=entity.id,
            account_type=payload.entity_type,
            auth_method="auth_xmss",
            email=email,
            is_master=is_master,
        )

    def change_password(
        self,
        current: CurrentAccount,
        payload: ChangePasswordRequest,
    ) -> MessageResponse:
        if current.sensitive_data_id is None:
            raise BadRequestException("This entity does not use password authentication")

        sensitive_data = self.session.get(
            __import__("app.database.model", fromlist=["SensitiveData"]).SensitiveData,
            current.sensitive_data_id,
        )

        if sensitive_data is None:
            raise BadRequestException("Associated account was not found")

        if not verify_password(payload.current_password, sensitive_data.password_hash):
            raise BadRequestException("Current password is incorrect")

        sensitive_data.password = payload.new_password
        self.session.add(sensitive_data)
        self.session.commit()
        self.session.refresh(sensitive_data)

        return MessageResponse(message="Password updated successfully")

    def _issue_token(
        self,
        *,
        account_id,
        account_type: AccountType,
        auth_method: str,
        email: str | None,
        is_master: bool,
    ) -> TokenResponse:
        token = create_access_token(
            {
                "sub": str(account_id),
                "email": email,
                "account_type": account_type,
                "type": account_type,
                "auth_method": auth_method,
                "is_master": is_master,
            }
        )

        return TokenResponse(
            access_token=token,
            account_type=account_type,
            auth_method=auth_method,
            is_master=is_master,
        )

    def _get_entity_for_xmss(
        self,
        *,
        entity_type: str,
        identifier: str,
        expected_is_master: bool | None,
    ):
        if entity_type == "administrator":
            resolved = self.repository.get_human_for_xmss(
                entity_type="administrator",
                identifier=identifier,
            )

            if resolved is None:
                return None

            self._validate_expected_admin_scope(
                entity_type=entity_type,
                is_master=resolved.is_master,
                expected_is_master=expected_is_master,
            )

            return resolved.account

        return self.repository.get_entity_for_xmss(
            entity_type=entity_type,
            identifier=identifier,
        )

    def _validate_expected_admin_scope(
        self,
        *,
        entity_type: str,
        is_master: bool,
        expected_is_master: bool | None,
    ) -> None:
        if entity_type != "administrator" or expected_is_master is None:
            return

        if is_master != expected_is_master:
            raise BadRequestException("Invalid credentials")


def get_shared_auth_service(session: SessionDep) -> SharedAuthService:
    return SharedAuthService(session)


SharedAuthServiceDep = Annotated[
    SharedAuthService,
    Depends(get_shared_auth_service),
]


def get_current_account_from_request(request: Request) -> CurrentAccount:
    current = getattr(request.state, "current_account", None)

    if not isinstance(current, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    try:
        sensitive_data_id = current.get("sensitive_data_id")

        return CurrentAccount(
            account_id=UUID(current["account_id"]),
            sensitive_data_id=UUID(sensitive_data_id) if sensitive_data_id else None,
            account_type=current["account_type"],
            email=current.get("email"),
            is_master=bool(current.get("is_master", False)),
            auth_method=current.get("auth_method"),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication context",
        ) from exc


CurrentAccountDep = Annotated[
    CurrentAccount,
    Depends(get_current_account_from_request),
]


def require_authenticated(
    _: Annotated[object, Depends(bearer_scheme)],
    current: CurrentAccountDep,
) -> CurrentAccount:
    return current


def require_admin(
    _: Annotated[object, Depends(bearer_scheme)],
    current: CurrentAccountDep,
) -> CurrentAccount:
    if current.account_type != "administrator":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges are required",
        )
    return current


def require_master_admin(
    _: Annotated[object, Depends(bearer_scheme)],
    current: CurrentAccountDep,
) -> CurrentAccount:
    if current.account_type != "administrator" or not current.is_master:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Master administrator privileges are required",
        )
    return current


def require_admin_or_manager(
    _: Annotated[object, Depends(bearer_scheme)],
    current: CurrentAccountDep,
) -> CurrentAccount:
    if current.account_type not in {"administrator", "manager"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator or manager privileges are required",
        )
    return current


async def logout_current_token(request: Request) -> MessageResponse:
    payload = getattr(request.state, "token_payload", None)

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    token_id = payload.get("jti")
    if not token_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token cannot be invalidated because it has no jti",
        )

    ttl_seconds = get_token_ttl_seconds(payload)

    repository = SessionRepository(settings.VALKEY_URL)
    try:
        if ttl_seconds > 0:
            await repository.add_to_blacklist(token_id, ttl_seconds=ttl_seconds)

        return MessageResponse(message="Logged out successfully")
    finally:
        await repository.close()