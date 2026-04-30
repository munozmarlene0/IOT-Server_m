from fastapi import APIRouter, Request

from app.shared.auth.schemas import (
    ChangePasswordRequest,
    EntityPuzzleLoginRequest,
    HumanLoginRequest,
    HumanScopedLoginRequest,
    HumanXMSSChallengeRequest,
    HumanXMSSVerifyRequest,
    MessageResponse,
    TokenResponse,
    XMSSChallengeRequest,
    XMSSChallengeResponse,
    XMSSVerifyRequest,
)
from app.shared.auth.service import (
    CurrentAccountDep,
    SharedAuthServiceDep,
    logout_current_token,
)


auth_router = APIRouter(prefix="/auth", tags=["Auth"])
auth_rc_router = APIRouter(prefix="/auth-rc", tags=["Auth RC"])
auth_xmss_router = APIRouter(prefix="/auth-xmss", tags=["Auth XMSS"])


def _build_human_login_request(
    entity_type: str,
    payload: HumanScopedLoginRequest,
) -> HumanLoginRequest:
    return HumanLoginRequest(
        entity_type=entity_type,
        email=payload.email,
        password=payload.password,
    )


def _build_human_xmss_challenge_request(
    entity_type: str,
    payload: HumanXMSSChallengeRequest,
) -> XMSSChallengeRequest:
    return XMSSChallengeRequest(
        entity_type=entity_type,
        identifier=payload.identifier,
        tree_height=payload.tree_height,
    )


def _build_human_xmss_verify_request(
    entity_type: str,
    payload: HumanXMSSVerifyRequest,
) -> XMSSVerifyRequest:
    return XMSSVerifyRequest(
        entity_type=entity_type,
        identifier=payload.identifier,
        challenge=payload.challenge,
        leaf_index=payload.leaf_index,
        message=payload.message,
        signature=payload.signature,
        ots_public_key=payload.ots_public_key,
        auth_path=payload.auth_path,
    )


@auth_router.patch("/change-password", response_model=MessageResponse)
def change_password(
    payload: ChangePasswordRequest,
    service: SharedAuthServiceDep,
    current: CurrentAccountDep,
):
    return service.change_password(current, payload)


@auth_router.post("/logout", response_model=MessageResponse)
async def logout(
    request: Request,
    _current: CurrentAccountDep,
):
    return await logout_current_token(request)


@auth_rc_router.post("/user/login", response_model=TokenResponse)
def login_user_rc(
    payload: HumanScopedLoginRequest,
    service: SharedAuthServiceDep,
):
    return service.login_human_rc(_build_human_login_request("user", payload))


@auth_rc_router.post("/manager/login", response_model=TokenResponse)
def login_manager_rc(
    payload: HumanScopedLoginRequest,
    service: SharedAuthServiceDep,
):
    return service.login_human_rc(_build_human_login_request("manager", payload))


@auth_rc_router.post("/admin/login", response_model=TokenResponse)
def login_admin_rc(
    payload: HumanScopedLoginRequest,
    service: SharedAuthServiceDep,
):
    return service.login_human_rc(
        _build_human_login_request("administrator", payload),
        expected_is_master=False,
    )


@auth_rc_router.post("/master/login", response_model=TokenResponse)
def login_master_rc(
    payload: HumanScopedLoginRequest,
    service: SharedAuthServiceDep,
):
    return service.login_human_rc(
        _build_human_login_request("administrator", payload),
        expected_is_master=True,
    )


@auth_rc_router.post("/devices/login", response_model=TokenResponse)
def login_device_rc(
    payload: EntityPuzzleLoginRequest,
    service: SharedAuthServiceDep,
):
    return service.login_device_rc(payload)


@auth_rc_router.post("/applications/login", response_model=TokenResponse)
def login_application_rc(
    payload: EntityPuzzleLoginRequest,
    service: SharedAuthServiceDep,
):
    return service.login_application_rc(payload)


@auth_xmss_router.post("/user/challenge", response_model=XMSSChallengeResponse)
def create_user_xmss_challenge(
    payload: HumanXMSSChallengeRequest,
    service: SharedAuthServiceDep,
):
    return service.create_xmss_challenge(
        _build_human_xmss_challenge_request("user", payload)
    )


@auth_xmss_router.post("/user/verify", response_model=TokenResponse)
def verify_user_xmss(
    payload: HumanXMSSVerifyRequest,
    service: SharedAuthServiceDep,
):
    return service.verify_xmss(_build_human_xmss_verify_request("user", payload))


@auth_xmss_router.post("/manager/challenge", response_model=XMSSChallengeResponse)
def create_manager_xmss_challenge(
    payload: HumanXMSSChallengeRequest,
    service: SharedAuthServiceDep,
):
    return service.create_xmss_challenge(
        _build_human_xmss_challenge_request("manager", payload)
    )


@auth_xmss_router.post("/manager/verify", response_model=TokenResponse)
def verify_manager_xmss(
    payload: HumanXMSSVerifyRequest,
    service: SharedAuthServiceDep,
):
    return service.verify_xmss(_build_human_xmss_verify_request("manager", payload))


@auth_xmss_router.post("/admin/challenge", response_model=XMSSChallengeResponse)
def create_admin_xmss_challenge(
    payload: HumanXMSSChallengeRequest,
    service: SharedAuthServiceDep,
):
    return service.create_xmss_challenge(
        _build_human_xmss_challenge_request("administrator", payload),
        expected_is_master=False,
    )


@auth_xmss_router.post("/admin/verify", response_model=TokenResponse)
def verify_admin_xmss(
    payload: HumanXMSSVerifyRequest,
    service: SharedAuthServiceDep,
):
    return service.verify_xmss(
        _build_human_xmss_verify_request("administrator", payload),
        expected_is_master=False,
    )


@auth_xmss_router.post("/master/challenge", response_model=XMSSChallengeResponse)
def create_master_xmss_challenge(
    payload: HumanXMSSChallengeRequest,
    service: SharedAuthServiceDep,
):
    return service.create_xmss_challenge(
        _build_human_xmss_challenge_request("administrator", payload),
        expected_is_master=True,
    )


@auth_xmss_router.post("/master/verify", response_model=TokenResponse)
def verify_master_xmss(
    payload: HumanXMSSVerifyRequest,
    service: SharedAuthServiceDep,
):
    return service.verify_xmss(
        _build_human_xmss_verify_request("administrator", payload),
        expected_is_master=True,
    )


@auth_xmss_router.post("/devices/challenge", response_model=XMSSChallengeResponse)
def create_device_xmss_challenge(
    payload: XMSSChallengeRequest,
    service: SharedAuthServiceDep,
):
    if payload.entity_type != "device":
        from app.shared.exceptions import BadRequestException

        raise BadRequestException("Invalid device entity type")

    return service.create_xmss_challenge(payload)


@auth_xmss_router.post("/devices/verify", response_model=TokenResponse)
def verify_device_xmss(
    payload: XMSSVerifyRequest,
    service: SharedAuthServiceDep,
):
    if payload.entity_type != "device":
        from app.shared.exceptions import BadRequestException

        raise BadRequestException("Invalid device entity type")

    return service.verify_xmss(payload)


@auth_xmss_router.post("/applications/challenge", response_model=XMSSChallengeResponse)
def create_application_xmss_challenge(
    payload: XMSSChallengeRequest,
    service: SharedAuthServiceDep,
):
    if payload.entity_type != "application":
        from app.shared.exceptions import BadRequestException

        raise BadRequestException("Invalid application entity type")

    return service.create_xmss_challenge(payload)


@auth_xmss_router.post("/applications/verify", response_model=TokenResponse)
def verify_application_xmss(
    payload: XMSSVerifyRequest,
    service: SharedAuthServiceDep,
):
    if payload.entity_type != "application":
        from app.shared.exceptions import BadRequestException

        raise BadRequestException("Invalid application entity type")

    return service.verify_xmss(payload)