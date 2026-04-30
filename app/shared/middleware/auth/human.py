from uuid import UUID
import logging

from fastapi import status
from sqlmodel import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import settings
from app.database import engine
from app.database.model import Administrator, Application, Device, Manager, User
from app.shared.auth.security import decode_access_token
from app.shared.session.repository import SessionRepository


PUBLIC_PATHS = {
    "/docs",
    "/openapi.json",
    "/redoc",

    "/api/v1/auth-rc/humans/login",
    "/api/v1/auth-rc/devices/login",
    "/api/v1/auth-rc/applications/login",

    "/api/v1/auth-xmss/humans/challenge",
    "/api/v1/auth-xmss/humans/verify",
    "/api/v1/auth-xmss/devices/challenge",
    "/api/v1/auth-xmss/devices/verify",
    "/api/v1/auth-xmss/applications/challenge",
    "/api/v1/auth-xmss/applications/verify",
}


logger = logging.getLogger(__name__)


class Human(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if path in PUBLIC_PATHS or path.startswith("/docs") or path.startswith("/redoc"):
            return await call_next(request)

        request.state.current_account = None
        request.state.token_payload = None

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return await call_next(request)

        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid token format"},
            )

        token = auth_header.replace("Bearer ", "", 1).strip()

        session_repository = SessionRepository(settings.VALKEY_URL)

        try:
            payload = decode_access_token(token)
            request.state.token_payload = payload

            token_id = payload.get("jti")
            if token_id:
                is_blacklisted = await session_repository.is_blacklisted(token_id)
                if is_blacklisted:
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"detail": "Token has been revoked"},
                    )

            raw_account_id = payload.get("sub")
            account_type = (
                payload.get("account_type")
                or payload.get("type")
                or payload.get("entity_type")
            )

            email = payload.get("email")
            is_master = bool(payload.get("is_master", False))
            auth_method = payload.get("auth_method", "auth_rc")

            if not raw_account_id:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Token is missing account identifier"},
                )

            model_map = {
                "administrator": Administrator,
                "manager": Manager,
                "user": User,
                "device": Device,
                "application": Application,
            }

            if account_type not in model_map:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid account type in token"},
                )

            if auth_method not in {"auth_rc", "auth_xmss"}:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid authentication method"},
                )

            account_id = UUID(str(raw_account_id))

            with Session(engine) as session:
                account = session.get(model_map[account_type], account_id)

                if account is None:
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"detail": "Token account does not exist"},
                    )

                if hasattr(account, "is_active") and not account.is_active:
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"detail": "Account is inactive"},
                    )

                sensitive_data_id = getattr(account, "sensitive_data_id", None)

                request.state.current_account = {
                    "account_id": str(account.id),
                    "sensitive_data_id": str(sensitive_data_id)
                    if sensitive_data_id
                    else None,
                    "account_type": account_type,
                    "email": email,
                    "is_master": is_master,
                    "auth_method": auth_method,
                }

        except Exception:
            logger.exception("Unhandled error in authentication middleware")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or expired token"},
            )
        finally:
            await session_repository.close()

        return await call_next(request)