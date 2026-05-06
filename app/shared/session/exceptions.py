from fastapi import HTTPException, status


class SessionNotFoundException(HTTPException):
    """Session lookup failed."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found",
        )


class SessionAlreadyExistsException(HTTPException):
    """Entity already has an active session."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="Conflict",
        )


class InvalidRefreshTokenException(HTTPException):
    """Refresh token invalid or expired."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )


class RateLimitExceededException(HTTPException):
    """Authentication rate limit exceeded."""

    def __init__(self, retry_after: int = 900):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Try again in {retry_after // 60} minutes.",
            headers={"Retry-After": str(retry_after)},
        )


class InvalidTokenException(HTTPException):
    """Access token invalid."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


class SessionExpiredException(HTTPException):
    """Session expired."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired",
        )


class InvalidTagException(HTTPException):
    """HMAC tag verification failed."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid request signature",
        )


class InvalidEntityIdException(HTTPException):
    """Invalid entity_id."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bad request",
        )


class InvalidKeySessionException(HTTPException):
    """Invalid key_session."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bad request",
        )


class InvalidMetadataException(HTTPException):
    """Invalid metadata."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bad request",
        )


class InvalidIpAddressException(HTTPException):
    """Invalid IP address."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bad request",
        )
