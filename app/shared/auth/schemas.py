import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


PASSWORD_COMPLEXITY_RE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9])\S{8,128}$"
)

AuthMethod = Literal["auth_rc", "auth_xmss"]
HumanEntityType = Literal["administrator", "manager", "user"]
EntityType = Literal["administrator", "manager", "user", "device", "application"]


class MessageResponse(BaseModel):
    message: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    account_type: EntityType
    auth_method: AuthMethod
    is_master: bool = False


class HumanLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    entity_type: HumanEntityType
    email: str = Field(min_length=6, max_length=254)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        email = value.strip().lower()
        if "@" not in email or email.startswith("@") or email.endswith("@"):
            raise ValueError("invalid email")
        return email


class HumanScopedLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email: str = Field(min_length=6, max_length=254)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        email = value.strip().lower()
        if "@" not in email or email.startswith("@") or email.endswith("@"):
            raise ValueError("invalid email")
        return email


class EncryptedPayload(BaseModel):
    ciphertext: str
    iv: str


class EntityPuzzleLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    identifier: str = Field(min_length=1)
    encrypted_payload: EncryptedPayload


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    current_password: str = Field(min_length=8, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        password = value.strip()

        if not PASSWORD_COMPLEXITY_RE.fullmatch(password):
            raise ValueError(
                "password must include uppercase, lowercase, number and special character"
            )

        return password


class XMSSChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    entity_type: EntityType
    identifier: str = Field(min_length=1)
    tree_height: int = Field(default=4, ge=2, le=16)


class HumanXMSSChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    identifier: str = Field(min_length=1)
    tree_height: int = Field(default=4, ge=2, le=16)

    @field_validator("identifier")
    @classmethod
    def normalize_identifier(cls, value: str) -> str:
        identifier = value.strip().lower()
        if "@" not in identifier or identifier.startswith("@") or identifier.endswith("@"):
            raise ValueError("invalid email")
        return identifier


class AuthPathNode(BaseModel):
    position: Literal["left", "right"]
    value: str


class XMSSChallengeResponse(BaseModel):
    auth_method: Literal["auth_xmss"] = "auth_xmss"
    entity_type: EntityType
    identifier: str
    challenge: str
    leaf_index: int
    expires_at: int
    public_root: str
    canonical_message: dict[str, Any]
    client_material_compact: dict[str, Any] | None = None


class XMSSVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    entity_type: EntityType
    identifier: str
    challenge: str
    leaf_index: int
    message: dict[str, Any]
    signature: dict[str, Any] = Field(default_factory=dict)
    ots_public_key: str | None = None
    auth_path: list[AuthPathNode]


class HumanXMSSVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    identifier: str
    challenge: str
    leaf_index: int
    message: dict[str, Any]
    signature: dict[str, Any] = Field(default_factory=dict)
    ots_public_key: str | None = None
    auth_path: list[AuthPathNode]

    @field_validator("identifier")
    @classmethod
    def normalize_identifier(cls, value: str) -> str:
        identifier = value.strip().lower()
        if "@" not in identifier or identifier.startswith("@") or identifier.endswith("@"):
            raise ValueError("invalid email")
        return identifier