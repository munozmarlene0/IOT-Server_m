from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    APP_NAME: str = "IoT Backend"
    DEBUG: bool = False

    SECRET_KEY: str = "change-me-in-env"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Session/Valkey Configuration
    VALKEY_URL: str = "redis://localhost:6379/0"
    ENCRYPTION_KEY: str = "change-me-32-byte-base64-key-here"  # Base64 encoded 32-byte key

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()