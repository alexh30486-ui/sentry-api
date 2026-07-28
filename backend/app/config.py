from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "API Security Scanner"
    environment: str = "development"

    database_url: str = (
        "postgresql+asyncpg://scanner:scanner@db:5432/scanner_db"
    )
    sync_database_url: str = (
        "postgresql+psycopg2://scanner:scanner@db:5432/scanner_db"
    )

    jwt_secret_key: str = "change-me-in-production-please"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24

    cors_origins: list[str] = ["http://localhost:8080", "http://localhost:5173"]

    # Safety guardrails: scans should only ever target hosts the operator
    # has explicitly allow-listed, to prevent this tool being pointed at
    # third-party infrastructure without authorization.
    allowed_scan_hosts: list[str] = ["localhost", "127.0.0.1", "host.docker.internal"]
    enforce_host_allowlist: bool = True

    max_concurrent_requests_per_scan: int = 10
    scan_request_timeout_seconds: int = 10


@lru_cache
def get_settings() -> Settings:
    return Settings()
