import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

ScanModule = Literal["rate_limit", "auth_bypass", "sqli", "idor"]


class ScanCreate(BaseModel):
    target_base_url: str = Field(..., description="Base URL of the API to scan")
    modules: list[ScanModule] = Field(default_factory=lambda: ["rate_limit", "auth_bypass", "sqli", "idor"])
    endpoints: list[str] = Field(
        default_factory=list,
        description="Specific endpoint paths to test, e.g. ['/api/users/{id}', '/api/orders']",
    )
    auth_header: str | None = Field(
        default=None, description="Optional Authorization header value to use as an authenticated session"
    )

    @field_validator("target_base_url")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")


class ScanOut(BaseModel):
    id: uuid.UUID
    target_base_url: str
    status: str
    modules: list[str]
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None

    model_config = {"from_attributes": True}


class ScanSummary(ScanOut):
    finding_count: int
    critical_count: int
    high_count: int
