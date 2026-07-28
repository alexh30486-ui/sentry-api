from __future__ import annotations

import abc
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from app.config import get_settings

settings = get_settings()


@dataclass
class ScanContext:
    """Shared state passed to every scanner module for a single scan run."""

    target_base_url: str
    endpoints: list[str]
    auth_header: str | None = None
    client: httpx.AsyncClient | None = None

    def headers(self) -> dict[str, str]:
        headers = {"User-Agent": "api-security-scanner/1.0"}
        if self.auth_header:
            headers["Authorization"] = self.auth_header
        return headers


@dataclass
class FindingDraft:
    module: str
    owasp_category: str
    title: str
    severity: str
    endpoint: str
    method: str
    description: str
    remediation: str
    evidence: dict = field(default_factory=dict)


class HostNotAllowedError(Exception):
    """Raised when a scan target isn't on the configured allow-list."""


def assert_host_allowed(base_url: str) -> None:
    if not settings.enforce_host_allowlist:
        return
    hostname = urlparse(base_url).hostname or ""
    if hostname not in settings.allowed_scan_hosts:
        raise HostNotAllowedError(
            f"Host '{hostname}' is not in the allow-list. This tool is intended to test "
            f"APIs you own or are explicitly authorized to assess. Add the host to "
            f"ALLOWED_SCAN_HOSTS to proceed."
        )


class BaseScanner(abc.ABC):
    """Every scanner module implements `run` and returns a list of FindingDraft."""

    module_name: str = "base"

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx

    @abc.abstractmethod
    async def run(self) -> list[FindingDraft]:
        raise NotImplementedError

    def url_for(self, endpoint: str) -> str:
        return f"{self.ctx.target_base_url}{endpoint}"
