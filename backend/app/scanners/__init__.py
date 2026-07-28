from app.scanners.auth_bypass import AuthBypassScanner
from app.scanners.base import BaseScanner, FindingDraft, HostNotAllowedError, ScanContext, assert_host_allowed
from app.scanners.idor import IDORScanner
from app.scanners.rate_limit import RateLimitScanner
from app.scanners.sqli import SQLiScanner

SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {
    "rate_limit": RateLimitScanner,
    "auth_bypass": AuthBypassScanner,
    "sqli": SQLiScanner,
    "idor": IDORScanner,
}

__all__ = [
    "SCANNER_REGISTRY",
    "BaseScanner",
    "FindingDraft",
    "ScanContext",
    "HostNotAllowedError",
    "assert_host_allowed",
]
