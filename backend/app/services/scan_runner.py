from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.scanners import SCANNER_REGISTRY, ScanContext, assert_host_allowed

logger = logging.getLogger(__name__)
settings = get_settings()


async def run_scan(
    scan_id: uuid.UUID,
    session_maker: async_sessionmaker[AsyncSession] | None = None,
) -> None:
    """
    Entry point for a background task. Opens its own DB session since it
    runs outside the request/response lifecycle where the request-scoped
    session would already be closed.

    `session_maker` is injected by the caller (see `routers/scans.py`,
    which resolves it via the `get_sessionmaker` FastAPI dependency) rather
    than imported directly, so tests that override `get_db` also cover the
    background task instead of it silently falling through to the real
    production database.
    """
    session_maker = session_maker or AsyncSessionLocal

    async with session_maker() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            logger.warning("run_scan called with unknown scan_id=%s", scan_id)
            return

        try:
            assert_host_allowed(scan.target_base_url)
        except Exception as exc:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()

        endpoints = scan.config.get("endpoints", [])
        auth_header = scan.config.get("auth_header")

        try:
            async with httpx.AsyncClient(
                timeout=settings.scan_request_timeout_seconds,
                follow_redirects=True,
            ) as http_client:
                ctx = ScanContext(
                    target_base_url=scan.target_base_url,
                    endpoints=endpoints,
                    auth_header=auth_header,
                    client=http_client,
                )

                for module_name in scan.modules:
                    scanner_cls = SCANNER_REGISTRY.get(module_name)
                    if scanner_cls is None:
                        logger.warning("Unknown scanner module requested: %s", module_name)
                        continue

                    scanner = scanner_cls(ctx)
                    try:
                        drafts = await scanner.run()
                    except Exception:
                        logger.exception("Scanner module %s raised an exception", module_name)
                        continue

                    for draft in drafts:
                        db.add(
                            Finding(
                                scan_id=scan.id,
                                module=draft.module,
                                owasp_category=draft.owasp_category,
                                title=draft.title,
                                severity=draft.severity,
                                endpoint=draft.endpoint,
                                method=draft.method,
                                description=draft.description,
                                evidence=draft.evidence,
                                remediation=draft.remediation,
                            )
                        )
                    await db.commit()

            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()

        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:2000]
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
