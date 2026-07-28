import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.deps import get_current_user
from app.database import get_db, get_sessionmaker
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanners.base import HostNotAllowedError, assert_host_allowed
from app.schemas.scan import ScanCreate, ScanOut, ScanSummary
from app.services.scan_runner import run_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])

_SCAN_CREATE_EXAMPLE = {
    "target_base_url": "http://localhost:8000",
    "modules": ["rate_limit", "auth_bypass", "sqli", "idor"],
    "endpoints": ["/api/users/{id}", "/api/orders/{order_id}"],
    "auth_header": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
}

_SCAN_OUT_EXAMPLE = {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "target_base_url": "http://localhost:8000",
    "status": "pending",
    "modules": ["rate_limit", "auth_bypass", "sqli", "idor"],
    "created_at": "2026-07-28T15:04:00Z",
    "started_at": None,
    "completed_at": None,
    "error_message": None,
}


@router.post(
    "",
    response_model=ScanOut,
    status_code=status.HTTP_201_CREATED,
    summary="Start a new scan",
    responses={
        201: {"content": {"application/json": {"example": _SCAN_OUT_EXAMPLE}}},
        400: {
            "description": "Target host is not on the allow-list",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Host 'evil.example.com' is not in the allow-list. "
                        "This tool is intended to test APIs you own or are explicitly "
                        "authorized to assess. Add the host to ALLOWED_SCAN_HOSTS to proceed."
                    }
                }
            },
        },
    },
    openapi_extra={"requestBody": {"content": {"application/json": {"example": _SCAN_CREATE_EXAMPLE}}}},
)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    session_maker: async_sessionmaker[AsyncSession] = Depends(get_sessionmaker),
) -> Scan:
    """
    Queue a new scan and return immediately.

    The scan itself runs as a background task -- this call returns as soon
    as the `Scan` row is created with `status: "pending"`. Poll
    `GET /api/scans/{scan_id}` (or the findings endpoint) to watch it move
    through `running` to `completed`/`failed`.

    The `target_base_url` host must appear in the server's
    `ALLOWED_SCAN_HOSTS` setting, or this returns `400` before any request
    is ever sent to the target.
    """
    try:
        assert_host_allowed(payload.target_base_url)
    except HostNotAllowedError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    endpoints = payload.endpoints or ["/api/health"]

    scan = Scan(
        owner_id=current_user.id,
        target_base_url=payload.target_base_url,
        status=ScanStatus.PENDING,
        modules=payload.modules,
        config={"endpoints": endpoints, "auth_header": payload.auth_header},
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(run_scan, scan.id, session_maker)

    return scan


@router.get(
    "",
    response_model=list[ScanSummary],
    summary="List your scans",
)
async def list_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ScanSummary]:
    """
    List every scan you own, most recent first, each annotated with a
    finding count and critical/high severity counts so the dashboard can
    render a summary without a second round-trip per scan.
    """
    result = await db.execute(
        select(Scan).where(Scan.owner_id == current_user.id).order_by(Scan.created_at.desc())
    )
    scans = result.scalars().all()

    summaries = []
    for scan in scans:
        counts = await db.execute(
            select(Finding.severity, func.count())
            .where(Finding.scan_id == scan.id)
            .group_by(Finding.severity)
        )
        severity_counts = {sev: count for sev, count in counts.all()}
        total = sum(severity_counts.values())
        summaries.append(
            ScanSummary(
                **ScanOut.model_validate(scan).model_dump(),
                finding_count=total,
                critical_count=severity_counts.get("critical", 0),
                high_count=severity_counts.get("high", 0),
            )
        )
    return summaries


@router.get(
    "/{scan_id}",
    response_model=ScanOut,
    summary="Get scan status",
    responses={
        200: {"content": {"application/json": {"example": _SCAN_OUT_EXAMPLE}}},
        404: {
            "description": "No scan with this ID owned by you",
            "content": {"application/json": {"example": {"detail": "Scan not found"}}},
        },
    },
)
async def get_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Scan:
    """Fetch a single scan's status. Ownership is enforced: scans belonging to other users 404 rather than 403, to avoid confirming their existence."""
    scan = await db.get(Scan, scan_id)
    if scan is None or scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scan",
    responses={404: {"description": "No scan with this ID owned by you"}},
)
async def delete_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a scan and cascade-delete its findings."""
    scan = await db.get(Scan, scan_id)
    if scan is None or scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    await db.delete(scan)
    await db.commit()
