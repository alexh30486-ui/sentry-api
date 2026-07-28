import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import case, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.database import get_db
from app.models.finding import Finding, Severity
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import FindingOut

router = APIRouter(prefix="/api/scans/{scan_id}/findings", tags=["findings"])

# Finding.severity is stored as a plain string column, so `.desc()` on it
# sorts alphabetically (medium, low, info, high, critical -- exactly
# backwards). This CASE expression maps each severity to its actual risk
# rank so "most severe first" means what it says. Uses SQLAlchemy 2.0's
# tuple-based case() syntax -- the old dict-based `whens={...}` form is
# deprecated/removed as of 2.0.
_SEVERITY_RANK = case(
    (Finding.severity == Severity.CRITICAL.value, 0),
    (Finding.severity == Severity.HIGH.value, 1),
    (Finding.severity == Severity.MEDIUM.value, 2),
    (Finding.severity == Severity.LOW.value, 3),
    (Finding.severity == Severity.INFO.value, 4),
    else_=5,
)

_FINDING_EXAMPLE = {
    "id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "module": "idor",
    "owasp_category": "API1:2023",
    "title": "Object accessible via ID guessing without ownership check",
    "severity": "high",
    "endpoint": "/api/orders/{order_id}",
    "method": "GET",
    "description": "Substituting 5 different IDs into this endpoint all returned "
    "success responses using the same caller identity, and none were rejected "
    "with 401/403.",
    "evidence": {"probed_ids": ["1", "2", "3"], "status_codes": [200, 200, 200]},
    "remediation": "Verify the authenticated user owns the requested resource "
    "before returning it, instead of trusting the path parameter alone.",
    "created_at": "2026-07-28T15:06:12Z",
}


@router.get(
    "",
    response_model=list[FindingOut],
    summary="List findings for a scan",
    responses={
        200: {"content": {"application/json": {"example": [_FINDING_EXAMPLE]}}},
        404: {
            "description": "No scan with this ID owned by you",
            "content": {"application/json": {"example": {"detail": "Scan not found"}}},
        },
    },
)
async def list_findings(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[Finding]:
    """
    List every finding for a scan, ordered by severity (critical first) then
    by discovery time. Safe to poll while a scan is still `running` --
    findings are written as each scanner module finishes, not batched at
    the end.
    """
    scan = await db.get(Scan, scan_id)
    if scan is None or scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(_SEVERITY_RANK, Finding.created_at.asc())
    )
    return list(result.scalars().all())
