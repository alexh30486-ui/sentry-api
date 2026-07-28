import uuid

from sqlalchemy.ext.asyncio import async_sessionmaker

from app.models.finding import Finding, Severity
from app.models.scan import Scan, ScanStatus
from tests.conftest import register_and_login


async def test_findings_are_returned_in_severity_rank_order_not_alphabetical(client, test_engine):
    """
    Regression test for a real bug found during review: `Finding.severity`
    is a plain string column, so ordering by `.desc()` sorted it
    alphabetically -- `medium, low, info, high, critical` -- which is
    exactly backwards from "most severe first". Seed one finding per
    severity level in a scrambled insertion order and confirm the API
    actually returns them ranked critical -> info.
    """
    token = await register_and_login(client, "ordering-user@example.com")
    me = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    user_id = uuid.UUID(me.json()["id"])

    session_maker = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_maker() as db:
        scan = Scan(
            owner_id=user_id,
            target_base_url="http://localhost:9",
            status=ScanStatus.COMPLETED,
            modules=["idor"],
            config={},
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        # Deliberately scrambled insertion order -- a correct query has to
        # actually re-sort these, not just return them as inserted.
        for severity in [
            Severity.LOW,
            Severity.CRITICAL,
            Severity.INFO,
            Severity.HIGH,
            Severity.MEDIUM,
        ]:
            db.add(
                Finding(
                    scan_id=scan.id,
                    module="idor",
                    owasp_category="API1:2023",
                    title=f"{severity.value} finding",
                    severity=severity,
                    endpoint="/api/x",
                    method="GET",
                    description="test",
                    evidence={},
                    remediation="test",
                )
            )
        await db.commit()
        scan_id = str(scan.id)

    resp = await client.get(
        f"/api/scans/{scan_id}/findings", headers={"Authorization": f"Bearer {token}"}
    )
    severities = [f["severity"] for f in resp.json()]
    assert severities == ["critical", "high", "medium", "low", "info"]
