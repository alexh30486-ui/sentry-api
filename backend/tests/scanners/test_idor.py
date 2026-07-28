import httpx
import respx

from app.scanners.base import ScanContext
from app.scanners.idor import IDORScanner


@respx.mock
async def test_flags_high_severity_when_every_id_returns_distinct_success():
    """Every probed ID returns 200 with a distinct body and nothing is ever
    rejected -- objects are readable by guessing IDs alone."""

    def responder(request: httpx.Request) -> httpx.Response:
        # Response body reflects the path, so different IDs naturally
        # produce different content lengths.
        return httpx.Response(200, content=str(request.url.path).encode())

    respx.get(url__regex=r"http://target\.test/api/orders/.*").mock(side_effect=responder)

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/orders/{order_id}"],
            client=http_client,
        )
        findings = await IDORScanner(ctx).run()

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].owasp_category == "API1:2023"


@respx.mock
async def test_medium_severity_when_bodies_are_identical():
    """All IDs return 200, but with an identical body -- still worth a
    look, but less alarming than distinct per-ID content, so this stays at
    medium rather than high."""
    respx.get(url__regex=r"http://target\.test/api/orders/.*").mock(
        return_value=httpx.Response(200, content=b"same-body-every-time")
    )

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/orders/{order_id}"],
            client=http_client,
        )
        findings = await IDORScanner(ctx).run()

    assert len(findings) == 1
    assert findings[0].severity == "medium"


@respx.mock
async def test_flags_mixed_200_404_with_no_ownership_gate():
    """Some IDs 404, some succeed, but nothing ever comes back 401/403 --
    existence is checked, ownership is not."""

    def responder(request: httpx.Request) -> httpx.Response:
        obj_id = request.url.path.rsplit("/", 1)[-1]
        if obj_id in ("1", "2"):
            return httpx.Response(200, content=b"found")
        return httpx.Response(404)

    respx.get(url__regex=r"http://target\.test/api/orders/.*").mock(side_effect=responder)

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/orders/{order_id}"],
            client=http_client,
        )
        findings = await IDORScanner(ctx).run()

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "ownership" in findings[0].title.lower()


@respx.mock
async def test_no_finding_when_endpoint_properly_rejects_other_users_objects():
    """A correctly-implemented endpoint returns 401/403 for objects the
    caller doesn't own -- the scanner should stay quiet."""
    respx.get(url__regex=r"http://target\.test/api/orders/.*").mock(
        return_value=httpx.Response(403)
    )

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/orders/{order_id}"],
            client=http_client,
        )
        findings = await IDORScanner(ctx).run()

    assert findings == []


async def test_skips_endpoints_without_an_id_placeholder():
    """Endpoints with no {id}-shaped placeholder aren't object-scoped, so
    the module should skip them without making any requests."""
    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/health"],
            client=http_client,
        )
        findings = await IDORScanner(ctx).run()

    assert findings == []
