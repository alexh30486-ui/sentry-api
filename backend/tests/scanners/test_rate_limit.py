import httpx
import respx

from app.scanners.base import ScanContext
from app.scanners.rate_limit import RateLimitScanner


@respx.mock
async def test_flags_endpoint_with_no_throttling():
    """An endpoint that returns 200 to every request, no matter how many
    hit it in a burst, should be flagged -- that's the whole point of the
    module."""
    respx.get("http://target.test/api/widgets").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/widgets"],
            client=http_client,
        )
        findings = await RateLimitScanner(ctx).run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.owasp_category == "API4:2023"
    assert finding.severity == "high"
    assert finding.endpoint == "/api/widgets"
    assert finding.evidence["total_requests"] == RateLimitScanner.BURST_SIZE * RateLimitScanner.NUM_BURSTS


@respx.mock
async def test_severity_downgraded_to_medium_when_headers_present_but_never_429():
    """If the app advertises rate-limit headers but never actually returns
    429, that's still a bug (a 'leaky bucket'), but less severe than an
    endpoint with zero rate-limiting awareness at all."""
    respx.get("http://target.test/api/widgets").mock(
        return_value=httpx.Response(
            200,
            json={"ok": True},
            headers={"X-RateLimit-Remaining": "999"},
        )
    )

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/widgets"],
            client=http_client,
        )
        findings = await RateLimitScanner(ctx).run()

    assert len(findings) == 1
    assert findings[0].severity == "medium"


@respx.mock
async def test_no_finding_when_endpoint_actually_throttles():
    """Once the target starts returning 429s partway through the burst, we
    should not flag it."""
    call_count = {"n": 0}

    def responder(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        if call_count["n"] % 3 == 0:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return httpx.Response(200, json={"ok": True})

    respx.get("http://target.test/api/widgets").mock(side_effect=responder)

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/widgets"],
            client=http_client,
        )
        findings = await RateLimitScanner(ctx).run()

    assert findings == []


@respx.mock
async def test_no_crash_on_transport_errors():
    """If individual requests in the burst error out (connection reset,
    etc.), the scanner should tolerate that rather than crashing the whole
    scan."""
    respx.get("http://target.test/api/flaky").mock(side_effect=httpx.ConnectError("boom"))

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/flaky"],
            client=http_client,
        )
        findings = await RateLimitScanner(ctx).run()

    # Every request failed, so there's no status-code evidence to reason
    # about -- the module should skip this endpoint rather than raising.
    assert findings == []
