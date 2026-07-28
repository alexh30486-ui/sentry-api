import httpx
import respx

from app.scanners.base import ScanContext
from app.scanners.sqli import SQLiScanner


@respx.mock
async def test_detects_error_based_injection():
    """A payload containing a quote character trips a naive query, and the
    driver's error message leaks back into the response body."""

    def responder(request: httpx.Request) -> httpx.Response:
        query = str(request.url.params.get("id", ""))
        if "'" in query:
            return httpx.Response(
                500,
                text="Warning: mysql_fetch_array(): supplied argument is not valid",
            )
        return httpx.Response(200, text="ok")

    respx.get(url__regex=r"http://target\.test/api/items.*").mock(side_effect=responder)

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/items/{id}"],
            client=http_client,
        )
        findings = await SQLiScanner(ctx).run()

    error_findings = [f for f in findings if "error" in f.title.lower()]
    assert len(error_findings) == 1
    assert error_findings[0].severity == "critical"
    assert error_findings[0].owasp_category == "API8:2023"


@respx.mock
async def test_detects_boolean_blind_injection():
    """An always-true payload should return a much longer body than an
    always-false one if the input reaches a conditional clause
    unsanitized."""

    def responder(request: httpx.Request) -> httpx.Response:
        query = str(request.url.params.get("id", ""))
        if "1=1" in query:
            return httpx.Response(200, text="row " * 200)
        if "1=2" in query:
            return httpx.Response(200, text="")
        return httpx.Response(200, text="normal-response-body")

    respx.get(url__regex=r"http://target\.test/api/items.*").mock(side_effect=responder)

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/items/{id}"],
            client=http_client,
        )
        findings = await SQLiScanner(ctx).run()

    blind_findings = [f for f in findings if "blind" in f.title.lower()]
    assert len(blind_findings) == 1
    assert blind_findings[0].severity == "high"


@respx.mock
async def test_no_findings_for_properly_parameterized_endpoint():
    """An endpoint using parameterized queries returns the same shape
    response no matter what garbage is thrown at the parameter."""
    respx.get(url__regex=r"http://target\.test/api/items.*").mock(
        return_value=httpx.Response(200, text="consistent-response")
    )

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/items/{id}"],
            client=http_client,
        )
        findings = await SQLiScanner(ctx).run()

    assert findings == []


def test_guess_query_param_extracts_placeholder_name():
    from app.scanners.sqli import _guess_query_param

    assert _guess_query_param("/api/orders/{order_id}") == "order_id"
    assert _guess_query_param("/api/health") == "id"  # sensible fallback


def test_strip_placeholder_substitutes_benign_default():
    from app.scanners.sqli import _strip_placeholder

    assert _strip_placeholder("/api/orders/{order_id}") == "/api/orders/1"
