import base64
import json

import httpx
import respx

from app.scanners.auth_bypass import AuthBypassScanner
from app.scanners.base import ScanContext


def _b64url(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


@respx.mock
async def test_flags_endpoint_open_with_no_auth_header_at_all():
    """The worst case: the endpoint returns success with zero Authorization
    header. Should short-circuit the other checks for this endpoint since
    it's already the most severe possible finding."""
    respx.get("http://target.test/api/secret").mock(return_value=httpx.Response(200))

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(target_base_url="http://target.test", endpoints=["/api/secret"], client=http_client)
        findings = await AuthBypassScanner(ctx).run()

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "without authentication" in findings[0].title


@respx.mock
async def test_flags_malformed_token_acceptance():
    """No auth at all should be rejected (401), but a syntactically bogus
    bearer token slipping through means validation isn't actually
    happening."""
    call_log = []

    def responder(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        call_log.append(auth)
        if auth == "":
            return httpx.Response(401)
        if auth == "Bearer not.a.real.token":
            return httpx.Response(200)
        return httpx.Response(401)

    respx.get("http://target.test/api/secret").mock(side_effect=responder)
    respx.route(method="DELETE", url="http://target.test/api/secret").mock(return_value=httpx.Response(401))
    respx.route(method="PUT", url="http://target.test/api/secret").mock(return_value=httpx.Response(401))
    respx.route(method="PATCH", url="http://target.test/api/secret").mock(return_value=httpx.Response(401))

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(target_base_url="http://target.test", endpoints=["/api/secret"], client=http_client)
        findings = await AuthBypassScanner(ctx).run()

    titles = [f.title for f in findings]
    assert any("malformed bearer token" in t for t in titles)


@respx.mock
async def test_flags_jwt_alg_none_forgery():
    """A real (well-formed) JWT is supplied via ctx.auth_header. The scanner
    should try re-signing it with alg=none and flag the endpoint if that
    forged token is accepted."""
    real_payload = _b64url({"sub": "user-123"})
    real_header = _b64url({"alg": "HS256", "typ": "JWT"})
    real_token = f"Bearer {real_header}.{real_payload}.fakesignature"

    forged_prefix = f"Bearer {_b64url({'alg': 'none', 'typ': 'JWT'})}.{real_payload}."

    def responder(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        if auth == forged_prefix:
            return httpx.Response(200)
        return httpx.Response(401)

    respx.get("http://target.test/api/secret").mock(side_effect=responder)
    respx.route(method="DELETE", url="http://target.test/api/secret").mock(return_value=httpx.Response(401))
    respx.route(method="PUT", url="http://target.test/api/secret").mock(return_value=httpx.Response(401))
    respx.route(method="PATCH", url="http://target.test/api/secret").mock(return_value=httpx.Response(401))

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            target_base_url="http://target.test",
            endpoints=["/api/secret"],
            auth_header=real_token,
            client=http_client,
        )
        findings = await AuthBypassScanner(ctx).run()

    assert any("alg: none" in f.title.lower() or "alg" in f.title.lower() for f in findings)
    assert any(f.severity == "critical" for f in findings)


@respx.mock
async def test_flags_verb_tampering():
    """GET requires auth, but DELETE on the same path doesn't -- middleware
    was clearly only wired up for some HTTP verbs."""

    def get_responder(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)  # GET is properly protected

    respx.get("http://target.test/api/secret").mock(side_effect=get_responder)
    respx.route(method="DELETE", url="http://target.test/api/secret").mock(return_value=httpx.Response(204))
    respx.route(method="PUT", url="http://target.test/api/secret").mock(return_value=httpx.Response(401))
    respx.route(method="PATCH", url="http://target.test/api/secret").mock(return_value=httpx.Response(401))

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(target_base_url="http://target.test", endpoints=["/api/secret"], client=http_client)
        findings = await AuthBypassScanner(ctx).run()

    assert any(f.method == "DELETE" and f.severity == "high" for f in findings)


@respx.mock
async def test_no_findings_for_properly_secured_endpoint():
    """Sanity check: an endpoint that rejects everything should produce no
    findings at all."""
    respx.get("http://target.test/api/secret").mock(return_value=httpx.Response(401))
    respx.route(method="DELETE", url="http://target.test/api/secret").mock(return_value=httpx.Response(401))
    respx.route(method="PUT", url="http://target.test/api/secret").mock(return_value=httpx.Response(401))
    respx.route(method="PATCH", url="http://target.test/api/secret").mock(return_value=httpx.Response(401))

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(target_base_url="http://target.test", endpoints=["/api/secret"], client=http_client)
        findings = await AuthBypassScanner(ctx).run()

    assert findings == []
