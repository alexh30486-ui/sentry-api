from __future__ import annotations

import base64
import json

from app.scanners.base import BaseScanner, FindingDraft, ScanContext


class AuthBypassScanner(BaseScanner):
    """
    Tests API2:2023 (Broken Authentication).

    Checks, per endpoint assumed to require auth:
      1. Does it respond successfully with NO Authorization header at all?
      2. Does it respond successfully with a syntactically-malformed token?
      3. If the token looks like a JWT, does the server accept a token whose
         header has been swapped to `{"alg": "none"}` with the signature
         stripped? (the classic "alg confusion" bypass)
      4. Does an alternate HTTP verb (e.g. the app protects GET but not
         DELETE/PUT on the same path) slip through unauthenticated?
    """

    module_name = "auth_bypass"

    SUCCESS_CODES = {200, 201, 202, 204}

    async def run(self) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        client = self.ctx.client
        assert client is not None

        for endpoint in self.ctx.endpoints:
            url = self.url_for(endpoint)

            # 1. No auth header at all
            resp_no_auth = await client.get(url, headers={"User-Agent": "api-security-scanner/1.0"})
            if resp_no_auth.status_code in self.SUCCESS_CODES:
                findings.append(
                    FindingDraft(
                        module=self.module_name,
                        owasp_category="API2:2023",
                        title="Endpoint accessible without authentication",
                        severity="critical",
                        endpoint=endpoint,
                        method="GET",
                        description=(
                            "The endpoint returned a success status code with no Authorization "
                            "header supplied at all, suggesting it is unintentionally unauthenticated."
                        ),
                        evidence={"status_code": resp_no_auth.status_code},
                        remediation=(
                            "Add an authentication dependency (e.g. FastAPI `Depends`) that "
                            "validates a session or bearer token before the route handler runs, "
                            "and ensure it's applied at the router level, not per-endpoint, so new "
                            "routes can't accidentally ship unauthenticated."
                        ),
                    )
                )
                continue  # no auth is the worst finding for this endpoint; skip other checks

            # 2. Malformed token
            resp_malformed = await client.get(
                url, headers={"Authorization": "Bearer not.a.real.token"}
            )
            if resp_malformed.status_code in self.SUCCESS_CODES:
                findings.append(
                    FindingDraft(
                        module=self.module_name,
                        owasp_category="API2:2023",
                        title="Endpoint accepts malformed bearer token",
                        severity="critical",
                        endpoint=endpoint,
                        method="GET",
                        description=(
                            "Sending a syntactically invalid token still returned a success "
                            "status, meaning token validation is likely not being enforced."
                        ),
                        evidence={"status_code": resp_malformed.status_code},
                        remediation=(
                            "Verify the token's signature and expiry server-side on every request "
                            "and return 401 for anything that fails decoding or verification."
                        ),
                    )
                )

            # 3. alg:none JWT confusion, only if we have a real-looking token to mutate
            if self.ctx.auth_header and self.ctx.auth_header.count(".") >= 2:
                forged = _build_alg_none_token(self.ctx.auth_header)
                if forged:
                    resp_forged = await client.get(url, headers={"Authorization": forged})
                    if resp_forged.status_code in self.SUCCESS_CODES:
                        findings.append(
                            FindingDraft(
                                module=self.module_name,
                                owasp_category="API2:2023",
                                title="JWT 'alg: none' signature bypass accepted",
                                severity="critical",
                                endpoint=endpoint,
                                method="GET",
                                description=(
                                    "The server accepted a JWT whose header algorithm was changed "
                                    "to 'none' and whose signature was stripped, meaning the "
                                    "signature is not being verified server-side."
                                ),
                                evidence={"status_code": resp_forged.status_code},
                                remediation=(
                                    "Explicitly pin the accepted signing algorithm(s) when decoding "
                                    "(e.g. `jwt.decode(token, key, algorithms=['HS256'])`) and reject "
                                    "any token whose header algorithm doesn't match. Never trust the "
                                    "algorithm advertised in the token itself."
                                ),
                            )
                        )

            # 4. Verb tampering: try DELETE/PUT/PATCH with no auth
            for method in ("DELETE", "PUT", "PATCH"):
                try:
                    resp_verb = await client.request(
                        method, url, headers={"User-Agent": "api-security-scanner/1.0"}
                    )
                except Exception:
                    continue
                if resp_verb.status_code in self.SUCCESS_CODES:
                    findings.append(
                        FindingDraft(
                            module=self.module_name,
                            owasp_category="API2:2023",
                            title=f"{method} on protected path accessible without authentication",
                            severity="high",
                            endpoint=endpoint,
                            method=method,
                            description=(
                                f"While GET on this path requires auth, {method} on the same path "
                                "returned a success status without any Authorization header, "
                                "suggesting auth middleware is only wired up for some verbs."
                            ),
                            evidence={"status_code": resp_verb.status_code},
                            remediation=(
                                "Apply authentication middleware/dependencies at the router or path "
                                "level so it covers every HTTP method, rather than per-handler."
                            ),
                        )
                    )

        return findings


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _build_alg_none_token(auth_header: str) -> str | None:
    """Given an existing 'Bearer <jwt>' header, produce a forged token with alg=none."""
    token = auth_header.removeprefix("Bearer ").strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded_payload = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded_payload))
    except Exception:
        return None

    forged_header = {"alg": "none", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(forged_header).encode())
    payload_b64 = _b64url_encode(json.dumps(payload).encode())
    # alg=none tokens carry an empty signature segment
    return f"Bearer {header_b64}.{payload_b64}."
