from __future__ import annotations

import re
from urllib.parse import urlencode

from app.scanners.base import BaseScanner, FindingDraft, ScanContext

# Signatures that commonly leak in error messages when a raw SQL query breaks.
# Detection-only: these payloads are designed to trigger a distinguishable
# error or boolean difference, not to extract or modify data.
_ERROR_SIGNATURES = [
    r"sql syntax.*mysql",
    r"warning.*mysql_",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"psycopg2\.",
    r"sqlalchemy\.",
    r"sqlite3\.",
    r"pg_query\(\)",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for SQL Server",
]

_ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' AND '1'='2"]
_BOOLEAN_TRUE_PAYLOAD = "1 OR 1=1"
_BOOLEAN_FALSE_PAYLOAD = "1 AND 1=2"


class SQLiScanner(BaseScanner):
    """
    Tests API8:2023 (Security Misconfiguration) / injection flaws broadly.

    Two detection strategies, both non-destructive (SELECT-shaped payloads only):
      1. Error-based: send payloads likely to break naive string concatenation
         into a query, and look for database error signatures reflected back.
      2. Boolean-based blind: compare response status/length between a
         "always true" and "always false" injected condition on a query
         parameter. A meaningful difference suggests the input reaches a
         query unsanitized.
    """

    module_name = "sqli"

    async def run(self) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        client = self.ctx.client
        assert client is not None

        for endpoint in self.ctx.endpoints:
            param_name = _guess_query_param(endpoint)
            base_url = self.url_for(_strip_placeholder(endpoint))

            # --- Error-based ---
            for payload in _ERROR_PAYLOADS:
                url = f"{base_url}?{urlencode({param_name: payload})}"
                try:
                    resp = await client.get(url, headers=self.ctx.headers())
                except Exception:
                    continue
                body_lower = resp.text.lower()
                for pattern in _ERROR_SIGNATURES:
                    if re.search(pattern, body_lower, re.IGNORECASE):
                        findings.append(
                            FindingDraft(
                                module=self.module_name,
                                owasp_category="API8:2023",
                                title="Possible SQL injection (database error reflected)",
                                severity="critical",
                                endpoint=endpoint,
                                method="GET",
                                description=(
                                    f"Sending the payload `{payload}` in the `{param_name}` "
                                    "parameter caused a database error signature to appear in "
                                    "the response body, suggesting the input reaches a raw SQL "
                                    "query without parameterization."
                                ),
                                evidence={
                                    "payload": payload,
                                    "matched_pattern": pattern,
                                    "status_code": resp.status_code,
                                },
                                remediation=(
                                    "Use parameterized queries / SQLAlchemy's bound parameters "
                                    "(never f-string or `%`-format user input into SQL). Also "
                                    "disable verbose error pages in production so stack traces and "
                                    "driver errors are never returned to clients."
                                ),
                            )
                        )
                        break
                else:
                    continue
                break  # one error finding per endpoint is enough signal

            # --- Boolean-based blind ---
            true_url = f"{base_url}?{urlencode({param_name: _BOOLEAN_TRUE_PAYLOAD})}"
            false_url = f"{base_url}?{urlencode({param_name: _BOOLEAN_FALSE_PAYLOAD})}"
            try:
                resp_true = await client.get(true_url, headers=self.ctx.headers())
                resp_false = await client.get(false_url, headers=self.ctx.headers())
            except Exception:
                continue

            length_delta = abs(len(resp_true.text) - len(resp_false.text))
            status_differs = resp_true.status_code != resp_false.status_code
            significant_length_diff = length_delta > 50

            if status_differs or significant_length_diff:
                findings.append(
                    FindingDraft(
                        module=self.module_name,
                        owasp_category="API8:2023",
                        title="Possible boolean-based blind SQL injection",
                        severity="high",
                        endpoint=endpoint,
                        method="GET",
                        description=(
                            f"An always-true condition (`{_BOOLEAN_TRUE_PAYLOAD}`) and an "
                            f"always-false condition (`{_BOOLEAN_FALSE_PAYLOAD}`) injected into "
                            f"`{param_name}` produced different response status codes or "
                            "substantially different body lengths, which is consistent with "
                            "unsanitized input reaching a conditional SQL clause."
                        ),
                        evidence={
                            "true_status": resp_true.status_code,
                            "false_status": resp_false.status_code,
                            "response_length_delta": length_delta,
                        },
                        remediation=(
                            "Use an ORM's parameterized query builder for all user-influenced "
                            "filters, and add input validation (type/format checks via Pydantic) "
                            "before values ever reach a query."
                        ),
                    )
                )

        return findings


def _guess_query_param(endpoint: str) -> str:
    match = re.search(r"\{(\w+)\}", endpoint)
    return match.group(1) if match else "id"


def _strip_placeholder(endpoint: str) -> str:
    # /api/users/{id} -> /api/users/1 (a benign numeric default before we
    # append our own query-string payload)
    return re.sub(r"\{\w+\}", "1", endpoint)
