from __future__ import annotations

import re
import uuid

from app.scanners.base import BaseScanner, FindingDraft, ScanContext

_ID_PLACEHOLDER = re.compile(r"\{(\w*id\w*)\}", re.IGNORECASE)

# Small, cheap probe set: sequential integers near common seed-data ranges,
# plus a random UUID in case IDs are UUID-shaped. This is a detection
# heuristic, not an exhaustive enumeration -- the goal is to surface whether
# *any* neighboring object is readable, not to enumerate the whole table.
_NUMERIC_PROBES = [1, 2, 3, 10, 100]


class IDORScanner(BaseScanner):
    """
    Tests API1:2023 (Broken Object Level Authorization).

    Strategy: for each templated endpoint (e.g. /api/orders/{order_id}),
    substitute a handful of neighboring IDs using the CALLER's own auth
    token and see whether objects that plausibly belong to a different
    user are still returned with a 200 instead of a 403/404.

    This can't know ground truth about who owns what without a paired
    "known-good" ID, so it flags endpoints where varying the ID never
    changes the authorization outcome (i.e. everything is either always
    allowed or the app never distinguishes -- both are signals worth a
    human look) and reports them as medium/high for manual triage rather
    than an auto-confirmed critical, to avoid false positives on
    intentionally public endpoints.
    """

    module_name = "idor"

    async def run(self) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        client = self.ctx.client
        assert client is not None

        for endpoint in self.ctx.endpoints:
            match = _ID_PLACEHOLDER.search(endpoint)
            if not match:
                continue  # not an object-scoped endpoint, skip

            results = []
            for probe_id in [*_NUMERIC_PROBES, str(uuid.uuid4())]:
                path = _ID_PLACEHOLDER.sub(str(probe_id), endpoint, count=1)
                url = self.url_for(path)
                try:
                    resp = await client.get(url, headers=self.ctx.headers())
                except Exception:
                    continue
                results.append((probe_id, resp.status_code, len(resp.content)))

            if not results:
                continue

            success_hits = [r for r in results if r[1] in (200, 201)]
            not_found_hits = [r for r in results if r[1] == 404]
            forbidden_hits = [r for r in results if r[1] in (401, 403)]

            # If every probed ID (including the random UUID guess) returns
            # 200 with distinct-looking bodies, objects are readable purely
            # by guessing IDs, with no ownership check in sight.
            if len(success_hits) >= 3 and not forbidden_hits:
                distinct_lengths = len({r[2] for r in success_hits})
                findings.append(
                    FindingDraft(
                        module=self.module_name,
                        owasp_category="API1:2023",
                        title="Object accessible via ID guessing without ownership check",
                        severity="high" if distinct_lengths > 1 else "medium",
                        endpoint=endpoint,
                        method="GET",
                        description=(
                            f"Substituting {len(success_hits)} different IDs into this endpoint "
                            "all returned success responses using the same caller identity, and "
                            "none were rejected with 401/403. If these objects belong to "
                            "different users, this indicates missing object-level authorization "
                            "checks (the caller can read resources by ID alone)."
                        ),
                        evidence={
                            "probed_ids": [str(r[0]) for r in success_hits],
                            "status_codes": [r[1] for r in results],
                            "distinct_response_lengths": distinct_lengths,
                        },
                        remediation=(
                            "On every object-fetching route, verify the authenticated user "
                            "actually owns or is permitted to access the requested resource "
                            "(e.g. `WHERE id = :id AND owner_id = :current_user_id`) instead of "
                            "trusting the path parameter alone. Return 404 rather than 403 for "
                            "objects the user can't access, to avoid confirming existence."
                        ),
                    )
                )
            elif success_hits and not_found_hits and not forbidden_hits:
                # Mixed 200/404 with zero 401/403 across the board is still
                # worth a human look -- it means "not found" is the only
                # gate, which some IDs might slip past.
                findings.append(
                    FindingDraft(
                        module=self.module_name,
                        owasp_category="API1:2023",
                        title="Endpoint distinguishes existence but not ownership",
                        severity="medium",
                        endpoint=endpoint,
                        method="GET",
                        description=(
                            "Some probed IDs returned success and others returned 404, but none "
                            "returned 401/403. This suggests the endpoint checks whether a "
                            "record exists but may not check whether the caller is allowed to "
                            "see it -- worth a manual check with two real accounts to confirm."
                        ),
                        evidence={"status_codes": [r[1] for r in results]},
                        remediation=(
                            "Add an explicit authorization check scoped to the current user "
                            "before returning any object, independent of whether the row exists."
                        ),
                    )
                )

        return findings
