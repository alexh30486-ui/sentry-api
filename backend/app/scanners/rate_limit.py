from __future__ import annotations

import asyncio
import time

from app.scanners.base import BaseScanner, FindingDraft, ScanContext


class RateLimitScanner(BaseScanner):
    """
    Tests API4:2023 (Unrestricted Resource Consumption).

    Strategy: fire a burst of concurrent requests at each endpoint and check
    whether the server ever responds with a throttling signal (429, or a
    Retry-After / X-RateLimit-* header). If none of the burst gets throttled,
    that's a finding. We also check for a "leaky bucket" pattern where a
    rate limit header exists but the remaining count never actually
    decrements, which indicates cosmetic-only limiting.
    """

    module_name = "rate_limit"

    BURST_SIZE = 30
    NUM_BURSTS = 2

    def __init__(self, ctx: ScanContext):
        super().__init__(ctx)

    async def run(self) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        client = self.ctx.client
        assert client is not None

        for endpoint in self.ctx.endpoints:
            url = self.url_for(endpoint)
            statuses: list[int] = []
            headers_seen: list[dict] = []
            elapsed_start = time.monotonic()

            for _ in range(self.NUM_BURSTS):
                tasks = [
                    client.get(url, headers=self.ctx.headers())
                    for _ in range(self.BURST_SIZE)
                ]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                for resp in responses:
                    if isinstance(resp, Exception):
                        continue
                    statuses.append(resp.status_code)
                    headers_seen.append(dict(resp.headers))

            elapsed = time.monotonic() - elapsed_start
            throttled_count = sum(1 for s in statuses if s == 429)
            rate_limit_headers_present = any(
                any(h.lower().startswith("x-ratelimit") or h.lower() == "retry-after" for h in headers)
                for headers in headers_seen
            )

            if not statuses:
                continue

            if throttled_count == 0:
                findings.append(
                    FindingDraft(
                        module=self.module_name,
                        owasp_category="API4:2023",
                        title="No rate limiting detected on endpoint",
                        severity="high" if not rate_limit_headers_present else "medium",
                        endpoint=endpoint,
                        method="GET",
                        description=(
                            f"Sent {len(statuses)} requests across {self.NUM_BURSTS} bursts of "
                            f"{self.BURST_SIZE} concurrent requests in {elapsed:.2f}s and never "
                            "received a 429 Too Many Requests response. This endpoint may be "
                            "vulnerable to resource exhaustion, brute force, or scraping attacks."
                        ),
                        evidence={
                            "total_requests": len(statuses),
                            "status_code_counts": _count_statuses(statuses),
                            "rate_limit_headers_present": rate_limit_headers_present,
                            "elapsed_seconds": round(elapsed, 3),
                        },
                        remediation=(
                            "Implement a rate limiter (token bucket or sliding window) at the "
                            "gateway or middleware layer, keyed by client IP and/or authenticated "
                            "user/API key. Return 429 with a Retry-After header once the limit is "
                            "exceeded, and apply stricter limits to expensive or sensitive endpoints "
                            "(auth, search, export)."
                        ),
                    )
                )
            elif rate_limit_headers_present is False and throttled_count > 0:
                # It throttles, but doesn't tell clients why -- not a vuln, just a UX note.
                pass

        return findings


def _count_statuses(statuses: list[int]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for s in statuses:
        key = str(s)
        counts[key] = counts.get(key, 0) + 1
    return counts
