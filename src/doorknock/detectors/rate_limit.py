"""Detect rate-limiting signals in headers."""

from __future__ import annotations

from typing import List

from doorknock.detectors.base import Detector, DetectorContext
from doorknock.models import Category, Finding, Severity


_RATE_HEADERS = [
    "x-ratelimit-limit",
    "x-rate-limit-limit",
    "ratelimit-limit",
    "x-ratelimit-remaining",
    "x-rate-limit-remaining",
    "ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-reset",
    "retry-after",
]


class RateLimitDetector(Detector):
    name = "rate_limit"

    def run(self, ctx: DetectorContext) -> List[Finding]:
        findings: List[Finding] = []
        present = {h: ctx.header(h) for h in _RATE_HEADERS if ctx.header(h)}

        if present:
            evidence = ", ".join(f"{k}={v}" for k, v in present.items())
            severity = Severity.MEDIUM
            if "retry-after" in present and (ctx.status_code or 0) in (429, 503):
                severity = Severity.HIGH
            findings.append(
                Finding(
                    name="Rate limiting headers present",
                    category=Category.RATE_LIMIT,
                    severity=severity,
                    description=(
                        "The server publishes rate-limit budget headers. Polling without "
                        "respecting them will get your IP throttled or banned quickly."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Read the limit/remaining/reset headers, back off when remaining "
                        "approaches zero, and rotate IPs if you need higher throughput."
                    ),
                )
            )

        if ctx.status_code == 429:
            findings.append(
                Finding(
                    name="HTTP 429 Too Many Requests on first hit",
                    category=Category.RATE_LIMIT,
                    severity=Severity.HIGH,
                    description=(
                        "The very first request was rate-limited, suggesting aggressive "
                        "per-IP or per-UA throttling is already in place."
                    ),
                    evidence=f"status={ctx.status_code}",
                    recommendation="Use rotating proxies and lower request rate.",
                )
            )

        return findings
