"""Generic security/header analysis."""

from __future__ import annotations

from typing import List

from doorknock.detectors.base import Detector, DetectorContext
from doorknock.models import Category, Finding, Severity


_NOTABLE_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "permissions-policy",
    "referrer-policy",
]


class HeadersDetector(Detector):
    name = "headers"

    def run(self, ctx: DetectorContext) -> List[Finding]:
        findings: List[Finding] = []

        # Vary: User-Agent / Accept-Encoding -> server differentiates by UA
        vary = ctx.header("vary").lower()
        if "user-agent" in vary:
            findings.append(
                Finding(
                    name="Vary: User-Agent",
                    category=Category.HEADERS,
                    severity=Severity.LOW,
                    description=(
                        "The server returns different responses depending on User-Agent, "
                        "which often indicates UA-based filtering or content gating."
                    ),
                    evidence=f"Vary: {ctx.header('vary')}",
                    recommendation="Use a realistic browser User-Agent.",
                )
            )

        # Server-Timing: cf-cache-status hidden info
        if ctx.header("server-timing"):
            findings.append(
                Finding(
                    name="Server-Timing instrumentation",
                    category=Category.HEADERS,
                    severity=Severity.INFO,
                    description="Server exposes timing telemetry — unrelated to bots but useful intel.",
                    evidence=ctx.header("server-timing")[:200],
                )
            )

        # Strict header set hints at a serious operator
        present_security = [h for h in _NOTABLE_SECURITY_HEADERS if ctx.header(h)]
        if len(present_security) >= 4:
            findings.append(
                Finding(
                    name="Mature security headers",
                    category=Category.HEADERS,
                    severity=Severity.LOW,
                    description=(
                        "The site sets a thorough set of modern security headers, "
                        "which correlates with operators who also invest in anti-bot."
                    ),
                    evidence="present: " + ", ".join(present_security),
                )
            )

        # X-Robots-Tag: noindex on the homepage suggests content not meant to be crawled
        xrt = ctx.header("x-robots-tag").lower()
        if "noindex" in xrt or "nofollow" in xrt:
            findings.append(
                Finding(
                    name="X-Robots-Tag discourages crawling",
                    category=Category.HEADERS,
                    severity=Severity.LOW,
                    description="Server sets noindex/nofollow via header.",
                    evidence=f"X-Robots-Tag: {ctx.header('x-robots-tag')}",
                )
            )

        return findings
