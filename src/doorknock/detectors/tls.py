"""TLS / HTTP version observations relevant to bot detection."""

from __future__ import annotations

from typing import List

from doorknock.detectors.base import Detector, DetectorContext
from doorknock.models import Category, Finding, Severity


class TLSDetector(Detector):
    name = "tls"

    def run(self, ctx: DetectorContext) -> List[Finding]:
        findings: List[Finding] = []
        meta = ctx.request_meta or {}

        http_version = meta.get("http_version")  # e.g. "HTTP/1.1", "HTTP/2"
        if http_version == "HTTP/2":
            findings.append(
                Finding(
                    name="HTTP/2 served on edge",
                    category=Category.TLS,
                    severity=Severity.LOW,
                    description=(
                        "Edge serves HTTP/2. Some advanced anti-bot vendors fingerprint "
                        "HTTP/2 frame ordering and SETTINGS, which differs between "
                        "browsers and HTTP libraries."
                    ),
                    evidence=f"http_version={http_version}",
                    recommendation=(
                        "If blocked, consider clients that mimic browser HTTP/2 behavior "
                        "(curl-impersonate, httpx with custom HTTP/2 settings, or a real browser)."
                    ),
                )
            )

        scheme = meta.get("scheme")
        if scheme == "https":
            findings.append(
                Finding(
                    name="HTTPS enforced",
                    category=Category.TLS,
                    severity=Severity.INFO,
                    description="Site is served over TLS — JA3/JA4 TLS fingerprinting is feasible by the operator.",
                )
            )

        # If the operator is a known JA3/JA4 fingerprinter (Cloudflare/Akamai/Datadome)
        # rely on bot management/WAF detectors to flag CRITICAL — here we just note it.
        return findings
