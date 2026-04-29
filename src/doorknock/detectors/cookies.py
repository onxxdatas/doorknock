"""Detect cookie-based session/clearance requirements."""

from __future__ import annotations

import re
from typing import List

from doorknock.detectors.base import Detector, DetectorContext
from doorknock.models import Category, Finding, Severity


class CookiesDetector(Detector):
    name = "cookies"

    def run(self, ctx: DetectorContext) -> List[Finding]:
        findings: List[Finding] = []

        if not ctx.cookies:
            return findings

        flags = []
        for raw in ctx.raw_set_cookie:
            lower = raw.lower()
            if "samesite=strict" in lower:
                flags.append("SameSite=Strict")
            if "httponly" in lower and "secure" in lower:
                flags.append("HttpOnly+Secure")

        # Many cookies set on initial GET often indicates session enforcement
        if len(ctx.cookies) >= 4:
            findings.append(
                Finding(
                    name="Many cookies set on initial response",
                    category=Category.COOKIES,
                    severity=Severity.LOW,
                    description=(
                        f"The server sets {len(ctx.cookies)} cookies on the first request, "
                        "suggesting session/state must be carried for subsequent calls."
                    ),
                    evidence="cookies: " + ", ".join(list(ctx.cookies.keys())[:10]),
                    recommendation=(
                        "Use a session (requests.Session) so cookies are persisted across "
                        "requests. Without it you may be challenged or rate-limited."
                    ),
                )
            )

        # __Host- / __Secure- prefixed cookies — strict security
        strict_named = [c for c in ctx.cookies if c.startswith("__Host-") or c.startswith("__Secure-")]
        if strict_named:
            findings.append(
                Finding(
                    name="Strict cookie naming (__Host- / __Secure-)",
                    category=Category.COOKIES,
                    severity=Severity.INFO,
                    description="Site uses prefixed cookies that bind to host and HTTPS.",
                    evidence=", ".join(strict_named[:6]),
                )
            )

        # CSRF token in cookie — requests usually need to echo it in a header
        csrfish = [
            c for c in ctx.cookies
            if re.search(r"csrf|xsrf|antiforgery", c, re.I)
        ]
        if csrfish:
            findings.append(
                Finding(
                    name="CSRF token cookie present",
                    category=Category.COOKIES,
                    severity=Severity.MEDIUM,
                    description=(
                        "The site uses a CSRF/XSRF token cookie. Mutating endpoints will "
                        "reject requests that don't echo this token in a header."
                    ),
                    evidence=", ".join(csrfish[:6]),
                    recommendation=(
                        "On POST/PUT/DELETE, read the cookie and include it in the "
                        "matching header (commonly X-CSRF-Token / X-XSRF-TOKEN)."
                    ),
                )
            )

        return findings
