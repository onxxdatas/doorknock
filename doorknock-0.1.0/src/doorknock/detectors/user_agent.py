"""Compare default-UA vs browser-UA responses to detect UA filtering."""

from __future__ import annotations

from typing import List

from doorknock.detectors.base import Detector, DetectorContext
from doorknock.models import Category, Finding, Severity


class UserAgentDetector(Detector):
    name = "user_agent"

    def run(self, ctx: DetectorContext) -> List[Finding]:
        findings: List[Finding] = []

        meta = ctx.request_meta or {}
        nobody_status = meta.get("nobody_status")
        nobody_len = meta.get("nobody_body_len")
        main_len = meta.get("main_body_len")
        main_status = ctx.status_code

        if nobody_status is None:
            return findings

        # Hostile when there's no UA but fine with a browser UA
        if (
            isinstance(main_status, int)
            and isinstance(nobody_status, int)
            and main_status < 400
            and nobody_status >= 400
        ):
            findings.append(
                Finding(
                    name="User-Agent filtering",
                    category=Category.USER_AGENT,
                    severity=Severity.HIGH,
                    description=(
                        "The site returned an error when no User-Agent was sent but "
                        "served content with a browser User-Agent — a strong signal "
                        "that requests without a realistic UA are blocked."
                    ),
                    evidence=f"with browser UA: {main_status}, no UA: {nobody_status}",
                    recommendation=(
                        "Always send a recent, realistic browser User-Agent and full "
                        "Accept/Accept-Language/Sec-* headers."
                    ),
                )
            )
        elif (
            isinstance(main_status, int)
            and isinstance(nobody_status, int)
            and main_status < 400
            and nobody_status < 400
            and isinstance(main_len, int)
            and isinstance(nobody_len, int)
            and main_len > 0
            and abs(main_len - nobody_len) / max(main_len, 1) > 0.4
        ):
            findings.append(
                Finding(
                    name="Different content based on User-Agent",
                    category=Category.USER_AGENT,
                    severity=Severity.LOW,
                    description=(
                        "The body length changed significantly between a browser UA and "
                        "an empty UA, indicating UA-based content variation."
                    ),
                    evidence=f"browser_len={main_len}, no_ua_len={nobody_len}",
                )
            )

        return findings
