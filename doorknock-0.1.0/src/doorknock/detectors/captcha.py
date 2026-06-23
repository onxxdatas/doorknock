"""Detect CAPTCHA challenges embedded in the page."""

from __future__ import annotations

import re
from typing import List, Tuple

from doorknock.detectors.base import Detector, DetectorContext
from doorknock.models import Category, Finding, Severity


_BODY_SIGNATURES: List[Tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"google\.com/recaptcha|grecaptcha", re.I), "Google reCAPTCHA", Severity.HIGH),
    (re.compile(r"recaptcha/api\.js", re.I), "Google reCAPTCHA", Severity.HIGH),
    (re.compile(r"recaptcha/enterprise", re.I), "Google reCAPTCHA Enterprise", Severity.CRITICAL),
    (re.compile(r"hcaptcha\.com|h-captcha", re.I), "hCaptcha", Severity.HIGH),
    (re.compile(r"challenges\.cloudflare\.com|cf-turnstile|turnstile", re.I),
     "Cloudflare Turnstile", Severity.HIGH),
    (re.compile(r"funcaptcha|arkoselabs\.com", re.I), "Arkose Labs FunCaptcha", Severity.CRITICAL),
    (re.compile(r"geetest", re.I), "GeeTest CAPTCHA", Severity.HIGH),
    (re.compile(r"captcha-delivery\.com", re.I), "DataDome CAPTCHA", Severity.CRITICAL),
    (re.compile(r"px-captcha|perimeterx.*captcha", re.I), "PerimeterX CAPTCHA", Severity.CRITICAL),
    (re.compile(r"<input[^>]+name=[\"']captcha[\"']", re.I), "Custom CAPTCHA input field",
     Severity.MEDIUM),
    (re.compile(r"<img[^>]+captcha", re.I), "Image CAPTCHA", Severity.MEDIUM),
    (re.compile(r"friendlycaptcha", re.I), "Friendly Captcha", Severity.MEDIUM),
    (re.compile(r"yandex\.ru/captcha", re.I), "Yandex SmartCaptcha", Severity.HIGH),
]


class CaptchaDetector(Detector):
    name = "captcha"

    def run(self, ctx: DetectorContext) -> List[Finding]:
        findings: List[Finding] = []
        seen = set()

        body = ctx.body or ""
        if not body:
            return findings

        sample = body[:120_000]
        for pattern, vendor, severity in _BODY_SIGNATURES:
            m = pattern.search(sample)
            if m and vendor not in seen:
                seen.add(vendor)
                findings.append(
                    Finding(
                        name=f"CAPTCHA: {vendor}",
                        category=Category.CAPTCHA,
                        severity=severity,
                        description=(
                            f"The page embeds {vendor}. Even if the CAPTCHA only "
                            "appears on submission, its presence usually means "
                            "automated requests are challenged."
                        ),
                        evidence=f"Body match: {m.group(0)[:120]}",
                        recommendation=(
                            "Use a CAPTCHA-solving service (2Captcha, AntiCaptcha, "
                            "CapSolver) or pivot to a non-CAPTCHA-protected endpoint. "
                            "Solving in-house is rarely worth the effort."
                        ),
                    )
                )

        return findings
