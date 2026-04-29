"""Detect commercial bot-management products."""

from __future__ import annotations

import re
from typing import List, Tuple

from doorknock.detectors.base import Detector, DetectorContext
from doorknock.models import Category, Finding, Severity


# (header_lower, regex, vendor)
_HEADER_SIGNATURES: List[Tuple[str, re.Pattern, str]] = [
    ("x-datadome", re.compile(r".+"), "DataDome"),
    ("x-dd-b", re.compile(r".+"), "DataDome"),
    ("x-px-block", re.compile(r".+"), "PerimeterX / HUMAN"),
    ("x-px-authorization", re.compile(r".+"), "PerimeterX / HUMAN"),
    ("x-kasada", re.compile(r".+"), "Kasada"),
    ("x-shape-fp", re.compile(r".+"), "Shape Security (F5)"),
    ("x-distil-cs", re.compile(r".+"), "Imperva Advanced Bot Protection (Distil)"),
    ("x-cdn-bot-protect", re.compile(r".+"), "Generic bot protection"),
    ("x-arkose", re.compile(r".+"), "Arkose Labs"),
    ("x-recaptcha-token", re.compile(r".+"), "reCAPTCHA Enterprise"),
]

# Cookie-prefix -> vendor
_COOKIE_PREFIXES = {
    "datadome": "DataDome",
    "_pxhd": "PerimeterX / HUMAN",
    "_px": "PerimeterX / HUMAN",
    "_pxvid": "PerimeterX / HUMAN",
    "pxcts": "PerimeterX / HUMAN",
    "x-kpsdk-": "Kasada",
    "kpsdk": "Kasada",
    "reese84": "F5 Shape Security",
    "TS01": "F5 Distributed Cloud Bot Defense",
    "ASP.NET_Bot": "ASP.NET bot protection",
}

# Body markers
_BODY_SIGNATURES: List[Tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"datadome", re.I), "DataDome", Severity.CRITICAL),
    (re.compile(r"captcha-delivery\.com", re.I), "DataDome (captcha)", Severity.CRITICAL),
    (re.compile(r"perimeterx|px-captcha|_pxAction", re.I), "PerimeterX / HUMAN", Severity.CRITICAL),
    (re.compile(r"kasada|kpsdk", re.I), "Kasada", Severity.CRITICAL),
    (re.compile(r"shape\s+security|f5shape", re.I), "Shape Security (F5)", Severity.CRITICAL),
    (re.compile(r"reese84|tss\.f5\.com", re.I), "F5 Bot Defense", Severity.CRITICAL),
    (re.compile(r"distil[_-]r_captcha|d_token", re.I), "Imperva Advanced Bot Protection (Distil)", Severity.HIGH),
    (re.compile(r"arkoselabs|funcaptcha", re.I), "Arkose Labs / FunCaptcha", Severity.CRITICAL),
    (re.compile(r"reblaze\.io|rbzns", re.I), "Reblaze Bot Manager", Severity.HIGH),
    (re.compile(r"radware|appwall", re.I), "Radware Bot Manager / AppWall", Severity.HIGH),
    (re.compile(r"netacea", re.I), "Netacea Bot Management", Severity.HIGH),
]


class BotManagementDetector(Detector):
    name = "bot_management"

    def run(self, ctx: DetectorContext) -> List[Finding]:
        findings: List[Finding] = []
        seen = set()

        def add(vendor: str, severity: Severity, evidence: str) -> None:
            key = (vendor, evidence[:80])
            if key in seen:
                return
            seen.add(key)
            findings.append(
                Finding(
                    name=f"Bot management: {vendor}",
                    category=Category.BOT_MANAGEMENT,
                    severity=severity,
                    description=(
                        f"Detected {vendor}. These products fingerprint browsers, score "
                        "behavior, and require valid sensor data — the hardest class of "
                        "anti-bot to bypass with plain HTTP clients."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Plain requests will almost certainly be blocked. You typically need "
                        "an undetected browser (Patchright/Playwright with stealth), residential "
                        "proxies, and possibly a CAPTCHA-solving service."
                    ),
                )
            )

        for header, pattern, vendor in _HEADER_SIGNATURES:
            value = ctx.header(header)
            if value and pattern.search(value):
                add(vendor, Severity.CRITICAL, f"Header {header}: {value[:120]}")

        for cookie_name in ctx.cookies:
            lname = cookie_name.lower()
            for prefix, vendor in _COOKIE_PREFIXES.items():
                if lname == prefix.lower() or lname.startswith(prefix.lower()):
                    add(vendor, Severity.CRITICAL, f"Cookie: {cookie_name}")

        body = ctx.body or ""
        if body:
            sample = body[:80_000]
            for pattern, vendor, severity in _BODY_SIGNATURES:
                m = pattern.search(sample)
                if m:
                    add(vendor, severity, f"Body match: {m.group(0)[:120]}")

        return findings
