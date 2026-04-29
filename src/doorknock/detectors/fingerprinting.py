"""Detect client-side fingerprinting libraries."""

from __future__ import annotations

import re
from typing import List, Tuple

from doorknock.detectors.base import Detector, DetectorContext
from doorknock.models import Category, Finding, Severity


_FP_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"fingerprintjs|fpjs|fp\.js", re.I), "FingerprintJS", Severity.HIGH),
    (re.compile(r"clientjs", re.I), "ClientJS fingerprinting", Severity.MEDIUM),
    (re.compile(r"castle\.io|_castle", re.I), "Castle device intelligence", Severity.HIGH),
    (re.compile(r"sift\.com|sift\.js", re.I), "Sift fraud detection", Severity.HIGH),
    (re.compile(r"forter", re.I), "Forter fraud detection", Severity.HIGH),
    (re.compile(r"riskified", re.I), "Riskified fraud detection", Severity.HIGH),
    (re.compile(r"threatmetrix", re.I), "ThreatMetrix (LexisNexis)", Severity.HIGH),
    (re.compile(r"iovation", re.I), "iovation device fingerprinting", Severity.HIGH),
    (re.compile(r"signifyd", re.I), "Signifyd fraud detection", Severity.MEDIUM),
    (re.compile(r"webgl_fingerprint|canvas_fingerprint|audiocontext.*fingerprint", re.I),
     "Custom canvas/WebGL/audio fingerprinting", Severity.MEDIUM),
]


class FingerprintingDetector(Detector):
    name = "fingerprinting"

    def run(self, ctx: DetectorContext) -> List[Finding]:
        findings: List[Finding] = []
        body = ctx.body or ""
        if not body:
            return findings

        sample = body[:120_000]
        seen = set()
        for pattern, vendor, severity in _FP_PATTERNS:
            m = pattern.search(sample)
            if m and vendor not in seen:
                seen.add(vendor)
                findings.append(
                    Finding(
                        name=f"Fingerprinting: {vendor}",
                        category=Category.FINGERPRINTING,
                        severity=severity,
                        description=(
                            f"Detected {vendor}. The site collects browser/device "
                            "fingerprints that are sent back for risk scoring. Plain "
                            "HTTP clients can't produce these, so requests will look "
                            "anomalous to the operator."
                        ),
                        evidence=f"Body match: {m.group(0)[:120]}",
                        recommendation=(
                            "Use a real browser with stealth patches; replaying captured "
                            "fingerprints rarely works long-term because they're tied to "
                            "session/IP/timing."
                        ),
                    )
                )
        return findings
