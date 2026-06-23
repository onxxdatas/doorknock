"""Detect JavaScript-based challenges and SPA-only rendering."""

from __future__ import annotations

import re
from typing import List

from doorknock.detectors.base import Detector, DetectorContext
from doorknock.models import Category, Finding, Severity


_JS_CHALLENGE_PATTERNS = [
    (re.compile(r"<title>\s*Just a moment", re.I), "Cloudflare JS challenge", Severity.CRITICAL),
    (re.compile(r"chk_jschl|jschl-answer|jschl_vc", re.I), "Cloudflare JS challenge", Severity.CRITICAL),
    (re.compile(r"window\._cf_chl_opt", re.I), "Cloudflare managed challenge", Severity.CRITICAL),
    (re.compile(r"_Incapsula_Resource", re.I), "Imperva (Incapsula) JS challenge", Severity.HIGH),
    (re.compile(r"document\.cookie\s*=\s*['\"]bm_", re.I), "Akamai sensor cookie", Severity.HIGH),
    (re.compile(r"window\.kpsdk", re.I), "Kasada KPSDK challenge", Severity.CRITICAL),
    (re.compile(r"window\.PX|PX\d+", re.I), "PerimeterX challenge", Severity.CRITICAL),
    (re.compile(r"checking your browser", re.I), "Generic 'checking your browser' interstitial",
     Severity.HIGH),
    (re.compile(r"enable javascript and cookies to continue", re.I),
     "JS+cookie enforcement page", Severity.HIGH),
]


class JSChallengeDetector(Detector):
    name = "js_challenge"

    def run(self, ctx: DetectorContext) -> List[Finding]:
        findings: List[Finding] = []
        body = ctx.body or ""
        sample = body[:80_000]

        seen = set()
        for pattern, name, severity in _JS_CHALLENGE_PATTERNS:
            m = pattern.search(sample)
            if m and name not in seen:
                seen.add(name)
                findings.append(
                    Finding(
                        name=name,
                        category=Category.JS_CHALLENGE,
                        severity=severity,
                        description=(
                            "The first response is an interstitial that requires JavaScript "
                            "execution to obtain a clearance cookie before real content loads."
                        ),
                        evidence=f"Body match: {m.group(0)[:120]}",
                        recommendation=(
                            "A plain HTTP client cannot pass this. Use a headless browser "
                            "(Playwright/Patchright) or a service that solves the challenge "
                            "and returns clearance cookies."
                        ),
                    )
                )

        # SPA / client-rendered content — small body but long page references many JS files.
        if 200 <= (ctx.status_code or 0) < 300:
            text_len = len(re.sub(r"\s+", "", body))
            visible_text = re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>", "", body)
            visible_len = len(re.sub(r"\s+", "", visible_text))
            script_count = len(re.findall(r"<script\b", body, re.I))
            if visible_len < 400 and script_count >= 3 and text_len > 500:
                findings.append(
                    Finding(
                        name="Likely SPA / client-rendered content",
                        category=Category.JS_CHALLENGE,
                        severity=Severity.MEDIUM,
                        description=(
                            "The HTML response contains very little visible text but many "
                            "<script> tags, suggesting the real content is rendered in the "
                            "browser via JavaScript (React/Vue/Angular/etc.)."
                        ),
                        evidence=(
                            f"visible_text_chars={visible_len}, script_tags={script_count}"
                        ),
                        recommendation=(
                            "Inspect the page in DevTools for an underlying JSON/API call "
                            "you can hit directly, or use a real browser to render the page."
                        ),
                    )
                )

        return findings
