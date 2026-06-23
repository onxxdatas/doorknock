"""Detect Web Application Firewalls (WAFs)."""

from __future__ import annotations

import re
from typing import List, Tuple

from doorknock.detectors.base import Detector, DetectorContext
from doorknock.models import Category, Finding, Severity


# Header signatures: (header_name_lower, regex, vendor, severity)
_HEADER_SIGNATURES: List[Tuple[str, re.Pattern, str, Severity]] = [
    ("server", re.compile(r"cloudflare", re.I), "Cloudflare", Severity.MEDIUM),
    ("cf-ray", re.compile(r".+"), "Cloudflare", Severity.MEDIUM),
    ("cf-cache-status", re.compile(r".+"), "Cloudflare", Severity.INFO),
    ("cf-mitigated", re.compile(r".+"), "Cloudflare (challenge)", Severity.CRITICAL),
    ("server", re.compile(r"AkamaiGHost|AkamaiNetStorage", re.I), "Akamai", Severity.MEDIUM),
    ("x-akamai-transformed", re.compile(r".+"), "Akamai", Severity.MEDIUM),
    ("akamai-grn", re.compile(r".+"), "Akamai", Severity.MEDIUM),
    ("server", re.compile(r"sucuri", re.I), "Sucuri", Severity.HIGH),
    ("x-sucuri-id", re.compile(r".+"), "Sucuri", Severity.HIGH),
    ("x-sucuri-cache", re.compile(r".+"), "Sucuri", Severity.MEDIUM),
    ("server", re.compile(r"BigIP|F5|BIG-IP", re.I), "F5 BIG-IP / Silverline", Severity.HIGH),
    ("x-cdn", re.compile(r"imperva|incapsula", re.I), "Imperva (Incapsula)", Severity.HIGH),
    ("x-iinfo", re.compile(r".+"), "Imperva (Incapsula)", Severity.HIGH),
    ("x-cdn", re.compile(r"fastly", re.I), "Fastly", Severity.LOW),
    ("server", re.compile(r"barracuda", re.I), "Barracuda WAF", Severity.HIGH),
    ("server", re.compile(r"awselb|aws", re.I), "AWS Load Balancer", Severity.LOW),
    ("x-amzn-waf-action", re.compile(r".+"), "AWS WAF", Severity.HIGH),
    ("x-amz-cf-id", re.compile(r".+"), "AWS CloudFront", Severity.LOW),
    ("server", re.compile(r"nginx-wallarm|wallarm", re.I), "Wallarm", Severity.HIGH),
    ("x-fireeye", re.compile(r".+"), "FireEye", Severity.HIGH),
    ("x-cdn", re.compile(r"airee", re.I), "Airee", Severity.MEDIUM),
    ("x-protected-by", re.compile(r"sqreen", re.I), "Sqreen", Severity.MEDIUM),
    ("x-powered-by-360wzb", re.compile(r".+"), "360 Web Application Firewall", Severity.HIGH),
    ("x-yunjiasu-status", re.compile(r".+"), "Yunjiasu (Baidu)", Severity.HIGH),
    ("server", re.compile(r"safedog", re.I), "Safedog WAF", Severity.HIGH),
    ("x-powered-by", re.compile(r"asp\.net.*aspshield", re.I), "ASPShield", Severity.MEDIUM),
    ("x-waf-event-info", re.compile(r".+"), "Generic WAF", Severity.HIGH),
    ("x-mod-pagespeed", re.compile(r".+"), "Google PageSpeed", Severity.INFO),
    ("server", re.compile(r"reblaze", re.I), "Reblaze", Severity.HIGH),
    ("x-rbz", re.compile(r".+"), "Reblaze", Severity.HIGH),
    ("server", re.compile(r"stackpath|netdna|maxcdn", re.I), "StackPath / MaxCDN", Severity.MEDIUM),
    ("x-cdn-provider", re.compile(r".+"), "Generic CDN", Severity.LOW),
    ("x-azure-ref", re.compile(r".+"), "Azure Front Door", Severity.MEDIUM),
    ("x-msedge-ref", re.compile(r".+"), "Azure / MS Edge", Severity.LOW),
]

# Cookie name -> vendor
_COOKIE_SIGNATURES = {
    "__cfduid": "Cloudflare",
    "__cf_bm": "Cloudflare Bot Management",
    "cf_clearance": "Cloudflare (challenge passed)",
    "incap_ses": "Imperva (Incapsula)",
    "visid_incap": "Imperva (Incapsula)",
    "nlbi_": "Imperva (Incapsula) load balancer",
    "ak_bmsc": "Akamai Bot Manager",
    "bm_sv": "Akamai Bot Manager",
    "bm_sz": "Akamai Bot Manager",
    "bm_mi": "Akamai Bot Manager",
    "_abck": "Akamai Bot Manager",
    "AKA_A2": "Akamai",
    "sucuri_cloudproxy_uuid": "Sucuri",
    "rbzid": "Reblaze",
}

_BODY_SIGNATURES = [
    (re.compile(r"Attention Required! \| Cloudflare", re.I), "Cloudflare (block page)", Severity.CRITICAL),
    (re.compile(r"Sorry, you have been blocked", re.I), "Cloudflare (block page)", Severity.CRITICAL),
    (re.compile(r"cf-error-details|cf-wrapper", re.I), "Cloudflare (error)", Severity.HIGH),
    (re.compile(r"Reference&#32;#\d+\.[a-f0-9]+", re.I), "Akamai (block page)", Severity.HIGH),
    (re.compile(r"Access Denied.*Reference Number", re.I | re.S), "Akamai / generic WAF block", Severity.HIGH),
    (re.compile(r"Sucuri WebSite Firewall", re.I), "Sucuri (block page)", Severity.HIGH),
    (re.compile(r"_Incapsula_Resource", re.I), "Imperva (Incapsula challenge)", Severity.HIGH),
    (re.compile(r"Request unsuccessful\. Incapsula", re.I), "Imperva (Incapsula block)", Severity.HIGH),
    (re.compile(r"<title>Just a moment", re.I), "Cloudflare JS challenge", Severity.CRITICAL),
    (re.compile(r"This website is using a security service to protect itself", re.I),
     "Generic WAF block notice", Severity.HIGH),
]


class WAFDetector(Detector):
    name = "waf"

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
                    name=f"WAF/CDN: {vendor}",
                    category=Category.WAF,
                    severity=severity,
                    description=f"Detected {vendor} fronting the response.",
                    evidence=evidence,
                    recommendation=(
                        "Expect IP/UA reputation scoring and possible JS challenges. "
                        "Use residential or rotating proxies, realistic browser headers, "
                        "and consider a real browser (Playwright) if challenged."
                    ),
                )
            )

        # Header signatures
        for header_name, pattern, vendor, severity in _HEADER_SIGNATURES:
            value = ctx.header(header_name)
            if value and pattern.search(value):
                add(vendor, severity, f"Header {header_name}: {value[:120]}")

        # Cookie signatures (check cookie names by prefix or exact)
        for cookie_name in list(ctx.cookies.keys()):
            for sig, vendor in _COOKIE_SIGNATURES.items():
                if cookie_name == sig or cookie_name.startswith(sig):
                    add(vendor, Severity.HIGH, f"Cookie: {cookie_name}")

        # Body signatures
        body = ctx.body or ""
        if body:
            sample = body[:60_000]
            for pattern, vendor, severity in _BODY_SIGNATURES:
                m = pattern.search(sample)
                if m:
                    add(vendor, severity, f"Body match: {m.group(0)[:120]}")

        # Status code based heuristics
        if ctx.status_code in (403, 406, 429, 503):
            server = ctx.header("server")
            evidence = f"HTTP {ctx.status_code} (server: {server or 'unknown'})"
            findings.append(
                Finding(
                    name=f"Hostile status code {ctx.status_code}",
                    category=Category.WAF,
                    severity=Severity.HIGH if ctx.status_code != 503 else Severity.MEDIUM,
                    description=(
                        "The site returned a status code commonly used by WAFs to block "
                        "or throttle automated clients on the very first request."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Try with a realistic browser User-Agent and full Accept headers. "
                        "If still blocked, the site is actively rejecting non-browser clients."
                    ),
                )
            )

        return findings
