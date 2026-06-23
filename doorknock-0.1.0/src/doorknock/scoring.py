"""Aggregate findings into a numeric scraping-difficulty score."""

from __future__ import annotations

from collections import Counter
from typing import List, Tuple

from doorknock.models import Category, Difficulty, Finding, Severity, severity_weight


# Per-category contribution caps so one chatty detector cannot dominate.
_CATEGORY_CAPS = {
    Category.WAF: 35,
    Category.BOT_MANAGEMENT: 50,
    Category.CAPTCHA: 35,
    Category.JS_CHALLENGE: 45,
    Category.RATE_LIMIT: 20,
    Category.HEADERS: 10,
    Category.USER_AGENT: 20,
    Category.COOKIES: 15,
    Category.TLS: 10,
    Category.ROBOTS: 10,
    Category.FINGERPRINTING: 30,
    Category.GEO: 15,
    Category.AUTH: 25,
    Category.OTHER: 10,
}


def compute_score(findings: List[Finding]) -> Tuple[int, Difficulty]:
    """Return (score 0..100, Difficulty) from findings."""
    per_category: Counter = Counter()
    for f in findings:
        per_category[f.category] += severity_weight(f.severity)

    capped = 0
    for cat, raw in per_category.items():
        cap = _CATEGORY_CAPS.get(cat, 15)
        capped += min(raw, cap)

    # Synergy bump: a serious bot-manager AND a WAF AND a CAPTCHA together is meaningfully
    # harder than the sum of parts.
    serious_categories = sum(
        1
        for c in (
            Category.BOT_MANAGEMENT,
            Category.JS_CHALLENGE,
            Category.CAPTCHA,
            Category.FINGERPRINTING,
        )
        if per_category.get(c, 0) >= severity_weight(Severity.HIGH)
    )
    if serious_categories >= 2:
        capped += 8 * (serious_categories - 1)

    score = max(0, min(100, capped))
    return score, Difficulty.from_score(score)


_SUMMARY_TEMPLATES = {
    Difficulty.EASY: (
        "No anti-bot defenses were detected. "
        "A plain requests script with a polite User-Agent is recommended to start, and you may be able to get away with less if the site is very permissive."
    ),
    Difficulty.MODERATE: (
        "Moderate difficulty. The site has some defenses (rate limits, UA filtering, "
        "or a CDN) but no hardcore bot management. Use a session, realistic headers, "
        "and back off on errors."
    ),
    Difficulty.HARD: (
        "Hard. The site is fronted by a serious WAF and/or uses CAPTCHAs or JS "
        "challenges. Plain HTTP scraping will likely be blocked; you may need a "
        "real browser, residential proxies, or CAPTCHA solving."
    ),
    Difficulty.VERY_HARD: (
        "Very hard. Multiple layered defenses (bot management + JS challenges or "
        "CAPTCHAs) are present. Expect to need an undetected browser, rotating "
        "residential proxies, and significant per-target tuning."
    ),
    Difficulty.EXTREME: (
        "Extreme. The site uses top-tier bot management (DataDome, PerimeterX, "
        "Kasada, Shape, etc.) plus other layers. Bypassing reliably is a serious "
        "engineering project and may require commercial unblockers."
    ),
}


def summary_for(difficulty: Difficulty) -> str:
    return _SUMMARY_TEMPLATES[difficulty]
