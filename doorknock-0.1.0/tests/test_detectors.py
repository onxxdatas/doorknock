"""Unit tests for detectors and scoring — all use synthetic DetectorContext (no network)."""

from __future__ import annotations

from doorknock.detectors import (
    BotManagementDetector,
    CaptchaDetector,
    CookiesDetector,
    FingerprintingDetector,
    HeadersDetector,
    JSChallengeDetector,
    RateLimitDetector,
    RobotsDetector,
    TLSDetector,
    UserAgentDetector,
    WAFDetector,
)
from doorknock.detectors.base import DetectorContext
from doorknock.models import Category, Difficulty, Severity
from doorknock.scoring import compute_score


def make_ctx(**overrides) -> DetectorContext:
    base = dict(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={},
        cookies={},
        raw_set_cookie=[],
        body="",
        elapsed_ms=10.0,
        history=[],
        robots_txt=None,
        robots_status=None,
        request_meta={},
    )
    base.update(overrides)
    return DetectorContext(**base)


def test_cloudflare_header_detected():
    ctx = make_ctx(headers={"server": "cloudflare", "cf-ray": "abc123"})
    findings = WAFDetector().run(ctx)
    names = [f.name for f in findings]
    assert any("Cloudflare" in n for n in names)
    assert any(f.category == Category.WAF for f in findings)


def test_cloudflare_block_body():
    body = "<html><head><title>Just a moment...</title></head></html>"
    ctx = make_ctx(body=body, status_code=403, headers={"server": "cloudflare"})
    findings = WAFDetector().run(ctx) + JSChallengeDetector().run(ctx)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_datadome_detected_from_cookie():
    ctx = make_ctx(cookies={"datadome": "xyz"})
    findings = BotManagementDetector().run(ctx)
    assert any("DataDome" in f.name for f in findings)
    assert findings[0].severity == Severity.CRITICAL


def test_recaptcha_detected_from_body():
    body = '<script src="https://www.google.com/recaptcha/api.js"></script>'
    ctx = make_ctx(body=body)
    findings = CaptchaDetector().run(ctx)
    assert any("reCAPTCHA" in f.name for f in findings)


def test_rate_limit_headers():
    ctx = make_ctx(headers={"x-ratelimit-limit": "60", "x-ratelimit-remaining": "0"})
    findings = RateLimitDetector().run(ctx)
    assert findings
    assert findings[0].category == Category.RATE_LIMIT


def test_csrf_cookie():
    ctx = make_ctx(cookies={"XSRF-TOKEN": "abc"})
    findings = CookiesDetector().run(ctx)
    assert any("CSRF" in f.name for f in findings)


def test_headers_security_set():
    ctx = make_ctx(headers={
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    })
    findings = HeadersDetector().run(ctx)
    assert any("security headers" in f.name for f in findings)


def test_user_agent_filtering():
    ctx = make_ctx(
        status_code=200,
        request_meta={"nobody_status": 403, "nobody_body_len": 100, "main_body_len": 5000},
    )
    findings = UserAgentDetector().run(ctx)
    assert any("User-Agent filtering" in f.name for f in findings)


def test_tls_http2_noted():
    ctx = make_ctx(request_meta={"http_version": "HTTP/2", "scheme": "https"})
    findings = TLSDetector().run(ctx)
    assert any(f.category == Category.TLS for f in findings)


def test_robots_disallow_all():
    ctx = make_ctx(
        robots_status=200,
        robots_txt="User-agent: *\nDisallow: /\n",
    )
    findings = RobotsDetector().run(ctx)
    assert any("disallows all" in f.name for f in findings)


def test_fingerprintjs_detected():
    body = '<script src="https://cdn.example/fingerprintjs.min.js"></script>'
    ctx = make_ctx(body=body)
    findings = FingerprintingDetector().run(ctx)
    assert any("FingerprintJS" in f.name for f in findings)


def test_score_easy_when_no_findings():
    score, diff = compute_score([])
    assert score == 0
    assert diff == Difficulty.EASY


def test_score_extreme_with_layered_defenses():
    # Combine bot management + JS challenge + captcha + fingerprinting all critical
    cf = WAFDetector().run(make_ctx(
        headers={"server": "cloudflare", "cf-ray": "x"},
        body="<title>Just a moment...</title>",
        status_code=403,
    ))
    dd = BotManagementDetector().run(make_ctx(cookies={"datadome": "y"}))
    cap = CaptchaDetector().run(make_ctx(
        body='<script src="https://hcaptcha.com/1/api.js"></script>'
    ))
    js = JSChallengeDetector().run(make_ctx(
        body="<title>Just a moment...</title>", status_code=403
    ))
    fp = FingerprintingDetector().run(make_ctx(body='<script src="fingerprintjs.js">'))
    score, diff = compute_score(cf + dd + cap + js + fp)
    assert score >= 60
    assert diff in (Difficulty.VERY_HARD, Difficulty.EXTREME)
