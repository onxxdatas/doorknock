# doorknock

> Detect a website's anti-bot defenses and rate how hard it is to scrape — from the command line or from Python.

`doorknock` performs a single set of HTTP probes against a target URL and runs a battery of detectors that look for:

- **WAFs / CDNs** — Cloudflare, Akamai, Sucuri, Imperva (Incapsula), F5 BIG-IP, AWS WAF, Fastly, Azure Front Door, StackPath, Wallarm, Reblaze, Barracuda, …
- **Bot management** — DataDome, PerimeterX / HUMAN, Kasada, Shape Security (F5), Imperva ABP (Distil), Arkose Labs, Reblaze, Radware, Netacea, …
- **CAPTCHAs** — Google reCAPTCHA / reCAPTCHA Enterprise, hCaptcha, Cloudflare Turnstile, Arkose FunCaptcha, GeeTest, DataDome captcha, custom image captchas, …
- **JavaScript challenges** — Cloudflare "Just a moment", Incapsula challenges, Akamai sensor cookies, Kasada KPSDK, PerimeterX interstitials, "checking your browser" pages, SPA / client-only rendering
- **Rate-limit signals** — `RateLimit-*`, `X-RateLimit-*`, `Retry-After`, hostile statuses (`403`/`406`/`429`/`503`)
- **User-Agent filtering** — compares a no-UA probe against a browser-UA probe
- **Cookie/session requirements** — large initial cookie sets, CSRF/XSRF tokens, `__Host-` / `__Secure-` cookies
- **TLS / HTTP version** — HTTPS, HTTP/2 (relevant to JA3/JA4 fingerprinting)
- **robots.txt rules** — `Disallow: /` for everyone, scraper-targeted user agents
- **Client-side fingerprinting** — FingerprintJS, Castle, Sift, Forter, ThreatMetrix, iovation, custom canvas/WebGL/audio probes

Findings are weighted by severity and aggregated into a single **scraping difficulty** rating from `EASY` to `EXTREME` along with a 0–100 score.

---

## Install

```bash
pip install doorknock
```

For colored, prettier CLI output you can also install the `cli` extras (uses Rich):

```bash
pip install "doorknock[cli]"
```

Requires Python 3.8+.

## CLI

```bash
doorknock https://example.com
```

```text
======================================================================
  Target:     https://example.com
  Final URL:  https://example.com/
  Status:     200
  Difficulty: EASY  (score 0/100)
======================================================================

  Looks easy to scrape. No meaningful anti-bot defenses were detected.
  A plain requests script with a polite User-Agent should work.
```

Useful flags:

| Flag | Purpose |
| --- | --- |
| `--json` | Emit machine-readable JSON. |
| `--timeout 10` | HTTP timeout in seconds. |
| `--no-verify` | Disable TLS verification. |
| `--no-robots` | Skip the robots.txt fetch. |
| `--no-color` | Disable ANSI colors in human output. |
| `--user-agent "..."` | Override the User-Agent for the main probe. |
| `--exit-code` | Exit non-zero when difficulty is `HARD` or worse (useful in CI). |

You can also run it without installing the entry point:

```bash
python -m doorknock https://example.com --json
```

## Library usage

```python
from doorknock import scan

result = scan("https://example.com")

print(result.difficulty)            # Difficulty.EASY
print(result.score)                  # 0..100
print(result.summary)
for f in result.findings:
    print(f.severity.value, f.category.value, f.name)
```

The same data is available as a plain dict / JSON:

```python
import json
print(json.dumps(result.to_dict(), indent=2))
# or
print(result.to_json())
```

For more control, use the class directly:

```python
from doorknock import AntiBotScanner

scanner = AntiBotScanner(
    timeout=10,
    user_agent="my-bot/1.0",
    extra_headers={"Accept-Language": "en-GB,en;q=0.9"},
    check_robots=True,
    probe_no_user_agent=True,
)
result = scanner.scan("https://example.com")
```

## Difficulty buckets

| Score | Difficulty | What it means |
| ---: | --- | --- |
| 0–14 | `EASY` | Nothing meaningful in the way. Plain `requests` works. |
| 15–34 | `MODERATE` | Light defenses — UA filtering, rate limits, generic CDN. Use a session and realistic headers. |
| 35–59 | `HARD` | Real WAF, CAPTCHA, or JS challenges. Plan for a real browser or proxies. |
| 60–84 | `VERY_HARD` | Layered defenses (bot management + CAPTCHA / JS challenge). Undetected browser + residential proxies likely. |
| 85–100 | `EXTREME` | Top-tier bot management (DataDome, PerimeterX, Kasada, Shape, …). Expect a serious engineering project or commercial unblockers. |

## How the scoring works

Every finding has a severity (`info`, `low`, `medium`, `high`, `critical`) which maps to a weight. Weights are summed per category and capped so one chatty detector cannot dominate the result. A small "synergy bonus" is added when multiple serious categories show up together (e.g. bot management + CAPTCHA + fingerprinting), because layered defenses are meaningfully harder than a single layer.

## What it does NOT do

- It does **not** attempt to bypass anything. It performs read-only HTTP requests (`GET /`, `GET /robots.txt`, plus a no-UA probe).
- It does **not** execute JavaScript. Findings come purely from headers, cookies, status codes, and the raw HTML body.
- It is a **heuristic** tool. Some defenses (TLS / JA3 fingerprinting, behavioral biometrics, server-side ML) cannot be observed from a single HTTP request and are inferred from vendor signatures. False negatives are possible — especially for in-house systems.
- Detection is best-effort: real-world sites mix vendors and rebrand things constantly.

## Ethics & legality

Use this tool to evaluate sites you have permission to access, to assess your own infrastructure, or for security research. Respect `robots.txt`, terms of service, and applicable law in your jurisdiction.

## License

MIT
