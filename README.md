# doorknock

> Detect a website's anti-bot defenses and rate how hard it is to scrape — from the command line or from Python.

`doorknock` performs a set of HTTP probes against a target URL and runs a battery of detectors that identify common anti-bot and scraping defenses.

## Features

- Detects common WAFs, CDNs, bot management systems, CAPTCHA solutions, and JS challenges
- Scores defenses on a 0–100 scale and maps the result to a difficulty bucket
- Supports both human-readable CLI output and JSON output for automation
- Provides a Python library API with structured scan results
- Includes optional robots.txt analysis and no-User-Agent probe comparisons
- Non-invasive: read-only HTTP checks only, no JavaScript execution or bypass attempts

## Install

```bash
pip install doorknock
```

To enable nicer CLI output, install the optional CLI extras:

```bash
pip install "doorknock[cli]"
```

Requires Python 3.8+.

## CLI usage

Scan a site from the terminal:

```bash
doorknock https://example.com
```

Sample human report:

```text
======================================================================
  Target:     https://example.com
  Final URL:  https://example.com/
  Status:     200
  Difficulty: EASY  (score 0/100)
======================================================================

  Looks easy to scrape. No meaningful anti-bot defenses were detected.
```

Available flags:

- `--json` — Print machine-readable JSON instead of the human report
- `--timeout <seconds>` — HTTP timeout in seconds (default: 15)
- `--no-verify` — Disable TLS certificate verification
- `--no-robots` — Skip the `robots.txt` check
- `--no-color` — Disable ANSI color in human output
- `--user-agent "..."` — Override the User-Agent for the main probe
- `--exit-code` — Exit non-zero when difficulty is `HARD` or worse

Run the CLI via Python if the entry point is not installed:

```bash
python -m doorknock https://example.com --json
```

## Library usage

```python
from doorknock import scan

result = scan("https://example.com")

print(result.difficulty)  # Difficulty.EASY
print(result.score)       # 0..100
print(result.summary)
for finding in result.findings:
    print(finding.severity.value, finding.category.value, finding.name)
```

Convert the result to JSON:

```python
import json
print(json.dumps(result.to_dict(), indent=2))
# or
print(result.to_json())
```

Use the scanner class directly for custom configuration:

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

| Score | Difficulty | Meaning |
| ---: | --- | --- |
| 0–14 | `EASY` | No meaningful defenses. Plain `requests` is likely enough. |
| 15–34 | `MODERATE` | Light defenses such as UA filtering, rate limiting, or generic CDN. |
| 35–59 | `HARD` | Real WAF, CAPTCHA, or JS challenge detected. Consider a browser-based approach. |
| 60–84 | `VERY_HARD` | Layered defenses or advanced bot management. Undetected browsers and proxies may be needed. |
| 85–100 | `EXTREME` | Top-tier bot management and anti-scraping protections. Expect a serious engineering effort. |

## How it works

`doorknock` performs a main browser-like fetch plus optional probes such as `robots.txt` and a no-User-Agent request. It inspects response headers, cookies, status codes, and HTML bodies to identify protections.

Each finding has a severity level and contributes to a weighted score. The final difficulty rating is derived from the aggregated score.

## What it does NOT do

- It does **not** bypass protections.
- It does **not** execute JavaScript.
- It does **not** rely on proprietary unblockers.
- It is a **heuristic** tool and may miss defenses that cannot be detected from a single HTTP request.

## Ethics & legal use

Use `doorknock` only on websites you have permission to test. Respect `robots.txt`, terms of service, and applicable law.

## License

MIT
