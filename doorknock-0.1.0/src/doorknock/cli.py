"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from doorknock.checker import scan
from doorknock.models import Difficulty, ScanResult, Severity


_DIFFICULTY_COLORS = {
    Difficulty.EASY: "\033[92m",       # green
    Difficulty.MODERATE: "\033[93m",   # yellow
    Difficulty.HARD: "\033[33m",       # orange
    Difficulty.VERY_HARD: "\033[91m",  # red
    Difficulty.EXTREME: "\033[95m",    # magenta
}
_SEVERITY_COLORS = {
    Severity.INFO: "\033[90m",
    Severity.LOW: "\033[36m",
    Severity.MEDIUM: "\033[93m",
    Severity.HIGH: "\033[91m",
    Severity.CRITICAL: "\033[95m",
}
_RESET = "\033[0m"


def _color(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{code}{text}{_RESET}"


def _print_human(result: ScanResult, color: bool) -> None:
    diff_color = _DIFFICULTY_COLORS.get(result.difficulty, "")
    print()
    print(_color("=" * 70, "\033[90m", color))
    print(f"  Target:     {result.url}")
    if result.final_url and result.final_url != result.url:
        print(f"  Final URL:  {result.final_url}")
    print(f"  Status:     {result.status_code}")
    diff_label = result.difficulty.value.upper().replace("_", " ")
    print(
        "  Difficulty: "
        + _color(f"{diff_label}  (score {result.score}/100)", diff_color, color)
    )
    print(_color("=" * 70, "\033[90m", color))
    print()
    print("  " + result.summary)
    print()

    if result.detected_protections:
        print(_color("  Detected protections:", "\033[1m", color))
        for name in result.detected_protections:
            print(f"    - {name}")
        print()

    if result.findings:
        print(_color("  Findings:", "\033[1m", color))
        for f in result.findings:
            sev_color = _SEVERITY_COLORS.get(f.severity, "")
            tag = _color(f"[{f.severity.value.upper():<8}]", sev_color, color)
            print(f"    {tag} {f.category.value}: {f.name}")
            print(f"             {f.description}")
            if f.evidence:
                print(f"             evidence: {f.evidence}")
            if f.recommendation:
                print(f"             ↳ {f.recommendation}")
            print()
    else:
        print("  No anti-bot findings.")
        print()

    if result.errors:
        print(_color("  Errors during scan:", "\033[91m", color))
        for e in result.errors:
            print(f"    - {e}")
        print()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="doorknock",
        description=(
            "Scan a website for anti-bot defenses and rate how hard it is to scrape."
        ),
    )
    parser.add_argument("url", help="Target URL (https://example.com)")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of a human report.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP timeout in seconds (default: 15).",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable TLS certificate verification.",
    )
    parser.add_argument(
        "--no-robots",
        action="store_true",
        help="Skip the robots.txt check.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color in human output.",
    )
    parser.add_argument(
        "--user-agent",
        default=None,
        help="Override the User-Agent used for the main probe.",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help=(
            "Exit with non-zero code if the difficulty is HARD or worse "
            "(useful for CI gating)."
        ),
    )
    args = parser.parse_args(argv)

    kwargs = {
        "timeout": args.timeout,
        "verify_tls": not args.no_verify,
        "check_robots": not args.no_robots,
    }
    if args.user_agent:
        kwargs["user_agent"] = args.user_agent

    try:
        result = scan(args.url, **kwargs)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(result.to_json())
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        _print_human(result, color=use_color)

    if args.exit_code and result.difficulty in (
        Difficulty.HARD,
        Difficulty.VERY_HARD,
        Difficulty.EXTREME,
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
