"""Top-level scanner orchestrator."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

import requests
from requests.exceptions import RequestException

from doorknock.detectors import ALL_DETECTORS
from doorknock.detectors.base import DetectorContext
from doorknock.models import (
    Category,
    Difficulty,
    Finding,
    ScanResult,
    Severity,
)
from doorknock.scoring import compute_score, summary_for


DEFAULT_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

DEFAULT_BROWSER_HEADERS = {
    "User-Agent": DEFAULT_BROWSER_UA,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Sec-Ch-Ua": '"Chromium";v="124", "Not.A/Brand";v="24"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
}


def _normalize_url(url: str) -> str:
    """Add scheme if missing and strip trailing whitespace."""
    url = (url or "").strip()
    if not url:
        raise ValueError("URL is empty")
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {url!r}")
    return url


def _http_version_label(resp: requests.Response) -> Optional[str]:
    raw = getattr(resp, "raw", None)
    version = getattr(raw, "version", None)
    if version is None:
        return None
    return {10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2"}.get(version, f"HTTP/{version}")


class AntiBotScanner:
    """Run all detectors against a URL and return a ScanResult."""

    def __init__(
        self,
        timeout: float = 15.0,
        verify_tls: bool = True,
        user_agent: str = DEFAULT_BROWSER_UA,
        extra_headers: Optional[Dict[str, str]] = None,
        check_robots: bool = True,
        probe_no_user_agent: bool = True,
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.user_agent = user_agent
        self.extra_headers = dict(extra_headers or {})
        self.check_robots = check_robots
        self.probe_no_user_agent = probe_no_user_agent

    # ------------------------------------------------------------------ probes

    def _browser_headers(self) -> Dict[str, str]:
        headers = dict(DEFAULT_BROWSER_HEADERS)
        headers["User-Agent"] = self.user_agent
        headers.update(self.extra_headers)
        return headers

    def _fetch(
        self,
        url: str,
        headers: Dict[str, str],
        allow_redirects: bool = True,
    ) -> requests.Response:
        return requests.get(
            url,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify_tls,
            allow_redirects=allow_redirects,
        )

    def _fetch_robots(self, base_url: str) -> tuple[Optional[str], Optional[int]]:
        try:
            parsed = urlparse(base_url)
            robots_url = urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))
            resp = requests.get(
                robots_url,
                headers={"User-Agent": self.user_agent},
                timeout=min(self.timeout, 10.0),
                verify=self.verify_tls,
                allow_redirects=True,
            )
            return resp.text if resp.ok else "", resp.status_code
        except RequestException:
            return None, None

    def _probe_no_ua(self, url: str) -> Dict[str, Any]:
        if not self.probe_no_user_agent:
            return {}
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": ""},
                timeout=min(self.timeout, 10.0),
                verify=self.verify_tls,
                allow_redirects=True,
            )
            return {
                "nobody_status": resp.status_code,
                "nobody_body_len": len(resp.text or ""),
            }
        except RequestException as exc:
            return {"nobody_error": str(exc)}

    # ------------------------------------------------------------------ scan

    def scan(self, url: str) -> ScanResult:
        original_url = _normalize_url(url)
        errors: List[str] = []
        request_meta: Dict[str, Any] = {}

        # --- Main browser-like fetch ----------------------------------------
        body = ""
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        raw_set_cookie: List[str] = []
        status_code: Optional[int] = None
        final_url = original_url
        elapsed_ms: float = 0.0
        history: List[Dict[str, Any]] = []
        main_resp: Optional[requests.Response] = None

        try:
            t0 = time.monotonic()
            main_resp = self._fetch(original_url, self._browser_headers())
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            status_code = main_resp.status_code
            final_url = main_resp.url
            try:
                body = main_resp.text or ""
            except Exception:
                body = ""
            headers = {k: v for k, v in main_resp.headers.items()}
            cookies = {c.name: c.value or "" for c in main_resp.cookies}
            raw_set_cookie = main_resp.raw.headers.getlist("Set-Cookie") if hasattr(main_resp.raw, "headers") else []
            history = [
                {"status": h.status_code, "url": h.url}
                for h in (main_resp.history or [])
            ]
            request_meta.update(
                {
                    "main_body_len": len(body),
                    "elapsed_ms": round(elapsed_ms, 1),
                    "http_version": _http_version_label(main_resp),
                    "scheme": urlparse(final_url).scheme,
                    "redirect_count": len(main_resp.history or []),
                    "content_type": headers.get("Content-Type", ""),
                }
            )
        except RequestException as exc:
            errors.append(f"main fetch failed: {exc}")

        # --- Secondary probes ----------------------------------------------
        nobody_meta = self._probe_no_ua(original_url)
        request_meta.update(nobody_meta)

        robots_txt: Optional[str] = None
        robots_status: Optional[int] = None
        if self.check_robots:
            robots_txt, robots_status = self._fetch_robots(final_url or original_url)

        ctx = DetectorContext(
            url=original_url,
            final_url=final_url,
            status_code=status_code,
            headers=headers,
            cookies=cookies,
            raw_set_cookie=raw_set_cookie,
            body=body,
            elapsed_ms=elapsed_ms,
            history=history,
            robots_txt=robots_txt,
            robots_status=robots_status,
            request_meta=request_meta,
        )

        # --- Run detectors --------------------------------------------------
        all_findings: List[Finding] = []
        for detector in ALL_DETECTORS:
            try:
                all_findings.extend(detector.run(ctx))
            except Exception as exc:  # never let a detector kill the scan
                errors.append(f"{detector.name} detector error: {exc}")

        # If we couldn't even reach the host, surface that as a critical signal.
        if status_code is None and not all_findings:
            all_findings.append(
                Finding(
                    name="Could not contact host",
                    category=Category.OTHER,
                    severity=Severity.HIGH,
                    description="The scanner failed to fetch the URL at all.",
                    evidence="; ".join(errors) or "no response",
                    recommendation=(
                        "Check connectivity, DNS, and whether the site is reachable from "
                        "your network. Some sites geoblock entire datacenters."
                    ),
                )
            )

        score, difficulty = compute_score(all_findings)
        summary = summary_for(difficulty)

        # Build a deduped list of detected protections for the headline.
        seen_names = []
        for f in all_findings:
            if f.category in (
                Category.WAF,
                Category.BOT_MANAGEMENT,
                Category.CAPTCHA,
                Category.JS_CHALLENGE,
                Category.FINGERPRINTING,
            ):
                if f.name not in seen_names:
                    seen_names.append(f.name)

        # Sort findings: by severity desc, then category, then name
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        all_findings.sort(key=lambda f: (severity_order[f.severity], f.category.value, f.name))

        return ScanResult(
            url=original_url,
            final_url=final_url,
            status_code=status_code,
            score=score,
            difficulty=difficulty,
            summary=summary,
            findings=all_findings,
            detected_protections=seen_names,
            request_meta=request_meta,
            errors=errors,
        )


def scan(url: str, **kwargs: Any) -> ScanResult:
    """Convenience function — scan a URL with default settings.

    Example:
        >>> from doorknock import scan
        >>> result = scan("https://example.com")
        >>> print(result.difficulty, result.score)
    """
    scanner = AntiBotScanner(**kwargs)
    return scanner.scan(url)
