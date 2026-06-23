"""Analyze robots.txt for explicit anti-scraper rules."""

from __future__ import annotations

import re
from typing import List

from doorknock.detectors.base import Detector, DetectorContext
from doorknock.models import Category, Finding, Severity


class RobotsDetector(Detector):
    name = "robots"

    def run(self, ctx: DetectorContext) -> List[Finding]:
        findings: List[Finding] = []
        body = ctx.robots_txt or ""

        if ctx.robots_status is None:
            return findings

        if ctx.robots_status == 404:
            findings.append(
                Finding(
                    name="No robots.txt published",
                    category=Category.ROBOTS,
                    severity=Severity.INFO,
                    description="Site does not publish robots.txt.",
                )
            )
            return findings

        if not body.strip():
            findings.append(
                Finding(
                    name="Empty robots.txt",
                    category=Category.ROBOTS,
                    severity=Severity.INFO,
                    description="robots.txt exists but is empty.",
                )
            )
            return findings

        # Look for star-disallow-all
        rules = body.splitlines()
        current_agents: List[str] = []
        global_disallow_all = False
        agent_disallows: dict = {}

        for line in rules:
            line = line.split("#", 1)[0].strip()
            if not line:
                current_agents = []
                continue
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()

            if key == "user-agent":
                current_agents.append(value)
            elif key == "disallow":
                for agent in current_agents or ["*"]:
                    agent_disallows.setdefault(agent, []).append(value)
                if value == "/" and "*" in (current_agents or ["*"]):
                    global_disallow_all = True

        if global_disallow_all:
            findings.append(
                Finding(
                    name="robots.txt disallows all user agents",
                    category=Category.ROBOTS,
                    severity=Severity.MEDIUM,
                    description=(
                        "robots.txt sets `User-agent: *` with `Disallow: /`. The site "
                        "explicitly does not want to be crawled."
                    ),
                    evidence="User-agent: * / Disallow: /",
                    recommendation=(
                        "Respect this if you want to scrape ethically/legally. "
                        "Even if you proceed, expect aggressive blocking."
                    ),
                )
            )

        # Disallow rules targeting common scraper UAs
        scraper_agents = [
            a for a in agent_disallows
            if re.search(r"bot|crawler|spider|scrape|wget|curl|httpclient|python", a, re.I)
        ]
        if scraper_agents:
            findings.append(
                Finding(
                    name="robots.txt targets scrapers/bots by name",
                    category=Category.ROBOTS,
                    severity=Severity.LOW,
                    description=(
                        "robots.txt names specific bot-like user agents in its rules, "
                        "indicating the operator pays attention to scraper traffic."
                    ),
                    evidence=", ".join(scraper_agents[:8]),
                )
            )

        return findings
