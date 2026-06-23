"""Data models for scan results."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """How much a finding contributes to scraping difficulty."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    """Type of anti-bot defense detected."""

    WAF = "waf"
    BOT_MANAGEMENT = "bot_management"
    CAPTCHA = "captcha"
    JS_CHALLENGE = "js_challenge"
    RATE_LIMIT = "rate_limit"
    HEADERS = "headers"
    USER_AGENT = "user_agent"
    COOKIES = "cookies"
    TLS = "tls"
    ROBOTS = "robots"
    FINGERPRINTING = "fingerprinting"
    GEO = "geo"
    AUTH = "auth"
    OTHER = "other"


class Difficulty(str, Enum):
    """Overall scraping difficulty bucket."""

    EASY = "easy"
    MODERATE = "moderate"
    HARD = "hard"
    VERY_HARD = "very_hard"
    EXTREME = "extreme"

    @classmethod
    def from_score(cls, score: int) -> "Difficulty":
        if score < 15:
            return cls.EASY
        if score < 35:
            return cls.MODERATE
        if score < 60:
            return cls.HARD
        if score < 85:
            return cls.VERY_HARD
        return cls.EXTREME


_SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 4,
    Severity.MEDIUM: 12,
    Severity.HIGH: 25,
    Severity.CRITICAL: 45,
}


def severity_weight(sev: Severity) -> int:
    return _SEVERITY_WEIGHTS[sev]


@dataclass
class Finding:
    """One observation about an anti-bot defense."""

    name: str
    category: Category
    severity: Severity
    description: str
    evidence: Optional[str] = None
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass
class ScanResult:
    """Final scan output."""

    url: str
    final_url: str
    status_code: Optional[int]
    score: int
    difficulty: Difficulty
    summary: str
    findings: List[Finding] = field(default_factory=list)
    detected_protections: List[str] = field(default_factory=list)
    request_meta: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "score": self.score,
            "difficulty": self.difficulty.value,
            "summary": self.summary,
            "detected_protections": self.detected_protections,
            "findings": [f.to_dict() for f in self.findings],
            "request_meta": self.request_meta,
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        import json

        return json.dumps(self.to_dict(), indent=indent, default=str)
