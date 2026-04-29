"""Base classes shared by every detector."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests


@dataclass
class DetectorContext:
    """Everything detectors need about the target site."""

    url: str
    final_url: str
    status_code: Optional[int]
    headers: Dict[str, str]
    cookies: Dict[str, str]
    raw_set_cookie: List[str]
    body: str
    elapsed_ms: float
    history: List[Dict[str, Any]] = field(default_factory=list)
    head_response: Optional[requests.Response] = None
    nobody_response: Optional[requests.Response] = None
    robots_txt: Optional[str] = None
    robots_status: Optional[int] = None
    request_meta: Dict[str, Any] = field(default_factory=dict)

    def header(self, name: str) -> str:
        """Case-insensitive header lookup that returns ``""`` when missing."""
        lname = name.lower()
        for k, v in self.headers.items():
            if k.lower() == lname:
                return v or ""
        return ""

    def all_header_values(self, name: str) -> List[str]:
        """Return every value for a header (including duplicates)."""
        lname = name.lower()
        out: List[str] = []
        for k, v in self.headers.items():
            if k.lower() == lname:
                out.append(v or "")
        return out


class Detector:
    """Base class for a detector. Subclasses implement ``run``."""

    name: str = "detector"

    def run(self, ctx: DetectorContext) -> List["Finding"]:  # type: ignore[name-defined]
        raise NotImplementedError
