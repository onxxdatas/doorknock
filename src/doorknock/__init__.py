"""doorknock — detect a website's anti-bot defenses and rate scraping difficulty."""

from doorknock.checker import scan, AntiBotScanner
from doorknock.models import (
    ScanResult,
    Finding,
    Severity,
    Difficulty,
    Category,
)

__version__ = "0.1.0"
__all__ = [
    "scan",
    "AntiBotScanner",
    "ScanResult",
    "Finding",
    "Severity",
    "Difficulty",
    "Category",
    "__version__",
]
