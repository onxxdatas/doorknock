"""Individual detector modules."""

from doorknock.detectors.base import DetectorContext, Detector
from doorknock.detectors.waf import WAFDetector
from doorknock.detectors.bot_management import BotManagementDetector
from doorknock.detectors.captcha import CaptchaDetector
from doorknock.detectors.javascript import JSChallengeDetector
from doorknock.detectors.rate_limit import RateLimitDetector
from doorknock.detectors.headers import HeadersDetector
from doorknock.detectors.cookies import CookiesDetector
from doorknock.detectors.user_agent import UserAgentDetector
from doorknock.detectors.tls import TLSDetector
from doorknock.detectors.robots import RobotsDetector
from doorknock.detectors.fingerprinting import FingerprintingDetector

ALL_DETECTORS = [
    WAFDetector(),
    BotManagementDetector(),
    CaptchaDetector(),
    JSChallengeDetector(),
    RateLimitDetector(),
    HeadersDetector(),
    CookiesDetector(),
    UserAgentDetector(),
    TLSDetector(),
    RobotsDetector(),
    FingerprintingDetector(),
]

__all__ = [
    "DetectorContext",
    "Detector",
    "ALL_DETECTORS",
    "WAFDetector",
    "BotManagementDetector",
    "CaptchaDetector",
    "JSChallengeDetector",
    "RateLimitDetector",
    "HeadersDetector",
    "CookiesDetector",
    "UserAgentDetector",
    "TLSDetector",
    "RobotsDetector",
    "FingerprintingDetector",
]
