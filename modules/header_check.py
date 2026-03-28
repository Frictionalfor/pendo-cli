"""
header_check.py - Security headers analysis
"""
import json
import os
from core.requester import fetch
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

_HEADERS_FILE = "data/patterns/headers.json"

def _load_required_headers():
    try:
        with open(_HEADERS_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return _FALLBACK_HEADERS

_FALLBACK_HEADERS = {
    "Content-Security-Policy":   {"risk": "Medium"},
    "X-Frame-Options":           {"risk": "Medium"},
    "Strict-Transport-Security": {"risk": "High"},
    "X-Content-Type-Options":    {"risk": "Low"},
    "Referrer-Policy":           {"risk": "Low"},
    "Permissions-Policy":        {"risk": "Low"},
}

def check_headers(target, explain=False, requester=None):
    """
    Fetch target and check for missing security headers.
    Returns a list of issue dicts.
    """
    from core.requester import Requester
    req = requester or Requester(cache_on=True)
    resp = req.get(target)
    if not resp:
        log.warning(f"Could not fetch headers for {target}")
        return []

    required = _load_required_headers()
    issues = []

    for header, meta in required.items():
        if header not in resp.headers:
            issue = {
                "type": "Missing Security Header",
                "header": header,
                "endpoint": target,
                "risk": meta.get("risk", "Low"),
            }
            if explain:
                issue["reason"] = get_explanation("header", header=header)
            issues.append(issue)
            log.debug(f"Missing header: {header}")

    return issues
