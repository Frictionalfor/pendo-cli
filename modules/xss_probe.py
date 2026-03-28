"""
xss_probe.py - Detect reflected input (XSS indicators) in responses
"""
import json
import re
import os
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

_PATTERNS_FILE = "data/patterns/xss_patterns.json"

def _load_patterns():
    try:
        with open(_PATTERNS_FILE) as f:
            return json.load(f).get("patterns", [])
    except (OSError, json.JSONDecodeError):
        return []

XSS_PATTERNS = _load_patterns()

def probe_xss(endpoints, limiter=None, explain=False):
    """Entry point when called directly (passive)."""
    return []

def detect_xss(resp, url, param=None, payload=None, explain=False,
               baseline_body=None):
    """
    Check if the payload is reflected in the response body.
    baseline_body: original response without injection — used to avoid
    flagging content that was already present before injection.
    """
    issues = []
    body = resp.text

    # Reflection check — only flag if payload wasn't already in the page
    if payload and payload in body:
        if baseline_body is None or payload not in baseline_body:
            issue = {
                "type": "Reflected Input (Possible XSS)",
                "endpoint": url,
                "param": param,
                "payload": payload,
                "risk": "Medium",
                "confidence": "High",
            }
            if explain:
                issue["reason"] = get_explanation("xss")
            issues.append(issue)
            log.debug(f"XSS reflection at {url} param={param}")
            return issues

    # Pattern-based check — only if pattern not in baseline
    for pattern in XSS_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            if baseline_body is None or not re.search(pattern, baseline_body, re.IGNORECASE):
                issue = {
                    "type": "XSS Pattern Detected",
                    "endpoint": url,
                    "param": param,
                    "payload": payload,
                    "risk": "Medium",
                    "confidence": "Medium",
                }
                if explain:
                    issue["reason"] = get_explanation("xss")
                issues.append(issue)
                break

    return issues
