"""
sqli_probe.py - Detect SQL injection error patterns in responses
"""
import json
import re
import os
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

_PATTERNS_FILE = "data/patterns/sqli_patterns.json"
_FALLBACK = [
    r"sql syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"syntax error",
    r"unclosed quotation",
    r"pg_query\(\)",
    r"sqlite3",
    r"you have an error in your sql",
    r"warning: mysql",
    r"division by zero",
    r"supplied argument is not a valid mysql",
    r"microsoft ole db provider for sql server",
]

def _load_patterns():
    try:
        with open(_PATTERNS_FILE) as f:
            return json.load(f).get("patterns", _FALLBACK)
    except (OSError, json.JSONDecodeError):
        return _FALLBACK

PATTERNS = _load_patterns()

def probe_sqli(endpoints, limiter=None, explain=False):
    """Entry point when called directly (passive, no injection)."""
    # Passive: just analyze already-fetched responses
    return []

def detect_sqli(resp, url, param=None, payload=None, explain=False):
    """
    Check a response for SQL error signatures.
    Returns a list of issue dicts.
    """
    body = resp.text
    for pattern in PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            issue = {
                "type": "Possible SQL Injection",
                "endpoint": url,
                "param": param,
                "payload": payload,
                "risk": "High",
            }
            if explain:
                issue["reason"] = get_explanation("sqli")
            log.debug(f"SQLi pattern matched at {url} param={param}")
            return [issue]
    return []
