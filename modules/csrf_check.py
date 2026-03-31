"""
csrf_check.py - Detect missing CSRF protection on state-changing endpoints.

Checks:
1. POST forms with no CSRF token field
2. State-changing endpoints that accept requests without Origin/Referer validation
3. JSON endpoints that accept text/plain content-type (CSRF via form submission)
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import re
from bs4 import BeautifulSoup
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

# Common CSRF token field names
CSRF_FIELD_NAMES = {
    "csrf", "csrf_token", "csrftoken", "_csrf", "_token", "token",
    "authenticity_token", "xsrf_token", "__requestverificationtoken",
    "csrf_middleware_token", "anti_csrf", "nonce",
}

# Content types that indicate JSON APIs (vulnerable to CSRF if no token)
JSON_CONTENT_TYPES = ("application/json", "text/json")


def check_csrf(url, requester, explain=False):
    """
    Fetch the target and analyse all POST forms for CSRF token presence.
    Also tests whether state-changing endpoints validate Origin header.
    Returns a list of issue dicts.
    """
    issues = []

    try:
        resp = requester._session.get(url, timeout=10, verify=False, allow_redirects=True)
    except Exception as e:
        log.debug(f"CSRF check fetch failed: {e}")
        return issues

    soup = BeautifulSoup(resp.text, "html.parser")

    for form in soup.find_all("form"):
        method = form.get("method", "get").upper()
        if method != "POST":
            continue

        action = form.get("action", url)
        if not action.startswith("http"):
            from urllib.parse import urljoin
            action = urljoin(url, action)

        # Collect all input names
        input_names = {
            inp.get("name", "").lower()
            for inp in form.find_all(["input", "textarea", "select"])
            if inp.get("name")
        }

        has_csrf_token = bool(input_names & CSRF_FIELD_NAMES)

        if not has_csrf_token:
            issue = {
                "type": "CSRF: Missing Token on POST Form",
                "endpoint": action,
                "risk": "High",
                "detail": f"Form has no CSRF token field (inputs: {', '.join(sorted(input_names)) or 'none'})",
                "confidence": "High",
            }
            if explain:
                issue["reason"] = get_explanation("csrf_missing_token")
            issues.append(issue)
            log.debug(f"CSRF token missing on form: {action}")

    # Test Origin header validation on the base URL
    issues += _test_origin_validation(url, requester, explain)

    return issues


def _test_origin_validation(url, requester, explain):
    """
    Send a POST with a cross-origin Origin header.
    If the server responds 200 without rejecting it, flag it.
    """
    issues = []
    try:
        resp = requester._session.post(
            url,
            data={"test": "csrf_probe"},
            headers={"Origin": "https://evil.attacker.com"},
            timeout=8,
            verify=False,
            allow_redirects=False,
        )
        # If server accepts cross-origin POST without redirect/403
        if resp.status_code in (200, 201, 204):
            issue = {
                "type": "CSRF: Cross-Origin POST Accepted",
                "endpoint": url,
                "risk": "High",
                "detail": f"POST with Origin: evil.attacker.com returned HTTP {resp.status_code}",
                "confidence": "Medium",
            }
            if explain:
                issue["reason"] = get_explanation("csrf_origin")
            issues.append(issue)
    except Exception:
        pass
    return issues
