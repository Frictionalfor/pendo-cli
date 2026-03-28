"""
cookie_check.py - Analyse Set-Cookie headers for missing security flags.
Checks HttpOnly, Secure, SameSite on every cookie set by the target.
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)


def check_cookies(url, requester, explain=False):
    """
    Fetch the URL and inspect all Set-Cookie headers.
    Returns a list of issue dicts.
    """
    try:
        resp = requester._session.get(url, timeout=10, verify=False, allow_redirects=True)
    except Exception as e:
        log.debug(f"Cookie check failed: {e}")
        return []

    issues = []
    raw_cookies = resp.headers.getlist("Set-Cookie") if hasattr(resp.headers, "getlist") \
        else [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]

    if not raw_cookies:
        return []

    for raw in raw_cookies:
        name = raw.split("=")[0].strip()
        lower = raw.lower()

        if "httponly" not in lower:
            issue = {
                "type": "Cookie Missing HttpOnly Flag",
                "endpoint": url,
                "risk": "Medium",
                "detail": f"Cookie: {name}",
                "confidence": "High",
            }
            if explain:
                issue["reason"] = get_explanation("cookie_httponly")
            issues.append(issue)

        if "secure" not in lower:
            issue = {
                "type": "Cookie Missing Secure Flag",
                "endpoint": url,
                "risk": "Medium",
                "detail": f"Cookie: {name}",
                "confidence": "High",
            }
            if explain:
                issue["reason"] = get_explanation("cookie_secure")
            issues.append(issue)

        if "samesite" not in lower:
            issue = {
                "type": "Cookie Missing SameSite Attribute",
                "endpoint": url,
                "risk": "Low",
                "detail": f"Cookie: {name}",
                "confidence": "High",
            }
            if explain:
                issue["reason"] = get_explanation("cookie_samesite")
            issues.append(issue)

    return issues
