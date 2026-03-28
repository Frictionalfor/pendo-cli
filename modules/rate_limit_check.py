"""
rate_limit_check.py - Test whether login/sensitive endpoints enforce rate limiting.
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

BURST_COUNT  = 15   # requests to send
LOGIN_PATHS  = ["/login", "/signin", "/auth", "/api/login", "/api/auth",
                "/api/v1/login", "/user/login", "/account/login"]


def check_rate_limiting(base_url, requester, explain=False):
    """
    For each known login-style path that exists (non-404), send a burst of
    POST requests and check if rate limiting kicks in.
    Returns a list of issue dicts.
    """
    issues = []
    base = base_url.rstrip("/")

    for path in LOGIN_PATHS:
        url = base + path
        try:
            probe = requester._session.get(url, timeout=5, verify=False, allow_redirects=False)
            if probe.status_code == 404:
                continue
        except Exception:
            continue

        # Endpoint exists — burst test it
        codes = []
        for _ in range(BURST_COUNT):
            try:
                r = requester._session.post(
                    url,
                    data={"username": "test", "password": "test"},
                    timeout=5,
                    verify=False,
                    allow_redirects=False,
                )
                codes.append(r.status_code)
            except Exception:
                break

        if not codes:
            continue

        has_429 = 429 in codes
        has_lockout = any(c in (423, 403) for c in codes)

        if not has_429 and not has_lockout:
            issue = {
                "type": "No Rate Limiting on Login Endpoint",
                "endpoint": url,
                "risk": "High",
                "detail": f"{BURST_COUNT} requests sent, all succeeded (codes: {set(codes)})",
                "confidence": "Medium",
            }
            if explain:
                issue["reason"] = get_explanation("rate_limit")
            issues.append(issue)
            log.debug(f"No rate limit detected at {url}")

    return issues
