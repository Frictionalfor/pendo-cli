"""
open_redirect.py - Detect open redirect vulnerabilities in URL parameters.
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "next", "return",
    "return_url", "returnTo", "goto", "dest", "destination", "target",
    "rurl", "r", "u", "link", "forward", "continue", "location", "ref",
]

CANARY = "https://evil.attacker.com"

def check_open_redirect(endpoints, requester, explain=False):
    """
    For each endpoint, check if any parameter name matches known redirect params.
    Inject a canary URL and check if the response redirects to it.
    Returns a list of issue dicts.
    """
    issues = []
    tested = set()

    for ep in endpoints:
        url = ep["url"]
        params = ep.get("params", {})

        for param in params:
            if param.lower() not in REDIRECT_PARAMS:
                continue

            key = f"{url}:{param}"
            if key in tested:
                continue
            tested.add(key)

            injected = dict(params)
            injected[param] = CANARY

            parsed = urlparse(url)
            new_url = urlunparse(parsed._replace(query=urlencode(injected)))

            try:
                # Don't follow redirects — we want to inspect the Location header
                resp = requester._session.get(
                    new_url, timeout=10, verify=False, allow_redirects=False
                )
            except Exception as e:
                log.debug(f"Open redirect check failed: {e}")
                continue

            location = resp.headers.get("Location", "")
            if CANARY in location or "evil.attacker.com" in location:
                issue = {
                    "type": "Open Redirect",
                    "endpoint": url,
                    "param": param,
                    "risk": "Medium",
                    "detail": f"Redirects to: {location}",
                    "confidence": "High",
                }
                if explain:
                    issue["reason"] = get_explanation("open_redirect")
                issues.append(issue)
                log.debug(f"Open redirect confirmed: {url} param={param}")

    return issues
