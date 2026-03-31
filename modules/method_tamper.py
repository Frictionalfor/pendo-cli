"""
method_tamper.py - HTTP method tampering detection.

Tests each discovered endpoint with non-standard HTTP methods:
PUT, DELETE, PATCH, OPTIONS, TRACE, HEAD

Flags endpoints that respond unexpectedly to dangerous methods,
especially DELETE/PUT returning 200/201/204 on API paths.
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

# Methods to test beyond GET/POST
TEST_METHODS = ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]

# Status codes that indicate the method was accepted
ACCEPTED_CODES = {200, 201, 204}

# Methods that are dangerous if accepted
DANGEROUS = {"PUT", "DELETE", "PATCH", "TRACE"}


def check_method_tampering(endpoints, requester, threads=10, explain=False):
    """
    For each endpoint, test all non-standard HTTP methods.
    Returns a list of issue dicts.
    """
    issues = []
    jobs = []

    for ep in endpoints:
        url = ep["url"]
        for method in TEST_METHODS:
            jobs.append((url, method))

    def _probe(url, method):
        try:
            resp = requester._session.request(
                method, url, timeout=8, verify=False, allow_redirects=False
            )
            return url, method, resp.status_code
        except Exception:
            return url, method, None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_probe, url, method): (url, method)
                   for url, method in jobs}
        for future in as_completed(futures):
            url, method, code = future.result()
            if code is None:
                continue

            if method == "OPTIONS":
                # Check Allow header for dangerous methods
                resp_obj = None
                try:
                    resp_obj = requester._session.options(
                        url, timeout=8, verify=False, allow_redirects=False
                    )
                    allow = resp_obj.headers.get("Allow", "")
                    dangerous_allowed = [
                        m for m in DANGEROUS if m in allow.upper()
                    ]
                    if dangerous_allowed:
                        issue = {
                            "type": "HTTP Method Tampering: Dangerous Methods Allowed",
                            "endpoint": url,
                            "risk": "Medium",
                            "detail": f"Allow: {allow}",
                            "confidence": "High",
                        }
                        if explain:
                            issue["reason"] = get_explanation("method_tamper_options")
                        issues.append(issue)
                except Exception:
                    pass
                continue

            if method in DANGEROUS and code in ACCEPTED_CODES:
                risk = "High" if method in ("DELETE", "PUT") else "Medium"
                issue = {
                    "type": f"HTTP Method Tampering: {method} Accepted",
                    "endpoint": url,
                    "risk": risk,
                    "detail": f"HTTP {method} returned {code}",
                    "confidence": "High" if code == 200 else "Medium",
                }
                if explain:
                    issue["reason"] = get_explanation("method_tamper", method=method)
                issues.append(issue)
                log.debug(f"Method tamper: {method} {url} -> {code}")

    return issues
