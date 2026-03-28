"""
behavior_analyzer.py - Detect abnormal response behaviors
"""
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

# Status codes that may indicate interesting behavior
INTERESTING_CODES = {
    500: ("Server Error Exposed", "High"),
    403: ("Access Forbidden (Possible Sensitive Endpoint)", "Low"),
    401: ("Unauthenticated Endpoint", "Low"),
    301: ("Redirect Detected", "Info"),
    302: ("Redirect Detected", "Info"),
}

# Large response size threshold (bytes)
LARGE_RESPONSE_THRESHOLD = 500_000

def analyze_behavior(url, resp, explain=False):
    """
    Analyze a response for behavioral anomalies.
    Returns a list of issue dicts.
    """
    issues = []

    # Status code analysis
    if resp.status_code in INTERESTING_CODES:
        label, risk = INTERESTING_CODES[resp.status_code]
        if risk not in ("Info",):  # skip pure info
            issue = {
                "type": label,
                "endpoint": url,
                "risk": risk,
                "detail": f"HTTP {resp.status_code}",
            }
            if explain:
                issue["reason"] = get_explanation("behavior", code=resp.status_code)
            issues.append(issue)

    # Unusually large response
    content_len = len(resp.content)
    if content_len > LARGE_RESPONSE_THRESHOLD:
        issue = {
            "type": "Unusually Large Response",
            "endpoint": url,
            "risk": "Low",
            "detail": f"{content_len // 1024} KB",
        }
        if explain:
            issue["reason"] = (
                "An unusually large response may indicate data leakage or "
                "an unintended data dump from the server."
            )
        issues.append(issue)

    # Server header disclosure — only flag if version info is present
    server = resp.headers.get("Server", "")
    if server and any(char.isdigit() for char in server):
        issue = {
            "type": "Server Version Disclosure",
            "endpoint": url,
            "risk": "Low",
            "detail": server,
        }
        if explain:
            issue["reason"] = (
                f"The server is disclosing its software version ({server}). "
                "This helps attackers identify known vulnerabilities for that version."
            )
        issues.append(issue)

    return issues
