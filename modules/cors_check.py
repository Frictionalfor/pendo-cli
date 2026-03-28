"""
cors_check.py - Detect CORS misconfigurations.
Uses a live request with a spoofed Origin — never cached.
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

EVIL_ORIGIN = "https://evil.attacker.com"

def check_cors(url, explain=False, requester=None):
    """
    Send a request with a spoofed Origin header and check if it's reflected.
    Returns a list of issue dicts.
    """
    from core.requester import Requester
    req = requester or Requester(cache_on=False)
    issues = []

    try:
        # Must be a raw session call with custom Origin header — bypass all cache
        resp = req._session.get(
            url, headers={"Origin": EVIL_ORIGIN}, timeout=10, verify=False
        )
    except Exception as e:
        log.warning(f"CORS check failed: {e}")
        return issues

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*":
        issue = {
            "type": "CORS: Wildcard Origin Allowed",
            "endpoint": url,
            "risk": "Medium",
            "detail": "Access-Control-Allow-Origin: *",
        }
        if explain:
            issue["reason"] = get_explanation("cors_wildcard")
        issues.append(issue)

    elif EVIL_ORIGIN in acao:
        risk = "High" if acac.lower() == "true" else "Medium"
        issue = {
            "type": "CORS: Arbitrary Origin Reflected",
            "endpoint": url,
            "risk": risk,
            "detail": f"ACAO: {acao}  ACAC: {acac or 'false'}",
        }
        if explain:
            issue["reason"] = get_explanation("cors_reflect")
        issues.append(issue)

    return issues
