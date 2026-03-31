"""
fuzzer.py - Mutation-based parameter fuzzer.

Takes a seed value and generates mutations:
- Type juggling (null, true, false, 0, -1, large int, float)
- Encoding variants (URL, double URL, HTML entity, unicode)
- Boundary values (empty, very long, special chars)
- Format string probes
- Template injection probes
- SSTI probes

Injects each mutation and flags anomalous responses
(status code change, response size delta, error strings).
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from urllib.parse import urlparse, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.deduplicator import deduplicate
from utils.logger import get_logger

log = get_logger(__name__)

# Error strings that indicate something interesting happened
ERROR_INDICATORS = [
    "exception", "traceback", "error", "undefined", "null",
    "syntax error", "unexpected", "invalid", "fatal",
    "stack trace", "at line", "warning:", "notice:",
    "division by zero", "index out of", "cannot read",
    "typeerror", "valueerror", "attributeerror",
    "{{", "}}", "${", "<%",   # template injection echoed back
]

# SSTI indicators in response
SSTI_INDICATORS = ["49", "7777777", "pendo_ssti"]


def generate_mutations(seed="test"):
    """Generate a list of mutation payloads from a seed value."""
    mutations = []

    # Type juggling
    mutations += [
        "null", "NULL", "None", "undefined",
        "true", "false", "True", "False",
        "0", "-1", "1", "999999999", "2147483647", "-2147483648",
        "0.0", "1.1", "NaN", "Infinity", "-Infinity",
        "[]", "{}", "[[]]",
    ]

    # Boundary values
    mutations += [
        "",                          # empty
        " ",                         # space
        "\t", "\n", "\r\n",
        "A" * 256,                   # long string
        "A" * 4096,
        "'", '"', "\\", "/",
        "<", ">", "&", ";",
        "%00",                       # null byte
        "%0a", "%0d",
        "../../etc/passwd",
    ]

    # Format string
    mutations += [
        "%s%s%s%s%s",
        "%d%d%d%d",
        "%x%x%x%x",
        "%.1000d",
        "%n",
    ]

    # SSTI probes (Jinja2, Twig, Freemarker, Velocity)
    mutations += [
        "{{7*7}}",           # Jinja2/Twig → 49
        "${7*7}",            # Freemarker/EL → 49
        "#{7*7}",            # Ruby ERB
        "<%= 7*7 %>",        # ERB
        "*{7*7}",            # Spring
        "{{7*'7'}}",         # Jinja2 → 7777777
        "pendo_ssti_{{1+1}}",
    ]

    # Encoding variants of the seed
    mutations += [
        seed.upper(),
        seed.lower(),
        seed + "'",
        seed + '"',
        seed + " OR 1=1",
        seed + "<script>",
        seed + "/../",
    ]

    return mutations


def run_fuzz(endpoints, requester, seed="test", threads=10, explain=False):
    """
    Fuzz all parameters of all endpoints with generated mutations.
    Returns a list of issue dicts.
    """
    mutations = generate_mutations(seed)
    jobs = []

    for ep in endpoints:
        if not ep.get("params"):
            continue
        for param in ep["params"]:
            # Get baseline first
            baseline = _get_baseline(ep, requester)
            for mutation in mutations:
                jobs.append((ep, param, mutation, baseline))

    if not jobs:
        return []

    results = []

    def _job(ep, param, mutation, baseline):
        return _fuzz_one(ep, param, mutation, baseline, requester, explain)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_job, ep, param, mut, bl): (ep, param, mut)
                   for ep, param, mut, bl in jobs}
        for future in as_completed(futures):
            try:
                found = future.result()
                if found:
                    results.append(found)
            except Exception as e:
                log.debug(f"Fuzz job error: {e}")

    return deduplicate(results)


def _get_baseline(ep, req):
    """Fetch the clean response for comparison."""
    try:
        resp = req._session.get(ep["url"], timeout=8, verify=False, allow_redirects=False)
        return {"status": resp.status_code, "length": len(resp.content), "body": resp.text}
    except Exception:
        return {"status": 200, "length": 0, "body": ""}


def _fuzz_one(ep, param, mutation, baseline, req, explain):
    """Inject one mutation and compare against baseline."""
    injected = dict(ep["params"])
    injected[param] = mutation
    parsed = urlparse(ep["url"])
    probe_url = urlunparse(parsed._replace(query=urlencode(injected)))

    try:
        resp = req._session.get(probe_url, timeout=8, verify=False, allow_redirects=False)
    except Exception:
        return None

    body   = resp.text.lower()
    status = resp.status_code
    length = len(resp.content)

    # Status code anomaly
    if status != baseline["status"] and status in (500, 502, 503):
        return {
            "type": "Fuzz: Server Error on Mutation",
            "endpoint": ep["url"],
            "param": param,
            "payload": mutation[:80],
            "risk": "High",
            "detail": f"Status changed: {baseline['status']} → {status}",
            "confidence": "Medium",
        }

    # Large response size delta (possible data leak or error dump)
    size_delta = abs(length - baseline["length"])
    if size_delta > 2000 and status == baseline["status"]:
        return {
            "type": "Fuzz: Anomalous Response Size",
            "endpoint": ep["url"],
            "param": param,
            "payload": mutation[:80],
            "risk": "Medium",
            "detail": f"Size delta: +{size_delta} bytes",
            "confidence": "Low",
        }

    # Error string in response
    for indicator in ERROR_INDICATORS:
        if indicator in body and indicator not in baseline["body"].lower():
            return {
                "type": "Fuzz: Error Disclosure on Mutation",
                "endpoint": ep["url"],
                "param": param,
                "payload": mutation[:80],
                "risk": "Medium",
                "detail": f"Error indicator: '{indicator}'",
                "confidence": "Medium",
            }

    # SSTI detection
    for ssti in SSTI_INDICATORS:
        if ssti in resp.text and ssti not in baseline["body"]:
            return {
                "type": "Fuzz: Possible SSTI (Template Injection)",
                "endpoint": ep["url"],
                "param": param,
                "payload": mutation[:80],
                "risk": "Critical",
                "detail": f"SSTI indicator '{ssti}' found in response",
                "confidence": "High",
            }

    return None
