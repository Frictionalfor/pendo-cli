"""
probe_engine.py - Threaded payload injection engine.
Probe requests always bypass cache — every injected request must be live.
"""
from urllib.parse import urlparse, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.requester import Requester
from modules.payload_manager import load_payloads
from modules.sqli_probe import detect_sqli
from modules.xss_probe import detect_xss
from utils.logger import get_logger

log = get_logger(__name__)


def run_probe(endpoints, payloads_source, limiter=None, explain=False,
              requester=None, threads=10):
    """
    Inject payloads into each parameter of each endpoint using a thread pool.
    Returns a flat list of issue dicts.
    """
    req = requester or Requester(cache_on=False)

    payloads = load_payloads(payloads_source)
    if not payloads:
        log.warning("No payloads loaded.")
        return []

    # Build all (endpoint, param, payload) jobs
    jobs = []
    for ep in endpoints:
        if not ep.get("params"):
            continue
        for param in ep["params"]:
            for payload in payloads:
                jobs.append((ep, param, payload))

    if not jobs:
        return []

    results = []
    tested  = 0

    def _job(ep, param, payload):
        if limiter:
            limiter.wait()
        resp = _send(ep, param, payload, req)
        if not resp:
            return []
        found = []
        found += detect_sqli(resp, ep["url"], param, payload, explain=explain)
        found += detect_xss(resp, ep["url"], param, payload, explain=explain,
                            baseline_body=_baselines.get(ep["url"]))
        return found

    # Pre-fetch baselines for XSS false-positive prevention
    _baselines = {}
    for ep in endpoints:
        if ep.get("params"):
            try:
                br = req.get(ep["url"], bypass_cache=True)
                if br:
                    _baselines[ep["url"]] = br.text
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_job, ep, param, payload): (ep, param, payload)
                   for ep, param, payload in jobs}
        for future in as_completed(futures):
            tested += 1
            try:
                results += future.result()
            except Exception as e:
                log.debug(f"Probe job error: {e}")

    log.info(f"Probe complete: {tested} request(s), {len(results)} finding(s)")
    return results


def _send(ep, param, payload, req):
    injected = dict(ep["params"])
    injected[param] = payload
    method = ep.get("method", "GET")
    url = ep["url"]

    if method == "POST":
        return req.post(url, data=injected)
    else:
        parsed = urlparse(url)
        new_url = urlunparse(parsed._replace(query=urlencode(injected)))
        return req.get(new_url, bypass_cache=True)
