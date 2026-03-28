"""
dir_bruteforce.py - Directory and file discovery via wordlist bruteforce.
"""
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)

DEFAULT_WORDLIST = "data/wordlists/dirs.txt"

# Status codes that indicate something exists
INTERESTING = {200, 201, 301, 302, 403, 401, 500}


def bruteforce_dirs(base_url, requester, wordlist=None, threads=10, explain=False):
    """
    Probe base_url + each word from the wordlist.
    Returns a list of issue dicts for discovered paths.
    """
    wl = wordlist or DEFAULT_WORDLIST
    words = _load_wordlist(wl)
    if not words:
        log.debug("Dir bruteforce: no wordlist loaded")
        return []

    base = base_url.rstrip("/")
    results = []

    def probe(word):
        url = f"{base}/{word.lstrip('/')}"
        try:
            resp = requester._session.get(url, timeout=8, verify=False, allow_redirects=False)
            if resp.status_code in INTERESTING:
                return url, resp.status_code
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe, w): w for w in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                url, code = result
                risk = "High" if code in (200, 201) else "Medium" if code in (301, 302) else "Low"
                issue = {
                    "type": "Exposed Path Discovered",
                    "endpoint": url,
                    "risk": risk,
                    "detail": f"HTTP {code}",
                    "confidence": "High" if code == 200 else "Medium",
                }
                if explain:
                    issue["reason"] = get_explanation("dir_bruteforce", code=code)
                results.append(issue)
                log.debug(f"Dir found: {url} [{code}]")

    return results


def _load_wordlist(path):
    if not os.path.exists(path):
        log.debug(f"Wordlist not found: {path}")
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]
