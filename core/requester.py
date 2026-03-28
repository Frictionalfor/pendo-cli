"""
requester.py - Controlled HTTP requester with integrated cache.

Rules:
  - GET requests are cached (TTL-based LRU).
  - POST / payload injection requests bypass cache entirely.
  - A single Requester instance is shared per scan session.
  - Auth headers (cookies, tokens) are injected at the session level.
  - purge_all() wipes every layer of state after each operation.
"""
import gc
import os
import requests
from core.cache import RequestCache
from utils.logger import get_logger

log = get_logger(__name__)

_DEFAULT_HEADERS = {"User-Agent": "PendoCLI/1.0 (Security Scanner)"}

# Registry of every Requester created this process — so purge_all() can reach them
_registry: list = []


class Requester:
    def __init__(
        self,
        cache_ttl=300,
        cache_size=256,
        cache_on=True,
        cookies=None,
        auth_header=None,
        timeout=10,
    ):
        self.timeout = timeout
        self.cache   = RequestCache(max_size=cache_size, ttl=cache_ttl, enabled=cache_on)

        self._session = requests.Session()
        self._session.headers.update(_DEFAULT_HEADERS)
        self._session.verify = False

        if cookies:
            self._session.cookies.update(cookies)
            log.debug(f"Session cookies set: {list(cookies.keys())}")

        if auth_header:
            name, value = auth_header
            self._session.headers[name] = value
            log.debug(f"Auth header set: {name}")

        _registry.append(self)

    # ------------------------------------------------------------------
    # Public fetch interface
    # ------------------------------------------------------------------

    def get(self, url, params=None, bypass_cache=False):
        cache_key = self._cache_key(url, params)
        if not bypass_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached
        resp = self._do_get(url, params)
        if resp is not None:
            self.cache.set(cache_key, resp)
        return resp

    def post(self, url, data=None):
        return self._do_post(url, data)

    def fetch(self, url, method="GET", params=None, data=None, bypass_cache=False):
        if method.upper() == "POST" or data:
            return self.post(url, data=data)
        return self.get(url, params=params, bypass_cache=bypass_cache)

    # ------------------------------------------------------------------
    # Cache / session control
    # ------------------------------------------------------------------

    def invalidate(self, url):
        self.cache.invalidate(url)

    def clear_cache(self):
        self.cache.clear()

    def cache_stats(self):
        return self.cache.stats()

    def set_cookie(self, name, value):
        self._session.cookies.set(name, value)

    def set_auth_header(self, name, value):
        self._session.headers[name] = value

    def wipe(self):
        """
        Full wipe of this instance:
        - LRU response cache
        - Session cookies
        - Session headers (back to default)
        - Close all open connections (urllib3 pool)
        """
        self.cache.clear()
        self._session.cookies.clear()
        self._session.headers.clear()
        self._session.headers.update(_DEFAULT_HEADERS)
        self._session.close()
        log.debug("Requester wiped: cache + session + connections closed")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _do_get(self, url, params=None):
        try:
            resp = self._session.get(
                url, params=params, timeout=self.timeout, allow_redirects=True
            )
            log.debug(f"GET {url} -> {resp.status_code}")
            return resp
        except requests.exceptions.Timeout:
            log.warning(f"Timeout: {url}")
        except requests.exceptions.ConnectionError:
            log.warning(f"Connection error: {url}")
        except requests.exceptions.RequestException as e:
            log.warning(f"Request failed: {url} - {e}")
        return None

    def _do_post(self, url, data=None):
        try:
            resp = self._session.post(
                url, data=data, timeout=self.timeout, allow_redirects=True
            )
            log.debug(f"POST {url} -> {resp.status_code}")
            return resp
        except requests.exceptions.Timeout:
            log.warning(f"Timeout: {url}")
        except requests.exceptions.ConnectionError:
            log.warning(f"Connection error: {url}")
        except requests.exceptions.RequestException as e:
            log.warning(f"Request failed: {url} - {e}")
        return None

    @staticmethod
    def _cache_key(url, params=None):
        if not params:
            return url
        from urllib.parse import urlencode
        return f"{url}?{urlencode(sorted(params.items()))}"


# ---------------------------------------------------------------------------
# Module-level singleton — used by modules that call fetch() directly
# ---------------------------------------------------------------------------
_default = Requester(cache_on=True)

def fetch(url, method="GET", params=None, data=None):
    """Backward-compatible shim."""
    return _default.fetch(url, method=method, params=params, data=data)


# ---------------------------------------------------------------------------
# Global purge — wipes EVERYTHING after an operation
# ---------------------------------------------------------------------------

def purge_all(store=None, silent=False):
    """
    Wipe every layer of in-memory state:
      1. All Requester instances (LRU cache + session cookies + connections)
      2. The _default singleton cache
      3. ResponseStore (crawl responses)
      4. gc.collect() to release response objects from memory
    """
    from utils.formatter import print_info

    # 1. Wipe every registered Requester
    wiped = 0
    for req in _registry:
        try:
            req.wipe()
            wiped += 1
        except Exception:
            pass
    _registry.clear()

    # Re-register a fresh _default so the shim still works
    global _default
    _default = Requester(cache_on=True)

    # 2. ResponseStore
    if store is not None:
        store._store.clear()

    # 3. Force GC — releases response body buffers held by urllib3
    gc.collect()

    if not silent:
        print_info(f"Full purge complete — {wiped} session(s) wiped, memory released.")
    """
    Wraps requests.Session with cache control.

    Parameters
    ----------
    cache_ttl   : seconds a cached GET response stays valid
    cache_size  : max number of responses to keep in memory
    cache_on    : set False to disable caching entirely (e.g. probe mode)
    cookies     : dict of cookie name→value to inject
    auth_header : tuple ("Header-Name", "value") e.g. ("Authorization", "Bearer ...")
    timeout     : per-request timeout in seconds
    """

    def __init__(
        self,
        cache_ttl=300,
        cache_size=256,
        cache_on=True,
        cookies=None,
        auth_header=None,
        timeout=10,
    ):
        self.timeout = timeout
        self.cache   = RequestCache(max_size=cache_size, ttl=cache_ttl, enabled=cache_on)

        self._session = requests.Session()
        self._session.headers.update(_DEFAULT_HEADERS)
        self._session.verify = False

        if cookies:
            self._session.cookies.update(cookies)
            log.debug(f"Session cookies set: {list(cookies.keys())}")

        if auth_header:
            name, value = auth_header
            self._session.headers[name] = value
            log.debug(f"Auth header set: {name}")

    # ------------------------------------------------------------------
    # Public fetch interface
    # ------------------------------------------------------------------

    def get(self, url, params=None, bypass_cache=False):
        """
        Cached GET. Returns response or None.
        bypass_cache=True forces a live request and refreshes the cache entry.
        """
        cache_key = self._cache_key(url, params)

        if not bypass_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached

        resp = self._do_get(url, params)
        if resp is not None:
            self.cache.set(cache_key, resp)
        return resp

    def post(self, url, data=None):
        """
        Uncached POST — always live, never stored.
        """
        return self._do_post(url, data)

    def fetch(self, url, method="GET", params=None, data=None, bypass_cache=False):
        """
        Unified fetch used by crawler and probe engine.
        POST and any request with a payload bypass cache automatically.
        """
        if method.upper() == "POST" or data:
            return self.post(url, data=data)
        return self.get(url, params=params, bypass_cache=bypass_cache)

    # ------------------------------------------------------------------
    # Cache control
    # ------------------------------------------------------------------

    def invalidate(self, url):
        self.cache.invalidate(url)

    def clear_cache(self):
        self.cache.clear()

    def cache_stats(self):
        return self.cache.stats()

    def set_cookie(self, name, value):
        self._session.cookies.set(name, value)
        log.debug(f"Cookie added: {name}")

    def set_auth_header(self, name, value):
        self._session.headers[name] = value
        log.debug(f"Auth header updated: {name}")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _do_get(self, url, params=None):
        try:
            resp = self._session.get(
                url, params=params, timeout=self.timeout, allow_redirects=True
            )
            log.debug(f"GET {url} -> {resp.status_code}")
            return resp
        except requests.exceptions.Timeout:
            log.warning(f"Timeout: {url}")
        except requests.exceptions.ConnectionError:
            log.warning(f"Connection error: {url}")
        except requests.exceptions.RequestException as e:
            log.warning(f"Request failed: {url} - {e}")
        return None

    def _do_post(self, url, data=None):
        try:
            resp = self._session.post(
                url, data=data, timeout=self.timeout, allow_redirects=True
            )
            log.debug(f"POST {url} -> {resp.status_code}")
            return resp
        except requests.exceptions.Timeout:
            log.warning(f"Timeout: {url}")
        except requests.exceptions.ConnectionError:
            log.warning(f"Connection error: {url}")
        except requests.exceptions.RequestException as e:
            log.warning(f"Request failed: {url} - {e}")
        return None

    @staticmethod
    def _cache_key(url, params=None):
        if not params:
            return url
        from urllib.parse import urlencode
        return f"{url}?{urlencode(sorted(params.items()))}"


# ---------------------------------------------------------------------------
# Module-level singleton for modules that import `fetch` directly
# (header_check, cors_check, behavior_analyzer).
# Replaced per-scan by the session-scoped Requester passed through the stack.
# ---------------------------------------------------------------------------
_default = Requester(cache_on=True)

def fetch(url, method="GET", params=None, data=None):
    """Backward-compatible shim used by standalone module calls."""
    return _default.fetch(url, method=method, params=params, data=data)
