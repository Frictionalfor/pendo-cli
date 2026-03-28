"""
cache.py - LRU response cache with TTL and size control.

Sits between the requester and the rest of the tool.
Every GET to the same URL within the TTL window returns the cached
response instead of hitting the network again.

POST/payload requests are never cached — they must always be live.
"""
import time
from collections import OrderedDict
from utils.logger import get_logger

log = get_logger(__name__)

# Defaults — override via CacheConfig
DEFAULT_MAX_SIZE = 256   # max cached responses
DEFAULT_TTL      = 300   # seconds a cached entry stays valid (5 min)


class CacheEntry:
    __slots__ = ("response", "stored_at", "hits")

    def __init__(self, response):
        self.response  = response
        self.stored_at = time.monotonic()
        self.hits      = 0

    def is_fresh(self, ttl):
        return (time.monotonic() - self.stored_at) < ttl


class RequestCache:
    """
    Thread-safe-ish LRU cache for HTTP responses.

    Key  : canonical URL string (GET only)
    Value: CacheEntry

    Eviction policy:
      1. Expired entries are pruned on every write.
      2. When max_size is reached, the least-recently-used entry is dropped.
    """

    def __init__(self, max_size=DEFAULT_MAX_SIZE, ttl=DEFAULT_TTL, enabled=True):
        self.max_size = max_size
        self.ttl      = ttl
        self.enabled  = enabled
        self._store   = OrderedDict()   # insertion/access order = LRU order
        self._hits    = 0
        self._misses  = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, url):
        """Return cached response or None (cache miss / expired)."""
        if not self.enabled:
            return None

        entry = self._store.get(url)
        if entry is None:
            self._misses += 1
            return None

        if not entry.is_fresh(self.ttl):
            del self._store[url]
            log.debug(f"Cache expired: {url}")
            self._misses += 1
            return None

        # Move to end = most recently used
        self._store.move_to_end(url)
        entry.hits += 1
        self._hits += 1
        log.debug(f"Cache hit [{entry.hits}x]: {url}")
        return entry.response

    def set(self, url, response):
        """Store a response. Evicts LRU entry if at capacity."""
        if not self.enabled:
            return

        self._evict_expired()

        if url in self._store:
            self._store.move_to_end(url)
            self._store[url] = CacheEntry(response)
            return

        if len(self._store) >= self.max_size:
            evicted_url, _ = self._store.popitem(last=False)
            log.debug(f"Cache evict (LRU): {evicted_url}")

        self._store[url] = CacheEntry(response)
        log.debug(f"Cache set: {url}  (size={len(self._store)})")

    def invalidate(self, url):
        """Remove a specific URL from cache."""
        removed = self._store.pop(url, None)
        if removed:
            log.debug(f"Cache invalidated: {url}")

    def clear(self):
        """Wipe the entire cache."""
        count = len(self._store)
        self._store.clear()
        self._hits   = 0
        self._misses = 0
        log.debug(f"Cache cleared ({count} entries removed)")

    def stats(self):
        """Return a dict of cache statistics."""
        total = self._hits + self._misses
        ratio = round(self._hits / total * 100, 1) if total else 0.0
        return {
            "size":      len(self._store),
            "max_size":  self.max_size,
            "ttl":       self.ttl,
            "hits":      self._hits,
            "misses":    self._misses,
            "hit_ratio": f"{ratio}%",
            "enabled":   self.enabled,
        }

    def __len__(self):
        return len(self._store)

    def __contains__(self, url):
        return self.get(url) is not None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _evict_expired(self):
        expired = [
            url for url, entry in self._store.items()
            if not entry.is_fresh(self.ttl)
        ]
        for url in expired:
            del self._store[url]
        if expired:
            log.debug(f"Cache pruned {len(expired)} expired entry(s)")
