"""
response_store.py - Store and organize HTTP responses during a scan session
"""

class ResponseStore:
    """In-memory store for HTTP responses keyed by URL."""

    def __init__(self):
        self._store = {}

    def save(self, url, response):
        self._store[url] = response

    def get(self, url):
        return self._store.get(url)

    def all(self):
        return dict(self._store)

    def urls(self):
        return list(self._store.keys())

    def clear(self):
        self._store.clear()

    def __len__(self):
        return len(self._store)
