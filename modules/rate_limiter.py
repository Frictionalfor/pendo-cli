"""
rate_limiter.py - Prevent aggressive requests
"""
import time
from utils.logger import get_logger

log = get_logger(__name__)

class RateLimiter:
    """Simple delay-based rate limiter."""

    def __init__(self, delay=0.5):
        self.delay = delay
        self._last = 0.0

    def wait(self):
        now = time.time()
        elapsed = now - self._last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last = time.time()
