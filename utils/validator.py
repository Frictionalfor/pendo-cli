"""
validator.py - URL validation and sanitization
"""
from urllib.parse import urlparse

def validate_url(url):
    """
    Validate and normalize a URL.
    Returns the cleaned URL string, or None if invalid.
    """
    if not url:
        return None

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        return None

    # Strip trailing slash for consistency
    return url.rstrip("/")
