"""
payload_manager.py - Load and manage payload lists
"""
import os
from utils.logger import get_logger

log = get_logger(__name__)

DEFAULT_PAYLOAD_DIR = "data/payloads"

def load_payloads(source):
    """
    Load payloads from a file path or a named category (sqli, xss, generic).
    Returns a list of payload strings.
    """
    # If it's a category name, resolve to file
    if not os.path.exists(source):
        candidate = os.path.join(DEFAULT_PAYLOAD_DIR, f"{source}.txt")
        if os.path.exists(candidate):
            source = candidate
        else:
            log.error(f"Payload source not found: {source}")
            return []

    try:
        with open(source) as f:
            payloads = [
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            ]
        log.info(f"Loaded {len(payloads)} payload(s) from {source}")
        return payloads
    except OSError as e:
        log.error(f"Failed to read payloads: {e}")
        return []
