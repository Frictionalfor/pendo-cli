"""
deduplicator.py - Deduplicate findings and assign confidence scores.

Dedup key: type + endpoint (normalized) + param + header
Confidence scoring:
  - Multiple independent detections of same issue → upgrade confidence
  - Boolean-based blind SQLi → Low (needs manual verify)
  - Time-based blind SQLi → Medium
  - Error-based SQLi / XSS reflection → High
  - Header/CORS/cookie issues → High (deterministic)
"""
from urllib.parse import urlparse

# Base confidence per finding type
_CONFIDENCE_MAP = {
    "Possible SQL Injection":                    "High",
    "Blind SQLi (Time-Based)":                   "Medium",
    "Blind SQLi (Boolean-Based)":                "Low",
    "Reflected Input (Possible XSS)":            "High",
    "XSS Pattern Detected":                      "Medium",
    "Missing Security Header":                   "High",
    "CORS: Wildcard Origin Allowed":             "High",
    "CORS: Arbitrary Origin Reflected":          "High",
    "Open Redirect":                             "High",
    "Exposed Path Discovered":                   "High",
    "No Rate Limiting on Login Endpoint":        "Medium",
    "Cookie Missing HttpOnly Flag":              "High",
    "Cookie Missing Secure Flag":                "High",
    "Cookie Missing SameSite Attribute":         "High",
    "SSL: Certificate Expired":                  "High",
    "SSL: Certificate Expiring Soon":            "High",
    "SSL: Self-Signed Certificate":              "High",
    "SSL: Weak Protocol Supported (TLS 1.0)":   "High",
    "SSL: Weak Protocol Supported (TLS 1.1)":   "High",
    "Server Error Exposed":                      "High",
    "Server Version Disclosure":                 "High",
    "Unauthenticated Endpoint":                  "Medium",
    "Access Forbidden (Possible Sensitive Endpoint)": "Medium",
    "Unusually Large Response":                  "Low",
    # V1.1
    "CSRF: Missing Token on POST Form":          "High",
    "CSRF: Cross-Origin POST Accepted":          "Medium",
    "HTTP Method Tampering: DELETE Accepted":    "High",
    "HTTP Method Tampering: PUT Accepted":       "High",
    "HTTP Method Tampering: PATCH Accepted":     "Medium",
    "HTTP Method Tampering: Dangerous Methods Allowed": "Medium",
    "XXE: XML External Entity Injection":        "High",
    "SSRF: Server-Side Request Forgery":         "High",
    "Path Traversal":                            "High",
    "Command Injection":                         "High",
    "JWT: Algorithm None Vulnerability":         "High",
    "JWT: Weak Secret":                          "High",
    "JWT: Missing Expiry (exp) Claim":           "Medium",
    "JWT: Token Expired":                        "Low",
    "JWT: Sensitive Data in Payload":            "High",
    "JWT: Missing 'iss' Claim":                  "Low",
    "JWT: Missing 'iat' Claim":                  "Low",
    "Fuzz: Server Error on Mutation":            "Medium",
    "Fuzz: Anomalous Response Size":             "Low",
    "Fuzz: Error Disclosure on Mutation":        "Medium",
    "Fuzz: Possible SSTI (Template Injection)":  "High",
}


def deduplicate(findings):
    """
    Remove duplicate findings and ensure every finding has a confidence field.
    Returns a sorted, deduplicated list.
    """
    seen = {}

    for f in findings:
        key = _make_key(f)
        if key not in seen:
            # Assign confidence if not already set
            if "confidence" not in f:
                f["confidence"] = _CONFIDENCE_MAP.get(f.get("type", ""), "Medium")
            seen[key] = f
        else:
            # Seen before — upgrade confidence if we have a second hit
            existing = seen[key]
            existing["confidence"] = _upgrade(existing.get("confidence", "Low"))

    # Sort: High risk first, then Medium, then Low
    order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    return sorted(seen.values(), key=lambda x: order.get(x.get("risk", "Low"), 3))


def _make_key(f):
    """Normalize endpoint URL (strip query string) for dedup key."""
    endpoint = f.get("endpoint", "")
    try:
        endpoint = urlparse(endpoint)._replace(query="", fragment="").geturl()
    except Exception:
        pass
    return (
        f.get("type", ""),
        endpoint,
        f.get("param", ""),
        f.get("header", ""),
    )


def _upgrade(confidence):
    order = ["Low", "Medium", "High"]
    idx = order.index(confidence) if confidence in order else 0
    return order[min(idx + 1, len(order) - 1)]
