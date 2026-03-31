"""
jwt_check.py - JWT (JSON Web Token) security analysis.

If a Bearer token is present in the auth header, decode and check:
- alg: none bypass vulnerability
- Weak HS256 secret (common password list)
- Token expiry
- Sensitive data in payload (PII, passwords, keys)
- Missing standard claims (exp, iat, iss)
"""
import base64
import json
import hmac
import hashlib
import time
from utils.logger import get_logger
from modules.explain import get_explanation

log = get_logger(__name__)

# Common weak secrets to test
WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin", "test",
    "key", "jwt", "token", "changeme", "supersecret", "mysecret",
    "your-256-bit-secret", "your-secret", "secret123", "pass",
    "", "null", "undefined", "jwt_secret", "app_secret",
]

# Sensitive field names to flag in payload
SENSITIVE_FIELDS = {
    "password", "passwd", "pwd", "secret", "key", "api_key",
    "apikey", "token", "credit_card", "ssn", "dob",
}


def check_jwt(auth_header_value, explain=False):
    """
    Analyse a JWT token from an Authorization header value.
    auth_header_value: the raw value e.g. 'Bearer eyJ...'
    Returns a list of issue dicts.
    """
    issues = []

    token = _extract_token(auth_header_value)
    if not token:
        return issues

    parts = token.split(".")
    if len(parts) != 3:
        return issues

    header  = _decode_part(parts[0])
    payload = _decode_part(parts[1])

    if not header or not payload:
        return issues

    log.debug(f"JWT header: {header}")

    # 1. alg: none
    alg = header.get("alg", "").lower()
    if alg == "none":
        issues.append({
            "type": "JWT: Algorithm None Vulnerability",
            "risk": "Critical",
            "detail": "Token uses alg: none — signature is not verified",
            "confidence": "High",
            "reason": get_explanation("jwt_alg_none") if explain else None,
        })

    # 2. Weak secret (HS256 only)
    if alg == "hs256":
        cracked = _crack_hs256(token, parts)
        if cracked is not None:
            issues.append({
                "type": "JWT: Weak Secret",
                "risk": "Critical",
                "detail": f"Secret cracked: '{cracked}'",
                "confidence": "High",
                "reason": get_explanation("jwt_weak_secret") if explain else None,
            })

    # 3. Expiry check
    exp = payload.get("exp")
    if exp is None:
        issues.append({
            "type": "JWT: Missing Expiry (exp) Claim",
            "risk": "Medium",
            "detail": "Token has no expiry — valid indefinitely",
            "confidence": "High",
            "reason": get_explanation("jwt_no_exp") if explain else None,
        })
    elif exp < time.time():
        issues.append({
            "type": "JWT: Token Expired",
            "risk": "Low",
            "detail": f"Token expired at {exp}",
            "confidence": "High",
        })

    # 4. Sensitive data in payload
    for field in payload:
        if field.lower() in SENSITIVE_FIELDS:
            issues.append({
                "type": "JWT: Sensitive Data in Payload",
                "risk": "High",
                "detail": f"Field '{field}' found in JWT payload (JWTs are base64 — not encrypted)",
                "confidence": "High",
                "reason": get_explanation("jwt_sensitive") if explain else None,
            })

    # 5. Missing standard claims
    for claim in ("iss", "iat"):
        if claim not in payload:
            issues.append({
                "type": f"JWT: Missing '{claim}' Claim",
                "risk": "Low",
                "detail": f"Standard claim '{claim}' is absent",
                "confidence": "High",
            })

    # Clean None reasons
    for i in issues:
        if i.get("reason") is None:
            i.pop("reason", None)

    return issues


def _extract_token(value):
    if not value:
        return None
    value = value.strip()
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    # Might be a raw token
    if value.count(".") == 2:
        return value
    return None


def _decode_part(part):
    try:
        padded = part + "=" * (4 - len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def _crack_hs256(token, parts):
    """Try to crack HS256 signature with common weak secrets."""
    header_payload = f"{parts[0]}.{parts[1]}".encode()
    try:
        sig_bytes = base64.urlsafe_b64decode(parts[2] + "==")
    except Exception:
        return None

    for secret in WEAK_SECRETS:
        expected = hmac.new(
            secret.encode(), header_payload, hashlib.sha256
        ).digest()
        if hmac.compare_digest(expected, sig_bytes):
            return secret
    return None
    return None
