"""
ssl_check.py - SSL/TLS certificate and configuration analysis.
Checks expiry, issuer, SANs, weak protocol support, and self-signed certs.
"""
import ssl
import socket
import datetime
from urllib.parse import urlparse
from modules.explain import get_explanation
from utils.logger import get_logger

log = get_logger(__name__)


def check_ssl(url, explain=False):
    """
    Perform SSL/TLS analysis on the target host.
    Returns a list of issue dicts.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return []  # nothing to check on plain HTTP

    host = parsed.hostname
    port = parsed.port or 443
    issues = []

    # ── Certificate info ──────────────────────────────────────────────
    cert_info = _get_cert(host, port)
    if cert_info is None:
        issues.append({
            "type": "SSL: Could Not Retrieve Certificate",
            "endpoint": url,
            "risk": "High",
            "detail": "Connection failed or certificate rejected",
            "confidence": "High",
        })
        return issues

    # Expiry check
    expiry = cert_info.get("notAfter")
    if expiry:
        try:
            exp_dt = datetime.datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_dt - datetime.datetime.utcnow()).days
            if days_left < 0:
                issues.append({
                    "type": "SSL: Certificate Expired",
                    "endpoint": url,
                    "risk": "High",
                    "detail": f"Expired: {expiry}",
                    "confidence": "High",
                    "reason": get_explanation("ssl_expired") if explain else None,
                })
            elif days_left < 30:
                issues.append({
                    "type": "SSL: Certificate Expiring Soon",
                    "endpoint": url,
                    "risk": "Medium",
                    "detail": f"Expires in {days_left} day(s): {expiry}",
                    "confidence": "High",
                    "reason": get_explanation("ssl_expiring") if explain else None,
                })
        except ValueError:
            pass

    # Self-signed check (issuer == subject)
    issuer  = dict(x[0] for x in cert_info.get("issuer", []))
    subject = dict(x[0] for x in cert_info.get("subject", []))
    if issuer.get("commonName") == subject.get("commonName"):
        issues.append({
            "type": "SSL: Self-Signed Certificate",
            "endpoint": url,
            "risk": "High",
            "detail": f"Issuer CN: {issuer.get('commonName')}",
            "confidence": "High",
            "reason": get_explanation("ssl_self_signed") if explain else None,
        })

    # ── Weak protocol support ─────────────────────────────────────────
    for proto, label in [
        (ssl.PROTOCOL_TLSv1,   "TLS 1.0"),
        (ssl.PROTOCOL_TLSv1_2, None),   # placeholder — we test via context
    ]:
        pass  # handled below

    for version, label in _weak_protocol_check(host, port):
        issues.append({
            "type": f"SSL: Weak Protocol Supported ({label})",
            "endpoint": url,
            "risk": "Medium",
            "detail": f"{label} is enabled",
            "confidence": "High",
            "reason": get_explanation("ssl_weak_proto") if explain else None,
        })

    # Clean None reasons
    for i in issues:
        if i.get("reason") is None:
            i.pop("reason", None)

    return issues


def _get_cert(host, port):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()
    except Exception as e:
        log.debug(f"SSL cert fetch failed for {host}:{port} — {e}")
        return None


def _weak_protocol_check(host, port):
    """Try to connect with TLS 1.0 and TLS 1.1 — flag if accepted."""
    weak = []
    for min_ver, max_ver, label in [
        (ssl.TLSVersion.TLSv1,   ssl.TLSVersion.TLSv1,   "TLS 1.0"),
        (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = min_ver
            ctx.maximum_version = max_ver
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    weak.append((min_ver, label))
        except Exception:
            pass
    return weak
