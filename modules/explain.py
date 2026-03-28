"""
explain.py - Human-readable explanations for findings
"""

_EXPLANATIONS = {
    "sqli": (
        "The response contains SQL error patterns, suggesting the application passes "
        "user input directly into a database query. An attacker could manipulate these "
        "queries to extract, modify, or delete data."
    ),
    "xss": (
        "The injected payload was reflected in the response without sanitization. "
        "This may allow an attacker to inject malicious scripts that execute in a "
        "victim's browser, leading to session hijacking or credential theft."
    ),
    "header_Content-Security-Policy": (
        "Missing Content-Security-Policy. Without CSP, browsers permit inline scripts "
        "and arbitrary external resources, significantly increasing XSS attack surface."
    ),
    "header_X-Frame-Options": (
        "Missing X-Frame-Options. The page can be embedded in an iframe, making it "
        "vulnerable to clickjacking attacks where users are tricked into clicking hidden elements."
    ),
    "header_Strict-Transport-Security": (
        "Missing HSTS header. Without it, connections may be downgraded from HTTPS to HTTP, "
        "enabling Man-in-the-Middle (MITM) attacks that intercept sensitive data."
    ),
    "header_X-Content-Type-Options": (
        "Missing X-Content-Type-Options. Browsers may MIME-sniff responses and execute "
        "content as a different type, potentially running malicious scripts."
    ),
    "header_Referrer-Policy": (
        "Missing Referrer-Policy. Sensitive URL paths or query parameters may be leaked "
        "to third-party sites via the HTTP Referer header."
    ),
    "header_Permissions-Policy": (
        "Missing Permissions-Policy. Browser features like camera, microphone, and "
        "geolocation are not explicitly restricted for this origin."
    ),
    "behavior_500": (
        "An HTTP 500 error was returned, which may expose internal stack traces, "
        "file paths, or database errors that aid an attacker in reconnaissance."
    ),
    "behavior_403": (
        "An HTTP 403 response indicates a restricted resource exists at this path. "
        "It may be accessible through authentication bypass or misconfiguration."
    ),
    "behavior_401": (
        "An HTTP 401 response indicates an unauthenticated endpoint. "
        "Weak or missing authentication controls could allow unauthorized access."
    ),
    "cors_wildcard": (
        "The server responds with 'Access-Control-Allow-Origin: *', allowing any website "
        "to make cross-origin requests. This can expose sensitive API responses to malicious sites."
    ),
    "cors_reflect": (
        "The server reflects the attacker-controlled Origin back in the ACAO header. "
        "Combined with 'Access-Control-Allow-Credentials: true', this allows a malicious "
        "site to make authenticated cross-origin requests and read the response."
    ),
    "open_redirect": (
        "The application redirects users to an attacker-controlled URL via a parameter. "
        "This can be used in phishing attacks to trick users into visiting malicious sites "
        "while appearing to originate from a trusted domain."
    ),
    "dir_bruteforce": (
        "A path was discovered that returns a non-404 response. Exposed admin panels, "
        "backup files, configuration files, or debug endpoints can lead to full compromise."
    ),
    "ssl_expired": (
        "The SSL certificate has expired. Browsers will show security warnings and "
        "encrypted connections may be rejected, exposing users to interception."
    ),
    "ssl_expiring": (
        "The SSL certificate is expiring soon. Failure to renew will cause browser "
        "warnings and potential service disruption."
    ),
    "ssl_self_signed": (
        "The certificate is self-signed and not trusted by browsers. This allows "
        "Man-in-the-Middle attacks as there is no trusted CA verification."
    ),
    "ssl_weak_proto": (
        "The server accepts connections using TLS 1.0 or TLS 1.1, which are deprecated "
        "and contain known vulnerabilities including POODLE and BEAST attacks."
    ),
    "cookie_httponly": (
        "The cookie is missing the HttpOnly flag. JavaScript can read this cookie, "
        "enabling session theft via XSS attacks."
    ),
    "cookie_secure": (
        "The cookie is missing the Secure flag. It will be transmitted over unencrypted "
        "HTTP connections, exposing it to network interception."
    ),
    "cookie_samesite": (
        "The cookie is missing the SameSite attribute. Without it, the cookie is sent "
        "with cross-site requests, enabling Cross-Site Request Forgery (CSRF) attacks."
    ),
    "rate_limit": (
        "The login endpoint does not enforce rate limiting. An attacker can send unlimited "
        "authentication attempts, enabling brute-force and credential stuffing attacks."
    ),
    "blind_sqli_time": (
        "The application delayed its response when a time-based SQL payload was injected. "
        "This strongly indicates a blind SQL injection vulnerability where the database "
        "executes injected commands even though no error is returned."
    ),
    "blind_sqli_bool": (
        "The application returned different response sizes for true and false SQL conditions. "
        "This may indicate boolean-based blind SQL injection. Manual verification is recommended."
    ),
}

def get_explanation(category, header=None, code=None):
    """Return a human-readable explanation for a finding category."""
    if category == "header" and header:
        key = f"header_{header}"
        return _EXPLANATIONS.get(key, f"The {header} header is missing, which may reduce security.")
    if category == "behavior" and code:
        key = f"behavior_{code}"
        return _EXPLANATIONS.get(key, f"HTTP {code} response may indicate a security-relevant condition.")
    if category == "dir_bruteforce" and code:
        return _EXPLANATIONS.get("dir_bruteforce", "An exposed path was discovered.")
    return _EXPLANATIONS.get(category, "This finding may indicate a security issue worth investigating.")
