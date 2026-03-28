# Changelog

## [1.0.0] - 2026-03-28

### Core
- `pendo scan` - Full passive security scan
- `pendo probe` - Active payload injection with threading
- `pendo reports` - Report management (list, open, delete)
- Global CLI install via setup.sh and termux-setup.sh
- No bytecode cache written (PYTHONDONTWRITEBYTECODE + python3 -B)

### Scan Modules
- Security headers analysis (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- CORS misconfiguration detection (wildcard origin, reflected origin with credentials)
- SSL/TLS analysis (certificate expiry, self-signed detection, TLS 1.0/1.1 weak protocol)
- Cookie security flag analysis (HttpOnly, Secure, SameSite)
- Open redirect detection (20 known redirect parameter names)
- Directory and file bruteforce (threaded, 80+ path wordlist)
- Login endpoint rate limit testing (burst detection, 429/423 check)
- Behavioral analysis (status codes, server version disclosure, large responses)

### Probe Modules
- Error-based SQL injection detection (MySQL, PostgreSQL, Oracle, SQLite, MSSQL patterns)
- Reflected XSS detection with baseline comparison (eliminates false positives)
- XSS pattern detection
- Time-based blind SQLi (MySQL SLEEP, MSSQL WAITFOR, PostgreSQL pg_sleep, Oracle, SQLite)
- Boolean-based blind SQLi (response size differential analysis)

### Output
- Confidence scoring on every finding (High / Medium / Low)
- Deduplication engine with confidence upgrade on repeat hits
- JSON and plain text report formats
- Auto-save to output/scans/ with timestamp
- --explain mode with human-readable reasoning per finding
- --silent mode for clean output piping
- --threads flag for concurrent bruteforce and probe

### Infrastructure
- LRU response cache with TTL and size control
- Full post-operation purge (cache, sessions, connections, gc.collect)
- Session-scoped Requester with cookie and auth header injection
- Rate limiter between requests
- Crawler with SPA support (common route probing + JS path extraction)
