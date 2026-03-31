# Changelog

## [1.1.0] - 2026-03-31

### New Command
- `pendo fuzz` - Mutation-based parameter fuzzing with 60+ generated mutations per parameter

### Scan Modules (new)
- CSRF detection — missing token on POST forms + cross-origin POST acceptance test
- HTTP method tampering — PUT, DELETE, PATCH, OPTIONS, TRACE testing (threaded)
- JWT analysis — alg:none bypass, weak HS256 secret cracking, expiry, sensitive payload fields, missing claims

### Probe Modules (new)
- XXE injection — XML external entity payloads across XML content types
- SSRF — internal URL injection into URL-like parameters (AWS metadata, localhost, Redis, MySQL)
- Path traversal — ../ sequences into file/path parameters with system file indicators
- Command injection — OS command separators (;id, |whoami, $(id)) appended to all parameters

### Fuzz Modules (new)
- Type juggling mutations (null, true, false, 0, -1, NaN, Infinity, [], {})
- Boundary values (empty, whitespace, null byte, 256/4096 char strings)
- Encoding variants (URL, double URL, HTML entity)
- Format string probes (%s, %d, %x, %n)
- SSTI probes (Jinja2, Twig, Freemarker, Spring, ERB)
- Anomaly detection: status code changes, response size deltas, error disclosure

### Output (new)
- Severity summary box after every scan/probe/fuzz — bar chart by risk level
- `utils/summary.py` — shared summary renderer for terminal and JSON

### Bug Fixes
- Dir bruteforce: SPA catch-all detection — Vite/React/Vue apps no longer flood results with false 200s
- Rate limit check: endpoints returning all-404 no longer flagged as missing rate limiting
- XSS probe: baseline comparison prevents false positives from static page content

### Infrastructure
- `core/fuzzer.py` — threaded mutation engine with baseline comparison
- `utils/summary.py` — severity summary renderer
- All new modules suppress urllib3 SSL warnings independently

---

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
- Reflected XSS detection with baseline comparison
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
