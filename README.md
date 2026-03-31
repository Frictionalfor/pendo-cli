# Pendo CLI

A terminal-based web application security probing tool for penetration testers and developers.
Performs payload-driven vulnerability detection with intelligent response analysis.

Where recon tools map the attack surface, Pendo probes it.

---

## Features

### Scan
- Security header analysis (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- CORS misconfiguration (wildcard origin, reflected origin with credentials)
- SSL/TLS analysis (certificate expiry, self-signed, TLS 1.0/1.1)
- Cookie security flags (HttpOnly, Secure, SameSite)
- Open redirect parameter injection
- Directory and file bruteforce (threaded, SPA-aware, 80+ path wordlist)
- Login endpoint rate limit testing
- CSRF detection (missing tokens on POST forms, cross-origin POST acceptance)
- HTTP method tampering (PUT, DELETE, PATCH, TRACE testing)
- JWT analysis (alg:none bypass, weak secret cracking, expiry, sensitive payload)
- Behavioral analysis (status codes, server disclosure, large responses)

### Probe
- Error-based SQL injection (MySQL, PostgreSQL, Oracle, SQLite, MSSQL)
- Time-based and boolean-based blind SQLi
- Reflected XSS with baseline comparison (no false positives)
- XXE injection (XML external entity across content types)
- SSRF (internal URL injection into URL-like parameters)
- Path traversal (../etc/passwd into file/path parameters)
- Command injection (;id, |whoami, $(id) appended to parameters)

### Fuzz
- 60+ mutations per parameter: type juggling, boundary values, encoding variants
- SSTI probes (Jinja2, Twig, Freemarker, Spring, ERB)
- Format string probes
- Anomaly detection: status code changes, response size deltas, error disclosure

### Output
- Severity summary box after every operation (bar chart by risk level)
- Confidence scoring per finding (High / Medium / Low)
- Deduplication with confidence upgrade on repeat hits
- JSON and plain text report formats
- Explain mode with human-readable reasoning per finding
- Silent mode for clean piping
- Auth header and cookie injection for authenticated scans
- No bytecode cache written at any point

---

## Requirements

- Python 3.8 or higher
- pip

```
requests
beautifulsoup4
urllib3
```

---

## Installation

### Linux (Kali / Debian / Ubuntu)

```bash
git clone https://github.com/Frictionalfor/pendo-cli
cd pendo-cli
bash setup.sh
```

Creates a global `pendo` command at `~/.local/bin/pendo`. Make sure it is in your PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Termux (Android, no root)

```bash
git clone https://github.com/Frictionalfor/pendo-cli
cd pendo-cli
bash termux-setup.sh
```

### Manual

```bash
pip install -r requirements.txt
python3 pendo.py -h
```

### Dependency check

```bash
bash check.sh
```

---

## Usage

```
pendo [-h] [-v] <command> [options] <url>

commands:
  scan     Full security scan
  probe    Deep payload injection
  fuzz     Mutation-based parameter fuzzing
  reports  Manage saved scan reports
```

---

## Commands

### scan

```bash
pendo scan https://example.com
pendo scan https://example.com --explain
pendo scan https://example.com --threads 20 --format json
pendo scan https://example.com --cookies 'session=abc;token=xyz'
pendo scan https://example.com --auth 'Authorization:Bearer TOKEN'
pendo scan https://example.com --silent -o report
```

Runs all scan modules: headers, CORS, SSL, cookies, open redirect, dir bruteforce,
rate limit, CSRF, method tampering, JWT (if --auth Bearer token provided), behavior.

### probe

```bash
pendo probe https://example.com --payloads sqli
pendo probe https://example.com --payloads xss --explain
pendo probe https://example.com --payloads generic --threads 20
pendo probe https://example.com --payloads data/payloads/sqli.txt
```

Runs: error-based SQLi, blind SQLi, XSS, XXE, SSRF, path traversal, command injection.

Payload categories resolve from `data/payloads/`:
- `sqli` -> `data/payloads/sqli.txt`
- `xss` -> `data/payloads/xss.txt`
- `generic` -> `data/payloads/generic.txt`

### fuzz

```bash
pendo fuzz https://example.com --seed admin
pendo fuzz https://example.com --seed 1 --threads 15
pendo fuzz https://example.com --seed test --format json -o fuzz_report
```

Generates 60+ mutations from the seed value and injects them into every discovered
parameter. Detects status anomalies, response size deltas, error disclosure, and SSTI.

### reports

```bash
pendo reports list
pendo reports open 1
pendo reports open localhost_20260328.txt
pendo reports delete 2
pendo reports delete all
```

---

## Options Reference

| Option | Description |
|---|---|
| `--explain` | Human-readable reasoning for each finding |
| `-o, --output FILE` | Save report to file (default: output/scans/) |
| `--format txt\|json` | Report format (default: txt) |
| `--threads N` | Thread count (default: 10) |
| `--delay SECONDS` | Delay between requests (default: 0.3) |
| `--cookies COOKIES` | Session cookies e.g. `session=abc;token=xyz` |
| `--auth HEADER` | Auth header e.g. `Authorization:Bearer TOKEN` |
| `--silent` | Suppress progress, print findings and summary only |
| `--no-cache` | Disable response caching |
| `--cache-ttl SECS` | Cache TTL in seconds (default: 300) |
| `--cache-size N` | Max cached responses (default: 256) |
| `--payloads FILE` | Payload file or category (probe only) |
| `--seed VALUE` | Seed for mutation generation (fuzz only, default: test) |

---

## Project Structure

```
pendo-cli/
├── pendo.py                  Entry point (v1.1.0)
├── version.txt
├── requirements.txt
├── CHANGELOG.md
├── setup.sh                  Linux installer
├── termux-setup.sh           Termux installer
├── update.sh                 One-command updater
├── check.sh                  Dependency checker
│
├── core/
│   ├── cache.py              LRU response cache with TTL and eviction
│   ├── requester.py          HTTP session manager with full post-op purge
│   ├── crawler.py            Endpoint discovery (links, forms, JS paths, common routes)
│   ├── probe_engine.py       Threaded payload injection engine
│   ├── fuzzer.py             Mutation-based fuzzing engine (v1.1)
│   └── response_store.py     In-memory response store per scan session
│
├── modules/
│   ├── header_check.py       Security header analysis
│   ├── cors_check.py         CORS misconfiguration detection
│   ├── ssl_check.py          SSL/TLS certificate and protocol analysis
│   ├── cookie_check.py       Cookie security flag analysis
│   ├── open_redirect.py      Open redirect parameter injection
│   ├── dir_bruteforce.py     Threaded directory discovery (SPA-aware)
│   ├── rate_limit_check.py   Login endpoint rate limit testing
│   ├── csrf_check.py         CSRF token and origin validation (v1.1)
│   ├── method_tamper.py      HTTP method tampering (v1.1)
│   ├── jwt_check.py          JWT security analysis (v1.1)
│   ├── sqli_probe.py         Error-based SQL injection
│   ├── xss_probe.py          Reflected XSS with baseline comparison
│   ├── blind_sqli.py         Time-based and boolean-based blind SQLi
│   ├── xxe_probe.py          XML external entity injection (v1.1)
│   ├── ssrf_probe.py         Server-side request forgery (v1.1)
│   ├── path_traversal.py     Directory traversal (v1.1)
│   ├── cmd_injection.py      OS command injection (v1.1)
│   ├── behavior_analyzer.py  Behavioral anomaly detection
│   ├── deduplicator.py       Finding deduplication and confidence scoring
│   ├── payload_manager.py    Payload file loader
│   ├── rate_limiter.py       Request rate control
│   └── explain.py            Human-readable finding explanations
│
├── utils/
│   ├── banner.py             Terminal banner and color constants
│   ├── formatter.py          CLI output formatting
│   ├── summary.py            Severity summary box (v1.1)
│   ├── validator.py          URL validation
│   └── logger.py             Logging system
│
├── data/
│   ├── payloads/
│   │   ├── sqli.txt
│   │   ├── xss.txt
│   │   └── generic.txt
│   ├── wordlists/
│   │   └── dirs.txt          80+ paths for directory bruteforce
│   └── patterns/
│       ├── sqli_patterns.json
│       ├── xss_patterns.json
│       └── headers.json
│
├── reports/
│   ├── report_generator.py   TXT and JSON report output
│   └── diff.py               Compare two JSON scan reports
│
└── output/
    └── scans/                Auto-saved scan reports
```

---

## Detection Logic

### SQL Injection (error-based)
Matches error signatures: MySQL, PostgreSQL, Oracle, SQLite, MSSQL error strings.

### Blind SQLi
Time-based: measures response delay after injecting SLEEP/WAITFOR/pg_sleep payloads.
Boolean-based: compares response size between true/false conditions.

### XSS
Checks if the injected payload appears verbatim in the response body, compared against
a baseline to eliminate false positives from static page content.

### CSRF
Checks POST forms for missing CSRF token fields. Tests cross-origin POST acceptance
by sending a request with `Origin: https://evil.attacker.com`.

### HTTP Method Tampering
Sends PUT, DELETE, PATCH, OPTIONS, TRACE to each endpoint. Flags dangerous methods
that return 200/201/204 or are advertised in the Allow header.

### JWT
Decodes the token from the --auth Bearer header. Tests alg:none bypass, attempts
to crack HS256 with 20 common weak secrets, checks expiry and sensitive payload fields.

### XXE
Posts XML payloads with external entity references to endpoints. Checks response
for /etc/passwd content, win.ini markers, and other file read indicators.

### SSRF
Injects internal URLs (127.0.0.1, localhost, 169.254.169.254) into URL-like parameters.
Checks response for AWS metadata, SSH banners, Redis version strings.

### Path Traversal
Injects ../ sequences into file/path parameters. Checks response for /etc/passwd,
/bin/bash, and Windows win.ini content.

### Command Injection
Appends command separators (;id, |whoami, $(id)) to parameter values. Checks response
for uid=, gid=, and command output indicators.

### Fuzz
Generates 60+ mutations from a seed value. Detects: HTTP 500 responses, response size
deltas over 2KB, error strings not present in the baseline, and SSTI indicators (49, 7777777).

### Security Headers
Checks for: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy.

### CORS
Spoofs Origin header and checks Access-Control-Allow-Origin response.
Flags wildcard and reflected origins, especially with credentials enabled.

### Behavioral Analysis
HTTP 500 (error disclosure), 401/403 (access control), server version in headers,
unusually large responses.

---

## Cache Behavior

- GET requests during crawl are cached (LRU, default TTL 300s, max 256 entries)
- Probe, fuzz, and payload requests always bypass cache
- After every operation, full purge runs:
  - All LRU cache entries cleared
  - Session cookies and auth headers wiped
  - urllib3 connection pools closed
  - ResponseStore cleared
  - gc.collect() called
- PYTHONDONTWRITEBYTECODE=1 and python3 -B prevent .pyc files

---

## Report Comparison

```bash
pendo scan https://example.com --format json -o scan_before
pendo scan https://example.com --format json -o scan_after
python3 -m reports.diff scan_before.json scan_after.json
```

---

## Update

```bash
bash update.sh
```

---

## Ethical Use

Pendo CLI is intended for authorized penetration testing, security research on systems
you own or have explicit permission to test, and educational purposes.

Unauthorized use against systems without permission is illegal.
The author assumes no liability for misuse.

---

## Author

Frictionalfor
https://github.com/Frictionalfor/pendo-cli
