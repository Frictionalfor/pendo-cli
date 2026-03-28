# Pendo CLI

A terminal-based web security probing and analysis tool for penetration testers and developers.
Performs payload-driven vulnerability detection with intelligent response analysis.

---

## Features

- Security header analysis (CSP, HSTS, X-Frame-Options, and more)
- CORS misconfiguration detection (wildcard + reflected origin with credentials)
- SSL/TLS analysis (certificate expiry, self-signed, TLS 1.0/1.1)
- Cookie security flag analysis (HttpOnly, Secure, SameSite)
- Open redirect detection via parameter injection
- Directory and file bruteforce (threaded, 80+ path wordlist)
- Login endpoint rate limit testing
- SQL injection — error-based pattern detection
- SQL injection — time-based and boolean-based blind detection
- Reflected XSS detection with baseline comparison (no false positives)
- Behavioral analysis (status codes, server disclosure, large responses)
- Endpoint discovery with SPA support (common route probing + JS path extraction)
- Threaded probe and bruteforce engine
- Confidence scoring on every finding (High / Medium / Low)
- Deduplication — duplicate findings merged, confidence upgraded on repeat hits
- LRU response cache with full post-operation purge
- JSON and plain text report output
- Report management from the CLI (list, open, delete)
- Explain mode with human-readable reasoning for every finding
- Silent mode for clean output piping
- Auth header and cookie injection for authenticated scans
- No bytecode cache written at any point

---

## Requirements

- Python 3.8 or higher
- pip

Dependencies:

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

The setup script installs dependencies and creates a global `pendo` command at `~/.local/bin/pendo`.
Make sure `~/.local/bin` is in your PATH. If it is not, add this to your `~/.bashrc` or `~/.zshrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Termux (Android, no root)

```bash
git clone https://github.com/Frictionalfor/pendo-cli
cd pendo-cli
bash termux-setup.sh
```

### Manual install (any platform)

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
  scan   <url>    Run full security scan (headers, CORS, behavior)
  probe  <url>    Inject payloads and detect SQLi / XSS
  reports         Manage saved scan reports
```

---

## Commands

### scan

Runs a full passive and active security scan against a target URL.

Checks performed:
- All HTTP security headers
- CORS policy
- SSL/TLS certificate and protocol analysis
- Cookie security flags (HttpOnly, Secure, SameSite)
- Open redirect parameter injection
- Directory and file bruteforce
- Login endpoint rate limit testing
- Endpoint discovery
- Behavioral anomalies per discovered endpoint

```bash
pendo scan https://example.com
pendo scan https://example.com --explain
pendo scan https://example.com -o report --format json
pendo scan https://example.com --silent
pendo scan https://example.com --cookies 'session=abc;token=xyz'
pendo scan https://example.com --auth 'Authorization:Bearer TOKEN'
pendo scan https://example.com --no-cache --delay 1
```

### probe

Crawls the target, then injects payloads into every discovered parameter.

```bash
pendo probe https://example.com --payloads sqli
pendo probe https://example.com --payloads xss
pendo probe https://example.com --payloads generic
pendo probe https://example.com --payloads data/payloads/sqli.txt --explain
pendo probe https://example.com --payloads sqli --format json -o result
```

Payload categories resolve automatically from `data/payloads/`:
- `sqli` -> `data/payloads/sqli.txt`
- `xss` -> `data/payloads/xss.txt`
- `generic` -> `data/payloads/generic.txt`

### reports

Manage saved scan output files stored in `output/scans/`.

```bash
pendo reports list
pendo reports open 1
pendo reports open localhost_20260328.txt
pendo reports delete 2
pendo reports delete all
```

`open` and `delete` accept an index number, exact filename, or partial filename match.

---

## Options Reference

| Option | Description |
|---|---|
| `--threads N` | Thread count for bruteforce and probe (default: 10) |
| `--explain` | Show human-readable reasoning for each finding |
| `-o, --output FILE` | Save report to a specific file |
| `--format txt\|json` | Report format (default: txt) |
| `--delay SECONDS` | Delay between requests (default: 0.3) |
| `--cookies COOKIES` | Session cookies, e.g. `session=abc;token=xyz` |
| `--auth HEADER` | Auth header, e.g. `Authorization:Bearer TOKEN` |
| `--silent` | Suppress progress output, print findings only |
| `--no-cache` | Disable response caching entirely |
| `--cache-ttl SECS` | Cache TTL in seconds (default: 300) |
| `--cache-size N` | Max cached responses (default: 256) |
| `--payloads FILE` | Payload file or category name (probe only) |

---

## Project Structure

```
pendo-cli/
├── pendo.py                  Entry point
├── version.txt               Current version
├── requirements.txt
├── CHANGELOG.md
├── setup.sh                  Linux installer
├── termux-setup.sh           Termux installer
├── update.sh                 One-command updater
├── check.sh                  Dependency checker
│
├── core/
│   ├── cache.py              LRU response cache with TTL and eviction
│   ├── requester.py          HTTP session manager with full purge
│   ├── crawler.py            Endpoint discovery (links, forms, JS paths, common routes)
│   ├── probe_engine.py       Payload injection engine
│   └── response_store.py     In-memory response store per scan session
│
├── modules/
│   ├── header_check.py       Security header analysis
│   ├── cors_check.py         CORS misconfiguration detection
│   ├── ssl_check.py          SSL/TLS certificate and protocol analysis
│   ├── cookie_check.py       Cookie security flag analysis
│   ├── open_redirect.py      Open redirect parameter injection
│   ├── dir_bruteforce.py     Threaded directory and file discovery
│   ├── rate_limit_check.py   Login endpoint rate limit testing
│   ├── sqli_probe.py         SQL injection pattern detection
│   ├── xss_probe.py          Reflected input detection with baseline comparison
│   ├── blind_sqli.py         Time-based and boolean-based blind SQLi
│   ├── behavior_analyzer.py  Behavioral anomaly detection
│   ├── deduplicator.py       Finding deduplication and confidence scoring
│   ├── payload_manager.py    Payload file loader
│   ├── rate_limiter.py       Request rate control
│   └── explain.py            Human-readable finding explanations
│
├── utils/
│   ├── banner.py             Terminal banner and color constants
│   ├── formatter.py          CLI output formatting
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

### SQL Injection

Matches error signatures in response bodies including:
- MySQL, PostgreSQL, Oracle, SQLite, MSSQL error strings
- Generic syntax error patterns

### Reflected Input (XSS)

- Checks if the injected payload appears verbatim in the response body
- Pattern-based detection for unencoded dangerous characters

### Security Headers

Checks for the presence of:
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

### CORS

Sends a request with a spoofed `Origin: https://evil.attacker.com` header and checks if it is reflected in `Access-Control-Allow-Origin`. Flags wildcard origins and credential-bearing reflected origins.

### Behavioral Analysis

- HTTP 500 responses (potential stack trace / error disclosure)
- HTTP 401 / 403 responses (access control indicators)
- Server version disclosure via `Server` header
- Unusually large responses (potential data leakage)

---

## Cache Behavior

- GET requests during crawl are cached in an LRU store (default TTL 300s, max 256 entries)
- Probe/payload requests always bypass cache and are never stored
- After every scan or probe operation, a full purge runs:
  - All LRU cache entries cleared
  - All session cookies and auth headers wiped
  - All urllib3 connection pools closed
  - ResponseStore cleared
  - `gc.collect()` called to release memory
- `PYTHONDONTWRITEBYTECODE=1` and `python3 -B` prevent `.pyc` files from being written

---

## Report Comparison

Compare two JSON reports to see what changed between scans:

```bash
pendo scan https://example.com --format json -o scan_before
# make changes or wait
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

Pendo CLI is intended for:
- Authorized penetration testing
- Security research on systems you own or have explicit permission to test
- Educational purposes

Unauthorized use against systems without permission is illegal.
The author assumes no liability for misuse.

---

## Author

Frictionalfor
https://github.com/Frictionalfor/pendo-cli
