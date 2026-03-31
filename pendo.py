#!/usr/bin/env python3
"""
pendo.py - Entry point for Pendo CLI
"""
import os
import sys

# Never write .pyc / __pycache__ — keeps the project directory clean
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True

import argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from utils.banner import print_banner, CYAN, RESET, DIM, BOLD, GREEN, YELLOW
from utils.validator import validate_url
from utils.logger import get_logger
from utils.formatter import print_info, print_success, print_error
from core.requester import Requester, purge_all
from core.crawler import crawl
from core.probe_engine import run_probe
from core.response_store import ResponseStore
from modules.header_check import check_headers
from modules.behavior_analyzer import analyze_behavior
from modules.cors_check import check_cors
from modules.cookie_check import check_cookies
from modules.ssl_check import check_ssl
from modules.open_redirect import check_open_redirect
from modules.dir_bruteforce import bruteforce_dirs
from modules.rate_limit_check import check_rate_limiting
from modules.blind_sqli import probe_blind_sqli
from modules.csrf_check import check_csrf
from modules.method_tamper import check_method_tampering
from modules.xxe_probe import probe_xxe
from modules.ssrf_probe import probe_ssrf
from modules.path_traversal import probe_path_traversal
from modules.cmd_injection import probe_cmd_injection
from modules.jwt_check import check_jwt
from modules.deduplicator import deduplicate
from modules.rate_limiter import RateLimiter
from utils.summary import print_summary, build_summary_dict
from core.fuzzer import run_fuzz
from reports.report_generator import generate_report

log = get_logger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Custom help formatter — prints banner then a hand-crafted usage block
# ─────────────────────────────────────────────────────────────────────────────

def _print_help():
    print_banner()
    print(f"""{CYAN}usage:{RESET} pendo [-h] [-v] <command> [options] <url>

{BOLD}Pendo CLI v1.1 — Web Application Security Probing Tool{RESET}

{YELLOW}commands:{RESET}
  scan   <url>              Full passive + active security scan
  probe  <url>              Deep payload injection (SQLi, XSS, XXE, SSRF,
                            path traversal, command injection, blind SQLi)
  fuzz   <url>              Mutation-based parameter fuzzing (SSTI, type
                            juggling, boundary values, encoding bypasses)
  reports                   Manage saved scan reports

{YELLOW}positional:{RESET}
  url                       Target URL  (e.g. https://example.com)

{YELLOW}scan / probe / fuzz options:{RESET}
  -h,  --help               Show this help message and exit
  -v,  --version            Show version and exit
       --explain            Show reasoning behind each finding
  -o,  --output FILE        Save report to file  (default: output/scans/)
       --format txt|json    Report format  (default: txt)
       --threads N          Thread count  (default: 10)
       --delay SECONDS      Delay between requests  (default: 0.3)
       --cookies COOKIES    Session cookies  e.g. {DIM}'session=abc;token=xyz'{RESET}
       --auth HEADER        Auth header     e.g. {DIM}'Authorization:Bearer TOKEN'{RESET}
       --silent             Suppress progress — only print findings + summary
       --no-cache           Disable response caching entirely
       --cache-ttl SECS     Cache TTL in seconds  (default: 300)
       --cache-size N       Max cached responses  (default: 256)

{YELLOW}probe-only options:{RESET}
       --payloads FILE      Payload file or category: sqli / xss / generic
                            (default: data/payloads/generic.txt)

{YELLOW}fuzz-only options:{RESET}
       --seed VALUE         Seed value for mutation generation  (default: test)

{YELLOW}scan modules (v1.0):{RESET}
  headers                   6 security headers
  cors                      CORS misconfiguration
  ssl                       Certificate expiry, self-signed, TLS 1.0/1.1
  cookies                   HttpOnly, Secure, SameSite flags
  open-redirect             Redirect parameter injection
  dir-bruteforce            Path discovery via wordlist (threaded)
  rate-limit                Login endpoint brute-force protection
  behavior                  Status codes, server disclosure

{YELLOW}scan modules (v1.1 new):{RESET}
  csrf                      Missing CSRF tokens + cross-origin POST acceptance
  method-tamper             PUT/DELETE/PATCH/TRACE method testing
  jwt                       alg:none, weak secret, expiry, sensitive payload

{YELLOW}probe modules (v1.0):{RESET}
  sqli                      Error-based SQL injection
  blind-sqli                Time-based + boolean-based blind SQLi
  xss                       Reflected input / XSS patterns

{YELLOW}probe modules (v1.1 new):{RESET}
  xxe                       XML External Entity injection
  ssrf                      Server-Side Request Forgery
  path-traversal            Directory traversal (../etc/passwd)
  cmd-injection             OS command injection (;id, |whoami)

{YELLOW}fuzz modules (v1.1 new):{RESET}
  mutations                 Type juggling, boundary values, encoding variants
  ssti                      Server-Side Template Injection detection
  error-disclosure          Anomalous status codes and response size deltas

{YELLOW}output:{RESET}
  summary                   Severity box printed after every scan
  confidence                High / Medium / Low per finding
  deduplication             Duplicate findings merged

{YELLOW}reports options:{RESET}
  reports list              List all saved reports
  reports open <id>         Print a report to terminal
  reports delete <id>       Delete a report  (index, filename, or 'all')

{YELLOW}examples:{RESET}
  {DIM}pendo scan https://example.com --explain{RESET}
  {DIM}pendo scan https://example.com --auth 'Authorization:Bearer TOKEN'{RESET}
  {DIM}pendo probe https://example.com --payloads sqli --threads 20{RESET}
  {DIM}pendo probe https://example.com --payloads xss --explain{RESET}
  {DIM}pendo fuzz https://example.com --seed admin --threads 15{RESET}
  {DIM}pendo fuzz https://example.com --seed 1 --format json -o fuzz_report{RESET}
  {DIM}pendo reports list{RESET}
  {DIM}pendo reports open 1{RESET}
  {DIM}pendo reports delete all{RESET}

{GREEN}repo:{RESET} https://github.com/Frictionalfor/pendo-cli  — by Frictionalfor
""")


class _HelpAction(argparse.Action):
    """Replace default -h with our custom banner+help."""
    def __init__(self, option_strings, dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest,
                         default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        _print_help()
        sys.exit(0)


# ─────────────────────────────────────────────────────────────────────────────
# Session builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_requester(args, cache_on=True):
    cookies     = _parse_cookies(getattr(args, "cookies", None))
    auth_header = _parse_auth(getattr(args, "auth", None))
    no_cache    = getattr(args, "no_cache", False)
    return Requester(
        cache_ttl=getattr(args, "cache_ttl", 300),
        cache_size=getattr(args, "cache_size", 256),
        cache_on=(cache_on and not no_cache),
        cookies=cookies,
        auth_header=auth_header,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_scan(args):
    silent = getattr(args, "silent", False)
    if not silent:
        print_banner()

    url = validate_url(args.url)
    if not url:
        print_error(f"Invalid URL: {args.url}")
        return

    if not silent:
        print_info(f"Target   : {url}")
        print_info(f"Mode     : Scan")
        print_info(f"Explain  : {args.explain}")

    results = []
    store   = ResponseStore()
    limiter = RateLimiter(delay=args.delay)
    req     = _build_requester(args, cache_on=True)
    threads = getattr(args, "threads", 10)

    if not silent: print_info("Checking security headers...")
    results += check_headers(url, explain=args.explain, requester=req)

    if not silent: print_info("Checking CORS policy...")
    results += check_cors(url, explain=args.explain, requester=req)

    if not silent: print_info("Checking SSL/TLS...")
    results += check_ssl(url, explain=args.explain)

    if not silent: print_info("Checking cookie security flags...")
    results += check_cookies(url, requester=req, explain=args.explain)

    if not silent: print_info("Discovering endpoints...")
    endpoints = crawl(url, limiter=limiter, store=store, requester=req)
    if not silent: print_info(f"Found {len(endpoints)} endpoint(s)")

    if not silent: print_info("Checking for open redirects...")
    results += check_open_redirect(endpoints, requester=req, explain=args.explain)

    if not silent: print_info("Checking rate limiting on auth endpoints...")
    results += check_rate_limiting(url, requester=req, explain=args.explain)

    if not silent: print_info("Running directory bruteforce...")
    results += bruteforce_dirs(url, requester=req, threads=threads, explain=args.explain)

    if not silent: print_info("Passive behavior analysis...")
    for ep in endpoints:
        resp = store.get(ep["url"])
        if resp:
            results += analyze_behavior(ep["url"], resp, explain=args.explain)

    if not silent: print_info("Checking CSRF protection...")
    results += check_csrf(url, requester=req, explain=args.explain)

    if not silent: print_info("Testing HTTP method tampering...")
    results += check_method_tampering(endpoints, requester=req,
                                      threads=threads, explain=args.explain)

    # JWT analysis if auth token provided
    auth_raw = getattr(args, "auth", None)
    if auth_raw and "bearer" in auth_raw.lower():
        if not silent: print_info("Analysing JWT token...")
        token_val = auth_raw.split(":", 1)[1].strip() if ":" in auth_raw else auth_raw
        results += check_jwt(token_val, explain=args.explain)

    # Deduplicate and score
    results = deduplicate(results)

    if not silent:
        _print_cache_stats(req)
        print_summary(results)

    generate_report(results, url, output_path=args.output,
                    fmt=args.format, explain=args.explain, silent=silent)

    purge_all(store=store, silent=silent)


def cmd_probe(args):
    silent = getattr(args, "silent", False)
    if not silent:
        print_banner()

    url = validate_url(args.url)
    if not url:
        print_error(f"Invalid URL: {args.url}")
        return

    if not silent:
        print_info(f"Target   : {url}")
        print_info(f"Mode     : Probe")
        print_info(f"Payloads : {args.payloads}")

    results   = []
    store     = ResponseStore()
    limiter   = RateLimiter(delay=args.delay)

    crawl_req = _build_requester(args, cache_on=True)
    if not silent: print_info("Discovering endpoints...")
    endpoints = crawl(url, limiter=limiter, store=store, requester=crawl_req)
    if not silent: print_info(f"Found {len(endpoints)} endpoint(s)")

    probe_req = _build_requester(args, cache_on=False)
    threads   = getattr(args, "threads", 10)

    if not silent: print_info("Injecting payloads (threaded)...")
    results += run_probe(endpoints, args.payloads, limiter=limiter,
                         explain=args.explain, requester=probe_req, threads=threads)

    if not silent: print_info("Testing blind SQLi...")
    results += probe_blind_sqli(endpoints, requester=probe_req,
                                limiter=limiter, explain=args.explain)

    if not silent: print_info("Testing XXE injection...")
    results += probe_xxe(endpoints, requester=probe_req, explain=args.explain)

    if not silent: print_info("Testing SSRF...")
    results += probe_ssrf(endpoints, requester=probe_req, explain=args.explain)

    if not silent: print_info("Testing path traversal...")
    results += probe_path_traversal(endpoints, requester=probe_req, explain=args.explain)

    if not silent: print_info("Testing command injection...")
    results += probe_cmd_injection(endpoints, requester=probe_req, explain=args.explain)

    # Deduplicate and score
    results = deduplicate(results)

    if not silent:
        _print_cache_stats(crawl_req)
        print_summary(results)

    generate_report(results, url, output_path=args.output,
                    fmt=args.format, explain=args.explain, silent=silent)

    purge_all(store=store, silent=silent)


def cmd_fuzz(args):
    silent = getattr(args, "silent", False)
    if not silent:
        print_banner()

    url = validate_url(args.url)
    if not url:
        print_error(f"Invalid URL: {args.url}")
        return

    if not silent:
        print_info(f"Target   : {url}")
        print_info(f"Mode     : Fuzz")
        print_info(f"Seed     : {args.seed}")

    store   = ResponseStore()
    limiter = RateLimiter(delay=args.delay)
    req     = _build_requester(args, cache_on=False)
    threads = getattr(args, "threads", 10)

    if not silent: print_info("Discovering endpoints...")
    endpoints = crawl(url, limiter=limiter, store=store, requester=req)
    if not silent: print_info(f"Found {len(endpoints)} endpoint(s)")

    if not silent: print_info("Fuzzing parameters with mutations...")
    results = run_fuzz(endpoints, requester=req, seed=args.seed,
                       threads=threads, explain=args.explain)

    results = deduplicate(results)

    if not silent:
        print_summary(results)

    generate_report(results, url, output_path=args.output,
                    fmt=args.format, explain=args.explain, silent=silent)

    purge_all(store=store, silent=silent)


def cmd_reports(args):
    """List, open, or delete saved scan reports."""
    import os
    import glob
    import subprocess

    SCANS_DIR = "output/scans"
    os.makedirs(SCANS_DIR, exist_ok=True)

    files = sorted(glob.glob(os.path.join(SCANS_DIR, "*")))

    # ── list ──────────────────────────────────────────────────────────
    if args.reports_action == "list" or args.reports_action is None:
        print_banner()
        if not files:
            print_info("No saved reports found.")
            return
        print_info(f"Saved reports in {SCANS_DIR}/\n")
        for i, f in enumerate(files, 1):
            size = os.path.getsize(f)
            name = os.path.basename(f)
            print(f"  {CYAN}[{i:>2}]{RESET}  {name}  {DIM}({size} bytes){RESET}")
        print()
        print_info(f"Total: {len(files)} report(s)")

    # ── open ──────────────────────────────────────────────────────────
    elif args.reports_action == "open":
        target = args.target
        path   = _resolve_report(files, target, SCANS_DIR)
        if not path:
            return
        print_info(f"Opening: {path}")
        try:
            with open(path) as f:
                print()
                print(f.read())
        except OSError as e:
            print_error(f"Could not read file: {e}")

    # ── delete ────────────────────────────────────────────────────────
    elif args.reports_action == "delete":
        target = args.target

        if target == "all":
            if not files:
                print_info("Nothing to delete.")
                return
            print_info(f"Deleting {len(files)} report(s)...")
            for f in files:
                os.remove(f)
                print_success(f"Deleted: {os.path.basename(f)}")
            return

        path = _resolve_report(files, target, SCANS_DIR)
        if not path:
            return
        os.remove(path)
        print_success(f"Deleted: {os.path.basename(path)}")


def _resolve_report(files, target, scans_dir):
    """
    Resolve a report by index number, filename, or partial name.
    Returns the full path or None.
    """
    import os

    if not target:
        print_error("Specify a report: index number, filename, or partial name.")
        return None

    # By index — only treat as index if it's a small integer that fits the list
    if target.isdigit():
        idx = int(target) - 1
        if 0 <= idx < len(files):
            return files[idx]
        # Doesn't fit as an index — fall through to partial name match

    # Exact path
    if os.path.exists(target):
        return target

    # Inside scans dir — exact filename
    candidate = os.path.join(scans_dir, target)
    if os.path.exists(candidate):
        return candidate

    # Partial match against basenames
    matches = [f for f in files if target in os.path.basename(f)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print_error(f"Ambiguous match for '{target}'. Be more specific:")
        for m in matches:
            print(f"    {os.path.basename(m)}")
        return None

    print_error(f"No report matching '{target}'. Run 'pendo reports list' to see available reports.")
    return None

def _print_cache_stats(req):
    s = req.cache_stats()
    print_info(
        f"Cache  : {s['size']}/{s['max_size']} entries  "
        f"hits={s['hits']}  misses={s['misses']}  "
        f"ratio={s['hit_ratio']}  ttl={s['ttl']}s"
    )

def _parse_cookies(raw):
    if not raw:
        return None
    result = {}
    for pair in raw.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result or None

def _parse_auth(raw):
    if not raw:
        return None
    if ":" in raw:
        name, value = raw.split(":", 1)
        return (name.strip(), value.strip())
    return None

def _get_version():
    try:
        with open("version.txt") as f:
            return f"Pendo CLI v{f.read().strip()}"
    except FileNotFoundError:
        return "Pendo CLI v1.0.0"


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="pendo",
        add_help=False,   # we handle -h ourselves
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-h", "--help",    action=_HelpAction)
    parser.add_argument("-v", "--version", action="version", version=_get_version())

    sub = parser.add_subparsers(dest="command", metavar="command")

    def add_common(p):
        p.add_argument("url")
        p.add_argument("--explain",    action="store_true")
        p.add_argument("-o", "--output")
        p.add_argument("--format",     choices=["txt", "json"], default="txt")
        p.add_argument("--delay",      type=float, default=0.3)
        p.add_argument("--threads",    type=int,   default=10)
        p.add_argument("--cookies")
        p.add_argument("--auth")
        p.add_argument("--silent",     action="store_true")
        p.add_argument("--no-cache",   action="store_true", dest="no_cache")
        p.add_argument("--cache-ttl",  type=int, default=300, dest="cache_ttl")
        p.add_argument("--cache-size", type=int, default=256, dest="cache_size")
        # sub-command help also shows banner
        p.add_argument("-h", "--help", action=_HelpAction)

    sp = sub.add_parser("scan",  add_help=False)
    add_common(sp)

    pp = sub.add_parser("probe", add_help=False)
    add_common(pp)
    pp.add_argument("--payloads", default="data/payloads/generic.txt")

    # ── fuzz ─────────────────────────────────────────────────────────
    fp = sub.add_parser("fuzz", add_help=False)
    add_common(fp)
    fp.add_argument("--seed", default="test", help="Seed value for mutation generation")

    # ── reports ──────────────────────────────────────────────────────
    rp = sub.add_parser("reports", add_help=False)
    rp.add_argument("-h", "--help", action=_HelpAction)
    rp.add_argument("reports_action", nargs="?",
                    choices=["list", "open", "delete"], default="list")
    rp.add_argument("target", nargs="?", default=None,
                    help="Report index, filename, or 'all' (for delete)")

    # No args at all → show help
    if len(sys.argv) == 1:
        _print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "probe":
        cmd_probe(args)
    elif args.command == "fuzz":
        cmd_fuzz(args)
    elif args.command == "reports":
        cmd_reports(args)
    else:
        _print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
