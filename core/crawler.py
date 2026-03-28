"""
crawler.py - Extract endpoints and query parameters from a target.
Handles SPAs by also probing common routes and extracting paths from JS.
"""
import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from core.requester import fetch, Requester
from utils.logger import get_logger

log = get_logger(__name__)

# Common routes to probe on any web app
COMMON_ROUTES = [
    "/login", "/register", "/signup", "/logout",
    "/admin", "/dashboard", "/api", "/api/v1",
    "/search", "/contact", "/profile", "/settings",
    "/forgot-password", "/reset-password",
    "/users", "/products", "/items",
]

def crawl(target, limiter=None, store=None, requester=None):
    """
    Fetch the target page, extract all links, form actions, and probe common routes.
    Returns a list of endpoint dicts: {url, params, method}
    """
    req = requester or Requester(cache_on=True)
    endpoints = []
    visited = set()
    base_netloc = urlparse(target).netloc
    base = f"{urlparse(target).scheme}://{base_netloc}"

    resp = _get(target, limiter, req)
    if not resp:
        return endpoints

    if store:
        store.save(target, resp)

    _add(target, {}, "GET", endpoints, visited)

    soup = BeautifulSoup(resp.text, "html.parser")

    # <a href> links
    for tag in soup.find_all("a", href=True):
        url = urljoin(base, tag["href"])
        if urlparse(url).netloc == base_netloc:
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            if _add(url, params, "GET", endpoints, visited):
                if params:
                    r = _get(url, limiter, req)
                    if r and store:
                        store.save(url, r)

    # <form> actions
    for form in soup.find_all("form"):
        action = urljoin(base, form.get("action") or target)
        method = form.get("method", "get").upper()
        inputs = {
            inp.get("name"): inp.get("value", "test")
            for inp in form.find_all("input")
            if inp.get("name")
        }
        key = f"{method}:{action}:{sorted(inputs.items())}"
        if key not in visited:
            visited.add(key)
            endpoints.append({"url": action, "params": inputs, "method": method})

    # Extract paths from inline JS / script src
    js_paths = _extract_js_paths(resp.text, base)
    for path in js_paths:
        url = urljoin(base, path)
        if urlparse(url).netloc == base_netloc:
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            _add(url, params, "GET", endpoints, visited)

    # Probe common routes
    log.info("Probing common routes...")
    for route in COMMON_ROUTES:
        url = base + route
        r = _get(url, limiter, req)
        if r and r.status_code not in (404,):
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            if _add(url, params, "GET", endpoints, visited):
                if store:
                    store.save(url, r)
                log.debug(f"Found route: {url} [{r.status_code}]")

    log.info(f"Crawled {len(endpoints)} endpoint(s) from {target}")
    return endpoints

def _get(url, limiter, req):
    if limiter:
        limiter.wait()
    return req.get(url)

def _add(url, params, method, endpoints, visited):
    key = f"{method}:{url}"
    if key in visited:
        return False
    visited.add(key)
    endpoints.append({"url": url, "params": params, "method": method})
    return True

def _extract_js_paths(html, base):
    """Pull API-style paths from inline JS and script tags."""
    paths = set()
    # Match strings like "/api/something" or "/path/to/resource"
    for match in re.finditer(r'["\'](/[a-zA-Z0-9_\-/]+(?:\?[^"\']*)?)["\']', html):
        path = match.group(1)
        # Skip asset paths
        if not any(path.endswith(ext) for ext in (".js", ".css", ".png", ".svg", ".ico", ".woff")):
            paths.add(path)
    return paths
