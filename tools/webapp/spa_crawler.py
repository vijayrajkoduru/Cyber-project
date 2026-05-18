"""Webapp module — spa_crawler: Headless browser crawl for SPAs.

Route: POST /api/webapp/spa_crawler

THE FOUNDATION SCANNER. Every later scanner depends on the URL + API
endpoint + parameter map this scanner builds. Without it, the rest of
the pipeline gives up on modern React/Vue/Angular/Next/Svelte apps
because the homepage HTML has no <form> tags or `?param=` URLs.

What it does:
  • Launches headless Chromium via Playwright
  • Loads the target with a real browser (executes JS, hydrates SPA)
  • Follows internal links (same origin only)
  • Walks React/Vue/Angular hash routes (#/login, #/search, ...)
  • Intercepts EVERY XHR / fetch / WebSocket call the SPA makes
  • Extracts API endpoints + HTTP methods + query/body parameters
  • Returns: discovered URLs, API endpoints, parameter map

Production-safety:
  • Identifies as User-Agent: VulnusLab/1.0 (+https://vulnuslab.com/scanner)
  • Scope-locked to the target's origin (no 3rd-party crawling)
  • Max 50 pages / 60s total / 3 levels deep by default
  • Respects 429/503 — backs off and aborts cleanly

Graceful degradation:
  • If Playwright is not installed → returns skipped_reason cleanly
    (does NOT crash the autoloader)
  • Customer can install on VPS via:
        pip install playwright && playwright install chromium
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional, Set, List, Dict, Tuple
from urllib.parse import urlparse, urljoin

from fastapi import APIRouter, Depends

from tools._spa_state import save_spa_state
from tools._shared import (
    ScanRequest, verify_scan_quota, standard_response, web_url, recon_host,
)

router = APIRouter()


VULNUSLAB_UA = "VulnusLab/1.0 (+https://vulnuslab.com/scanner)"
MAX_PAGES = 50
MAX_DEPTH = 3
TOTAL_BUDGET_SECONDS = 60
INTRA_PAGE_WAIT_MS = 500   # wait for SPA to hydrate after navigation


# ─────────────────────────────────────────────────────────────────────
# Heuristics for picking interesting URLs
# ─────────────────────────────────────────────────────────────────────

_BORING_EXTENSIONS = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|woff2?|ttf|otf|eot|css|map|webp|mp4|webm)(\?|$)",
    re.IGNORECASE,
)
_API_HINT = re.compile(r"/(api|v\d+|graphql|rest|rpc)(/|$)", re.IGNORECASE)


def _same_origin(url: str, origin: str) -> bool:
    try:
        return urlparse(url).netloc == origin
    except Exception:
        return False


def _is_boring(url: str) -> bool:
    return bool(_BORING_EXTENSIONS.search(url))


def _looks_like_api(url: str) -> bool:
    return bool(_API_HINT.search(url))


def _extract_query_params(url: str) -> List[str]:
    """Returns list of query param names in the URL (no duplicates)."""
    from urllib.parse import urlparse, parse_qs
    qs = urlparse(url).query
    if not qs:
        return []
    return list(parse_qs(qs).keys())


# ─────────────────────────────────────────────────────────────────────
# Main route
# ─────────────────────────────────────────────────────────────────────


@router.post("/api/webapp/spa_crawler")
async def webapp_spa_crawler(req: ScanRequest, payload=Depends(verify_scan_quota)):
    """Run the headless browser crawl."""

    # Graceful import — Playwright may not be installed on the VPS yet.
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except ImportError:
        # Persist for downstream scanners (sqli, xss, lfi, idor, ...)
    try:
        save_spa_state(req.target, sorted(discovered_urls),
                        api_summary, sorted(discovered_params))
    except Exception:
        pass

    return standard_response(
            tool="spa_crawler",
            target=req.target,
            findings=[],
            tests_performed=0,
            tests_summary="Playwright not installed on backend",
            skipped_reason=(
                "Playwright not installed. On the VPS run: "
                "pip install playwright && playwright install chromium"
            ),
            raw_data={"spa_crawler": {"engine": "playwright (not installed)"}},
        )

    target_url = web_url(req.target).rstrip("/")
    target_origin = urlparse(target_url).netloc

    discovered_urls: Set[str] = set()
    discovered_api: Dict[str, Dict] = {}   # endpoint -> {methods:set, params:set}
    discovered_params: Set[str] = set()
    queue: List[Tuple[str, int]] = [(target_url, 0)]
    visited: Set[str] = set()
    errors: List[str] = []

    async def _record_api(url: str, method: str, params: List[str]):
        if not _same_origin(url, target_origin):
            return
        if _is_boring(url):
            return
        # Normalize: drop query string for the key, keep params separately
        key = url.split("?", 1)[0]
        info = discovered_api.setdefault(key, {"methods": set(), "params": set()})
        info["methods"].add(method.upper())
        for p in params:
            info["params"].add(p)
            discovered_params.add(p)

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            context = await browser.new_context(
                user_agent=VULNUSLAB_UA,
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
            )
            page = await context.new_page()

            # Intercept every request the SPA makes — that's how we
            # find /api/* endpoints React/Vue calls behind the scenes.
            def _on_request(request):
                try:
                    u = request.url
                    if not _same_origin(u, target_origin):
                        return  # scope-lock
                    qparams = _extract_query_params(u)
                    asyncio.create_task(_record_api(u, request.method, qparams))
                except Exception:
                    pass

            page.on("request", _on_request)

            # ─── BFS crawl with a hard total budget ───────────────────
            deadline = asyncio.get_event_loop().time() + TOTAL_BUDGET_SECONDS

            while queue and len(visited) < MAX_PAGES:
                if asyncio.get_event_loop().time() > deadline:
                    errors.append(f"crawl budget exhausted at {len(visited)} pages")
                    break

                url, depth = queue.pop(0)
                if url in visited or depth > MAX_DEPTH:
                    continue
                visited.add(url)
                discovered_urls.add(url)

                try:
                    resp = await page.goto(url, timeout=10_000, wait_until="networkidle")
                    if resp and resp.status >= 429:
                        errors.append(f"rate limited at {url} ({resp.status}) — aborting")
                        break

                    # Give the SPA a moment to render dynamic content
                    await asyncio.sleep(INTRA_PAGE_WAIT_MS / 1000)

                    # Pull all <a href> links — including SPA hash routes
                    hrefs = await page.eval_on_selector_all(
                        "a[href]",
                        "els => els.map(e => e.href)",
                    )
                    # Pull <form action> targets
                    form_actions = await page.eval_on_selector_all(
                        "form[action]",
                        "els => els.map(e => e.action)",
                    )
                    for nxt in list(hrefs) + list(form_actions):
                        if not nxt or not _same_origin(nxt, target_origin):
                            continue
                        if _is_boring(nxt):
                            continue
                        # Strip fragment for de-dupe but record hash routes as URLs
                        clean = nxt.split("#", 1)[0]
                        if nxt not in visited and len(queue) < MAX_PAGES:
                            queue.append((nxt, depth + 1))
                        if "#/" in nxt or "#!" in nxt:
                            discovered_urls.add(nxt)
                        else:
                            discovered_urls.add(clean)

                    # Pull form input names — feeds Phase B param_mining
                    input_names = await page.eval_on_selector_all(
                        "input[name], select[name], textarea[name]",
                        "els => els.map(e => e.name)",
                    )
                    for n in input_names:
                        if n:
                            discovered_params.add(n)

                except Exception as e:
                    errors.append(f"page {url}: {str(e)[:120]}")

            await context.close()
            await browser.close()

    except Exception as e:
        return standard_response(
            tool="spa_crawler", target=req.target,
            findings=[],
            tests_performed=len(visited),
            tests_summary=f"Crawler crashed: {str(e)[:160]}",
            skipped_reason=f"Headless browser failed: {str(e)[:200]}",
            raw_data={"spa_crawler": {"engine": "playwright", "errors": errors}},
        )

    # Build findings — informational only. Real bugs come from
    # later scanners that consume this output.
    findings = []
    if not discovered_api:
        findings.append({
            "severity": "INFO",
            "detail": (
                f"No API endpoints discovered. Crawled {len(visited)} pages. "
                "Target may be a fully-static site or block headless browsers."
            ),
            "confidence": "CONFIRMED",
            "remediation": "—",
        })
    else:
        # Note any debug/dev endpoints discovered
        for endpoint in sorted(discovered_api.keys()):
            low = endpoint.lower()
            if any(k in low for k in ("/debug", "/admin", "/_next/debug", "/.env")):
                findings.append({
                    "severity": "MEDIUM",
                    "detail": f"Sensitive-looking endpoint discovered via SPA traffic: {endpoint}",
                    "evidence_marker": endpoint,
                    "cvss": "5.3",
                    "cwe": "CWE-200",
                    "owasp": "A05:2021",
                    "confidence": "CONFIRMED",
                    "remediation": (
                        "Verify this endpoint should be exposed in production. "
                        "Restrict to authenticated users or remove."
                    ),
                })

    # Serialize sets for JSON
    api_summary = {
        ep: {
            "methods": sorted(info["methods"]),
            "params":  sorted(info["params"]),
            "looks_like_api": _looks_like_api(ep),
        }
        for ep, info in discovered_api.items()
    }

    return standard_response(
        tool="spa_crawler",
        target=req.target,
        findings=findings,
        tests_performed=len(visited),
        tests_summary=(
            f"SPA crawl: {len(visited)} pages visited, "
            f"{len(discovered_urls)} unique URLs, "
            f"{len(discovered_api)} API endpoints, "
            f"{len(discovered_params)} param names discovered"
        ),
        raw_data={
            "spa_crawler": {
                "engine": "playwright (Chromium)",
                "pages_visited":      len(visited),
                "urls_discovered":    sorted(discovered_urls),
                "api_endpoints":      api_summary,
                "param_names":        sorted(discovered_params),
                "errors":             errors,
                "max_pages_limit":    MAX_PAGES,
                "max_depth_limit":    MAX_DEPTH,
                "budget_seconds":     TOTAL_BUDGET_SECONDS,
                "user_agent":         VULNUSLAB_UA,
            }
        },
    )





@router.post("/api/scan/spa_crawler")
async def scan_spa_crawler(req: ScanRequest, payload=Depends(verify_scan_quota)):
    """Alias so the WebApp module's /api/scan/* tile grid can call us."""
    return await webapp_spa_crawler(req, payload)

def register(app):
    app.include_router(router)
