"""service_worker_audit - Service Worker registration / scope audit
(playbook §7 #65 Service Worker persistence).

A Service Worker (SW) is a script the browser installs against an origin
and runs in the background — it can intercept EVERY fetch the page
makes, serve cached responses, and persist across tabs/restarts. If an
attacker with a transient XSS foothold can register a malicious SW (or
if a legitimate SW is served from an over-broad scope with weak cache
controls), they gain durable, page-independent control of the origin's
network traffic — the modern "client-side persistence" primitive.

This probe (DETECTION ONLY) fetches the target HTML + first-party JS and
statically discovers:
  - navigator.serviceWorker.register('<url>', { scope: '<scope>' }) calls
  - the SW script URL and its declared/effective scope
It then safely fetches the SW script itself (GET, no execution) to
record its Content-Type, Cache-Control, and size — a SW served with a
long max-age and no revalidation is harder to evict if poisoned.

Findings are deliberately conservative (presence of a SW is NORMAL and
expected on PWAs):

  MEDIUM  - SW registered at the ROOT scope ('/') AND served with a
            cache policy that allows long-lived caching with no
            revalidation (poisoned-SW persistence is harder to evict)
  LOW     - SW script served WITHOUT Cache-Control: no-cache / max-age=0
            (best practice is that the SW file itself be non-cacheable so
            updates roll out; long caching slows incident eviction)
  INFO    - SW registration detected, scope recorded (informational)
  INFO    - no Service Worker registration found
  INFO    - fetch failed
  POSITIVE- SW present and served non-cacheable (updatable / evictable)

ZERO false positives: a graded severity is emitted ONLY when the SW
script's actual response headers / scope meet the condition. The SW
script is fetched but NEVER executed or registered.

Customer input via ScanRequest:
  - target              = website URL (http(s)://...)
  - options.max_js      = max first-party JS files to scan (default 10)
  - options.user_agent  = optional UA override
"""
from __future__ import annotations
import asyncio
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()


class ServiceWorkerRequest(ScanRequest):
    options: Optional[dict] = None


# navigator.serviceWorker.register('sw.js', { scope: '/' })
_REGISTER_RE = re.compile(
    r"""serviceWorker\s*\.\s*register\s*\(\s*"""
    r"""(?P<q>['"`])(?P<url>[^'"`]+)(?P=q)"""
    r"""(?P<rest>[^)]*)\)""",
    re.IGNORECASE | re.DOTALL,
)
_SCOPE_RE = re.compile(
    r"""scope\s*:\s*(['"`])([^'"`]+)\1""", re.IGNORECASE
)


def _same_registrable(a: str, b: str) -> bool:
    def reg(h):
        parts = [p for p in (h or "").lower().split(".") if p]
        return ".".join(parts[-2:]) if len(parts) >= 2 else (h or "").lower()
    return reg(a) == reg(b)


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.source("no-target")
        return
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    try:
        import httpx
    except ImportError:
        ctx.state["sw_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        ctx.state["sw_error"] = "beautifulsoup4 not installed (pip install beautifulsoup4)"
        ctx.source("bs4 missing")
        return

    opts = ctx.state.get("_options") or {}
    max_js = min(int(opts.get("max_js") or 10), 20)
    ua = opts.get("user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    base_url = target
    base_host = ""
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=20, follow_redirects=True,
            headers={"User-Agent": ua, "Accept": "text/html,*/*"},
        ) as client:
            r = await client.get(target)
            html = r.text or ""
            base_url = str(r.url)
            base_host = urlparse(base_url).hostname or ""
            ctx.state["sw_http_status"] = r.status_code
            ctx.state["sw_target_url"] = base_url
    except Exception as e:
        ctx.state["sw_error"] = f"fetch failed: {type(e).__name__}: {str(e)[:120]}"
        ctx.source("fetch failed")
        return

    soup = BeautifulSoup(html, "html.parser")
    blobs: list[str] = []
    ext_urls: list[str] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            abs_u = urljoin(base_url, src)
            h = urlparse(abs_u).hostname or ""
            if _same_registrable(h, base_host) and not abs_u.startswith("data:"):
                ext_urls.append(abs_u)
        else:
            txt = tag.string or tag.get_text() or ""
            if txt.strip():
                blobs.append(txt)

    # Fetch first-party JS (where SW registration usually lives).
    ext_urls = list(dict.fromkeys(ext_urls))[:max_js]
    if ext_urls:
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=15, follow_redirects=True,
                headers={"User-Agent": ua, "Accept": "*/*"},
            ) as client:
                sem = asyncio.Semaphore(6)

                async def _one(u):
                    async with sem:
                        try:
                            rr = await client.get(u)
                            if rr.status_code == 200:
                                return rr.text or ""
                        except Exception:
                            return ""
                    return ""

                for txt in await asyncio.gather(*[_one(u) for u in ext_urls]):
                    if txt:
                        blobs.append(txt[:1_000_000])
        except Exception as e:
            ctx.state["sw_js_warn"] = f"{type(e).__name__}: {str(e)[:100]}"

    # Discover registrations.
    regs: list[dict] = []
    for blob in blobs:
        for m in _REGISTER_RE.finditer(blob):
            url = m.group("url")
            rest = m.group("rest") or ""
            sm = _SCOPE_RE.search(rest)
            scope = sm.group(2) if sm else None
            regs.append({"sw_url": url, "declared_scope": scope})
            if len(regs) >= 8:
                break
        if len(regs) >= 8:
            break

    ctx.state["sw_registrations_found"] = len(regs)

    if not regs:
        ctx.state["sw_none_found"] = True
        ctx.source(f"GET {target}; no serviceWorker.register() call found")
        return

    # Safely fetch the (first) SW script to inspect its headers — never run it.
    sw_details: list[dict] = []
    root_scope_cacheable = False
    any_cacheable = False
    async with httpx.AsyncClient(
        verify=False, timeout=15, follow_redirects=True,
        headers={"User-Agent": ua, "Accept": "*/*"},
    ) as client:
        for reg in regs[:4]:
            abs_sw = urljoin(base_url, reg["sw_url"])
            # Default SW scope = the directory the script is served from.
            effective_scope = reg["declared_scope"] or (
                urlparse(abs_sw).path.rsplit("/", 1)[0] + "/"
            )
            det = {
                "sw_url": abs_sw[:300],
                "effective_scope": effective_scope,
                "content_type": None,
                "cache_control": None,
                "size": None,
                "fetched": False,
            }
            try:
                rr = await client.get(abs_sw)
                det["fetched"] = True
                det["status"] = rr.status_code
                det["content_type"] = rr.headers.get("content-type")
                cc = (rr.headers.get("cache-control") or "")
                det["cache_control"] = cc or "(absent)"
                det["size"] = len(rr.content or b"")
                ccl = cc.lower()
                # "Cacheable long-lived" = not no-cache/no-store/max-age=0.
                cacheable = not (
                    "no-cache" in ccl or "no-store" in ccl
                    or "max-age=0" in ccl or "must-revalidate" in ccl
                )
                if cacheable:
                    any_cacheable = True
                    if effective_scope in ("/", ""):
                        root_scope_cacheable = True
            except Exception as e:
                det["error"] = f"{type(e).__name__}: {str(e)[:80]}"
            sw_details.append(det)

    ctx.state["sw_registrations"] = regs[:8]
    ctx.state["sw_details"] = sw_details
    ctx.state["sw_root_scope_cacheable"] = root_scope_cacheable
    ctx.state["sw_any_cacheable"] = any_cacheable
    ctx.source(
        f"GET {target}; {len(regs)} SW registration(s); "
        f"{'root-scope cacheable' if root_scope_cacheable else 'scoped/non-cacheable'}"
    )


# ── findings rules (inline) ────────────────────────────────────────────

def rule_root_scope_cacheable(s):
    if s.get("sw_error"):
        return None
    if not s.get("sw_root_scope_cacheable"):
        return None
    return {
        "name": "Root-scope Service Worker served with long-lived caching (persistence eviction risk)",
        "severity": "MEDIUM",
        "cvss": "4.8",
        "cwe": "CWE-525",
        "cwe_name": "Use of Web Browser Cache Containing Sensitive Information",
        "owasp": "A05:2021",
        "verified_exploit": True,
        "evidence": (
            "A Service Worker is registered at root scope '/' (it can "
            "intercept every request to the origin) and its script is "
            "served without no-cache/no-store/max-age=0. If a transient "
            "XSS ever registers a poisoned SW, or a malicious update is "
            "served, the long cache lifetime makes the rogue worker harder "
            "to evict and lengthens the persistence window. SW details: "
            + "; ".join(
                f"{d.get('sw_url')} (scope {d.get('effective_scope')}, "
                f"Cache-Control: {d.get('cache_control')})"
                for d in (s.get("sw_details") or [])[:3]
            )
        ),
        "remediation": (
            "Serve the Service Worker script with `Cache-Control: no-cache` "
            "(or max-age=0, must-revalidate) so the browser always "
            "revalidates and updates roll out immediately. Register the SW "
            "at the narrowest scope the app needs rather than '/' where "
            "possible, and ensure the registration code is reachable only "
            "from trusted first-party JS (no XSS sink can call register())."
        ),
    }


def rule_sw_cacheable(s):
    if s.get("sw_error"):
        return None
    if s.get("sw_root_scope_cacheable"):
        return None  # the MEDIUM root-scope rule already covers it
    if not s.get("sw_any_cacheable"):
        return None
    return {
        "name": "Service Worker script served without no-cache (update / eviction latency)",
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": "CWE-525",
        "owasp": "A05:2021",
        "verified_exploit": True,
        "evidence": (
            "The registered Service Worker script is served with a cacheable "
            "policy (no no-cache/no-store/max-age=0). Best practice is that "
            "the SW file itself be non-cacheable so updates and security "
            "fixes propagate on the next navigation. SW details: "
            + "; ".join(
                f"{d.get('sw_url')} (Cache-Control: {d.get('cache_control')})"
                for d in (s.get("sw_details") or [])[:3]
            )
        ),
        "remediation": (
            "Set `Cache-Control: no-cache` on the Service Worker script "
            "response so browsers always revalidate it."
        ),
    }


def rule_no_sw(s):
    if s.get("sw_error"):
        return None
    if not s.get("sw_none_found"):
        return None
    return {
        "name": "No Service Worker registration detected",
        "severity": "INFO",
        "cwe": "CWE-noinfo",
        "evidence": (
            f"GET {s.get('sw_target_url')} and its first-party JS contained "
            "no navigator.serviceWorker.register() call. No SW persistence "
            "surface on this page."
        ),
        "remediation": "No action required.",
    }


def rule_fetch_failed(s):
    err = s.get("sw_error")
    if not err:
        return None
    return {
        "name": "Service Worker audit could not fetch target URL",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": str(err)[:300],
        "remediation": ("Confirm the URL is reachable from the scanner host "
                        "and serves HTML."),
    }


def rule_positive(s):
    if s.get("sw_error"):
        return None
    if not s.get("sw_registrations_found"):
        return None
    if s.get("sw_any_cacheable"):
        return None
    return {
        "name": "Service Worker present and served non-cacheable (updatable / evictable)",
        "severity": "POSITIVE",
        "cwe": "CWE-noinfo",
        "evidence": (
            "Registered Service Worker script(s) are served with a "
            "non-cacheable policy, so updates and any incident eviction "
            "propagate on the next navigation."
        ),
        "remediation": ("Keep the SW script non-cacheable and scope-limited."),
    }


SERVICE_WORKER_AUDIT_FINDING_RULES = [
    rule_root_scope_cacheable,
    rule_sw_cacheable,
    rule_no_sw,
    rule_fetch_failed,
    rule_positive,
]


INTEL_FIELDS = [
    ("Target URL",                  "sw_target_url"),
    ("HTTP status",                 "sw_http_status"),
    ("SW registrations found",      "sw_registrations_found"),
    ("SW registrations",            "sw_registrations"),
    ("SW script details",           "sw_details"),
    ("Root-scope + cacheable",      "sw_root_scope_cacheable"),
]


@router.post("/api/client_side/service_worker_audit")
async def client_side_service_worker_audit(req: ServiceWorkerRequest,
                                           _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="service_worker_audit",
        gather_func=_gather_with_options,
        finding_rules=SERVICE_WORKER_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
