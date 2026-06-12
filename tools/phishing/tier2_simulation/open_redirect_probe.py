"""open_redirect_probe - Open-redirect abuse surface on the customer's own
URLs (playbook §2 #21 — open-redirect abuse for phishing link laundering).

Phishers love an open redirect on a trusted domain: the lure link reads
`https://acme.com/go?url=...` (which mail filters and users trust) but the
server bounces the victim to the attacker's harvest page. This probe tests
a CUSTOMER-SUPPLIED redirect endpoint on the customer's OWN domain to see
whether it will redirect off-site to an arbitrary external host.

SAFETY / VA-not-PT:
  - The redirect target is a benign, non-routable canary host
    (`vl-open-redirect-canary.invalid` — the `.invalid` TLD is reserved by
    RFC 6761 and never resolves), so even if the server redirects, the
    victim browser would go nowhere real. We only read the 3xx Location
    header; we DO NOT follow it.
  - No payloads, no exploitation, no chaining into another scanner. We
    confirm the *capability* (off-site redirect to an arbitrary host) and
    report it. Acting on it is the customer's pentest decision.

What it does:
  1. Take options.redirect_url — a URL on the customer's domain that has a
     redirect parameter, e.g. https://acme.com/login?next=PLACEHOLDER or
     https://acme.com/out?url=PLACEHOLDER. The customer marks the param
     value to fuzz with the literal token VL_REDIR (or we auto-detect a
     common redirect param name and append our canary).
  2. Issue a single GET with follow_redirects=False and inspect the 3xx
     Location header.
  3. If Location points at our external canary host -> CONFIRMED open
     redirect (HIGH). If it stays same-origin or doesn't redirect ->
     POSITIVE/INFO.

Severity model — graded ONLY on a confirmed off-site Location:

  HIGH     - server returned a 3xx whose Location host == our external
             canary host (the endpoint redirects to an arbitrary off-site
             host -> phishing link-laundering surface CONFIRMED)
  INFO     - no redirect_url supplied / httpx missing / fetch failed
  INFO     - server did not redirect off-site (echoed same-origin or 2xx) —
             reported as not-vulnerable evidence
  POSITIVE - endpoint refused / sanitized the off-site target

ZERO-FP guard: HIGH fires ONLY when the parsed Location host exactly equals
the canary host we injected. Any same-origin redirect, relative Location,
or non-3xx response is INFO/POSITIVE.

Customer input via ScanRequest.options:
  - redirect_url   = the URL to test (required). Put the literal token
                     `VL_REDIR` where the redirect target value goes, OR
                     supply a URL whose redirect param we can auto-detect.
  - timeout_sec    = HTTP timeout (default 15, hard cap 45)

References:
  - CWE-601 (URL Redirection to Untrusted Site / Open Redirect)
  - OWASP "Unvalidated Redirects and Forwards" Cheat Sheet
  - RFC 6761 (.invalid reserved TLD), RFC 2606
"""
from __future__ import annotations
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.open_redirect_probe_findings import (
    OPEN_REDIRECT_PROBE_FINDING_RULES,
)

router = APIRouter()


class OpenRedirectRequest(ScanRequest):
    options: Optional[dict] = None


# Non-routable canary. The .invalid TLD (RFC 6761) is guaranteed never to
# resolve, so a redirect to it goes nowhere real — pure capability detection.
_CANARY_HOST = "vl-open-redirect-canary.invalid"
_CANARY_URL = f"https://{_CANARY_HOST}/vl-probe"
_REDIR_TOKEN = "VL_REDIR"

# Common redirect parameter names — used only to auto-detect where to put
# the canary when the customer didn't place the VL_REDIR token themselves.
_COMMON_REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_uri", "redirect_url", "return",
    "returnurl", "return_url", "returnto", "return_to", "dest",
    "destination", "continue", "goto", "go", "out", "target", "rurl",
    "redir", "r", "u", "link",
]


def _build_probe_url(redirect_url: str) -> tuple[Optional[str], Optional[str]]:
    """Return (probe_url, mode). mode is 'token' if the VL_REDIR token was
    substituted, 'param' if we appended a detected/synthetic redirect param,
    or (None, error) if we couldn't construct a probe."""
    if _REDIR_TOKEN in redirect_url:
        return redirect_url.replace(_REDIR_TOKEN, _CANARY_URL), "token"

    parsed = urlparse(redirect_url)
    if not parsed.scheme:
        parsed = urlparse("https://" + redirect_url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))

    # If an existing query param matches a known redirect-param name, swap
    # its value for the canary. Otherwise append the first common name.
    chosen = None
    for k in qs:
        if k.lower() in _COMMON_REDIRECT_PARAMS:
            chosen = k
            break
    if chosen:
        qs[chosen] = _CANARY_URL
    else:
        qs[_COMMON_REDIRECT_PARAMS[0]] = _CANARY_URL  # "next"
    new_query = urlencode(qs)
    probe = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment))
    return probe, "param"


async def gather(ctx: ScanContext):
    target_domain = (ctx.host or "").strip()
    if not target_domain:
        ctx.source("no-target")
        return

    opts = ctx.state.get("_options") or {}
    redirect_url = (opts.get("redirect_url") or "").strip()
    if not redirect_url:
        ctx.state["openredir_input_missing"] = True
        ctx.source("no redirect_url in options")
        return
    try:
        timeout = min(max(int(opts.get("timeout_sec") or 15), 5), 45)
    except (TypeError, ValueError):
        timeout = 15

    probe_url, mode = _build_probe_url(redirect_url)
    if not probe_url:
        ctx.state["openredir_error"] = f"could not construct probe URL: {mode}"
        ctx.source("bad redirect_url")
        return
    ctx.state["openredir_input_url"] = redirect_url
    ctx.state["openredir_probe_url"] = probe_url
    ctx.state["openredir_probe_mode"] = mode
    ctx.state["openredir_canary_host"] = _CANARY_HOST

    try:
        import httpx
    except ImportError:
        ctx.state["openredir_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return

    try:
        # CRITICAL: follow_redirects=False — we READ the Location, never go.
        async with httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=False,
            headers={
                "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/120.0.0.0 Safari/537.36"),
            },
        ) as client:
            r = await client.get(probe_url)
    except Exception as e:
        ctx.state["openredir_error"] = (
            f"fetch failed: {type(e).__name__}: {str(e)[:120]}"
        )
        ctx.source("fetch failed")
        return

    status = r.status_code
    location = r.headers.get("location") or ""
    ctx.state["openredir_status"] = status
    ctx.state["openredir_location"] = location[:300]

    is_3xx = 300 <= status < 400
    loc_host = None
    redirects_to_canary = False
    if location:
        try:
            loc_parsed = urlparse(location)
            loc_host = (loc_parsed.netloc or "").lower()
            # netloc may be empty for a relative Location (same-origin) — that
            # is NOT an open redirect.
            if loc_host == _CANARY_HOST:
                redirects_to_canary = True
        except Exception:
            loc_host = None

    ctx.state["openredir_location_host"] = loc_host
    ctx.state["openredir_is_3xx"] = is_3xx
    ctx.state["openredir_confirmed"] = bool(is_3xx and redirects_to_canary)
    ctx.state["openredir_evaluated"] = True   # a real probe ran

    ctx.source(
        f"GET {probe_url} -> {status}"
        + (f"; Location host={loc_host}" if location else "; no Location")
        + (f"; OPEN-REDIRECT CONFIRMED" if ctx.state["openredir_confirmed"]
           else "")
    )


INTEL_FIELDS = [
    ("Customer redirect URL",   "openredir_input_url"),
    ("Probe URL (canary)",      "openredir_probe_url"),
    ("Probe mode",              "openredir_probe_mode"),
    ("Canary host",             "openredir_canary_host"),
    ("HTTP status",             "openredir_status"),
    ("Location header",         "openredir_location"),
    ("Location host",           "openredir_location_host"),
    ("Open redirect confirmed", "openredir_confirmed"),
]


@router.post("/api/phishing/open_redirect_probe")
async def phishing_open_redirect_probe(req: OpenRedirectRequest,
                                       _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="open_redirect_probe",
        gather_func=_gather_with_options,
        finding_rules=OPEN_REDIRECT_PROBE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
