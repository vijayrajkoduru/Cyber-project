"""bitb_frameability_check - Browser-in-the-Browser / iframe-embed exposure
of the customer's login page (playbook §3 #26 — BitB iframe).

Browser-in-the-Browser (BitB) and classic clickjacking both rely on the
victim's real login page being *embeddable*. If the login page can be put
inside an <iframe> (or rendered framed in a fake "browser chrome" overlay),
a phishing site can present the genuine origin's login UI while the
surrounding window lies about the URL bar. The single hard defence is the
page refusing to be framed: `X-Frame-Options: DENY/SAMEORIGIN` or a CSP
`frame-ancestors` directive that excludes attacker origins.

This probe is a READ-ONLY HTTP GET of the customer-supplied login URL and
an inspection of the framing-control response headers. It frames nothing,
embeds nothing, and runs no JavaScript — it only reads what the server
sends back.

What it checks (a DETECTED condition — header present/absent is a fact):
  - X-Frame-Options  : DENY / SAMEORIGIN / ALLOW-FROM / absent / malformed
  - CSP frame-ancestors : 'none' / 'self' / explicit allowlist / wildcard /
    absent
  - The combined verdict: is the page framable by an arbitrary origin?

Severity model — graded ONLY on what was actually observed in the live
response headers (no inference, no assumption):

  MEDIUM   - page is framable by ANY origin (no XFO and CSP frame-ancestors
             absent OR contains a `*` / unsafe wildcard) -> BitB +
             clickjacking surface is real
  LOW      - XFO present but uses the deprecated/ignored `ALLOW-FROM`
             directive (no effect in modern browsers) and CSP doesn't cover
  INFO     - fetch could not run / no URL supplied / non-2xx login page
  POSITIVE - framing denied (XFO DENY/SAMEORIGIN OR CSP frame-ancestors
             'none'/'self'/explicit non-wildcard list)

ZERO-FP guard: MEDIUM/LOW are emitted ONLY after a successful HTTP fetch
whose headers were parsed. A failed/blocked fetch is INFO, never a graded
finding.

Customer input via ScanRequest.options:
  - target_url    = full URL of the login page (required, e.g.
                    https://acme.com/login)
  - timeout_sec   = HTTP fetch timeout (default 15, hard cap 45)

References:
  - mr.d0x "Browser In The Browser (BITB) Attack" (2022)
  - OWASP Clickjacking Defense Cheat Sheet
  - RFC 7034 (X-Frame-Options), CSP Level 3 frame-ancestors
"""
from __future__ import annotations
import re
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.bitb_frameability_check_findings import (
    BITB_FRAMEABILITY_CHECK_FINDING_RULES,
)

router = APIRouter()


class BitbRequest(ScanRequest):
    options: Optional[dict] = None


def _parse_frame_ancestors(csp: str) -> Optional[list[str]]:
    """Return the frame-ancestors source list (lowercased tokens) if the
    directive is present, else None."""
    if not csp:
        return None
    m = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
    if not m:
        return None
    return [t.strip().lower() for t in m.group(1).split() if t.strip()]


def _evaluate_framability(xfo: str, frame_ancestors: Optional[list[str]]) -> dict:
    """Decide whether an arbitrary attacker origin can frame the page.

    Returns a dict with booleans the rules engine reads. This is a pure
    function over the OBSERVED headers — no network, no inference."""
    out = {
        "xfo_value":            xfo or None,
        "xfo_denies":           False,
        "xfo_allow_from":       False,
        "fa_value":             frame_ancestors,
        "fa_denies":            False,
        "fa_wildcard":          False,
        "framable_by_any":      False,
        "deny_reason":          None,
    }
    x = (xfo or "").strip().lower()
    if x in ("deny", "sameorigin"):
        out["xfo_denies"] = True
        out["deny_reason"] = f"X-Frame-Options: {xfo}"
    elif x.startswith("allow-from"):
        # ALLOW-FROM is obsolete and ignored by Chrome/Firefox/Edge — it
        # does NOT protect, so it does not count as a deny.
        out["xfo_allow_from"] = True

    if frame_ancestors is not None:
        # CSP frame-ancestors overrides XFO when present.
        toks = frame_ancestors
        if any(t in ("*",) or t.endswith("*") or t == "http:" or t == "https:"
               for t in toks):
            out["fa_wildcard"] = True
        elif "'none'" in toks:
            out["fa_denies"] = True
            out["deny_reason"] = "CSP frame-ancestors 'none'"
        else:
            # 'self' or an explicit host list = denies arbitrary origins
            # (as long as no wildcard token was present).
            out["fa_denies"] = True
            out["deny_reason"] = (out["deny_reason"]
                                  or f"CSP frame-ancestors {' '.join(toks)}")

    # Framable by an arbitrary origin when NOTHING denies it. CSP, when
    # present, is authoritative (overrides XFO).
    if frame_ancestors is not None:
        out["framable_by_any"] = not out["fa_denies"]
    else:
        out["framable_by_any"] = not out["xfo_denies"]
    return out


async def gather(ctx: ScanContext):
    target_domain = (ctx.host or "").strip()
    if not target_domain:
        ctx.source("no-target")
        return

    opts = ctx.state.get("_options") or {}
    url = (opts.get("target_url") or "").strip()
    if not url:
        ctx.state["bitb_input_missing"] = True
        ctx.source("no target_url in options")
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        timeout = min(max(int(opts.get("timeout_sec") or 15), 5), 45)
    except (TypeError, ValueError):
        timeout = 15

    try:
        import httpx
    except ImportError:
        ctx.state["bitb_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=True,
            headers={
                "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/120.0.0.0 Safari/537.36"),
                "Accept": "text/html,application/xhtml+xml,*/*",
            },
        ) as client:
            r = await client.get(url)
    except Exception as e:
        ctx.state["bitb_error"] = f"fetch failed: {type(e).__name__}: {str(e)[:120]}"
        ctx.source("fetch failed")
        return

    ctx.state["bitb_target_url"] = str(r.url)
    ctx.state["bitb_http_status"] = r.status_code

    # Header lookups are case-insensitive in httpx.
    xfo = r.headers.get("x-frame-options") or ""
    csp = (r.headers.get("content-security-policy") or "")
    # If CSP is in report-only mode it does NOT enforce framing — treat as
    # absent for enforcement purposes (but record it for evidence).
    csp_ro = (r.headers.get("content-security-policy-report-only") or "")
    frame_ancestors = _parse_frame_ancestors(csp)

    verdict = _evaluate_framability(xfo, frame_ancestors)
    ctx.state["bitb_xfo"] = xfo or None
    ctx.state["bitb_csp"] = (csp[:300] or None)
    ctx.state["bitb_csp_report_only"] = (csp_ro[:300] or None)
    ctx.state["bitb_frame_ancestors"] = frame_ancestors
    ctx.state["bitb_verdict"] = verdict
    ctx.state["bitb_framable_by_any"] = verdict["framable_by_any"]
    ctx.state["bitb_fetched_ok"] = (200 <= r.status_code < 400)

    ctx.source(
        f"GET {url} -> {r.status_code}; "
        f"XFO={xfo or 'absent'}; "
        f"frame-ancestors={frame_ancestors if frame_ancestors is not None else 'absent'}; "
        f"framable_by_any={verdict['framable_by_any']}"
    )


INTEL_FIELDS = [
    ("Login URL probed",        "bitb_target_url"),
    ("HTTP status",             "bitb_http_status"),
    ("X-Frame-Options",         "bitb_xfo"),
    ("CSP (enforced)",          "bitb_csp"),
    ("CSP (report-only)",       "bitb_csp_report_only"),
    ("CSP frame-ancestors",     "bitb_frame_ancestors"),
    ("Framable by any origin",  "bitb_framable_by_any"),
    ("Framing verdict",         "bitb_verdict"),
]


@router.post("/api/phishing/bitb_frameability_check")
async def phishing_bitb_frameability_check(req: BitbRequest,
                                           _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="bitb_frameability_check",
        gather_func=_gather_with_options,
        finding_rules=BITB_FRAMEABILITY_CHECK_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
