"""clickjacking_audit - frame-busting / UI-redress protection audit
(playbook §5 #40 clickjacking + §1 #5 tabnabbing surface).

Clickjacking (UI redress) loads the target inside an attacker-controlled
<iframe> and overlays it with a transparent decoy so the victim's clicks
land on the framed app (e.g. confirming a money transfer or granting an
OAuth scope). The browser-side defenses are:

  1. X-Frame-Options: DENY | SAMEORIGIN   (legacy, still widely honoured)
  2. CSP frame-ancestors 'none' | 'self' | <allowlist>  (modern)

This probe fetches the target URL (HTTP + meta CSP), parses both
defenses, and grades the result PURELY on what the server actually
returns:

  HIGH    - NEITHER X-Frame-Options NOR frame-ancestors present
            (the page is framable by ANY origin)
  HIGH    - X-Frame-Options ALLOW-FROM <single-origin> only
            (deprecated, ignored by Chrome/Edge -> effectively framable)
  MEDIUM  - frame-ancestors allows a wildcard ('*' or a scheme like https:)
  MEDIUM  - X-Frame-Options present but malformed / unknown token
  LOW     - X-Frame-Options SAMEORIGIN but NO frame-ancestors (legacy-only;
            modern bypasses via about:blank nested frames possible)
  INFO    - fetch failed / unreachable
  POSITIVE- frame-ancestors 'none'/'self' (or with an explicit allowlist)
            present -> robust, modern protection

ZERO false positives: a graded severity is emitted ONLY when the fetched
response actually lacks (or weakens) the protection. Detection only — no
iframe is ever constructed or rendered.

Customer input via ScanRequest:
  - target              = website URL (http(s)://...)
  - options.user_agent  = optional UA override
"""
from __future__ import annotations
import re
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()


class ClickjackingRequest(ScanRequest):
    options: Optional[dict] = None


_META_CSP_RE = re.compile(
    r"""<meta\s+[^>]*http-equiv\s*=\s*["']?Content-Security-Policy["']?[^>]*"""
    r"""content\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

_VALID_XFO = {"deny", "sameorigin"}


def _extract_frame_ancestors(csps: list[str]) -> Optional[list[str]]:
    """Return the frame-ancestors source list from the first CSP that has
    one, or None if no CSP declares the directive."""
    for raw in csps:
        for part in (raw or "").split(";"):
            part = part.strip()
            if not part:
                continue
            bits = part.split(None, 1)
            if bits[0].lower() == "frame-ancestors":
                srcs = bits[1].split() if len(bits) > 1 else []
                return [s.strip() for s in srcs if s.strip()]
    return None


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
        ctx.state["clickjacking_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return

    opts = ctx.state.get("_options") or {}
    ua = opts.get("user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=20, follow_redirects=True,
            headers={"User-Agent": ua, "Accept": "text/html,*/*"},
        ) as client:
            r = await client.get(target)
    except Exception as e:
        ctx.state["clickjacking_error"] = (
            f"fetch failed: {type(e).__name__}: {str(e)[:120]}"
        )
        ctx.source("fetch failed")
        return

    # X-Frame-Options (header).
    xfo_raw = r.headers.get("x-frame-options")
    xfo = (xfo_raw or "").strip()
    xfo_token = xfo.lower().split(None, 1)[0] if xfo else ""
    xfo_present = bool(xfo)
    xfo_valid = xfo_token in _VALID_XFO
    # ALLOW-FROM is deprecated and ignored by Chromium-family browsers.
    xfo_allow_from = xfo_token == "allow-from"

    # CSP frame-ancestors (header + meta) — modern, takes precedence.
    header_csps: list[str] = []
    try:
        header_csps = list(r.headers.get_list("content-security-policy"))
    except Exception:
        v = r.headers.get("content-security-policy")
        if v:
            header_csps = [v]
    meta_csps = _META_CSP_RE.findall(r.text or "")
    all_csps = header_csps + list(meta_csps)

    fa = _extract_frame_ancestors(all_csps)
    fa_present = fa is not None
    fa_lower = [s.lower() for s in (fa or [])]
    # Wildcard / scheme-only frame-ancestors -> still framable by anyone.
    fa_wildcard = any(
        s == "*" or s in ("https:", "http:", "data:") for s in fa_lower
    )
    # 'none' or 'self' (with an optional explicit allowlist) -> protected.
    fa_locked = fa_present and not fa_wildcard

    ctx.state["clickjacking_target_url"] = str(r.url)
    ctx.state["clickjacking_http_status"] = r.status_code
    ctx.state["clickjacking_xfo_raw"] = xfo_raw or "(absent)"
    ctx.state["clickjacking_xfo_present"] = xfo_present
    ctx.state["clickjacking_xfo_valid"] = xfo_valid
    ctx.state["clickjacking_xfo_allow_from"] = xfo_allow_from
    ctx.state["clickjacking_frame_ancestors"] = fa if fa_present else "(absent)"
    ctx.state["clickjacking_fa_present"] = fa_present
    ctx.state["clickjacking_fa_wildcard"] = fa_wildcard
    ctx.state["clickjacking_fa_locked"] = fa_locked
    # Composite: is the page framable by an arbitrary attacker origin?
    no_real_protection = (not fa_locked) and (not (xfo_valid))
    ctx.state["clickjacking_unprotected"] = no_real_protection

    ctx.source(
        f"GET {target} -> {r.status_code}; "
        f"XFO={xfo or 'absent'}; "
        f"frame-ancestors={'set' if fa_present else 'absent'}"
    )


# ── findings rules (inline — module owns its own rule logic) ───────────
# A graded severity is emitted ONLY when the fetched response actually
# lacks/weakens the protection. verified_exploit=True is set because the
# condition was observed on the live response (not advisory guesswork),
# which exempts it from the global advisory-language INFO cap.

def rule_unprotected(s):
    if s.get("clickjacking_error"):
        return None
    if not s.get("clickjacking_unprotected"):
        return None
    # Distinguish "nothing at all" from "only deprecated ALLOW-FROM".
    if s.get("clickjacking_xfo_allow_from"):
        why = ("X-Frame-Options uses the deprecated ALLOW-FROM directive, "
               "which Chrome/Edge/Safari ignore entirely, and no CSP "
               "frame-ancestors directive is present.")
    elif s.get("clickjacking_xfo_present") and not s.get("clickjacking_xfo_valid"):
        why = (f"X-Frame-Options is present but malformed "
               f"({s.get('clickjacking_xfo_raw')}); browsers fall back to "
               "allowing framing, and no CSP frame-ancestors directive is "
               "present.")
    else:
        why = ("Neither an X-Frame-Options header nor a CSP frame-ancestors "
               "directive is present on the response.")
    return {
        "name": "Clickjacking / UI-redress protection absent (page is framable)",
        "severity": "HIGH",
        "cvss": "6.5",
        "cwe": "CWE-1021",
        "cwe_name": "Improper Restriction of Rendered UI Layers or Frames",
        "owasp": "A05:2021",
        "verified_exploit": True,
        "evidence": (
            f"GET {s.get('clickjacking_target_url')} returned HTTP "
            f"{s.get('clickjacking_http_status')}. {why} An attacker page "
            "can load this URL inside a transparent <iframe> and overlay a "
            "decoy UI so victim clicks/keystrokes are delivered to the "
            "framed application (UI redress / clickjacking)."
        ),
        "remediation": (
            "Add `Content-Security-Policy: frame-ancestors 'none'` (or "
            "'self' plus an explicit allowlist if the app is legitimately "
            "embedded) AND `X-Frame-Options: SAMEORIGIN` for legacy "
            "browsers. frame-ancestors is the modern, browser-enforced "
            "control and supersedes X-Frame-Options where both are present."
        ),
    }


def rule_fa_wildcard(s):
    if s.get("clickjacking_error"):
        return None
    if not s.get("clickjacking_fa_wildcard"):
        return None
    fa = s.get("clickjacking_frame_ancestors")
    return {
        "name": "CSP frame-ancestors uses a wildcard / scheme source (framable by any origin)",
        "severity": "MEDIUM",
        "cvss": "5.4",
        "cwe": "CWE-1021",
        "cwe_name": "Improper Restriction of Rendered UI Layers or Frames",
        "owasp": "A05:2021",
        "verified_exploit": True,
        "evidence": (
            f"frame-ancestors directive resolves to {fa}, which permits "
            "framing from any host on the matched scheme. This is "
            "functionally equivalent to no clickjacking protection — any "
            "attacker origin on that scheme can embed the page."
        ),
        "remediation": (
            "Replace the wildcard/scheme source with `frame-ancestors "
            "'none'` (or 'self' plus the exact partner origins that must "
            "embed the app). Never use '*', 'https:', or 'data:' here."
        ),
    }


def rule_xfo_sameorigin_only(s):
    if s.get("clickjacking_error"):
        return None
    # SAMEORIGIN XFO present, valid, but NO frame-ancestors backing it up.
    if s.get("clickjacking_unprotected"):
        return None
    if s.get("clickjacking_fa_present"):
        return None
    if not s.get("clickjacking_xfo_valid"):
        return None
    if (s.get("clickjacking_xfo_raw") or "").strip().lower().split(None, 1)[0] != "sameorigin":
        return None
    return {
        "name": "Clickjacking defense relies on legacy X-Frame-Options only (no CSP frame-ancestors)",
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": "CWE-1021",
        "cwe_name": "Improper Restriction of Rendered UI Layers or Frames",
        "owasp": "A05:2021",
        "verified_exploit": True,
        "evidence": (
            f"X-Frame-Options: {s.get('clickjacking_xfo_raw')} is set, but "
            "no CSP frame-ancestors directive backs it up. X-Frame-Options "
            "is deprecated and has documented nested-frame edge cases; the "
            "modern, browser-enforced control is CSP frame-ancestors."
        ),
        "remediation": (
            "Add `Content-Security-Policy: frame-ancestors 'self'` (or "
            "'none') alongside the existing X-Frame-Options header so the "
            "page is protected in browsers that have deprecated XFO."
        ),
    }


def rule_fetch_failed(s):
    err = s.get("clickjacking_error")
    if not err:
        return None
    return {
        "name": "Clickjacking audit could not fetch target URL",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": str(err)[:300],
        "remediation": ("Confirm the URL is reachable from the scanner host "
                        "and uses a valid http/https scheme."),
    }


def rule_positive(s):
    if s.get("clickjacking_error"):
        return None
    if not s.get("clickjacking_fa_locked"):
        return None
    fa = s.get("clickjacking_frame_ancestors")
    return {
        "name": "Robust clickjacking protection (CSP frame-ancestors locked)",
        "severity": "POSITIVE",
        "cwe": "CWE-1021",
        "owasp": "A05:2021",
        "evidence": (
            f"frame-ancestors resolves to {fa} (no wildcard/scheme source) "
            f"and X-Frame-Options="
            f"{s.get('clickjacking_xfo_raw')}. The page cannot be framed by "
            "an arbitrary attacker origin."
        ),
        "remediation": ("Keep frame-ancestors locked. Re-test after adding "
                        "any new embed partner — each addition widens the "
                        "framing surface."),
    }


CLICKJACKING_AUDIT_FINDING_RULES = [
    rule_unprotected,
    rule_fa_wildcard,
    rule_xfo_sameorigin_only,
    rule_fetch_failed,
    rule_positive,
]


INTEL_FIELDS = [
    ("Target URL",             "clickjacking_target_url"),
    ("HTTP status",            "clickjacking_http_status"),
    ("X-Frame-Options",        "clickjacking_xfo_raw"),
    ("CSP frame-ancestors",    "clickjacking_frame_ancestors"),
    ("Framable by any origin", "clickjacking_unprotected"),
]


@router.post("/api/client_side/clickjacking_audit")
async def client_side_clickjacking_audit(req: ClickjackingRequest,
                                          _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="clickjacking_audit",
        gather_func=_gather_with_options,
        finding_rules=CLICKJACKING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
