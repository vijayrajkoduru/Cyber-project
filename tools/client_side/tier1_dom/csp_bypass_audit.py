"""csp_bypass_audit - Content-Security-Policy weakness classes
(playbook §5 #40 + §7 #69).

Fetches the target URL and parses both the HTTP `Content-Security-Policy`
response header AND any `<meta http-equiv="Content-Security-Policy">`
elements in the rendered HTML. Then tests for bypass classes that
defeat CSP-as-XSS-mitigation:

  1. 'unsafe-inline' in script-src   — any reflected XSS still fires
  2. 'unsafe-eval'   in script-src   — eval()/setTimeout(str) attacker primitive
  3. JSONP-callable trusted hosts    — e.g. storage.googleapis.com,
                                        ajax.googleapis.com (well-known
                                        bypass vectors)
  4. Too-permissive script-src       — `*`, `https:`, or `data:` source
  5. Missing object-src              — flash/object/embed XSS pivot
  6. Missing base-uri                — <base> tag injection redirects
                                        all relative URLs

Each bypass class is reported as HIGH (CSP is a defense-in-depth layer
that's *designed* to fail closed — open it and you give attackers a
straight path).

Customer input via ScanRequest:
  - target              = website URL (http(s)://...)
  - options.user_agent  = optional UA override

References:
  - https://csp-evaluator.withgoogle.com/
  - https://csp.withgoogle.com/docs/strict-csp.html
  - Weichselbaum et al., CSP Is Dead, Long Live CSP (CCS'16)
"""
from __future__ import annotations
import re
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.csp_bypass_audit_findings import CSP_BYPASS_AUDIT_FINDING_RULES

router = APIRouter()


class CspBypassRequest(ScanRequest):
    options: Optional[dict] = None


# Well-known JSONP / open-callback hosts that, if listed in script-src,
# let an attacker execute arbitrary JS via ?callback=evil-payload.
# Source: cure53 "H5SC" + Google CSP bypass cheat sheet + PortSwigger.
JSONP_TRUSTED_HOSTS = {
    "storage.googleapis.com",
    "ajax.googleapis.com",
    "www.google-analytics.com",
    "www.googletagmanager.com",
    "*.googleusercontent.com",
    "fonts.googleapis.com",
    "ssl.google-analytics.com",
    "apis.google.com",
    "accounts.google.com",
    "www.googleapis.com",
    "*.cloudfront.net",
    "s3.amazonaws.com",
    "*.s3.amazonaws.com",
    "*.azureedge.net",
    "*.akamaihd.net",
    "ajax.aspnetcdn.com",
    "ajax.microsoft.com",
    "cdnjs.cloudflare.com",
}


def _parse_csp(raw: str) -> dict:
    """Parse a CSP string into {directive: [source, ...]} keeping order."""
    out: dict = {}
    if not raw:
        return out
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        bits = part.split(None, 1)
        directive = bits[0].lower().strip()
        sources = bits[1].split() if len(bits) > 1 else []
        out[directive] = [s.strip() for s in sources if s.strip()]
    return out


_META_CSP_RE = re.compile(
    r"""<meta\s+[^>]*http-equiv\s*=\s*["']?Content-Security-Policy["']?[^>]*"""
    r"""content\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


def _extract_meta_csps(html: str) -> list[str]:
    if not html:
        return []
    return [m.group(1) for m in _META_CSP_RE.finditer(html)]


def _analyze_csp(parsed: dict) -> dict:
    """Return a dict of detected weaknesses from one parsed CSP."""
    out: dict = {
        "unsafe_inline_script":  False,
        "unsafe_eval_script":    False,
        "unsafe_inline_style":   False,
        "wildcard_script_src":   False,
        "https_scheme_script":   False,
        "data_scheme_script":    False,
        "missing_object_src":    False,
        "missing_base_uri":      False,
        "missing_default_src":   False,
        "jsonp_trusted_hosts":   [],
        "script_src_present":    False,
    }
    if not parsed:
        return out

    script_src = parsed.get("script-src") or parsed.get("default-src") or []
    out["script_src_present"] = bool(parsed.get("script-src"))
    style_src = parsed.get("style-src") or parsed.get("default-src") or []
    sl = [s.lower() for s in script_src]
    tl = [s.lower() for s in style_src]

    if "'unsafe-inline'" in sl:
        out["unsafe_inline_script"] = True
    if "'unsafe-eval'" in sl:
        out["unsafe_eval_script"] = True
    if "'unsafe-inline'" in tl:
        out["unsafe_inline_style"] = True
    if "*" in sl:
        out["wildcard_script_src"] = True
    if any(s in ("https:", "http:") for s in sl):
        out["https_scheme_script"] = True
    if "data:" in sl:
        out["data_scheme_script"] = True

    # JSONP / open-callback hosts
    for src in sl:
        host = src.strip("'")
        # Strip scheme
        for prefix in ("https://", "http://", "//"):
            if host.startswith(prefix):
                host = host[len(prefix):]
                break
        host = host.split("/", 1)[0].split(":", 1)[0]
        if host in JSONP_TRUSTED_HOSTS:
            out["jsonp_trusted_hosts"].append(host)

    if not parsed.get("object-src") and not parsed.get("default-src"):
        out["missing_object_src"] = True
    elif parsed.get("object-src") and "'none'" not in [
        s.lower() for s in parsed["object-src"]
    ]:
        # object-src present but not locked to 'none'
        out["missing_object_src"] = True
    if not parsed.get("base-uri"):
        out["missing_base_uri"] = True
    if not parsed.get("default-src") and not parsed.get("script-src"):
        out["missing_default_src"] = True
    return out


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
        ctx.state["csp_error"] = "httpx not installed (pip install httpx)"
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
        ctx.state["csp_error"] = f"fetch failed: {type(e).__name__}: {str(e)[:120]}"
        ctx.source("fetch failed")
        return

    # Collect every CSP source: response header (may appear N times), then meta tags
    header_csps: list[str] = []
    # httpx merges multi-value headers into a comma-joined string but provides
    # .get_list for split values
    try:
        header_csps = list(r.headers.get_list("content-security-policy"))
    except Exception:
        v = r.headers.get("content-security-policy")
        if v:
            header_csps = [v]

    # Also check Content-Security-Policy-Report-Only — telling for "monitor" mode
    report_only: list[str] = []
    try:
        report_only = list(r.headers.get_list("content-security-policy-report-only"))
    except Exception:
        v = r.headers.get("content-security-policy-report-only")
        if v:
            report_only = [v]

    meta_csps = _extract_meta_csps(r.text or "")

    all_csps = header_csps + meta_csps  # treat both as enforced
    parsed_all = [_parse_csp(c) for c in all_csps]
    analyses = [_analyze_csp(p) for p in parsed_all]

    # Aggregate: a weakness is "present" if ANY enforced CSP exhibits it
    # (the most permissive policy wins from an attacker's POV — though
    # browsers actually intersect multiple CSPs; here we report each so
    # the customer sees every issue).
    no_csp = (not header_csps) and (not meta_csps)
    summary = {
        "unsafe_inline_script":  False,
        "unsafe_eval_script":    False,
        "unsafe_inline_style":   False,
        "wildcard_script_src":   False,
        "https_scheme_script":   False,
        "data_scheme_script":    False,
        "missing_object_src":    False,
        "missing_base_uri":      False,
        "missing_default_src":   False,
        "jsonp_trusted_hosts":   [],
        "report_only_used":      bool(report_only),
        "policy_count":          len(all_csps),
    }
    for a in analyses:
        for k, v in a.items():
            if k == "jsonp_trusted_hosts":
                summary["jsonp_trusted_hosts"] = list({*summary["jsonp_trusted_hosts"], *v})
            elif isinstance(v, bool) and v:
                summary[k] = True

    ctx.state["csp_target_url"] = str(r.url)
    ctx.state["csp_http_status"] = r.status_code
    ctx.state["csp_policies_header"] = header_csps
    ctx.state["csp_policies_meta"] = meta_csps
    ctx.state["csp_policies_report_only"] = report_only
    ctx.state["csp_no_csp_at_all"] = no_csp
    ctx.state["csp_summary"] = summary

    src_label = (
        f"{len(header_csps)} header CSP(s), {len(meta_csps)} meta CSP(s)"
        if (header_csps or meta_csps)
        else "no CSP present"
    )
    ctx.source(f"GET {target} -> {r.status_code}; {src_label}")


INTEL_FIELDS = [
    ("Target URL",                "csp_target_url"),
    ("HTTP status",               "csp_http_status"),
    ("Header CSP policies",       "csp_policies_header"),
    ("Meta CSP policies",         "csp_policies_meta"),
    ("Report-Only CSP",           "csp_policies_report_only"),
    ("No CSP at all",             "csp_no_csp_at_all"),
    ("Weakness summary",          "csp_summary"),
]


@router.post("/api/client_side/csp_bypass_audit")
async def client_side_csp_bypass_audit(req: CspBypassRequest,
                                        _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="csp_bypass_audit",
        gather_func=_gather_with_options,
        finding_rules=CSP_BYPASS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
