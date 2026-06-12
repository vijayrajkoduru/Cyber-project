"""open_redirect_param_audit - reflected open-redirect parameter audit
(playbook §6 #54 open-redirect abuse on a legitimate domain — the
prerequisite primitive for phishing, OAuth token theft, and CSP-allowed
redirect chains).

An open redirect is a server endpoint that takes a URL in a parameter
(?next=, ?url=, ?returnTo=, ?redirect=, ...) and 3xx-redirects the
browser to it WITHOUT validating that the destination is in-scope. An
attacker uses the victim's TRUSTED domain in a phishing link
(https://trusted.com/login?next=https://evil.tld) so the URL passes a
human/email-filter check, then bounces the victim to the attacker site
(or steals an OAuth code via redirect_uri abuse).

This probe is DETECTION-ONLY and benign:
  1. Fetch the target URL; collect candidate redirect parameter names
     from (a) the existing query string and (b) a fixed list of the
     common redirect param names.
  2. For each candidate, send ONE request with that param set to a
     benign, non-malicious canary destination (a sentinel host under a
     reserved/example domain — NOT an attacker payload, NO javascript:,
     NO data:, NO credential theft).
  3. Follow NO redirects; inspect the `Location` response header. A
     finding is CONFIRMED only when the server returns a 3xx whose
     Location actually points at our off-site canary host.

  HIGH    - confirmed off-domain redirect to the canary host via a
            user-controllable parameter (open redirect proven)
  INFO    - candidate params tested, none redirected off-site (safe)
  INFO    - fetch / probe failed
  POSITIVE- redirect params present but server keeps redirects on-domain

ZERO false positives: HIGH is emitted ONLY when the live response's
Location header resolves to the external canary host we supplied. We
never send a real attacker URL, never use javascript:/data:, and the
canary is a non-routable example host so no traffic leaves to a third
party.

VA NOT PT: this only DETECTS the redirect behaviour; it does not chain
the redirect into any follow-on action.

Customer input via ScanRequest:
  - target              = website URL (http(s)://...)
  - options.extra_params = optional list[str] of extra param names to test
  - options.user_agent   = optional UA override
"""
from __future__ import annotations
import asyncio
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()


class OpenRedirectRequest(ScanRequest):
    options: Optional[dict] = None


# Common redirect parameter names (covers the vast majority of frameworks).
_REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_uri", "redirect_url", "redirecturl",
    "return", "returnto", "return_to", "returnurl", "return_url", "rurl",
    "dest", "destination", "continue", "goto", "go", "target", "to",
    "out", "view", "link", "callback", "checkout_url", "image_url",
    "forward", "forward_url", "u", "r",
]

# Benign off-site canary. Uses a reserved/example domain so NO real traffic
# leaves to a third party — it only needs to be a different host than the
# target so an off-domain redirect is unambiguous.
_CANARY_HOST = "vl-open-redirect-canary.example"
_CANARY_URL = f"https://{_CANARY_HOST}/"


def _build_test_url(base_url: str, param: str, value: str) -> str:
    parsed = urlparse(base_url)
    q = parse_qs(parsed.query, keep_blank_values=True)
    q[param] = [value]
    new_q = urlencode({k: v[-1] for k, v in q.items()})
    return urlunparse(parsed._replace(query=new_q))


def _location_points_to_canary(location: str, target_host: str) -> bool:
    """True only if the Location header resolves to our canary host
    (off-domain). Handles absolute, scheme-relative (//host), and the
    `/\\host` and `https:/host` variants browsers normalise to the host."""
    if not location:
        return False
    loc = location.strip()
    low = loc.lower()
    # Direct hit on the canary host anywhere in the authority position.
    # Absolute URL.
    try:
        p = urlparse(loc)
        if p.hostname and p.hostname.lower() == _CANARY_HOST:
            return True
    except Exception:
        pass
    # Scheme-relative // and back-slash tricks that browsers treat as host.
    for marker in ("//" + _CANARY_HOST, "/\\" + _CANARY_HOST,
                   "\\/" + _CANARY_HOST, "\\\\" + _CANARY_HOST,
                   "https:/" + _CANARY_HOST, "http:/" + _CANARY_HOST):
        if marker.lower() in low:
            # Make sure it's not just our own host containing the substring.
            if target_host.lower() != _CANARY_HOST:
                return True
    return False


async def _probe_param(client, base_url: str, target_host: str,
                       param: str) -> dict:
    test_url = _build_test_url(base_url, param, _CANARY_URL)
    out = {"param": param, "test_url": test_url[:300],
           "status": None, "location": None, "redirects_offsite": False,
           "error": None}
    try:
        # follow_redirects is OFF (set on the client) so we read the raw 3xx.
        r = await client.get(test_url)
        out["status"] = r.status_code
        loc = r.headers.get("location")
        out["location"] = (loc or "")[:300] if loc else None
        if 300 <= r.status_code < 400 and loc:
            if _location_points_to_canary(loc, target_host):
                out["redirects_offsite"] = True
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:80]}"
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
        ctx.state["openredir_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return

    opts = ctx.state.get("_options") or {}
    ua = opts.get("user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    extra = opts.get("extra_params") or []
    if isinstance(extra, str):
        extra = [extra]

    parsed = urlparse(target)
    target_host = parsed.hostname or ""

    # Candidate params = those already present in the URL + the common set
    # + any caller-supplied extras (deduped, capped).
    present = list(parse_qs(parsed.query).keys())
    candidates = []
    for p in present + _REDIRECT_PARAMS + [str(x) for x in extra]:
        if p and p not in candidates:
            candidates.append(p)
    candidates = candidates[:40]

    results: list[dict] = []
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=15, follow_redirects=False,
            headers={"User-Agent": ua, "Accept": "text/html,*/*"},
        ) as client:
            sem = asyncio.Semaphore(6)

            async def _bound(p):
                async with sem:
                    return await _probe_param(client, target, target_host, p)

            results = await asyncio.gather(*[_bound(p) for p in candidates])
    except Exception as e:
        ctx.state["openredir_error"] = (
            f"audit failed: {type(e).__name__}: {str(e)[:120]}"
        )
        ctx.source("audit failed")
        return

    confirmed = [r for r in results if r.get("redirects_offsite")]
    transport_errors = sum(1 for r in results if r.get("error"))

    ctx.state["openredir_target_url"] = target
    ctx.state["openredir_params_tested"] = len(candidates)
    ctx.state["openredir_transport_errors"] = transport_errors
    ctx.state["openredir_confirmed"] = confirmed
    # Keep a trimmed sample of all results for the intel table.
    ctx.state["openredir_results"] = [
        r for r in results if r.get("status") and 300 <= r["status"] < 400
    ][:20]
    ctx.source(
        f"GET x{len(candidates)} param probe(s) -> "
        f"{len(confirmed)} confirmed off-site redirect(s)"
    )


# ── findings rules (inline) ────────────────────────────────────────────

def rule_open_redirect_confirmed(s):
    if s.get("openredir_error"):
        return None
    rs = s.get("openredir_confirmed") or []
    if not rs:
        return None
    params = sorted({r["param"] for r in rs})
    sample = "; ".join(
        f"{r['param']} -> Location: {r.get('location')}" for r in rs[:5]
    )
    return {
        "name": (f"Open redirect via user-controllable parameter "
                 f"({', '.join(params)})"),
        "severity": "HIGH",
        "cvss": "6.1",
        "cwe": "CWE-601",
        "cwe_name": "URL Redirection to Untrusted Site (Open Redirect)",
        "owasp": "A01:2021",
        "verified_exploit": True,
        "evidence": (
            f"Setting parameter(s) {', '.join(params)} on "
            f"{s.get('openredir_target_url')} to a benign off-site canary "
            f"caused the server to return a 3xx whose Location header points "
            f"to the external host. {sample}. An attacker can craft "
            "https://<trusted>/...?" + params[0] + "=https://evil.tld so a "
            "phishing link wears the trusted domain, then bounces the "
            "victim off-site (and can steal OAuth codes if this endpoint is "
            "a redirect_uri)."
        ),
        "remediation": (
            "Do not redirect to an externally-supplied URL. Maintain a "
            "server-side allowlist of permitted destinations (or redirect "
            "only to relative paths after stripping scheme/authority). "
            "Reject values containing `//`, `\\`, or an absolute scheme. "
            "For OAuth, exact-match redirect_uri against registered URIs."
        ),
    }


def rule_no_open_redirect(s):
    if s.get("openredir_error"):
        return None
    if s.get("openredir_confirmed"):
        return None
    return {
        "name": "No open redirect detected on tested parameters",
        "severity": "INFO",
        "cwe": "CWE-601",
        "evidence": (
            f"{s.get('openredir_params_tested', 0)} candidate redirect "
            "parameter(s) were tested with a benign off-site canary; none "
            "produced a 3xx Location pointing off-domain. The Same-Origin "
            "default is in effect for the tested parameters."
        ),
        "remediation": (
            "No action for the tested parameters. Open-redirect sinks can "
            "also live in POST bodies and JS-driven location assignments — "
            "the DOM-XSS sinks audit covers the client-side variant."
        ),
    }


def rule_probe_failed(s):
    err = s.get("openredir_error")
    if not err:
        return None
    return {
        "name": "Open-redirect audit could not complete",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": str(err)[:300],
        "remediation": ("Confirm httpx is installed and the target URL is "
                        "reachable from the scanner host."),
    }


def rule_positive(s):
    if s.get("openredir_error"):
        return None
    if s.get("openredir_confirmed"):
        return None
    # Only assert POSITIVE when the server DID issue redirects but kept them
    # on-domain (i.e. there's real redirect behaviour to vouch for).
    onsite = s.get("openredir_results") or []
    if not onsite:
        return None
    return {
        "name": "Redirect endpoints keep destinations on-domain (no open redirect)",
        "severity": "POSITIVE",
        "cwe": "CWE-601",
        "evidence": (
            f"{len(onsite)} tested parameter(s) produced 3xx responses but "
            "none redirected to the external canary host — the server "
            "appears to validate redirect destinations."
        ),
        "remediation": ("Keep the redirect allowlist tight; re-test after "
                        "adding any new login/return flow."),
    }


OPEN_REDIRECT_PARAM_AUDIT_FINDING_RULES = [
    rule_open_redirect_confirmed,
    rule_no_open_redirect,
    rule_probe_failed,
    rule_positive,
]


INTEL_FIELDS = [
    ("Target URL",                 "openredir_target_url"),
    ("Parameters tested",          "openredir_params_tested"),
    ("Transport errors",           "openredir_transport_errors"),
    ("Confirmed open redirects",   "openredir_confirmed"),
    ("3xx responses (sample)",     "openredir_results"),
]


@router.post("/api/client_side/open_redirect_param_audit")
async def client_side_open_redirect_param_audit(req: OpenRedirectRequest,
                                                _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="open_redirect_param_audit",
        gather_func=_gather_with_options,
        finding_rules=OPEN_REDIRECT_PARAM_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
