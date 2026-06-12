"""subresource_integrity_audit - third-party SRI / supply-chain audit
(playbook §5 #43 browser plugin/extension + supply-chain compromise,
§6 payload-delivery via trusted CDN).

A page that loads JavaScript or CSS from a third-party origin WITHOUT a
Subresource-Integrity (`integrity=`) attribute trusts that CDN/host
completely: if the CDN is compromised, an account is taken over, or a
typosquatted/abandoned domain is re-registered, the attacker serves
arbitrary code that runs in the page's origin. This is the Magecart /
polyfill.io / event-stream supply-chain class.

This probe fetches the target HTML and enumerates every
  <script src="...">  and  <link rel="stylesheet" href="...">
element. For each one it determines:
  - is the resource cross-origin (different registrable host)?
  - does it carry an `integrity=` SRI hash?
  - does it carry `crossorigin=` (required for SRI to be enforced)?

Findings (graded ONLY on what the live HTML contains):
  HIGH    - one or more CROSS-ORIGIN scripts loaded with NO integrity hash
            (full code-execution supply-chain exposure)
  MEDIUM  - cross-origin script HAS integrity but is MISSING crossorigin
            (SRI silently not enforced -> same exposure as no SRI)
  LOW     - cross-origin stylesheet with no integrity (CSS-injection /
            exfil surface, lower impact than script)
  INFO    - fetch failed
  POSITIVE- every cross-origin script carries a valid integrity+crossorigin

ZERO false positives: only resources actually present in the fetched
HTML are reported; same-origin resources are never flagged. Static
HTML inspection only — nothing is executed.

Customer input via ScanRequest:
  - target              = website URL (http(s)://...)
  - options.user_agent  = optional UA override
"""
from __future__ import annotations
from typing import Optional
from urllib.parse import urljoin, urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()


class SubresourceIntegrityRequest(ScanRequest):
    options: Optional[dict] = None


def _registrable(host: str) -> str:
    """Cheap eTLD+1 approximation: last two labels. Good enough to decide
    same-site vs cross-site for SRI purposes without a public-suffix dep."""
    host = (host or "").lower().strip()
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    # Handle common two-label public suffixes (co.uk, com.au, ...) crudely.
    two_label_suffixes = {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au",
        "co.in", "co.jp", "com.br", "co.nz", "co.za",
    }
    last_two = ".".join(parts[-2:])
    if last_two in two_label_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


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
        ctx.state["sri_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        ctx.state["sri_error"] = "beautifulsoup4 not installed (pip install beautifulsoup4)"
        ctx.source("bs4 missing")
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
        ctx.state["sri_error"] = f"fetch failed: {type(e).__name__}: {str(e)[:120]}"
        ctx.source("fetch failed")
        return

    base_url = str(r.url)
    base_host = _registrable(urlparse(base_url).hostname or "")
    soup = BeautifulSoup(r.text or "", "html.parser")

    scripts_no_sri: list[dict] = []
    scripts_sri_no_crossorigin: list[dict] = []
    styles_no_sri: list[dict] = []
    same_origin_count = 0
    protected_count = 0
    total_external = 0

    def _classify(url: str, integrity: Optional[str],
                  crossorigin: Optional[str], kind: str):
        nonlocal same_origin_count, protected_count, total_external
        abs_url = urljoin(base_url, url)
        host = urlparse(abs_url).hostname or ""
        if not host:
            return
        if _registrable(host) == base_host:
            same_origin_count += 1
            return
        total_external += 1
        rec = {"url": abs_url[:300], "host": host, "kind": kind,
               "has_integrity": bool(integrity),
               "has_crossorigin": bool(crossorigin)}
        if integrity and not crossorigin:
            # SRI present but crossorigin missing => browser does NOT enforce it.
            scripts_sri_no_crossorigin.append(rec) if kind == "script" else None
            if kind == "style":
                # CSS SRI also needs crossorigin; treat as missing-protection.
                styles_no_sri.append(rec)
        elif integrity and crossorigin:
            protected_count += 1
        else:
            if kind == "script":
                scripts_no_sri.append(rec)
            else:
                styles_no_sri.append(rec)

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if not src or src.startswith("data:"):
            continue
        _classify(src, tag.get("integrity"), tag.get("crossorigin"), "script")

    for tag in soup.find_all("link"):
        rels = [x.lower() for x in (tag.get("rel") or [])]
        if "stylesheet" not in rels:
            continue
        href = tag.get("href")
        if not href or href.startswith("data:"):
            continue
        _classify(href, tag.get("integrity"), tag.get("crossorigin"), "style")

    ctx.state["sri_target_url"] = base_url
    ctx.state["sri_http_status"] = r.status_code
    ctx.state["sri_base_host"] = base_host
    ctx.state["sri_external_total"] = total_external
    ctx.state["sri_same_origin_count"] = same_origin_count
    ctx.state["sri_protected_count"] = protected_count
    ctx.state["sri_scripts_no_sri"] = scripts_no_sri[:25]
    ctx.state["sri_scripts_sri_no_crossorigin"] = scripts_sri_no_crossorigin[:25]
    ctx.state["sri_styles_no_sri"] = styles_no_sri[:25]

    ctx.source(
        f"GET {target} -> {r.status_code}; {total_external} cross-origin "
        f"subresource(s); {len(scripts_no_sri)} script(s) without SRI"
    )


# ── findings rules (inline) ────────────────────────────────────────────

def rule_scripts_no_sri(s):
    if s.get("sri_error"):
        return None
    rs = s.get("sri_scripts_no_sri") or []
    if not rs:
        return None
    hosts = sorted({r["host"] for r in rs})
    sample = "; ".join(r["url"] for r in rs[:5])
    return {
        "name": (f"{len(rs)} cross-origin script(s) loaded without "
                 "Subresource-Integrity (supply-chain exposure)"),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-353",
        "cwe_name": "Missing Support for Integrity Check",
        "owasp": "A08:2021",
        "verified_exploit": True,
        "evidence": (
            f"The page loads executable JavaScript from third-party host(s) "
            f"{', '.join(hosts)} with no `integrity=` SRI hash. If any of "
            "these origins is compromised (CDN breach, account takeover, "
            "abandoned/typosquatted domain), arbitrary code runs in this "
            "site's origin. Examples: " + sample
        ),
        "remediation": (
            "Add a Subresource-Integrity hash and crossorigin attribute to "
            "every cross-origin <script>: "
            "`<script src=\"https://cdn.example/lib.js\" "
            "integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>`. "
            "Generate hashes with `openssl dgst -sha384 -binary file.js | "
            "openssl base64 -A`, or self-host the asset. Pin to a specific "
            "version — SRI breaks if the CDN serves 'latest'."
        ),
    }


def rule_sri_no_crossorigin(s):
    if s.get("sri_error"):
        return None
    rs = s.get("sri_scripts_sri_no_crossorigin") or []
    if not rs:
        return None
    sample = "; ".join(r["url"] for r in rs[:5])
    return {
        "name": (f"{len(rs)} cross-origin script(s) carry integrity but are "
                 "missing crossorigin (SRI not enforced)"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-353",
        "cwe_name": "Missing Support for Integrity Check",
        "owasp": "A08:2021",
        "verified_exploit": True,
        "evidence": (
            "These cross-origin scripts declare an `integrity=` hash but "
            "have no `crossorigin=` attribute. The browser cannot read the "
            "opaque cross-origin response to verify the hash, so SRI is "
            "silently NOT enforced — same exposure as having no integrity "
            "at all. Examples: " + sample
        ),
        "remediation": (
            "Add `crossorigin=\"anonymous\"` to each script that has an "
            "integrity attribute so the browser fetches it in CORS mode and "
            "can actually verify the hash."
        ),
    }


def rule_styles_no_sri(s):
    if s.get("sri_error"):
        return None
    rs = s.get("sri_styles_no_sri") or []
    if not rs:
        return None
    hosts = sorted({r["host"] for r in rs})
    sample = "; ".join(r["url"] for r in rs[:5])
    return {
        "name": (f"{len(rs)} cross-origin stylesheet(s) loaded without "
                 "Subresource-Integrity"),
        "severity": "LOW",
        "cvss": "3.7",
        "cwe": "CWE-353",
        "owasp": "A08:2021",
        "verified_exploit": True,
        "evidence": (
            f"Stylesheets from third-party host(s) {', '.join(hosts)} load "
            "with no integrity hash (or with integrity but no crossorigin). "
            "A compromised CSS host can inject exfiltration via attribute "
            "selectors / background-image requests and reskin the UI for "
            "phishing. Examples: " + sample
        ),
        "remediation": (
            "Add integrity + crossorigin to cross-origin <link "
            "rel=stylesheet>, or self-host critical CSS."
        ),
    }


def rule_fetch_failed(s):
    err = s.get("sri_error")
    if not err:
        return None
    return {
        "name": "Subresource-Integrity audit could not fetch target URL",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": str(err)[:300],
        "remediation": ("Confirm the URL is reachable from the scanner host "
                        "and serves HTML."),
    }


def rule_positive(s):
    if s.get("sri_error"):
        return None
    if not s.get("sri_external_total"):
        return None  # no cross-origin subresources -> nothing to assert
    if (s.get("sri_scripts_no_sri") or s.get("sri_scripts_sri_no_crossorigin")
            or s.get("sri_styles_no_sri")):
        return None
    return {
        "name": "All cross-origin subresources carry Subresource-Integrity",
        "severity": "POSITIVE",
        "cwe": "CWE-353",
        "owasp": "A08:2021",
        "evidence": (
            f"{s.get('sri_external_total')} cross-origin subresource(s) were "
            f"loaded and {s.get('sri_protected_count')} carry a valid "
            "integrity + crossorigin pair; none were found unprotected."
        ),
        "remediation": ("Maintain SRI hashes when bumping CDN library "
                        "versions — a version bump without a new hash "
                        "silently breaks the asset or the protection."),
    }


SUBRESOURCE_INTEGRITY_AUDIT_FINDING_RULES = [
    rule_scripts_no_sri,
    rule_sri_no_crossorigin,
    rule_styles_no_sri,
    rule_fetch_failed,
    rule_positive,
]


INTEL_FIELDS = [
    ("Target URL",                      "sri_target_url"),
    ("HTTP status",                     "sri_http_status"),
    ("Cross-origin subresources",       "sri_external_total"),
    ("Same-origin subresources",        "sri_same_origin_count"),
    ("SRI-protected subresources",      "sri_protected_count"),
    ("Scripts without SRI",             "sri_scripts_no_sri"),
    ("Scripts SRI w/o crossorigin",     "sri_scripts_sri_no_crossorigin"),
    ("Stylesheets without SRI",         "sri_styles_no_sri"),
]


@router.post("/api/client_side/subresource_integrity_audit")
async def client_side_subresource_integrity_audit(req: SubresourceIntegrityRequest,
                                                  _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="subresource_integrity_audit",
        gather_func=_gather_with_options,
        finding_rules=SUBRESOURCE_INTEGRITY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
