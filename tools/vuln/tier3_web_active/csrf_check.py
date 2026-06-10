"""CSRF token presence check - passive form inspection. VL-METHOD Wave 3.

Refactored 2026-06-09 to MethodologyScanner. Verify re-fetches each flagged
page once more to confirm the missing-CSRF result is stable rather than a
race with delayed form rendering or A/B-tested page variants.
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async
from tools._vl_core.verify import vl_verify

router = APIRouter()

PROBE_PATHS_QUICK = ["/", "/login", "/contact"]
PROBE_PATHS_DEEP  = ["/register", "/checkout", "/account"]
CSRF_FIELD_PATTERNS = [r'name=["\']csrf', r'name=["\']_csrf', r'name=["\']_token',
                       r'name=["\']authenticity_token',
                       r'name=["\']__requestverificationtoken']
FORM_RE = re.compile(r"<form[^>]*method=[\"']post[\"'][^>]*>(.+?)</form>",
                     re.IGNORECASE | re.DOTALL)


async def _scan_paths(base_url, paths):
    no_csrf, forms_found = [], 0
    for path in paths:
        url = f"{base_url}{path}"
        r = await http_get_async(url, timeout=8, read=40000)
        if not r or r.get("status", 0) >= 400:
            continue
        forms = FORM_RE.findall(r.get("body", ""))
        if not forms:
            continue
        for form in forms:
            forms_found += 1
            form_lower = form.lower()
            if not any(re.search(pat, form_lower) for pat in CSRF_FIELD_PATTERNS):
                no_csrf.append({"path": path})
                break
    return no_csrf, forms_found


class CsrfCheck(MethodologyScanner):
    name = "csrf_check"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["probed_paths"] = len(PROBE_PATHS_QUICK) + len(PROBE_PATHS_DEEP)
        ctx.state["post_forms_found"] = 0
        return True

    async def fingerprint(self, ctx):
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {
                "server": (hdrs.get("server") or "")[:80],
            }

    async def quick_probe(self, ctx):
        no_csrf, found = await _scan_paths(ctx.state["base_url"], PROBE_PATHS_QUICK)
        ctx.state["quick_hits"] = no_csrf
        ctx.state["post_forms_found"] += found
        return [dict(h) for h in no_csrf]

    async def deep_scan(self, ctx):
        no_csrf, found = await _scan_paths(ctx.state["base_url"], PROBE_PATHS_DEEP)
        ctx.state["deep_hits"] = no_csrf
        ctx.state["post_forms_found"] += found
        return [dict(h) for h in no_csrf]

    async def verify(self, ctx, finding):
        # Re-fetch the page; the form should still be missing CSRF on second look
        url = f"{ctx.state['base_url']}{finding['path']}"
        r = await http_get_async(url, timeout=8, read=40000)
        if not r or r.get("status", 0) >= 400:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "refetch-non-2xx"
            return finding
        forms = FORM_RE.findall(r.get("body", ""))
        if not forms:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "refetch-no-form"
            return finding
        for form in forms:
            form_lower = form.lower()
            if not any(re.search(pat, form_lower) for pat in CSRF_FIELD_PATTERNS):
                finding["confidence"] = "CONFIRMED"
                finding["verification_method"] = "refetch-still-missing-csrf"
                return finding
        finding["confidence"] = "SUSPECTED"
        finding["verification_method"] = "refetch-csrf-now-present"
        return finding


def _r_csrf(s):
    verified = s.get("methodology_findings") or []
    if not verified:
        return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        return {"name": f"{len(confirmed)} POST form(s) missing anti-CSRF token (CONFIRMED)",
                "severity": "MEDIUM", "cvss": 6.5, "cwe": "CWE-352",
                "evidence": "Pages with POST forms but no CSRF token field on two fetches: " +
                             ", ".join(n["path"] for n in confirmed),
                "remediation": "Add a per-session CSRF token hidden field and validate on POST. "
                                "Use SameSite=Strict cookies as defence in depth."}
    return {"name": f"{len(verified)} POST form(s) missing CSRF token on first fetch (SUSPECTED)",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-352",
            "evidence": "Possible A/B-tested or JS-injected form. Pages: " +
                         ", ".join(n["path"] for n in verified),
            "remediation": "Manually inspect each page."}


FINDING_RULES = [_r_csrf]
INTEL_FIELDS = [
    ("POST forms found", "post_forms_found"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits", "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/csrf_check")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = CsrfCheck()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
