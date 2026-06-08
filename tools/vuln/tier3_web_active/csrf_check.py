"""CSRF token presence check - passive form inspection. Self-contained.
Strategy: probe common state-changing form pages, parse HTML for anti-CSRF token field."""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async

router = APIRouter()

PROBE_PATHS = ["/", "/login", "/contact", "/register", "/checkout", "/account"]
CSRF_FIELD_PATTERNS = [r'name=["\']csrf', r'name=["\']_csrf', r'name=["\']_token',
                        r'name=["\']authenticity_token', r'name=["\']__requestverificationtoken']
FORM_RE = re.compile(r"<form[^>]*method=[\"']post[\"'][^>]*>(.+?)</form>", re.IGNORECASE | re.DOTALL)


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probed_paths"] = len(PROBE_PATHS)
    no_csrf = []
    forms_found = 0
    for path in PROBE_PATHS:
        url = f"{base_url}{path}"
        r = await http_get_async(url, timeout=8, read=40000)
        if not r or r.get("status", 0) >= 400:
            continue
        body = r.get("body", "")
        forms = FORM_RE.findall(body)
        if not forms:
            continue
        for form in forms:
            forms_found += 1
            form_lower = form.lower()
            if not any(re.search(pat, form_lower) for pat in CSRF_FIELD_PATTERNS):
                no_csrf.append({"path": path})
                break
    ctx.state["post_forms_found"] = forms_found
    ctx.state["forms_without_csrf"] = no_csrf


def _r_csrf(s):
    no = s.get("forms_without_csrf") or []
    if not no:
        return None
    return {"name": f"{len(no)} POST form(s) missing anti-CSRF token", "severity": "MEDIUM", "cvss": 6.5,
            "cwe": "CWE-352",
            "evidence": "Pages with POST forms but no recognised CSRF token field: " + ", ".join(n["path"] for n in no),
            "remediation": "Add a per-session CSRF token hidden field and validate on POST. Use SameSite=Strict cookies as defence in depth."}


FINDING_RULES = [_r_csrf]
INTEL_FIELDS = [("POST forms found", "post_forms_found"), ("No-CSRF forms", "forms_without_csrf")]


@router.post("/api/vuln/csrf_check")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="csrf_check",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
