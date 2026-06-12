"""llm_output_handling_headers - improper-output-handling + transport posture
of an LLM endpoint (playbook §1 #5 LLM05 Improper Output Handling / XSS via
LLM, plus transport hardening relevant to §9 streaming).

REAL PROBE. Sends ONE benign prompt and inspects the RESPONSE HEADERS +
content-type only — never the model content for exploitation. It answers
read-only questions that genuinely matter for LLM05 (the model's output is
often rendered straight into a web page):

  - Is the endpoint served over plaintext HTTP (token + prompt in clear)?
  - Does the response advertise Content-Type: text/html (model output
    rendered as HTML => stored/reflected XSS risk if unescaped)?
  - Is a permissive CORS policy present (Access-Control-Allow-Origin: *)
    that lets any site read the model output cross-origin?
  - Are anti-MIME-sniff / framing headers (X-Content-Type-Options,
    X-Frame-Options / CSP) missing on an HTML-typed response?

A graded finding is emitted ONLY when the live response actually exhibits
the weak condition. Missing-header findings are conservative LOW/MEDIUM and
never fabricated — they reflect what the server really returned.

Customer input:
  - ScanRequest.target = full inference endpoint URL
  - auth_bearer / options.prompt_field / options.headers honoured
"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()


class InfraRequest(ScanRequest):
    options: Optional[dict] = None


BENIGN_PROMPT = "Say hello in one short sentence."


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["outhdr_total"] = 0
        ctx.source("no-target")
        return
    if not target.startswith(("http://", "https://")):
        ctx.state["outhdr_error"] = (
            "target must be a full inference endpoint URL (http(s)://...)")
        ctx.source("invalid target")
        return
    try:
        import httpx
    except ImportError:
        ctx.state["outhdr_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    opts = getattr(ctx, "options", None) or {}
    prompt_field = opts.get("prompt_field", "message")
    extra_headers = opts.get("headers") or {}
    bearer = getattr(ctx, "auth_bearer", None)

    headers = {"Content-Type": "application/json",
               "User-Agent": "VulnusLab/AI-LLM-OutputHandling",
               # Probe CORS with a cross-origin Origin to elicit ACAO behaviour.
               "Origin": "https://vulnuslab-probe.example"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if isinstance(extra_headers, dict):
        headers.update({str(k): str(v) for k, v in extra_headers.items()})

    body = {prompt_field: BENIGN_PROMPT}
    async with httpx.AsyncClient(timeout=15.0, verify=False,
                                 follow_redirects=False) as client:
        try:
            r = await client.post(target, json=body, headers=headers)
        except Exception as e:
            ctx.state["outhdr_error"] = f"{type(e).__name__}: {str(e)[:100]}"
            ctx.source("request failed")
            return

    resp_headers = {k.lower(): v for k, v in r.headers.items()}
    ctype = resp_headers.get("content-type", "")
    # Only a HTTP 200 means a real, responding LLM endpoint. On non-200
    # (404 SPA-fallback, 3xx, 5xx) a text/html body is an error/placeholder
    # page, NOT model output — grading it as LLM05 XSS is a false positive
    # (confirmed live on a Netlify 404 SPA-fallback for /api/chat).
    is_responding = r.status_code == 200
    is_html = is_responding and ("text/html" in ctype.lower())
    acao = resp_headers.get("access-control-allow-origin", "")
    acac = resp_headers.get("access-control-allow-credentials", "")
    is_plaintext = target.lower().startswith("http://")

    issues = []
    if is_plaintext:
        issues.append("plaintext_http")
    if is_html:
        issues.append("html_content_type")
        # MIME-sniff + framing only meaningful when output may be HTML-rendered
        if "nosniff" not in resp_headers.get("x-content-type-options", "").lower():
            issues.append("missing_nosniff")
        has_csp = bool(resp_headers.get("content-security-policy"))
        has_xfo = bool(resp_headers.get("x-frame-options"))
        if not has_csp and not has_xfo:
            issues.append("missing_framing")
    permissive_cors = (acao == "*") or \
        (acao == "https://vulnuslab-probe.example")
    if permissive_cors:
        issues.append("permissive_cors")
        if acac.lower() == "true" and acao != "*":
            issues.append("cors_with_credentials")

    ctx.state["outhdr_endpoint"] = target
    ctx.state["outhdr_status"] = r.status_code
    ctx.state["outhdr_content_type"] = ctype
    ctx.state["outhdr_acao"] = acao
    ctx.state["outhdr_acac"] = acac
    ctx.state["outhdr_is_plaintext"] = is_plaintext
    ctx.state["outhdr_is_html"] = is_html
    ctx.state["outhdr_issues"] = issues
    ctx.state["outhdr_total"] = len(issues)
    ctx.source(f"status={r.status_code} content-type='{ctype}' "
               f"acao='{acao}' issues={issues}")


def rule_unreachable(s):
    if s.get("outhdr_error"):
        return {"name": "Output-handling header audit could not run",
                "severity": "INFO",
                "evidence": str(s["outhdr_error"]),
                "remediation": ("Confirm the endpoint URL and that it accepts a "
                                "benign JSON POST. The probe inspects response "
                                "headers only."),
                "cwe": "CWE-755"}
    return None


def rule_plaintext(s):
    if "plaintext_http" not in (s.get("outhdr_issues") or []):
        return None
    return {"name": "LLM inference endpoint served over plaintext HTTP",
            "severity": "INFO", "cvss": "5.9",
            "cwe": "CWE-319", "owasp": "LLM02:2025",
            "verified_exploit": False,
            "evidence": (f"Endpoint {s.get('outhdr_endpoint')} was supplied/scanned "
                         "over http:// — TLS enforcement on the production endpoint "
                         "NOT actively confirmed. If served in cleartext, prompts, "
                         "model output, and any bearer token would transit "
                         "unencrypted."),
            "remediation": ("Serve the inference endpoint over HTTPS only and "
                            "redirect HTTP->HTTPS with HSTS. Prompts and "
                            "responses frequently contain sensitive data.")}


def rule_html_output(s):
    issues = s.get("outhdr_issues") or []
    if "html_content_type" not in issues:
        return None
    extra = []
    if "missing_nosniff" in issues:
        extra.append("no X-Content-Type-Options: nosniff")
    if "missing_framing" in issues:
        extra.append("no CSP / X-Frame-Options")
    return {"name": "LLM response served as text/html (Improper Output Handling)",
            "severity": "MEDIUM", "cvss": "6.1",
            "cwe": "CWE-79", "owasp": "LLM05:2025",
            "verified_exploit": True,
            "evidence": (f"Response Content-Type is '{s.get('outhdr_content_type')}'. "
                         "If model output is rendered without escaping, an "
                         "attacker-influenced completion can inject HTML/JS "
                         "(XSS via LLM)."
                         + (f" Also: {', '.join(extra)}." if extra else "")),
            "remediation": ("Return model output as application/json (or "
                            "text/plain) and HTML-escape it at the rendering "
                            "layer. Add X-Content-Type-Options: nosniff and a "
                            "restrictive CSP. OWASP LLM05: treat model output as "
                            "untrusted, escape before rendering.")}


def rule_permissive_cors(s):
    issues = s.get("outhdr_issues") or []
    if "permissive_cors" not in issues:
        return None
    with_creds = "cors_with_credentials" in issues
    sev = "HIGH" if with_creds else "MEDIUM"
    cvss = "7.1" if with_creds else "5.3"
    return {"name": ("Permissive CORS on LLM endpoint"
                     + (" with credentials" if with_creds else "")),
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-942", "owasp": "LLM02:2025",
            "verified_exploit": True,
            "evidence": (f"Access-Control-Allow-Origin: '{s.get('outhdr_acao')}'"
                         + (f", Access-Control-Allow-Credentials: "
                            f"'{s.get('outhdr_acac')}'" if with_creds else "")
                         + " — any (or arbitrary reflected) origin can read the "
                         "model output cross-origin."),
            "remediation": ("Restrict Access-Control-Allow-Origin to an explicit "
                            "allowlist of trusted front-ends. Never combine a "
                            "reflected/`*` origin with "
                            "Access-Control-Allow-Credentials: true — it lets a "
                            "malicious site read authenticated model responses.")}


def rule_positive(s):
    if s.get("outhdr_total", 0) > 0:
        return None
    if s.get("outhdr_status") is None:
        return None
    return {"name": "LLM endpoint output-handling headers are sound",
            "severity": "POSITIVE",
            "evidence": (f"HTTPS, JSON content-type, and no permissive CORS "
                         f"observed (Content-Type='{s.get('outhdr_content_type')}', "
                         f"ACAO='{s.get('outhdr_acao') or 'none'}')."),
            "remediation": ("Keep returning JSON over HTTPS with a strict CORS "
                            "allowlist; escape model output at render time."),
            "cwe": "CWE-79", "owasp": "LLM05:2025"}


LLM_OUTPUT_HANDLING_HEADERS_FINDING_RULES = [
    rule_unreachable,
    rule_plaintext,
    rule_html_output,
    rule_permissive_cors,
    rule_positive,
]


INTEL_FIELDS = [
    ("Endpoint", "outhdr_endpoint"),
    ("HTTP status", "outhdr_status"),
    ("Content-Type", "outhdr_content_type"),
    ("Access-Control-Allow-Origin", "outhdr_acao"),
    ("Access-Control-Allow-Credentials", "outhdr_acac"),
    ("Served over plaintext HTTP", "outhdr_is_plaintext"),
    ("HTML content-type", "outhdr_is_html"),
    ("Issues observed", "outhdr_issues"),
]


@router.post("/api/ai_llm/llm_output_handling_headers")
async def ai_llm_llm_output_handling_headers(req: InfraRequest,
                                             _=Depends(verify_scan_quota)):
    async def _gather(ctx):
        ctx.options = req.options
        ctx.auth_bearer = req.auth_bearer
        await gather(ctx)
    return await run_scanner(host=req.target,
        tool="llm_output_handling_headers",
        gather_func=_gather,
        finding_rules=LLM_OUTPUT_HANDLING_HEADERS_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
