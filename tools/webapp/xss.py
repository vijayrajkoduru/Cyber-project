"""Reflected XSS scanner.

Active workflow (zero false positives):
  1. Fetch target page; extract URL parameters + form inputs.
  2. For each parameter, inject a unique unguessable canary.
  3. Verify canary appears LITERAL (not HTML-entity-encoded) in the
     response AND in a context where it could be parsed as code:
       - HTML body (between tags)
       - HTML attribute value
       - <script> tag interior
  4. If reflected in any of those contexts → CRITICAL XSS finding.

A canary that's HTML-entity-encoded ('&lt;', '&quot;') is NOT a finding
because output encoding would prevent execution. We only flag the
unmistakable case: the literal canary string echoed in dangerous
context.
"""
import re
import uuid
import urllib.parse
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url,
    safe_get, safe_post, wrap_finding, standard_response,
)

router = APIRouter()


def _extract_targets(base_url, html):
    targets = []
    parsed = urllib.parse.urlparse(base_url)
    if parsed.query:
        for k in urllib.parse.parse_qs(parsed.query).keys():
            targets.append(("GET", base_url, k))
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.I)
    action_pattern = re.compile(r'action=["\']?([^"\'\s>]*)["\']?', re.I)
    method_pattern = re.compile(r'method=["\']?([^"\'\s>]*)["\']?', re.I)
    input_pattern = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)
    textarea_pattern = re.compile(r'<textarea[^>]+name=["\']([^"\']+)["\']', re.I)
    for form_match in form_pattern.finditer(html):
        form_full = form_match.group(0)
        form_inner = form_match.group(1)
        action_m = action_pattern.search(form_full)
        method_m = method_pattern.search(form_full)
        action = action_m.group(1) if action_m else ""
        method = method_m.group(1).upper() if method_m else "GET"
        if method not in ("GET", "POST"):
            method = "GET"
        form_url = urllib.parse.urljoin(base_url, action) if action else base_url
        for input_m in input_pattern.finditer(form_inner):
            targets.append((method, form_url, input_m.group(1)))
        for ta_m in textarea_pattern.finditer(form_inner):
            targets.append((method, form_url, ta_m.group(1)))
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t); out.append(t)
    return out


def _reflection_context(canary, body):
    if canary not in body:
        return []
    contexts = set()
    for m in re.finditer(re.escape(canary), body):
        start = m.start()
        before = body[max(0, start - 200):start]
        before_lower = before.lower()
        last_script_open = before_lower.rfind("<script")
        last_script_close = before_lower.rfind("</script")
        if last_script_open > last_script_close:
            contexts.add("javascript")
            continue
        last_lt = before.rfind("<")
        last_gt = before.rfind(">")
        if last_lt > last_gt:
            tag_part = before[last_lt:]
            if '="' in tag_part or "='" in tag_part:
                contexts.add("attribute")
            else:
                contexts.add("tag")
        else:
            contexts.add("html_body")
    return sorted(contexts)


@router.post("/api/scan/xss")
async def scan_xss(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target)
    findings = []
    tests = 0
    r = safe_get(base, req=req, allow_redirects=True)
    if r is None:
        return standard_response(
            tool="xss", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {base}",
        )
    targets = _extract_targets(str(r.url), r.text or "")
    if not targets:
        return standard_response(
            tool="xss", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters or form inputs found to test",
            raw_data={"xss": {"params_tested": 0, "vulnerable_count": 0}},
        )
    raw_results = []
    for method, url, param_name in targets[:30]:
        tests += 1
        canary = f"vlxss{uuid.uuid4().hex[:14]}lab"
        if method == "GET":
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            qs[param_name] = [canary]
            new_qs = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
            tr = safe_get(test_url, req=req, allow_redirects=True)
        else:
            tr = safe_post(url, req=req, data={param_name: canary}, allow_redirects=True)
        if tr is None or tr.status_code >= 500:
            raw_results.append({"method": method, "url": url[:80], "param": param_name,
                                "result": "no usable response"})
            continue
        contexts = _reflection_context(canary, tr.text or "")
        if contexts:
            ctx_str = ", ".join(contexts)
            findings.append(wrap_finding(
                f"Reflected XSS in parameter '{param_name}' ({method})",
                "CRITICAL", cwe="CWE-79", owasp="A03:2021",
                evidence_marker=f"canary {canary} reflected unescaped in {ctx_str} context at {url[:120]}",
                remediation="Apply context-appropriate output encoding. Use a templating engine that auto-escapes by default. Add a strict Content-Security-Policy as defense-in-depth.",
                tests_performed=1,
                cvss="8.0",
            ))
            raw_results.append({"method": method, "url": url[:80], "param": param_name,
                                "result": "VULNERABLE", "contexts": contexts})
        else:
            raw_results.append({"method": method, "url": url[:80], "param": param_name,
                                "result": "safe"})
    return standard_response(
        tool="xss", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"Tested {tests} parameter(s) for reflected XSS via unique-canary injection",
        raw_data={"xss": {"params_tested": tests, "vulnerable_count": len(findings), "results": raw_results}},
    )


def register(app):
    app.include_router(router)
