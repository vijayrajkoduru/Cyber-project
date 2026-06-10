"""dom_clobbering_probe — search homepage HTML for known clobbering sinks.

DOM clobbering: HTML elements with name/id attributes shadow JS globals.
e.g. <a id="config"> makes `window.config` point to that element. If the
app does `if (config && config.allowed)` to gate behavior, attacker can
plant HTML to bypass.

Static-source heuristic: find <img>/<form>/<a name=... | id=...> with
names matching common JS-global patterns (config, options, app, state,
auth, user, settings).
"""
import re
from collections import Counter
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

DANGEROUS_NAMES = {
    "config", "options", "settings", "app", "state", "auth", "user",
    "admin", "session", "token", "csrf", "secret", "key",
    "globalThis", "document", "window", "innerHTML", "outerHTML",
    "location", "constructor",
}
ELEMENT_RE = re.compile(
    r'<(?:a|img|form|input|iframe|object|embed)\b[^>]*\b(?:id|name)=["\']([a-zA-Z_$][\w$]*)["\']',
    re.IGNORECASE)


@router.post("/api/webapp/scan/dom_clobbering_probe")
@vl_turbo()
@vl_verify()
def scan_dom_clobbering_probe(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    r = safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=10, allow_redirects=True)
    if r is None or r.status_code >= 400:
        return standard_response(
            tool="dom_clobbering_probe", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not fetch homepage (HTTP {r.status_code if r else 'no-resp'})")

    body = r.text or ""
    matches = ELEMENT_RE.findall(body)
    dangerous = [m for m in matches if m.lower() in DANGEROUS_NAMES]
    counts = Counter(dangerous)

    findings = []
    if dangerous:
        findings.append(wrap_finding(
            f"DOM clobbering risk: {len(dangerous)} element(s) with global-shadowing names",
            "MEDIUM", cvss="5.3", cwe="CWE-1321", owasp="A03:2021",
            remediation="Each named element creates window.<name> reference. "
                        "(1) Audit JS for `if (config)` / `if (window.foo)` checks — "
                        "if any rely on those globals existing only when JS sets them, "
                        "they're bypassable via element injection. "
                        "(2) Prefer `if (typeof config === 'object' && config !== null)` "
                        "and assign globals explicitly. "
                        "(3) Add a strict CSP that blocks injected HTML at the source "
                        "(no user-controlled HTML rendering).",
            evidence_marker=" | ".join(f"{name} ({c}x)" for name, c in counts.most_common(8))))
    else:
        findings.append(wrap_finding(
            f"No DOM-clobbering candidates ({len(matches)} named elements, none in danger-list)",
            "POSITIVE", cwe="CWE-1321",
            remediation="Maintain. Continue avoiding dangerous global-shadow names in HTML id/name.",
            evidence_marker=f"scanned {len(matches)} named elements"))

    return standard_response(
        tool="dom_clobbering_probe", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(dangerous),
        tests_summary=f"{len(matches)} named elements, {len(dangerous)} risky",
        raw_data={"total_named_elements": len(matches),
                   "dangerous_names": dict(counts.most_common(20))})


def register(app):
    app.include_router(router)
