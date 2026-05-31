"""client_side_template_injection — Vue/Angular/Handlebars/Twig CSTI.

Client-side template injection: app reflects user input into a position
that's processed by a client-side template engine (Vue `{{x}}`, Angular
`{{x}}`, Handlebars `{{x}}`, AlpineJS `x-text="x"`). The expression
is evaluated at render time → XSS without ever hitting a `<script>` tag.

Test: inject `{{7*7}}` and `{{constructor.constructor('alert(1)')()}}`
into common reflected parameters; if response body contains `49` or
markers of execution, CSTI.
"""
from urllib.parse import quote
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()

PAYLOADS = [
    ("{{7*7}}",                    "49"),     # Vue, Angular, Handlebars, Twig
    ("${7*7}",                     "49"),     # JS template literal, Spring SpEL
    ("[[7*7]]",                    "49"),     # Mustache no-escape variant
    ("{{constructor.constructor('alert(1)')()}}", "alert(1)"),  # Vue sandbox-escape (≤ v2.5)
]
PROBE_PATHS = [
    "/", "/?q=", "/?search=", "/?name=", "/?lang=",
    "/?ref=", "/?utm_source=", "/profile?name=",
]


@router.post("/api/webapp/scan/client_side_template_injection")
def scan_client_side_template_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    hits = []
    tested = 0

    for path in PROBE_PATHS:
        # Inject MARKER first to confirm reflection point
        sep = "&" if "?" in path else "?"
        marker = "VULNCSTIMARKER" + str(hash(path) & 0xFFFFFF)
        url = base + path + (sep + "VULNUSLAB=" + marker if "?" not in path or path.endswith("=") else marker)
        if path.endswith("="):
            url = base + path + marker
        r = safe_request("GET", url,
            headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r is None or r.status_code >= 400: continue
        if marker not in (r.text or ""): continue  # no reflection
        tested += 1

        # Reflection confirmed. Try CSTI payloads.
        for pl, expected in PAYLOADS:
            target_url = base + path
            if path.endswith("="):
                target_url += quote(pl, safe="")
            else:
                target_url += (sep + "VULNUSLAB=" + quote(pl, safe=""))
            r2 = safe_request("GET", target_url,
                headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
                req=req, timeout=8, allow_redirects=False)
            if r2 is None: continue
            body = (r2.text or "")[:50000]
            # CSTI signal: expected output (49 / alert(1)) in body AND payload NOT
            # echoed as literal (rendered, not stored)
            if expected in body and pl not in body[:5000]:
                # Confirmed evaluation
                hits.append({"path": path, "payload": pl,
                              "expected": expected})
                break  # one finding per path

    findings = []
    if hits:
        findings.append(wrap_finding(
            f"CLIENT-SIDE TEMPLATE INJECTION at {len(hits)} location(s)",
            "HIGH", cvss="7.5", cwe="CWE-1336", owasp="A03:2021",
            remediation="Reflected user input flows into a client-side template "
                        "expression. Vue / Angular / Handlebars / Twig templates "
                        "execute these → XSS bypass. Fix at the server: HTML-encode "
                        "AND escape template-trigger chars (`{`, `}`, `${`, `[[`, `]]`) "
                        "before serving. At the framework: Vue v-html should never "
                        "render user input; Angular use [innerText] not [innerHTML]; "
                        "Handlebars use `{{{x}}}` only for trusted content.",
            evidence_marker=" | ".join(
                f"{h['path']}: {h['payload']} → {h['expected']} in response"
                for h in hits[:3]
            )))
    elif tested > 0:
        findings.append(wrap_finding(
            f"CSTI rejected at {tested} reflection point(s)",
            "POSITIVE", cwe="CWE-1336",
            remediation="Maintain. Audit templating helpers for safe-by-default behavior.",
            evidence_marker=f"{tested} reflections × {len(PAYLOADS)} payloads"))
    else:
        return standard_response(
            tool="client_side_template_injection", target=req.target, findings=[],
            tests_performed=len(PROBE_PATHS), vulnerable=False,
            skipped_reason="No reflection points found in probe paths")

    return standard_response(
        tool="client_side_template_injection", target=req.target, findings=findings,
        tests_performed=tested * len(PAYLOADS),
        vulnerable=bool(hits),
        tests_summary=f"{tested} reflections, {len(hits)} CSTI",
        raw_data={"hits": hits})


def register(app):
    app.include_router(router)
