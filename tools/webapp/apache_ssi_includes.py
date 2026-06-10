"""apache_ssi_includes — Apache Server Side Includes injection probe.

If Apache has Options +Includes enabled AND user input is reflected into
.shtml files (or files with handlers), SSI directives like
<!--#exec cmd="ls"--> execute server commands.

Probe by injecting SSI directives into reflection points + look for
SSI evaluation markers (timestamps, computed values).
"""
from urllib.parse import quote
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
SSI_PAYLOADS = [
    ('<!--#echo var="DATE_LOCAL"-->',  "DATE_LOCAL"),
    ('<!--#config timefmt="%Y"--><!--#echo var="DATE_LOCAL"-->', "20"),
]
PROBE_PATHS = ["/?q=", "/search?q=", "/?name=", "/contact?msg="]


@router.post("/api/webapp/scan/apache_ssi_includes")
@vl_turbo()
@vl_verify()
def scan_apache_ssi_includes(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    hits = []
    tested = 0
    for path in PROBE_PATHS:
        for pl, marker in SSI_PAYLOADS:
            url = base + path + quote(pl, safe="")
            r = safe_request("GET", url,
                headers={"User-Agent": "VulnusLab/1.0"},
                req=req, timeout=8, allow_redirects=False)
            if r is None: continue
            tested += 1
            body = (r.text or "")[:30000]
            # SSI evaluated: marker appears AND payload doesn't appear as literal
            if pl not in body[:5000] and marker in body:
                hits.append({"path": path, "payload": pl, "marker": marker})
                break
    findings = []
    if hits:
        findings.append(wrap_finding(
            f"SSI INJECTION at {len(hits)} location(s)",
            "CRITICAL", cvss="9.0", cwe="CWE-97", owasp="A03:2021",
            remediation="Disable Apache Options +Includes / +IncludesNoExec on "
                        "user-content paths. If SSI is required, sanitize all "
                        "user input before writing to .shtml files. SSI #exec "
                        "= immediate RCE.",
            evidence_marker=" | ".join(f"{h['path']}: {h['payload']}" for h in hits[:3])))
    elif tested > 0:
        findings.append(wrap_finding(
            f"No SSI evaluation ({tested} probes)", "POSITIVE", cwe="CWE-97",
            remediation="Maintain.", evidence_marker=f"{tested} probes clean"))
    else:
        return standard_response(tool="apache_ssi_includes", target=req.target,
            findings=[], tests_performed=0, vulnerable=False,
            skipped_reason="No reflection points")
    return standard_response(
        tool="apache_ssi_includes", target=req.target, findings=findings,
        tests_performed=tested, vulnerable=bool(hits),
        tests_summary=f"{tested} probes, {len(hits)} SSI hits",
        raw_data={"hits": hits})


def register(app):
    app.include_router(router)
