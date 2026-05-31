"""github_actions_oidc_leak — GHA OIDC token / workflow artifact leaks in HTML."""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()
PATTERNS = [
    ("GHA Actions runner token",  re.compile(rb"AGEKEYFROM[A-Z0-9]{40,}")),
    ("GHA workflow ID URL",       re.compile(rb"actions/runs/\d{10,}")),
    ("GHA OIDC audience",         re.compile(rb"actions\.githubusercontent\.com")),
    ("GHA artifact URL",          re.compile(rb"artifacts\.githubusercontent\.com/[A-Za-z0-9_/-]+")),
    ("GHA workflow YAML path",    re.compile(rb"\.github/workflows/[a-z0-9_-]+\.ya?ml")),
]
SCRIPT_SRC_RE = re.compile(r'<script[^>]*\bsrc=["\']([^"\']+\.js)["\']', re.IGNORECASE)


@router.post("/api/webapp/scan/github_actions_oidc_leak")
def scan_github_actions_oidc_leak(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    root = safe_request("GET", base + "/",
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=True)
    if root is None or root.status_code >= 400:
        return standard_response(tool="github_actions_oidc_leak", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="no homepage")
    sources = {"inline": root.content}
    fetched = 0
    for m in SCRIPT_SRC_RE.finditer(root.text):
        if fetched >= 8: break
        src = m.group(1)
        if src.startswith("/"): src = base + src
        elif not src.startswith("http"): src = base + "/" + src
        if not src.startswith(base): continue
        r = safe_request("GET", src,
            headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
            req=req, timeout=6, allow_redirects=True)
        if r is None or r.status_code != 200: continue
        sources[src] = r.content[:300_000]
        fetched += 1
    hits = []
    for src_name, content in sources.items():
        for name, pat in PATTERNS:
            for m in pat.finditer(content):
                hits.append({"type": name, "preview": m.group(0).decode(errors="ignore")[:60],
                              "source": src_name[:80]})
                if len(hits) >= 10: break
            if len(hits) >= 10: break
    findings = []
    high = [h for h in hits if "token" in h["type"].lower() or
                                  "artifact" in h["type"].lower()]
    if high:
        findings.append(wrap_finding(
            f"CRITICAL: GitHub Actions secrets/artifacts in bundle ({len(high)})",
            "CRITICAL", cvss="9.0", cwe="CWE-798", owasp="A07:2021",
            remediation="GHA OIDC tokens grant cloud access. Rotate IMMEDIATELY at "
                        "Actions workflow + cloud IAM. Artifact URLs may be public; "
                        "if so, audit for secrets. Never log/echo OIDC token in "
                        "workflow output — it'll end up in artifact bundles.",
            evidence_marker=" | ".join(f"{h['type']}: {h['preview']}" for h in high[:3])))
    elif hits:
        findings.append(wrap_finding(
            f"GHA workflow references in bundle ({len(hits)})",
            "INFO", cwe="CWE-200",
            remediation="Workflow YAML paths reveal build pipeline structure — "
                        "useful to recon but not directly exploitable.",
            evidence_marker=" | ".join(f"{h['type']}: {h['preview']}" for h in hits[:5])))
    else:
        findings.append(wrap_finding("No GHA leaks detected", "POSITIVE",
            cwe="CWE-200", remediation="Maintain.",
            evidence_marker=f"scanned {1+fetched} sources × {len(PATTERNS)} patterns"))
    return standard_response(
        tool="github_actions_oidc_leak", target=req.target, findings=findings,
        tests_performed=1+fetched, vulnerable=bool(high),
        tests_summary=f"{len(hits)} hits ({len(high)} critical)",
        raw_data={"hits": hits[:10]})


def register(app): app.include_router(router)
