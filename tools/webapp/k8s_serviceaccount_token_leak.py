"""k8s_serviceaccount_token_leak — K8s SA token + env var leak in HTTP responses."""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()
LEAK_PROBES = ["/", "/debug/vars", "/_status", "/.env",
                "/api/debug", "/healthz", "/api/health/env"]
PATTERNS = [
    ("K8s SA token path",  re.compile(rb"/var/run/secrets/kubernetes\.io/serviceaccount/")),
    ("K8s SA token (JWT)", re.compile(rb"eyJhbGciOiJSUzI1NiI[A-Za-z0-9_-]{20,}\."
                                       rb"eyJpc3MiOiJrdWJlcm5ldGVz[A-Za-z0-9_-]{20,}\."
                                       rb"[A-Za-z0-9_-]{20,}")),
    ("KUBERNETES_SERVICE_HOST env", re.compile(rb"KUBERNETES_SERVICE_HOST[\"'=:][A-Za-z0-9.]+")),
    ("KUBE_TOKEN env",     re.compile(rb"KUBE_TOKEN[\"'=:][A-Za-z0-9_-]{40,}")),
]


@router.post("/api/webapp/scan/k8s_serviceaccount_token_leak")
def scan_k8s_serviceaccount_token_leak(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    hits = []
    for path in LEAK_PROBES:
        r = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r is None or r.status_code == 404: continue
        content = r.content[:200_000]
        for name, pat in PATTERNS:
            for m in pat.finditer(content):
                hits.append({"path": path, "type": name,
                              "preview": m.group(0).decode(errors="ignore")[:60]})
                if len(hits) >= 10: break
            if len(hits) >= 10: break
    findings = []
    if hits:
        critical = [h for h in hits if "token" in h["type"].lower()]
        findings.append(wrap_finding(
            f"K8s service-account token / env LEAKED ({len(hits)})",
            "CRITICAL" if critical else "HIGH",
            cvss="9.8" if critical else "7.5",
            cwe="CWE-798", owasp="A07:2021",
            remediation="K8s SA tokens grant cluster API access scoped to that "
                        "service account. ROTATE token + audit RBAC bindings. "
                        "Don't expose debug-vars / /env endpoints publicly. "
                        "Use NetworkPolicy to firewall pod's outbound API access.",
            evidence_marker=" | ".join(f"{h['path']}: {h['type']}: {h['preview']}" for h in hits[:5])))
    else:
        findings.append(wrap_finding(
            "No K8s SA token leakage detected", "POSITIVE", cwe="CWE-798",
            remediation="Maintain.",
            evidence_marker=f"checked {len(LEAK_PROBES)} probe paths × {len(PATTERNS)} patterns"))
    return standard_response(
        tool="k8s_serviceaccount_token_leak", target=req.target, findings=findings,
        tests_performed=len(LEAK_PROBES), vulnerable=bool(hits),
        tests_summary=f"{len(hits)} leaks", raw_data={"hits": hits[:10]})


def register(app): app.include_router(router)
