"""opa_policy_bypass — Open Policy Agent (OPA) endpoint detection + default-allow."""
import json
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
OPA_PATHS = ["/v1/data/", "/v1/policies", "/v1/query", "/health",
              "/metrics", "/diagnostics"]


@router.post("/api/webapp/scan/opa_policy_bypass")
@vl_turbo()
@vl_verify()
def scan_opa_policy_bypass(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    is_opa = False
    exposed = []

    def _probe(path):
        r = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0", "Accept": "application/json"},
            req=req, timeout=8, allow_redirects=False)
        if r is None or r.status_code == 404: return None
        body = (r.text or "")[:5000]
        if "openpolicyagent" in body.lower() or '"result"' in body or "rego" in body.lower():
            return {"path": path, "status": r.status_code}
        return None

    # VL-TURBO deep: parallelize 6 probes via pool(6).
    # Was ~48s sequential, now ~8s parallel.
    with ThreadPoolExecutor(max_workers=min(6, len(OPA_PATHS))) as pool:
        for result in pool.map(_probe, OPA_PATHS, timeout=21):
            if result is not None:
                is_opa = True
                exposed.append(result)
    if is_opa:
        # Try default-allow query
        rq = safe_request("POST", base + "/v1/query",
            headers={"Content-Type": "application/json",
                      "User-Agent": "VulnusLab/1.0"},
            data='{"query": "data.allow"}', req=req, timeout=8,
            allow_redirects=False)
        allowed = False
        if rq is not None and rq.status_code == 200:
            try:
                allowed = "true" in (rq.text or "").lower()[:200]
            except Exception: pass
        findings.append(wrap_finding(
            f"OPA control plane EXPOSED on internet ({len(exposed)} endpoint(s))"
            + (" + default-allow active" if allowed else ""),
            "CRITICAL" if allowed else "HIGH",
            cvss="9.0" if allowed else "7.5",
            cwe="CWE-732", owasp="A05:2021",
            remediation="OPA decision plane MUST be internal-only. Bind to "
                        "127.0.0.1 or behind mTLS. Public exposure = attacker "
                        "queries any policy + extracts policy bundle. If 'allow' "
                        "defaults true, attacker bypasses authz. opa run "
                        "--server --addr 127.0.0.1:8181.",
            evidence_marker=" | ".join(f"{e['path']}: HTTP {e['status']}" for e in exposed[:5])))
    else:
        findings.append(wrap_finding(
            "No OPA control plane exposed", "POSITIVE", cwe="CWE-732",
            remediation="Maintain.",
            evidence_marker=f"checked {len(OPA_PATHS)} OPA paths"))
    return standard_response(
        tool="opa_policy_bypass", target=req.target, findings=findings,
        tests_performed=len(OPA_PATHS) + (1 if is_opa else 0),
        vulnerable=is_opa,
        tests_summary=f"OPA: {is_opa}, exposed_paths: {len(exposed)}",
        raw_data={"is_opa": is_opa, "exposed": exposed})


def register(app): app.include_router(router)
