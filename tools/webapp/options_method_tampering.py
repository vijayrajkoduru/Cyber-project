"""options_method_tampering — OPTIONS verb response audit.

OPTIONS reveals server's supported methods via Allow header (or
Access-Control-Allow-Methods). Audit:
  - PUT/DELETE/PATCH advertised but not actually used → admin surface
  - TRACE / CONNECT enabled (legacy XST / proxy abuse)
  - Allow header overly permissive (lists every standard verb = generic
    framework default, not curated)
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

SENSITIVE_PATHS = ["/", "/api/", "/api/users", "/api/admin",
                    "/admin", "/login", "/upload"]
DANGEROUS_METHODS = {"TRACE", "CONNECT", "PUT", "DELETE", "PATCH"}


def _options(url, req):
    return safe_request("OPTIONS", url,
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)


@router.post("/api/webapp/scan/options_method_tampering")
@vl_turbo()
@vl_verify()
def scan_options_method_tampering(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    method_inventory = {}

    for path in SENSITIVE_PATHS:
        url = base + path
        r = _options(url, req)
        if r is None: continue
        allow = (r.headers.get("allow") or r.headers.get("Allow") or "").upper()
        ac_allow = (r.headers.get("access-control-allow-methods") or "").upper()
        combined = set(m.strip() for m in (allow + "," + ac_allow).split(",") if m.strip())
        if combined:
            method_inventory[path] = sorted(combined)

    if not method_inventory:
        return standard_response(
            tool="options_method_tampering", target=req.target, findings=[],
            tests_performed=len(SENSITIVE_PATHS), vulnerable=False,
            skipped_reason="No paths returned an Allow / Access-Control-Allow-Methods header")

    findings = []
    dangerous_endpoints = []
    over_permissive = []

    for path, methods in method_inventory.items():
        dangerous = set(methods) & DANGEROUS_METHODS
        if dangerous:
            # TRACE / CONNECT especially bad
            if "TRACE" in dangerous or "CONNECT" in dangerous:
                dangerous_endpoints.append({
                    "path": path, "methods": list(dangerous),
                    "severity": "HIGH"
                })
            elif {"PUT", "DELETE", "PATCH"} & set(methods):
                dangerous_endpoints.append({
                    "path": path, "methods": list({"PUT", "DELETE", "PATCH"} & set(methods)),
                    "severity": "INFO"
                })
        # Over-permissive: more than 7 methods listed (probably generic framework default)
        if len(methods) > 7:
            over_permissive.append({"path": path, "count": len(methods)})

    if dangerous_endpoints:
        trace_connect = [d for d in dangerous_endpoints if any(
            m in d["methods"] for m in ("TRACE", "CONNECT"))]
        if trace_connect:
            findings.append(wrap_finding(
                f"TRACE/CONNECT method advertised at {len(trace_connect)} path(s)",
                "HIGH", cvss="7.5", cwe="CWE-200", owasp="A05:2021",
                remediation="Disable TRACE (legacy debugging; enables XST attack) "
                            "and CONNECT (proxy abuse). nginx: doesn't speak TRACE "
                            "by default. Apache: `TraceEnable Off`. IIS: HTTP method "
                            "restrictions in URL rewrite.",
                evidence_marker=" | ".join(
                    f"{d['path']}: {','.join(d['methods'])}" for d in trace_connect[:3]
                )))
        write_methods = [d for d in dangerous_endpoints if "TRACE" not in d["methods"]]
        if write_methods:
            findings.append(wrap_finding(
                f"Write methods (PUT/DELETE/PATCH) advertised at {len(write_methods)} path(s)",
                "INFO", cwe="CWE-200",
                remediation="Allow header can leak admin attack surface. If these "
                            "methods aren't actually used at the path, remove them "
                            "from Allow (manually whitelist; many frameworks "
                            "advertise all methods by default).",
                evidence_marker=" | ".join(
                    f"{d['path']}: {','.join(d['methods'])}" for d in write_methods[:5]
                )))

    if over_permissive:
        findings.append(wrap_finding(
            f"Over-permissive Allow header at {len(over_permissive)} path(s)",
            "LOW", cwe="CWE-200",
            remediation="Curate the Allow header to only methods actually handled. "
                        "Defaults often list every HTTP verb regardless of use.",
            evidence_marker=" | ".join(
                f"{o['path']}: {o['count']} methods" for o in over_permissive[:5]
            )))

    if not findings:
        findings.append(wrap_finding(
            f"OPTIONS responses look curated ({len(method_inventory)} paths)",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain.",
            evidence_marker=" | ".join(
                f"{p}: {','.join(m)}" for p, m in list(method_inventory.items())[:3]
            )))

    return standard_response(
        tool="options_method_tampering", target=req.target, findings=findings,
        tests_performed=len(SENSITIVE_PATHS),
        vulnerable=bool(dangerous_endpoints),
        tests_summary=f"{len(method_inventory)} paths, {len(dangerous_endpoints)} risky",
        raw_data={"method_inventory": method_inventory,
                   "dangerous_endpoints": dangerous_endpoints})


def register(app):
    app.include_router(router)
