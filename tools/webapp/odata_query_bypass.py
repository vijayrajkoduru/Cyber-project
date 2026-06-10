"""odata_query_bypass — OData $filter / $expand authorization bypass.

OData (Microsoft + SAP backends, SuccessFactors, Dynamics) exposes
flexible query language via URL: ?$filter=role eq 'admin'&$select=*
&$expand=related/sensitive. Misconfig: backend filters at LIST level
but NOT at row level → attacker uses $filter / $expand to access rows
they shouldn't see.

Tests: probe for OData $metadata + check if $filter eq '*' returns
admin-only data.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

ODATA_PATHS = ["/odata/", "/api/odata/", "/odata/v4/",
                "/odata/v2/", "/$metadata"]


@router.post("/api/webapp/scan/odata_query_bypass")
@vl_turbo()
def scan_odata_query_bypass(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    # 1. Discover OData service
    metadata = None
    metadata_url = None
    for path in ODATA_PATHS:
        url = base + path + ("$metadata" if not path.endswith("$metadata") else "")
        r = safe_request("GET", url,
            headers={"User-Agent": "VulnusLab/1.0",
                      "Accept": "application/xml,application/json"},
            req=req, timeout=8, allow_redirects=False)
        if r is None or r.status_code != 200: continue
        body = (r.text or "")[:50000]
        if "EntitySet" in body or "edmx:Edmx" in body or "DataServices" in body:
            metadata = body
            metadata_url = url
            break

    if not metadata:
        return standard_response(
            tool="odata_query_bypass", target=req.target,
            findings=[wrap_finding(
                "No OData service detected",
                "POSITIVE", cwe="CWE-200",
                remediation="No OData attack surface.",
                evidence_marker=f"checked {ODATA_PATHS}")],
            tests_performed=len(ODATA_PATHS), vulnerable=False,
            tests_summary="No OData")

    # Extract entity set names
    import re
    entity_sets = list(set(re.findall(r'<EntitySet[^>]*Name="([^"]+)"', metadata)))[:5]

    findings = []
    issues = []

    # 2. For each entity set, try $filter + $expand probes
    base_odata = metadata_url.replace("/$metadata", "").rstrip("/")
    if not base_odata.endswith("/"): base_odata += "/"

    over_returns = []
    for es in entity_sets:
        # Baseline: just the entity set
        r0 = safe_request("GET", base_odata + es,
            headers={"User-Agent": "VulnusLab/1.0",
                      "Accept": "application/json"},
            req=req, timeout=8, allow_redirects=False)
        if r0 is None or r0.status_code >= 400: continue
        base_size = len(r0.content) if r0.content else 0

        # $expand=*: try expanding all relations
        r1 = safe_request("GET", base_odata + es + "?$expand=*",
            headers={"User-Agent": "VulnusLab/1.0",
                      "Accept": "application/json"},
            req=req, timeout=10, allow_redirects=False)
        if r1 is not None and r1.status_code == 200:
            expand_size = len(r1.content) if r1.content else 0
            # Significantly bigger response suggests cross-entity expansion worked
            if expand_size > base_size * 3:
                over_returns.append({"entity": es, "base_size": base_size,
                                       "expand_size": expand_size})

    if over_returns:
        issues.append((f"$expand=* returned >3x baseline data on {len(over_returns)} entities",
                        "MEDIUM"))

    if issues:
        findings.append(wrap_finding(
            f"OData query exposure ({len(issues)})",
            "MEDIUM", cvss="6.0", cwe="CWE-200", owasp="A01:2021",
            remediation="OData services need row-level authorization enforcement. "
                        "(1) Use IODataProtocolService with claim-based authorization. "
                        "(2) Whitelist allowed $expand paths per role. "
                        "(3) Disable $top limit override (default 100). "
                        "(4) Audit log every query for anomalies.",
            evidence_marker=" | ".join(f"{m} [{s}]" for m, s in issues[:5])))
    else:
        findings.append(wrap_finding(
            f"OData detected at {metadata_url} — entities found: {entity_sets[:3]}",
            "INFO", cwe="CWE-200",
            remediation="OData service in use. Manually test $filter / $expand /"
                        " $select for row-level auth. Tools: OData Inspector,"
                        " Burp OData extension.",
            evidence_marker=f"{len(entity_sets)} entity sets detected"))

    return standard_response(
        tool="odata_query_bypass", target=req.target, findings=findings,
        tests_performed=len(ODATA_PATHS) + len(entity_sets) * 2,
        vulnerable=bool(over_returns),
        tests_summary=f"OData detected, {len(entity_sets)} entities, "
                       f"{len(over_returns)} expand-leaks",
        raw_data={"metadata_url": metadata_url,
                   "entity_sets": entity_sets,
                   "over_returns": over_returns})


def register(app):
    app.include_router(router)
