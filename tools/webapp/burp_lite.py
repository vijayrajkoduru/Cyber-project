"""Webapp: burp_lite - aggregator that runs ALL webapp scanners in one click.

Like Burp Suite's automated scan, but for our 32 webapp scanners.
Findings are tagged by source_tool so customers see which sub-check fired each finding.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, standard_response

router = APIRouter()

# All non-aggregator webapp scanners (skip nikto, nuclei, burp_lite itself)
_SCANNERS = [
    "crawler","jsendpoints","wayback","robotsmap","directory_brute","exposed_files",
    "cms_detection","waf_cdn","tech_stack","param_discovery",
    "xss","sqli","cmd_injection","xxe","ssrf","lfi","open_redirect",
    "jwt","cookies","security_headers","cors","http_methods","clickjacking",
    "wpscan","ssl_deep","secrets","favicon","cve_match",
    "swagger_discovery","graphql_introspection","ssti","idor_detector","authenticated_scan",
    "nosqli","prototype_pollution","file_upload_bypass","race_condition","retire_js",
    "backup_files","directory_listing","host_header_injection","mass_assignment","broken_auth",
    "session_fixation","crlf_injection","forced_browsing","weak_crypto","drupal_scan",
    "ldap_injection","xpath_injection","password_reset_flaws","cache_poisoning","joomla_scan",
    "param_reflection","api_endpoint_fuzz","deserialization_probe","oauth_redirect_bypass","privilege_escalation",
    "http_smuggling","csp_bypass",
]


@router.post("/api/webapp/burp_lite")
async def webapp_burp_lite(req: ScanRequest, payload=Depends(verify_scan_quota)):
    all_findings = []
    sub_results = {}
    total_tests = 0
    
    for name in _SCANNERS:
        try:
            mod = __import__(f"tools.webapp.{name}", fromlist=[f"webapp_{name}"])
            fn = getattr(mod, f"webapp_{name}")
            result = await fn(req, payload)
            for f in result.get("findings", []):
                f["source_tool"] = name
                all_findings.append(f)
            total_tests += result.get("tests_performed", 0)
            sub_results[name] = {
                "findings_count":  len(result.get("findings", [])),
                "tests":           result.get("tests_performed", 0),
                "skipped_reason":  result.get("skipped_reason"),
            }
        except Exception as exc:
            sub_results[name] = {"error": str(exc)[:120]}
    
    return standard_response(
        tool="burp_lite", target=req.target,
        findings=all_findings,
        tests_performed=total_tests,
        tests_summary=(f"burp_lite: aggregated {len(_SCANNERS)} webapp scanners "
                       f"({total_tests} tests, {len(all_findings)} findings)"),
        raw_data={"burp_lite": {"sub_scanners": sub_results}},
    )


def register(app):
    app.include_router(router)
