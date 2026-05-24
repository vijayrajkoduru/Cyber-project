"""Webapp: Joomla-specific scanner."""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response

router = APIRouter()

# AI-curated 150-entry Joomla-specific path list with CVE markers
try:
    from tools._payloads.joomla_scan_paths import JOOMLA_SCAN_PATHS as _AI_JOOMLA_PATHS
    _AI_JOOMLA_PATHS = _AI_JOOMLA_PATHS if isinstance(_AI_JOOMLA_PATHS, list) else []
except Exception:
    _AI_JOOMLA_PATHS = []


def _is_joomla(base, req):
    r = safe_get(base + "/", req=req, allow_redirects=True, timeout=8)
    if r is not None and re.search(r"generator.{0,40}Joomla", r.text or "", re.I):
        return True
    r2 = safe_get(base + "/administrator/", req=req, allow_redirects=False, timeout=8)
    if r2 is not None and r2.status_code == 200 and "joomla" in (r2.text or "").lower()[:5000]:
        return True
    r3 = safe_get(base + "/language/en-GB/en-GB.xml", req=req, allow_redirects=False, timeout=8)
    if r3 is not None and r3.status_code == 200 and "joomla" in (r3.text or "").lower()[:2000]:
        return True
    return False


@router.post("/api/webapp/joomla_scan")
async def webapp_joomla_scan(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    if not _is_joomla(base, req):
        return standard_response(
            tool="joomla_scan", target=req.target, findings=[],
            tests_performed=3, skipped_reason="Target is not Joomla (no generator meta / /administrator / language XML)",
        )

    findings = []
    tests = 3

    # 1. /administrator publicly reachable
    tests += 1
    r = safe_get(base + "/administrator/", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200:
        findings.append(wrap_finding(
            "Joomla /administrator/ is publicly reachable - should be IP-restricted",
            "MEDIUM",
            cvss="5.3", cwe="CWE-284",
            cwe_name="Improper Access Control",
            owasp="A01:2021",
            remediation=".htaccess or nginx allow only admin IPs. Or place /administrator/ behind VPN / HTTP basic auth.",
            evidence_marker="GET /administrator/ returned HTTP 200",
        ))

    # 2. /language/en-GB/en-GB.xml exposes version
    tests += 1
    r = safe_get(base + "/language/en-GB/en-GB.xml", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200:
        m = re.search(r"<version>([\d.]+)</version>", r.text or "", re.I)
        if m:
            findings.append(wrap_finding(
                f"Joomla version disclosed via /language/en-GB/en-GB.xml: {m.group(1)}",
                "MEDIUM",
                cvss="5.3", cwe="CWE-200",
                owasp="A05:2021",
                remediation="Block public access to /language/en-GB/en-GB.xml.",
                evidence_marker=f"GET /language/en-GB/en-GB.xml returned version {m.group(1)}",
            ))

    # 3. /administrator/manifests/files/joomla.xml exposes version
    tests += 1
    r = safe_get(base + "/administrator/manifests/files/joomla.xml", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200:
        m = re.search(r"<version>([\d.]+)</version>", r.text or "", re.I)
        if m:
            findings.append(wrap_finding(
                f"Joomla version disclosed via /administrator/manifests/files/joomla.xml: {m.group(1)}",
                "MEDIUM",
                cvss="5.3", cwe="CWE-200",
                owasp="A05:2021",
                remediation="Block /administrator/manifests/ at the web server.",
                evidence_marker=f"Joomla manifest disclosed version {m.group(1)}",
            ))

    # 4. /configuration.php (sometimes left readable)
    tests += 1
    r = safe_get(base + "/configuration.php", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200 and "JConfig" in (r.text or "")[:1000]:
        findings.append(wrap_finding(
            "Joomla configuration.php exposed - DB credentials & secret keys leaked",
            "CRITICAL",
            cvss="9.8", cwe="CWE-200",
            cwe_name="Information Exposure",
            owasp="A05:2021",
            remediation="Verify PHP is executing in the web server (not serving .php as text). Move configuration.php above the web root if possible. Rotate ALL leaked credentials immediately.",
            evidence_marker="GET /configuration.php returned PHP source with JConfig class definition",
        ))

    return standard_response(
        tool="joomla_scan", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Joomla-specific scanner: {tests} probes (admin / version XMLs / configuration.php)",
        raw_data={"joomla_scan": {"is_joomla": True}},
    )


def register(app):
    app.include_router(router)
