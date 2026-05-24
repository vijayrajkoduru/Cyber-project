"""Webapp: Drupal-specific scanner (CHANGELOG, install pages, version disclosure)."""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response

router = APIRouter()

# AI-curated 150-entry Drupal-specific path list with CVE markers
try:
    from tools._payloads.drupal_scan_paths import DRUPAL_SCAN_PATHS as _AI_DRUPAL_PATHS
    _AI_DRUPAL_PATHS = _AI_DRUPAL_PATHS if isinstance(_AI_DRUPAL_PATHS, list) else []
except Exception:
    _AI_DRUPAL_PATHS = []


def _is_drupal(base, req):
    r1 = safe_get(base + "/", req=req, allow_redirects=True, timeout=8)
    if r1 is not None and re.search(r"generator.{0,40}Drupal", r1.text or "", re.I):
        return True, r1
    r2 = safe_get(base + "/sites/default/files/", req=req, allow_redirects=False, timeout=8)
    if r2 is not None and r2.status_code in (200, 403):
        return True, r1
    r3 = safe_get(base + "/CHANGELOG.txt", req=req, allow_redirects=False, timeout=8)
    if r3 is not None and r3.status_code == 200 and "Drupal" in (r3.text or "")[:200]:
        return True, r1
    return False, r1


@router.post("/api/webapp/drupal_scan")
async def webapp_drupal_scan(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    is_drupal, home_r = _is_drupal(base, req)
    if not is_drupal:
        return standard_response(
            tool="drupal_scan", target=req.target, findings=[],
            tests_performed=3, skipped_reason="Target is not Drupal (no generator meta / sites/default / CHANGELOG.txt)",
        )

    findings = []
    tests = 3

    # 1. CHANGELOG.txt exposes version
    tests += 1
    r = safe_get(base + "/CHANGELOG.txt", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200:
        m = re.search(r"Drupal\s+(\d+\.\d+(?:\.\d+)?)", r.text or "")
        if m:
            findings.append(wrap_finding(
                f"Drupal version disclosed via /CHANGELOG.txt: {m.group(1)}",
                "MEDIUM",
                cvss="5.3", cwe="CWE-200",
                cwe_name="Information Exposure",
                owasp="A05:2021",
                remediation="Delete /CHANGELOG.txt - it reveals the exact Drupal version to CVE-seeking attackers.",
                evidence_marker=f"GET /CHANGELOG.txt returned Drupal {m.group(1)}",
            ))

    # 2. /core/CHANGELOG.txt (Drupal 8+)
    tests += 1
    r = safe_get(base + "/core/CHANGELOG.txt", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200:
        m = re.search(r"Drupal\s+(\d+\.\d+(?:\.\d+)?)", r.text or "")
        if m:
            findings.append(wrap_finding(
                f"Drupal 8+ version disclosed via /core/CHANGELOG.txt: {m.group(1)}",
                "MEDIUM",
                cvss="5.3", cwe="CWE-200",
                owasp="A05:2021",
                remediation="Delete /core/CHANGELOG.txt or block access at the web server.",
                evidence_marker=f"GET /core/CHANGELOG.txt returned Drupal {m.group(1)}",
            ))

    # 3. /install.php accessible (should be blocked post-install)
    tests += 1
    r = safe_get(base + "/install.php", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200 and "drupal" in (r.text or "").lower()[:5000]:
        findings.append(wrap_finding(
            "Drupal /install.php is publicly accessible - re-installation possible",
            "HIGH",
            cvss="8.1", cwe="CWE-284",
            cwe_name="Improper Access Control",
            owasp="A01:2021",
            remediation="Block /install.php at the web server level (deny all). It should only be accessible during initial setup.",
            evidence_marker="GET /install.php returned HTTP 200 with Drupal content",
        ))

    # 4. /update.php publicly reachable
    tests += 1
    r = safe_get(base + "/update.php", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200 and "drupal" in (r.text or "").lower()[:5000]:
        findings.append(wrap_finding(
            "Drupal /update.php is publicly reachable",
            "MEDIUM",
            cvss="5.3", cwe="CWE-284",
            cwe_name="Improper Access Control",
            owasp="A01:2021",
            remediation="Restrict /update.php to admin IPs or require authentication.",
            evidence_marker="GET /update.php returned HTTP 200",
        ))

    # 5. /user/register publicly enabled
    tests += 1
    r = safe_get(base + "/user/register", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200 and re.search(r'<input[^>]*name=["\']?mail', r.text or "", re.I):
        findings.append(wrap_finding(
            "Drupal /user/register is open - unrestricted user registration",
            "LOW",
            cvss="3.1", cwe="CWE-284",
            owasp="A05:2021",
            remediation="Require admin approval for new registrations: /admin/config/people/accounts -> 'Who can register accounts?' -> Administrators only.",
            evidence_marker="GET /user/register returned a usable registration form",
        ))

    return standard_response(
        tool="drupal_scan", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Drupal-specific scanner: {tests} active probes (CHANGELOG / install / update / user/register)",
        raw_data={"drupal_scan": {"is_drupal": True}},
    )


def register(app):
    app.include_router(router)
