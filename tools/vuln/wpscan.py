"""WordPress-specific scanner — runs only on confirmed WordPress targets."""
import random, re, string
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
router = APIRouter()

def _spa(probe, b):
    if not b or probe is None: return False
    if probe.status_code != b["status"]: return False
    if abs(len(probe.content) - b["size"]) > 100: return False
    return (probe.text or "")[:5000].lower() == b["body"]

def _is_wp(base, req):
    r = safe_get(base + "/wp-login.php", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200 and "wordpress" in (r.text or "").lower(): return True
    r2 = safe_get(base, req=req, allow_redirects=True, timeout=8)
    return r2 is not None and re.search(r"generator.{0,40}WordPress", r2.text or "", re.I) is not None

@router.post("/api/scan/wpscan")
async def scan_wpscan(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    if not _is_wp(base, req):
        return standard_response(tool="wpscan", target=req.target, findings=[],
            tests_performed=2, vulnerable=False,
            skipped_reason="Target is not WordPress")
    rnd = "/_vl_wp_" + "".join(random.choices(string.ascii_lowercase, k=12)) + ".nonexistent"
    br = safe_get(base + rnd, req=req, allow_redirects=False, timeout=8)
    baseline = None
    if br is not None:
        baseline = {"status": br.status_code, "size": len(br.content), "body": (br.text or "")[:5000].lower()}
    findings, tests = [], 0
    tests += 1
    r = safe_get(base + "/xmlrpc.php", req=req, allow_redirects=False, timeout=8)
    if r is not None and not _spa(r, baseline) and (r.status_code in (200, 405) or "XML-RPC" in (r.text or "")):
        findings.append(wrap_finding(
            "XML-RPC endpoint exposed — auth brute / pingback DDoS",
            "MEDIUM", cvss="5.3", cwe="CWE-307", owasp="A07:2021",
            remediation="Disable XML-RPC. nginx: 'location = /xmlrpc.php { deny all; }'",
            evidence_marker=f"HTTP {r.status_code} on /xmlrpc.php"))
    tests += 1
    r = safe_get(base + "/wp-admin/", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code in (200, 302) and not _spa(r, baseline):
        findings.append(wrap_finding(
            "/wp-admin/ publicly reachable — should be IP-restricted",
            "LOW", cvss="3.1", cwe="CWE-284", owasp="A01:2021",
            remediation="Restrict /wp-admin/ by IP (.htaccess / nginx allow) or VPN.",
            evidence_marker=f"HTTP {r.status_code} on /wp-admin/"))
    tests += 1
    r = safe_get(base + "/readme.html", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200 and "wordpress" in (r.text or "").lower():
        m = re.search(r"[Vv]ersion\s+(\d+\.\d+(?:\.\d+)?)", r.text or "")
        if m:
            findings.append(wrap_finding(
                f"WordPress version disclosed via /readme.html: {m.group(1)}",
                "LOW", cvss="3.1", cwe="CWE-200", owasp="A05:2021",
                remediation="Delete /readme.html — reveals WP version to CVE-seeking attackers.",
                evidence_marker=f"readme.html: version {m.group(1)}"))
    tests += 1
    r = safe_get(base + "/wp-json/wp/v2/users", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200 and r.headers.get("Content-Type", "").startswith("application/json"):
        try:
            users = r.json()
            if isinstance(users, list) and len(users) > 0:
                findings.append(wrap_finding(
                    f"User enumeration via /wp-json/wp/v2/users — {len(users)} usernames exposed",
                    "LOW", cvss="3.7", cwe="CWE-200", owasp="A05:2021",
                    remediation="Disable REST API user endpoint or require authentication.",
                    evidence_marker=f"/wp-json/wp/v2/users returned {len(users)} users"))
        except: pass
    tests += 1
    r = safe_get(base + "/wp-content/debug.log", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200 and len(r.text or "") > 50 and not _spa(r, baseline):
        findings.append(wrap_finding(
            "/wp-content/debug.log publicly exposed — leaks PHP errors + secrets",
            "HIGH", cvss="7.5", cwe="CWE-200", owasp="A05:2021",
            remediation="Delete file. Set WP_DEBUG=false in wp-config.php for production.",
            evidence_marker=f"/wp-content/debug.log returned {len(r.text)} bytes"))
    return standard_response(tool="wpscan", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"WordPress scanner: {tests} active probes",
        raw_data={"wpscan": {"is_wordpress": True}})
def register(app): app.include_router(router)
