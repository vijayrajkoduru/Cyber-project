"""WordPress Scanner — Pure-Python with SPA-fallback detection.

Pattern: TEMPLATE for vuln-scan tools that must avoid SPA false positives.
The baseline-fingerprint pattern here is the standard for any tool that
probes well-known paths against a target that might be a single-page app.
"""
import re
import random
import string
import datetime
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, safe_get,
    web_url, wrap_finding, standard_response,
)

router = APIRouter()


def _matches_spa_baseline(probe, baseline):
    """True if this response looks like the SPA catch-all fallback.
    Used to filter false positives on Angular/React/Vue sites that
    return 200 for every URL."""
    if not baseline or probe is None: return False
    if probe.status_code != baseline["status"]: return False
    if abs(len(probe.content) - baseline["size"]) > 50: return False
    return (probe.text or "")[:5000].lower() == baseline["body"]


def _has_wp_markers(r) -> bool:
    """Body contains WordPress-specific markers. Required for a 200
    response to count as 'WordPress detected'."""
    if r is None: return False
    body = (r.text or "")[:8000].lower()
    return any(m in body for m in (
        "wp-content", "wp-includes", "wp-json", "wordpress",
        "wp_enqueue_script", "wp-emoji-release", "wp-block-",
        '<meta name="generator" content="wordpress',
    ))


@router.post("/api/vuln/wpscan")
async def vuln_wpscan(req: ScanRequest, user=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    now_z = lambda: datetime.datetime.utcnow().isoformat() + "Z"

    # ── Baseline probe — fingerprint SPA fallback ────────────────
    rnd = "/_vulnuslab_wp_baseline_" + "".join(
        random.choices(string.ascii_lowercase, k=18)) + ".nonexistent"
    br = safe_get(base + rnd, retries=1, timeout=8, req=req,
                  allow_redirects=False)
    baseline = None
    if br is not None:
        baseline = {"status": br.status_code, "size": len(br.content),
                    "body": (br.text or "")[:5000].lower()}

    # ── Step 1 — is this WordPress at all? ───────────────────────
    indicators = ["/wp-login.php", "/wp-admin/", "/wp-content/",
                  "/wp-includes/", "/xmlrpc.php"]
    hits = {}
    for path in indicators:
        tests += 1
        r = safe_get(base + path, retries=1, timeout=8, req=req,
                     allow_redirects=False)
        if r is None: continue
        if _matches_spa_baseline(r, baseline): continue
        if r.status_code in (301, 302, 401, 403):
            hits[path] = r.status_code
        elif r.status_code == 200 and _has_wp_markers(r):
            hits[path] = r.status_code

    if not hits:
        return standard_response(
            tool="wpscan", target=req.target, findings=[],
            tests_performed=tests,
            tests_summary=f"{tests} probes for WordPress indicator paths — "
                          f"target is not WordPress",
            skipped_reason="Target does not appear to be WordPress — none of "
                           "/wp-login.php, /wp-admin/, /wp-content/, "
                           "/wp-includes/, /xmlrpc.php responded with WP-typical "
                           "status codes",
            raw_data={"is_wordpress": False},
        )

    # ── Step 2 — WP confirmed, run active checks ─────────────────
    if "/xmlrpc.php" in hits:
        tests += 1
        findings.append(wrap_finding(
            "XML-RPC endpoint exposed at /xmlrpc.php — usable for password "
            "bruteforce amplification (system.multicall) and pingback DDoS",
            "MEDIUM", cvss="5.3", cwe="CWE-307",
            cwe_name="Improper Restriction of Authentication Attempts",
            owasp="A07:2021",
            remediation="Disable XML-RPC unless required.",
            evidence_marker=f"HTTP {hits['/xmlrpc.php']} on /xmlrpc.php",
        ))

    if "/wp-admin/" in hits and hits["/wp-admin/"] in (200, 302):
        tests += 1
        findings.append(wrap_finding(
            "/wp-admin/ is publicly reachable — should be IP-restricted "
            "on production",
            "LOW", cvss="3.1", cwe="CWE-284",
            cwe_name="Improper Access Control", owasp="A01:2021",
            remediation="Restrict /wp-admin/ by IP (.htaccess / nginx allow) "
                        "or place behind VPN.",
            evidence_marker=f"HTTP {hits['/wp-admin/']} on /wp-admin/",
        ))

    # Version disclosure via /readme.html
    tests += 1
    rr = safe_get(base + "/readme.html", retries=1, timeout=6, req=req)
    if rr is not None and rr.status_code == 200 and "wordpress" in (rr.text or "").lower():
        m = re.search(r"[Vv]ersion\s+(\d+\.\d+(?:\.\d+)?)", rr.text or "")
        if m:
            findings.append(wrap_finding(
                f"WordPress version disclosed via /readme.html: {m.group(1)}",
                "LOW", cvss="3.1", cwe="CWE-200",
                cwe_name="Information Exposure", owasp="A05:2021",
                remediation="Delete /readme.html — it reveals the WP version "
                            "to attackers searching for CVEs.",
                evidence_marker=f"readme.html disclosed version: {m.group(1)}",
            ))

    return standard_response(
        tool="wpscan", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"{tests} active probes — WP indicators, XML-RPC, "
                      f"wp-admin reachability, readme.html version disclosure",
        raw_data={"is_wordpress": True, "indicators": list(hits.keys())},
    )


def register(app):
    app.include_router(router)
