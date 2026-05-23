"""WordPress-specific scanner — runs only on confirmed WordPress targets.

Path dictionary: tools/_payloads/vuln/wpscan_paths.json (52 AI-curated
WordPress exploit paths covering: backup config, REST user enumeration,
plugin/theme fingerprinting, directory listings, admin/install endpoints,
wp-content backup paths, version disclosure files).

Each path entry is data-driven (no hardcoded if-branches per path):
  - match_status: list of HTTP codes that count as a hit (e.g. [200, 302])
  - match_text: optional regex; if set, must also match (case-insensitive)
  - severity / cvss / title / cwe / owasp / remediation: finding shape
"""
import random, re, string
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools.vuln._vuln_common import vuln_response, precheck_target
from tools._payloads.vuln._loader import load_json
router = APIRouter()

_FALLBACK_PATHS = [
    {"path": "/xmlrpc.php",        "match_status": [200, 405], "match_text": "XML-RPC", "severity": "MEDIUM", "cvss": "5.3",
     "title": "XML-RPC endpoint exposed — auth brute / pingback DDoS", "cwe": "CWE-307", "owasp": "A07:2021",
     "remediation": "Disable XML-RPC."},
    {"path": "/wp-admin/",          "match_status": [200, 302], "match_text": None,      "severity": "LOW",    "cvss": "3.1",
     "title": "/wp-admin/ publicly reachable — should be IP-restricted",  "cwe": "CWE-284", "owasp": "A01:2021",
     "remediation": "Restrict /wp-admin/ by IP or VPN."},
    {"path": "/readme.html",        "match_status": [200],       "match_text": "WordPress","severity": "LOW",    "cvss": "3.1",
     "title": "WordPress version disclosed via /readme.html", "cwe": "CWE-200", "owasp": "A05:2021",
     "remediation": "Delete /readme.html — reveals WP version to CVE-seeking attackers."},
    {"path": "/wp-content/debug.log","match_status":[200], "match_text": "PHP|Stack trace", "severity": "HIGH", "cvss": "7.5",
     "title": "/wp-content/debug.log publicly exposed", "cwe": "CWE-200", "owasp": "A05:2021",
     "remediation": "Delete file. Set WP_DEBUG=false in wp-config.php."},
]
_loaded = load_json("wpscan_paths")
_WP_PATHS = _loaded if isinstance(_loaded, list) and _loaded else _FALLBACK_PATHS


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


def _matches_entry(r, entry, baseline):
    """Return (matched, evidence_str)."""
    if r is None: return False, None
    if _spa(r, baseline):
        return False, None
    statuses = entry.get("match_status") or [200]
    if r.status_code not in statuses:
        return False, None
    marker = entry.get("match_text")
    if marker:
        try:
            if not re.search(marker, r.text or "", re.IGNORECASE):
                return False, None
        except re.error:
            return False, None
    return True, f"HTTP {r.status_code} on {entry['path']}"


@router.post("/api/vuln/wpscan")
def scan_wpscan(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    if not _is_wp(base, req):
        return vuln_response(tool="wpscan", target=req.target, findings=[],
            tested=2,
            skipped_reason="Target is not WordPress")
    # SPA-shell baseline
    rnd = "/_vl_wp_" + "".join(random.choices(string.ascii_lowercase, k=12)) + ".nonexistent"
    br = safe_get(base + rnd, req=req, allow_redirects=False, timeout=8)
    baseline = None
    if br is not None:
        baseline = {"status": br.status_code, "size": len(br.content),
                    "body": (br.text or "")[:5000].lower()}

    findings, tests = [], 0
    for entry in _WP_PATHS:
        tests += 1
        r = safe_get(base + entry["path"], req=req, allow_redirects=False, timeout=8)
        matched, evidence = _matches_entry(r, entry, baseline)
        if not matched:
            continue
        findings.append(wrap_finding(
            entry["title"],
            entry.get("severity", "LOW"),
            cvss=entry.get("cvss", "3.0"),
            cwe=entry.get("cwe", "CWE-200"),
            owasp=entry.get("owasp", "A05:2021"),
            remediation=entry.get("remediation", "Review exposure of this WP path."),
            evidence_marker=evidence))

    # Always try the REST user enumeration extra-deeply (it has a payload check)
    r = safe_get(base + "/wp-json/wp/v2/users", req=req, allow_redirects=False, timeout=8)
    if r is not None and r.status_code == 200 and r.headers.get("Content-Type", "").startswith("application/json"):
        try:
            users = r.json()
            if isinstance(users, list) and len(users) > 0:
                # avoid duplicate emission if data-driven entry already fired
                if not any("wp-json/wp/v2/users" in (f.get("evidence_marker") or "") for f in findings):
                    findings.append(wrap_finding(
                        f"User enumeration via /wp-json/wp/v2/users — {len(users)} usernames exposed",
                        "LOW", cvss="3.7", cwe="CWE-200", owasp="A05:2021",
                        remediation="Disable REST API user endpoint or require authentication.",
                        evidence_marker=f"/wp-json/wp/v2/users returned {len(users)} users"))
        except Exception:
            pass

    return vuln_response(tool="wpscan", target=req.target, findings=findings,
        tested=tests,
        what_checked=f"WordPress-specific paths ({len(_WP_PATHS)}-entry AI-curated wordlist: backup configs, xmlrpc, admin, themes, plugins, user-enum, debug logs)",
        tests_summary=f"WordPress scanner: {tests} active probes against {len(_WP_PATHS)}-entry wordlist",
        raw_data={"wpscan": {"is_wordpress": True, "wordlist_size": len(_WP_PATHS)}})


def register(app): app.include_router(router)
