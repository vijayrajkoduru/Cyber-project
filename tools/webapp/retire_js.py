"""Webapp: Vulnerable JavaScript library detection (retire.js-equivalent)."""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync

router = APIRouter()

# AI-curated 200-entry signature list — extends _VULN_LIBS with additional
# library/version/CVE entries. Loaded with safe fallback.
try:
    from tools._payloads.retire_js_signatures import RETIRE_JS_SIGNATURES as _AI_RETIRE
    _AI_RETIRE = _AI_RETIRE if isinstance(_AI_RETIRE, list) else []
except Exception:
    _AI_RETIRE = []

# Format: (library_name, vulnerable_version_regex, fixed_version, cve, severity, description)
_VULN_LIBS = [
    ("jQuery",      r"jquery[/-](?:v)?(1\.(?:[0-9]|1[0-1])\.[0-9]+|2\.[01]\.[0-9])", "3.5.0",  "CVE-2020-11023", "MEDIUM", "XSS via HTML manipulation in append()"),
    ("AngularJS",   r"angular(?:js)?[/-](?:v)?(1\.[0-7]\.[0-9]+)",                     "1.8.0",  "CVE-2020-7676",  "MEDIUM", "AngularJS XSS via Object.prototype pollution"),
    ("lodash",      r"lodash[/-](?:v)?([0-3]\.[0-9]+\.[0-9]+|4\.(?:[0-9]|1[0-6])\.[0-9]+|4\.17\.(?:[0-9]|1[01]))", "4.17.12", "CVE-2019-10744", "HIGH", "Prototype pollution in defaultsDeep"),
    ("Moment.js",   r"moment[/-](?:v)?(2\.(?:[0-9]|1[0-9]|2[0-8])\.[0-9]+)",          "2.29.4", "CVE-2022-31129", "HIGH", "ReDoS in moment.parsing"),
    ("Bootstrap",   r"bootstrap[/-](?:v)?(3\.[0-3]\.[0-9]+|4\.[0-2]\.[0-9]+)",      "4.3.1",  "CVE-2019-8331",  "MEDIUM", "XSS in tooltip/popover data-template"),
    ("Handlebars",  r"handlebars[/-](?:v)?([0-3]\.[0-9]+\.[0-9]+|4\.[0-6]\.[0-9]+)",  "4.7.7",  "CVE-2021-23369", "CRITICAL","Prototype pollution leading to RCE"),
]

# Convert AI-curated entries to the same 6-tuple shape and extend _VULN_LIBS
for _ai in _AI_RETIRE:
    if not isinstance(_ai, dict): continue
    lib = _ai.get("library", "")
    det = _ai.get("detection_regex", "")
    cve = _ai.get("cve", "") or ""
    sev = _ai.get("severity", "MEDIUM")
    vuln_versions = _ai.get("vulnerable_versions", "")
    # Use detection_regex as the version-match regex too (it should capture version)
    # Fallback: skip entries with no useful detection regex
    if not lib or not det: continue
    desc = f"AI-curated {lib} CVE — vulnerable versions {vuln_versions}"
    _VULN_LIBS.append((lib, det, "(see CVE)", cve, sev, desc))


@router.post("/api/webapp/retire_js")
async def webapp_retire_js(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []
    tests = 0
    detected = []
    
    # Fetch homepage + extract JS file URLs
    r = safe_get(base + "/", req=req, allow_redirects=True, timeout=10)
    if r is None:
        return standard_response(
            tool="retire_js", target=req.target, findings=[],
            tests_performed=0, skipped_reason="Could not reach target",
        )
    js_urls = list(set(re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', r.text or "", re.I)))[:25]
    
    # Inline page content + each JS file
    bodies = [(r.text or "")[:200000]]
    for ju in js_urls:
        tests += 1
        full = ju if ju.startswith("http") else (base + (ju if ju.startswith("/") else "/" + ju))
        jr = safe_get(full, req=req, timeout=6)
        if jr is not None and jr.status_code == 200:
            bodies.append((jr.text or "")[:200000])
    
    seen = set()
    for body in bodies:
        for lib_name, vuln_re, fixed, cve, sev, desc in _VULN_LIBS:
            m = re.search(vuln_re, body, re.I)
            if m and (lib_name, m.group(1)) not in seen:
                seen.add((lib_name, m.group(1)))
                detected.append({"library": lib_name, "version": m.group(1), "cve": cve, "fixed_in": fixed})
                cvss = {"CRITICAL":"9.8","HIGH":"7.5","MEDIUM":"5.4","LOW":"3.1"}.get(sev, "5.0")
                findings.append(wrap_finding(
                    f"Vulnerable library: {lib_name} {m.group(1)} - {desc}",
                    sev,
                    cvss=cvss, cwe="CWE-1104",
                    cwe_name="Use of Unmaintained Third-Party Components",
                    owasp="A06:2021",
                    remediation=f"Upgrade {lib_name} to >= {fixed} (CVE: {cve})",
                    evidence_marker=f"Found '{lib_name} {m.group(1)}' in target's loaded JavaScript",
                ))

    return standard_response(
        tool="retire_js", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Scanned {len(bodies)} JS source(s) against {len(_VULN_LIBS)} known-vulnerable library signatures",
        raw_data={"retire_js": {"detected": detected, "js_files_scanned": len(bodies),
                                   "spa_catchall": spa["is_spa"]}},
    )


def register(app):
    app.include_router(router)
