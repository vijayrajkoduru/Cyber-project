"""recon_jslib_cve — detect outdated JS libraries with known CVEs (retire.js pattern)."""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, safe_get, web_url

router = APIRouter()

# Minimal retire.js-style DB. Each entry: (regex on URL/content, lib name,
# fixed-from version, list of [(introduced_version, fixed_version, CVE, severity, summary)])
VULN_DB = [
    ("jquery",   r"jquery[-/]([12]\.\d+\.\d+)", [
        ("1.0.0",  "1.6.3",  "CVE-2011-4969", "MEDIUM", "XSS via location.hash"),
        ("1.0.0",  "1.9.0",  "CVE-2012-6708", "MEDIUM", "XSS via $.html()"),
        ("1.0.0",  "3.0.0",  "CVE-2015-9251", "MEDIUM", "XSS via cross-domain ajax"),
        ("1.2.0",  "3.5.0",  "CVE-2019-11358","MEDIUM", "Prototype pollution"),
        ("1.0.0",  "3.5.0",  "CVE-2020-11022","MEDIUM", "XSS via .html() with crafted HTML"),
        ("1.0.0",  "3.5.0",  "CVE-2020-11023","MEDIUM", "XSS via .html() with <option> tags"),
    ]),
    ("jquery-ui", r"jquery[-/]?ui[-/]?(\d+\.\d+\.\d+)", [
        ("0.0.0",  "1.12.0", "CVE-2016-7103", "MEDIUM", "XSS in dialog close text"),
    ]),
    ("angular",  r"angular[-/.]?(\d+\.\d+\.\d+)", [
        ("1.0.0",  "1.6.3",  "CVE-2017-1000033","HIGH",  "Multiple XSS vulnerabilities"),
        ("1.0.0",  "1.8.0",  "CVE-2019-14863", "MEDIUM", "XSS via merge"),
        ("1.0.0",  "1.8.0",  "CVE-2020-7676",  "MEDIUM", "XSS via xlink:href"),
    ]),
    ("bootstrap", r"bootstrap[-./]?(\d+\.\d+\.\d+)", [
        ("3.0.0",  "3.4.1",  "CVE-2018-14041","MEDIUM", "XSS via data-target"),
        ("4.0.0",  "4.3.1",  "CVE-2019-8331", "MEDIUM", "XSS in tooltip data-template"),
        ("3.0.0",  "3.4.0",  "CVE-2018-14042","MEDIUM", "XSS in data-container"),
    ]),
    ("lodash",   r"lodash[-./]?(\d+\.\d+\.\d+)", [
        ("0.0.0",  "4.17.5", "CVE-2018-3721", "MEDIUM", "Prototype pollution via defaultsDeep"),
        ("0.0.0",  "4.17.11","CVE-2018-16487","MEDIUM", "Prototype pollution via merge"),
        ("0.0.0",  "4.17.21","CVE-2021-23337","HIGH",   "Command injection via template"),
    ]),
    ("moment",   r"moment[-./]?(\d+\.\d+\.\d+)", [
        ("0.0.0",  "2.29.4","CVE-2022-31129","HIGH",   "ReDoS in moment.parsing"),
    ]),
    ("vue",      r"vue[-./]?(\d+\.\d+\.\d+)", [
        ("2.0.0",  "2.7.14","CVE-2024-9506", "MEDIUM", "Various Vue 2.x XSS"),
    ]),
    ("react",    r"react[-./@]?(\d+\.\d+\.\d+)", [
        ("15.0.0", "15.6.2","CVE-2018-6341", "HIGH",   "XSS via injected attributes"),
    ]),
    ("dompurify", r"dompurify[-./]?(\d+\.\d+\.\d+)", [
        ("0.0.0", "2.3.4",  "CVE-2021-39126","HIGH",   "Mutation XSS bypass"),
    ]),
]


def _version_lt(a, b):
    """Return True if version a < b."""
    try:
        pa = tuple(int(x) for x in a.split("."))
        pb = tuple(int(x) for x in b.split("."))
        return pa < pb
    except Exception:
        return False


@router.post("/api/recon/jslib_cve")
async def recon_jslib_cve(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings, libs_detected = [], []
    r = safe_get(base, req=req)
    if r is None:
        return {"ok": True, "vulnerable": False, "skipped_reason": "Could not reach target"}

    # Collect all <script src=> URLs
    js_refs = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', r.text or "", re.I):
        js_refs.append(m.group(1))

    # Detect libs from URL filename patterns
    for lib_name, url_pattern, cves in VULN_DB:
        for js_url in js_refs:
            m = re.search(url_pattern, js_url, re.I)
            if not m:
                continue
            detected_version = m.group(1)
            libs_detected.append({
                "lib": lib_name, "version": detected_version, "url": js_url,
                "vulnerable_cves": [],
            })
            for intro, fixed, cve_id, sev, summary in cves:
                if _version_lt(detected_version, fixed):
                    findings.append({
                        "title": f"{lib_name} {detected_version} vulnerable — {cve_id}",
                        "severity": sev, "cvss": 7.5 if sev == "HIGH" else 5.3,
                        "cwe": "CWE-1395", "owasp": "A06:2021",
                        "evidence": (f"Detected {lib_name} {detected_version} at {js_url} — "
                                     f"{cve_id}: {summary}. Fixed in {fixed}."),
                        "remediation": (f"Upgrade {lib_name} to {fixed} or later. "
                                        "Consider switching to a maintained alternative.")
                    })
                    libs_detected[-1]["vulnerable_cves"].append(cve_id)

    # Dedupe by (lib, version) to avoid double-reporting
    seen, unique_libs = set(), []
    for lib in libs_detected:
        k = (lib["lib"], lib["version"])
        if k in seen: continue
        seen.add(k)
        unique_libs.append(lib)

    return {"ok": True, "vulnerable": len(findings) > 0, "findings": findings,
            "libs_detected": unique_libs,
            "js_files_scanned": len(js_refs),
            "total_findings": len(findings),
            "engine": f"retire.js-style detector ({len(VULN_DB)} libs, "
                      f"{sum(len(v[2]) for v in VULN_DB)} CVEs in DB)"}


def register(app):
    app.include_router(router)
