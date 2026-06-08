"""A06 Vulnerable Components - passive script src parsing for known-vuln library versions.
Self-contained. Strategy: parse <script src=> for jQuery/Bootstrap/Angular/Lodash and flag
versions with known CVEs (very conservative ranges)."""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url

router = APIRouter()

# Pattern: (regex, library, vulnerable_max_version, severity, cwe_note)
VULN_RULES = [
    (r"jquery[/-](\d+\.\d+(?:\.\d+)?)", "jQuery", (3, 5, 0), "MEDIUM", "Multiple XSS/prototype-pollution CVEs"),
    (r"bootstrap[/-](\d+\.\d+(?:\.\d+)?)", "Bootstrap", (3, 4, 1), "MEDIUM", "Multiple XSS CVEs in 2.x/3.x"),
    (r"angular[/-](\d+\.\d+(?:\.\d+)?)", "AngularJS", (1, 8, 0), "HIGH", "AngularJS sandbox bypass, EOL"),
    (r"lodash[.-](\d+\.\d+(?:\.\d+)?)", "Lodash", (4, 17, 19), "HIGH", "Prototype pollution CVE-2019-10744"),
    (r"moment[.-](\d+\.\d+(?:\.\d+)?)", "moment.js", (2, 29, 4), "MEDIUM", "ReDoS in <2.29.4"),
]


def _parse_version(v):
    parts = v.split(".")
    try:
        return tuple(int(x) for x in parts[:3]) + ((0,) * (3 - len(parts[:3])))
    except Exception:
        return (0, 0, 0)


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = probe_url(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    body = (base.get("body") or "").lower()
    found_libs = []
    vuln_libs = []
    for pattern, lib, max_vuln, sev, note in VULN_RULES:
        for m in re.finditer(pattern, body):
            ver_str = m.group(1)
            ver = _parse_version(ver_str)
            found_libs.append({"lib": lib, "version": ver_str})
            if ver <= max_vuln:
                vuln_libs.append({"lib": lib, "version": ver_str, "severity": sev, "note": note})
    ctx.state["libs_found"] = found_libs
    ctx.state["libs_vulnerable"] = vuln_libs


def _r_high(s):
    high = [l for l in (s.get("libs_vulnerable") or []) if l["severity"] == "HIGH"]
    if not high:
        return None
    return {"name": f"{len(high)} HIGH-severity vulnerable JS library version(s) loaded",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-1395",
            "evidence": "; ".join(f"{l['lib']} {l['version']} ({l['note']})" for l in high),
            "remediation": "Upgrade to maintained versions. Subresource integrity (SRI) + monitor with retire.js."}


def _r_med(s):
    med = [l for l in (s.get("libs_vulnerable") or []) if l["severity"] == "MEDIUM"]
    if not med:
        return None
    return {"name": f"{len(med)} vulnerable JS library version(s) loaded",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-1395",
            "evidence": "; ".join(f"{l['lib']} {l['version']}" for l in med),
            "remediation": "Upgrade these libraries to latest patch versions."}


FINDING_RULES = [_r_high, _r_med]
INTEL_FIELDS = [("JS libs detected", "libs_found"), ("Vulnerable libs", "libs_vulnerable")]


@router.post("/api/vuln/a06_vulnerable_components")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="a06_vulnerable_components",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
