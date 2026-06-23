"""CMS fingerprint (WordPress/Drupal/Joomla) + version disclosure.
VL-FORGE Vuln tier2 - playbook §2 #17."""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    home = await asyncio.to_thread(http_get, base + "/")
    if not home:
        ctx.state["tested"] = 0
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    body = home.get("body", "")
    mg = re.search(r'name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', body, re.I)
    gen = mg.group(1) if mg else ""
    cms = version = None
    low = body.lower()
    if "wordpress" in low or "/wp-content/" in body or "wordpress" in gen.lower():
        cms = "WordPress"
        mv = re.search(r"WordPress\s+(\d+\.\d+(?:\.\d+)?)", gen, re.I)
        version = mv.group(1) if mv else None
    elif "drupal" in low or "drupal" in gen.lower() or "/sites/default/" in body:
        cms = "Drupal"
        mv = re.search(r"Drupal\s+(\d+)", gen, re.I)
        version = mv.group(1) if mv else None
    elif "joomla" in gen.lower() or "/media/jui/" in body:
        cms = "Joomla"
        mv = re.search(r"Joomla!?\s*(\d+\.\d+)", gen, re.I)
        version = mv.group(1) if mv else None
    if cms:
        ctx.state["cms"] = cms
        if version:
            ctx.state["cms_version"] = version


def _r_version(s):
    if not s.get("cms") or not s.get("cms_version"):
        return None
    # ZERO-FP: the version comes from the meta-generator tag (a real signal),
    # but this finding is graded purely for version DISCLOSURE - we have NOT
    # confirmed this exact version falls inside any CVE's affected range. A
    # disclosed version is an information-leak (LOW), not a proven
    # vulnerability. Grading MEDIUM/HIGH would require mapping this exact
    # version into a known-vulnerable CVE range (use wpscan/droopescan for
    # that). So: LOW with an explicit version-inferred note.
    return {"name": f"{s['cms']} version disclosed: {s['cms_version']}", "severity": "LOW",
            "cwe": "CWE-200", "evidence": f"Meta generator exposes {s['cms']} {s['cms_version']}. Version-inferred, NOT range-confirmed - verify this exact version against known {s['cms']} CVE ranges before treating it as vulnerable.",
            "remediation": f"Remove generator meta; keep {s['cms']} core+plugins patched; run wpscan/droopescan to confirm whether this exact version is in an affected CVE range."}


def _r_cms(s):
    if not s.get("cms") or s.get("cms_version"):
        return None
    return {"name": f"{s['cms']} detected", "severity": "INFO", "cwe": "CWE-200",
            "evidence": f"{s['cms']} fingerprinted (no version leaked)",
            "remediation": f"Keep {s['cms']} patched; audit plugins/themes for CVEs."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or s.get("cms"):
        return None
    return {"name": "No known CMS fingerprinted", "severity": "POSITIVE",
            "evidence": "No WordPress/Drupal/Joomla markers in homepage."}


FINDING_RULES = [_r_version, _r_cms, _r_clean]
INTEL_FIELDS = [("CMS", "cms"), ("CMS version", "cms_version")]


@router.post("/api/vuln/cms_fingerprint_cve")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="cms_fingerprint_cve",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
