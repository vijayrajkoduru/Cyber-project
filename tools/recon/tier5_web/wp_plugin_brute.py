"""WordPress Plugin Brute-Force Enumeration — VL-FORGE pattern.

Route: /api/recon/wp_plugin_brute

Probes /wp-content/plugins/<slug>/readme.txt for each slug in
tools/_payloads/recon/wordpress_plugins_top.txt (WPScan top 2000 list).
Zero-FP: WP-presence gate first, then readme.txt status=200 +
'=== Plugin Name ===' marker required for a confirmed hit.
"""
import asyncio, re
from pathlib import Path
import requests
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, recon_host, web_url)
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()

_PAYLOAD = (Path(__file__).resolve().parent.parent.parent
            / "_payloads" / "recon" / "wordpress_plugins_top.txt")
_FALLBACK = ["akismet","jetpack","contact-form-7","yoast-seo","woocommerce",
             "elementor","wordfence","all-in-one-seo-pack","wp-super-cache",
             "really-simple-ssl"]
_MAX, _TO, _CONC = 200, 4, 30


def _load():
    try:
        if _PAYLOAD.exists():
            lines = _PAYLOAD.read_text(encoding="utf-8").splitlines()
            return [ln.strip().lower() for ln in lines
                    if ln.strip() and not ln.startswith("#")][:_MAX]
    except Exception:
        pass
    return _FALLBACK


def _get(url):
    try:
        return requests.get(url, timeout=_TO, verify=False,
                            headers={"User-Agent": "VulnusLab/1.0"},
                            allow_redirects=False)
    except Exception:
        return None


def _probe(base, slug):
    r = _get(f"{base}/wp-content/plugins/{slug}/readme.txt")
    if not r or r.status_code != 200:
        return None
    body = (r.text or "")[:4096]
    nm = re.search(r"^===\s*(.+?)\s*===", body, re.MULTILINE)
    if not nm:
        return None
    vm = re.search(r"^Stable tag:\s*([\w.\-]+)", body, re.MULTILINE)
    return {"slug": slug, "name": nm.group(1)[:80],
            "version": vm.group(1) if vm else None}


def _is_wp(base):
    r = _get(base + "/wp-login.php")
    if r and r.status_code == 200 and "WordPress" in (r.text or "")[:8192]:
        return True
    r = _get(base + "/wp-json")
    if r and r.status_code == 200:
        try:
            d = r.json()
            return isinstance(d, dict) and ("name" in d or "url" in d)
        except Exception:
            return False
    return False


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    wp = await asyncio.to_thread(_is_wp, base)
    ctx.state["wp_detected"] = wp
    if not wp:
        ctx.state["plugins_probed"] = 0
        return
    ctx.source("wp-detected")
    plugins = _load()
    ctx.state["plugins_probed"] = len(plugins)
    ctx.source(f"wordlist ({len(plugins)})")
    sem = asyncio.Semaphore(_CONC)

    async def one(s):
        async with sem:
            return await asyncio.to_thread(_probe, base, s)

    results = await asyncio.gather(*[one(s) for s in plugins])
    found = [r for r in results if r]
    ctx.state["plugins_found"] = found
    ctx.state["plugins_found_count"] = len(found)
    if found:
        ctx.source(f"enumerated ({len(found)})")
    versioned = [p for p in found if p.get("version") and p["version"] != "trunk"]
    ctx.state["plugins_versioned"] = versioned
    ctx.state["plugins_versioned_count"] = len(versioned)


def r_no_wp(s):
    if s.get("wp_detected"): return None
    return {"name": "WordPress not detected — plugin brute skipped",
            "severity": "INFO",
            "evidence": "wp-login.php + /wp-json both negative"}


def r_enum(s):
    f = s.get("plugins_found") or []
    if not f: return None
    return {"name": f"WordPress plugins enumerable ({len(f)})",
            "severity": "MEDIUM", "cwe": "CWE-200",
            "cwe_name": "Information Exposure",
            "owasp": "A05:2021 — Security Misconfiguration",
            "evidence": "Plugins: " + ", ".join(p["slug"] for p in f[:8]),
            "remediation": "Block /wp-content/plugins/*/readme.txt at WAF. Each plugin = CVE lookup target."}


def r_versions(s):
    v = s.get("plugins_versioned") or []
    if not v: return None
    return {"name": f"Plugin versions disclosed ({len(v)})",
            "severity": "HIGH", "cwe": "CWE-1104",
            "cwe_name": "Use of Unmaintained Third Party Components",
            "owasp": "A06:2021 — Vulnerable and Outdated Components",
            "evidence": ", ".join(f"{p['slug']}@{p['version']}" for p in v[:5]),
            "remediation": "Audit each version against wpscan.com / CVE Mitre. Block readme.txt at WAF."}


def r_clean(s):
    if not s.get("wp_detected"): return None
    if (s.get("plugins_found") or []): return None
    return {"name": "WordPress detected but no plugins enumerable",
            "severity": "POSITIVE",
            "evidence": f"Probed {s.get('plugins_probed', 0)} slugs — all 404 or non-readme"}


def r_probed(s):
    n = s.get("plugins_probed") or 0
    if n == 0: return None
    return {"name": f"Brute-forced {n} WordPress plugin slugs",
            "severity": "INFO",
            "evidence": "WPScan top-2000 wordlist (wordpress_plugins_top.txt)"}


FINDING_RULES = [r_no_wp, r_enum, r_versions, r_clean, r_probed]
INTEL_FIELDS = [("WordPress detected", "wp_detected"),
                ("Plugins probed", "plugins_probed"),
                ("Plugins enumerated", "plugins_found_count"),
                ("Plugin versions caught", "plugins_versioned_count")]


@router.post("/api/recon/wp_plugin_brute")
async def recon_wp_plugin_brute(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=recon_host(req.target), tool="wp_plugin_brute",
        gather_func=gather, finding_rules=FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["wp_detected", "plugins_found",
                         "plugins_found_count", "plugins_versioned"])


def register(app):
    app.include_router(router)
