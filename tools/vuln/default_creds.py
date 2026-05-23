"""Admin Panel Exposure v2 — VL-FORGE pattern.

Route: /api/recon/default_creds

Conservative implementation: DETECTS panel exposure only — does NOT
attempt login (avoids account lockout liability). Reports panels that
historically ship with default credentials.

Sources (parallel):
  1. Probe 40+ common admin panel paths
  2. Match HTML response against known panel signatures
  3. Flag panels with documented default-credential history
"""
import asyncio
import re

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.tier5_findings import ADMIN_PANEL_FINDING_RULES

router = APIRouter()


# (path, product, signature_regex_or_None, has_default_cred_history)
_PANEL_SIGNATURES = [
    # WordPress
    ("/wp-admin/", "WordPress", r"<body class=[\"']login", False),
    ("/wp-login.php", "WordPress", r"WordPress &rsaquo;|wp-submit", False),
    # phpMyAdmin
    ("/phpmyadmin/", "phpMyAdmin", r"phpMyAdmin", True),
    ("/pma/", "phpMyAdmin", r"phpMyAdmin", True),
    ("/myadmin/", "phpMyAdmin", r"phpMyAdmin", True),
    # Adminer
    ("/adminer/", "Adminer", r"Adminer", True),
    ("/adminer.php", "Adminer", r"Adminer", True),
    # Jenkins
    ("/jenkins/", "Jenkins", r"Jenkins|hudson", True),
    ("/jenkins/login", "Jenkins", r"Jenkins|hudson", True),
    # Tomcat
    ("/manager/", "Tomcat Manager", r"Tomcat|Manager App", True),
    ("/manager/html", "Tomcat Manager", r"Tomcat", True),
    ("/host-manager/", "Tomcat Host Manager", r"Host Manager", True),
    # Kibana
    ("/app/kibana", "Kibana", r"Kibana", False),
    ("/kibana/", "Kibana", r"Kibana", False),
    # Grafana
    ("/login", "Grafana / Generic", r"Grafana", True),
    # Jolokia
    ("/jolokia/", "Jolokia", r"Jolokia", False),
    # Solr
    ("/solr/", "Apache Solr", r"Solr Admin", True),
    # Cisco / network gear
    ("/level/15/", "Cisco IOS", r"Cisco", True),
    # CMS
    ("/admin/", "Generic Admin", r"<form[^>]*(login|signin|password)", False),
    ("/admin.php", "Generic Admin", None, False),
    ("/administrator/", "Joomla", r"Joomla", True),
    ("/drupal/", "Drupal", r"Drupal", False),
    # Webmin / Plesk / cPanel
    ("/webmin/", "Webmin", r"Webmin", True),
    ("/:10000/", "Webmin", r"Webmin", True),
    ("/cpanel", "cPanel", r"cPanel", True),
    ("/plesk", "Plesk", r"Plesk", True),
    # Routers
    ("/setup.cgi", "Router (generic)", r"router|gateway", True),
    # Misc
    ("/zabbix/", "Zabbix", r"Zabbix", True),
    ("/nagios/", "Nagios", r"Nagios", True),
    ("/influxdb/", "InfluxDB", r"InfluxDB", False),
    ("/elasticsearch/", "Elasticsearch", r"elasticsearch", False),
    # OAuth/SSO
    ("/auth/realms/", "Keycloak", r"Keycloak", False),
    ("/oauth2/", "OAuth proxy", r"OAuth", False),
]


def _probe(url, signature, base_404_len):
    try:
        r = requests.get(url, timeout=6, verify=False, allow_redirects=False,
                          headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code not in (200, 301, 302, 401, 403):
            return None
        # Skip if response is identical to base-404 (custom 404 catch)
        if base_404_len and abs(len(r.content) - base_404_len) < 96:
            return None
        text = (r.text or "")[:5000]
        if signature and not re.search(signature, text, re.I):
            return None
        return {"status": r.status_code, "length": len(r.content)}
    except Exception:
        return None


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    ctx.state["base_reachable"] = True

    # Calibrate 404 baseline
    base_404_len = None
    try:
        r = await asyncio.to_thread(
            requests.get, base + "/_vlabprobe_nonexistent_xyz",
            timeout=6, verify=False, allow_redirects=False,
            headers={"User-Agent": "VulnusLab/1.0"})
        if r is not None:
            base_404_len = len(r.content)
    except Exception:
        pass

    # Parallel probe all panel paths
    tasks = [asyncio.to_thread(_probe, base + path, sig, base_404_len)
             for path, _, sig, _ in _PANEL_SIGNATURES]
    results = await asyncio.gather(*tasks)

    panels_found = []
    for (path, product, sig, default_creds), result in zip(_PANEL_SIGNATURES, results):
        if result:
            panels_found.append({
                "path": path,
                "product": product,
                "status": result["status"],
                "default_creds_risk": default_creds,
            })

    ctx.state["panels_found"] = panels_found
    ctx.state["paths_probed"] = len(_PANEL_SIGNATURES)
    ctx.source(f"admin-panel-probe ({len(_PANEL_SIGNATURES)} paths)")
    if panels_found:
        ctx.source(f"signature-match ({len(panels_found)})")


INTEL_FIELDS = [
    ("Paths probed",          "paths_probed"),
    ("Panels found",          "panels_count_display"),
    ("Default-cred prone",    "default_cred_display"),
]


@router.post("/api/vuln/default_creds")
async def recon_default_creds(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        pf = ctx.state.get("panels_found") or []
        if pf:
            ctx.state["panels_count_display"] = (
                f"{len(pf)}: " + ", ".join(
                    f"{p['path']} ({p['product']})" for p in pf[:3]))
        risky = [p for p in pf if p.get("default_creds_risk")]
        if risky:
            ctx.state["default_cred_display"] = ", ".join(
                p.get("product") for p in risky[:5])

    return await run_scanner(
        host=host, tool="default_creds",
        gather_func=gather_with_display,
        finding_rules=ADMIN_PANEL_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["panels_found"],
    )


def register(app):
    app.include_router(router)
