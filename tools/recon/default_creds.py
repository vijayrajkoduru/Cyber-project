"""recon_default_creds — detect exposed admin panels with known default-cred risk.

Conservative implementation: DETECTS panel exposure only — does NOT actually
attempt credential login (avoids lockout liability). Reports panels that
historically ship with known default credentials.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, safe_get, web_url

router = APIRouter()

PANELS = [
    {"path": "/jenkins/login", "name": "Jenkins", "default_creds": "admin/admin (older versions)",
     "marker_signatures": ["jenkins", "j_acegi_security_check"]},
    {"path": "/manager/html", "name": "Apache Tomcat Manager", "default_creds": "tomcat/tomcat, admin/admin",
     "marker_signatures": ["tomcat", "manager"]},
    {"path": "/host-manager/html", "name": "Apache Tomcat Host Manager",
     "default_creds": "admin/admin, tomcat/tomcat", "marker_signatures": ["tomcat", "host-manager"]},
    {"path": "/phpmyadmin/", "name": "phpMyAdmin", "default_creds": "root/empty, admin/admin",
     "marker_signatures": ["phpmyadmin", "pma_password"]},
    {"path": "/pma/", "name": "phpMyAdmin (alt)", "default_creds": "root/empty",
     "marker_signatures": ["phpmyadmin"]},
    {"path": "/grafana/login", "name": "Grafana", "default_creds": "admin/admin",
     "marker_signatures": ["grafana", "Grafana"]},
    {"path": "/admin/", "name": "Generic /admin", "default_creds": "varies by app",
     "marker_signatures": ["login", "password"]},
    {"path": "/wp-admin/", "name": "WordPress wp-admin", "default_creds": "varies (admin/admin/password common)",
     "marker_signatures": ["wp-login", "wordpress"]},
    {"path": "/administrator/", "name": "Joomla Administrator", "default_creds": "admin/admin",
     "marker_signatures": ["joomla", "administrator"]},
    {"path": "/login.action", "name": "Atlassian Confluence", "default_creds": "varies",
     "marker_signatures": ["confluence", "atlassian"]},
    {"path": "/druid/index.html", "name": "Apache Druid Coordinator", "default_creds": "no auth by default",
     "marker_signatures": ["druid"]},
    {"path": "/solr/", "name": "Apache Solr Admin", "default_creds": "no auth by default",
     "marker_signatures": ["solr"]},
    {"path": "/console/login.html", "name": "Oracle WebLogic", "default_creds": "weblogic/welcome1",
     "marker_signatures": ["weblogic", "Oracle"]},
    {"path": "/_cat/health", "name": "Elasticsearch (no auth)", "default_creds": "no auth",
     "marker_signatures": ["elasticsearch", "epoch"]},
    {"path": "/_plugin/kibana/", "name": "Kibana", "default_creds": "elastic/changeme",
     "marker_signatures": ["kibana", "elastic"]},
    {"path": "/nagios/", "name": "Nagios Monitoring", "default_creds": "nagiosadmin/nagiosadmin",
     "marker_signatures": ["nagios"]},
    {"path": "/zabbix/", "name": "Zabbix", "default_creds": "Admin/zabbix",
     "marker_signatures": ["zabbix"]},
    {"path": "/portainer/", "name": "Portainer", "default_creds": "admin/admin (first run)",
     "marker_signatures": ["portainer"]},
    {"path": "/rancher/", "name": "Rancher", "default_creds": "admin/admin",
     "marker_signatures": ["rancher"]},
]


@router.post("/api/recon/default_creds")
async def recon_default_creds(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings, panels_found = [], []

    for panel in PANELS:
        r = safe_get(f"{base}{panel['path']}", req=req, allow_redirects=True)
        if r is None or r.status_code in (404, 0):
            continue
        # Skip if status is not 200/401/403 (rules out random redirects)
        if r.status_code not in (200, 401, 403):
            continue
        # Check marker signatures
        body = (r.text or "")[:5000].lower()
        matched_markers = [m for m in panel["marker_signatures"] if m.lower() in body]
        if not matched_markers:
            continue

        panels_found.append({
            "panel": panel["name"],
            "url": f"{base}{panel['path']}",
            "status": r.status_code,
            "default_creds": panel["default_creds"],
            "matched_markers": matched_markers,
        })

        findings.append({"title": f"{panel['name']} admin panel exposed at {panel['path']}",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-284", "owasp": "A05:2021",
            "evidence": f"HTTP {r.status_code} response with markers {matched_markers} at {base}{panel['path']}",
            "remediation": f"Restrict {panel['name']} access via IP allow-list, VPN, or strong auth. "
                          f"Known default credentials: {panel['default_creds']} — change immediately if exposed."})

    return {"ok": True, "vulnerable": len(findings) > 0, "findings": findings,
            "panels_tested": len(PANELS),
            "panels_found": panels_found,
            "total_panels_found": len(panels_found),
            "engine": f"admin panel exposure probe ({len(PANELS)} panels) — credential test deliberately skipped to avoid lockout"}


def register(app):
    app.include_router(router)
