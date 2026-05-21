"""recon_gobuster -- isolated tool (Kali-style architecture).

Route: /api/recon/gobuster
Split from recon_module.py monolith by scripts/split_recon_module.py.
Failure here is quarantined by the healing autoloader -- other tools unaffected.
"""

import asyncio
import base64
import datetime
import hashlib
import re
import socket
from typing import Optional
import requests
import dns.resolver
import dns.asyncresolver
import whois as whois_lib
from fastapi import APIRouter, Depends
from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host, safe_get, web_url,
)
import aiohttp as _aiohttp_crawl
import ssl as _ssl_mod

from fastapi import APIRouter, Depends

router = APIRouter()

# === GOBUSTER-AI-WORDLIST-V2 ===
import pathlib as _pl
_AI_PATHS = None
try:
    _p = _pl.Path(__file__).resolve().parent.parent / "_payloads" / "recon" / "consolidated_paths.txt"
    if _p.exists():
        _AI_PATHS = [ln.strip() for ln in _p.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
except Exception:
    _AI_PATHS = None
# === /GOBUSTER-AI-WORDLIST-V2 ===


_COMMON_DIRS = [
    "admin","administrator","admin.php","admin/login","admin/index","login","login.php","signin",
    "cpanel","wp-admin","wp-login.php","phpmyadmin","pma","adminer","myadmin","manage","management","manager",
    "panel","controlpanel","dashboard","moderator","webadmin","sysadmin","admin1","admin2","admincp","admins",
    "admin-area","admin-portal","admin/dashboard","admin/users","admin/system","admin/config",
    "administracao","administracion","backend","backstage","console","control","cpadmin","cms","cms/admin",
    ".env",".env.local",".env.production",".env.development",".env.staging",".env.backup",".env.example",".env.test",
    "config.php","config.json","config.yaml","config.yml","config.xml","configuration.php","configuration.json",
    "settings.php","settings.json","settings.py","appsettings.json","web.config","wp-config.php","db.config",
    ".aws/credentials",".aws/config",".ssh/id_rsa",".ssh/authorized_keys",".docker/config.json",
    "secrets.json","secrets.yml","secrets.yaml","credentials.json","credentials.txt","credentials.yml",
    "config/database.yml","config/secrets.yml","config/master.key",
    ".git/config",".git/HEAD",".git/index",".git/logs/HEAD",".gitignore",".gitconfig",".gitlab-ci.yml",".github/workflows",
    ".svn/entries",".svn/wc.db",".svn/format",".hg/hgrc",".bzr/README",".DS_Store",
    ".vscode/settings.json",".idea/workspace.xml",".idea/dataSources.xml","Thumbs.db",
    "backup","backup.zip","backup.tar.gz","backup.tar","backup.tar.bz2","backup.sql","backup.rar","backup.7z","backup.tgz",
    "backup-old","backups","backup_old","backup/index.html","site-backup.zip","www.zip","www.tar.gz",
    "html.zip","public.zip","sql.zip","db.zip","old.zip","old.tar.gz","prod.zip","prod.tar.gz",
    "dump.sql","db.sql","database.sql","mysql.sql","postgres.sql","mongodump","data.sql","data.zip",
    "wp-config.php.bak","wp-config.php~","wp-config.bak","config.php.bak","config.php~",
    "index.php.bak","index.php~","index.html.bak","login.php.bak","login.bak",
    "phpinfo.php","info.php","test.php","p.php","i.php","x.php","debug.php","trace.php","testing.php",
    "server-status","server-info","status","stats","statistics","metrics","monitor","monitoring","health","healthcheck","healthz",
    "ping","heartbeat","alive","ready","probe","liveness","readiness",
    "api","api/v1","api/v2","api/v3","api/v4","api/docs","api-docs","api-doc","swagger","swagger.json","swagger.yaml","swagger-ui",
    "openapi.json","openapi.yaml","redoc","graphql","graphql-playground","graphiql","apollo-explorer",
    "rest","rest/v1","actuator","actuator/health","actuator/env","actuator/metrics","actuator/info","actuator/heapdump",
    "actuator/threaddump","actuator/beans","actuator/configprops","actuator/mappings",
    "dev","development","develop","staging","stage","beta","test","testing","preview","sandbox","sandbox/admin",
    "demo","tmp","temp","old","new","backup-old","internal","intranet","extranet","private","portal",
    "uploads","upload","files","file","download","downloads","docs","documents","document","papers",
    "images","img","media","assets","static","public","data","resources","resource","content",
    "wp-content","wp-includes","wp-content/uploads","wp-content/plugins","wp-content/themes","wp-content/debug.log",
    "wp-content/backup-db","wp-cron.php","wp-config.php","xmlrpc.php","wp-json","wp-json/wp/v2",
    "sites/default","sites/default/files","sites/default/settings.php","sites/all","sites/all/modules",
    "administrator/index.php","administrator/components","joomla","drupal","drupal/install.php",
    "robots.txt","sitemap.xml","sitemap_index.xml","sitemap.xml.gz","humans.txt","ads.txt","security.txt",
    ".well-known/security.txt",".well-known/openid-configuration",".well-known/change-password",
    ".well-known/openid-credential-issuer",".well-known/oauth-authorization-server",
    ".htaccess",".htpasswd",".bash_history",".profile",".bashrc",".zshrc","crossdomain.xml","clientaccesspolicy.xml",
    "logs","log","error.log","access.log","debug.log","application.log","app.log","system.log","auth.log","trace.log",
    "phpunit.xml","composer.json","composer.lock","package.json","package-lock.json","yarn.lock","pnpm-lock.yaml",
    "Gemfile","Gemfile.lock","requirements.txt","Pipfile","Pipfile.lock","go.mod","go.sum","Cargo.toml","Cargo.lock",
    "Dockerfile","docker-compose.yml","docker-compose.yaml","Vagrantfile","Makefile","Procfile",
    "README.md","README.txt","CHANGELOG.md","LICENSE","TODO.txt","NOTES.md","HISTORY.md","CONTRIBUTING.md",
    "console","actuator","jolokia","prometheus","grafana","kibana","kibana/app/kibana","jenkins","jenkins/script",
    "users","user","accounts","account","profile","profiles","settings","preferences","preferences.php",
    "register","signup","sign-up","forgot-password","reset-password","change-password","password-reset",
    "logout","signout","sign-out","oauth","oauth/authorize","oauth/token","saml","saml/login","sso",
    "search","search.php","find","query","report","reports","report.php","export","import","feed","rss",
    "errors","error","404","403","500","error.html","error.php",
    "node_modules","vendor","build","dist","coverage","target","out",
    "git","cvs","backup_db","backup-db","tmp/install.php","install","install.php","setup","setup.php","update.php",
]

@router.post("/api/recon/gobuster")
async def recon_gobuster_impl(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    found = []

    # Build soft-404 fingerprint from 3 randomized non-existent paths.
    # If the target uniformly returns 400 (Apache Host-mismatch on some lab
    # containers), retry with Host: localhost — real customer targets don't
    # need this fallback because their Host matches the URL.
    def _probe_set(extra_headers):
        results = []
        for i in range(3):
            probe_key = hashlib.sha1(f"{req.target}-{i}-vlfp".encode()).hexdigest()[:16]
            rp = safe_get(f"{base}/{probe_key}-nonexistent-zzz",
                          req=req, headers=extra_headers or {},
                          allow_redirects=False)
            if rp is None:
                continue
            loc = (rp.headers.get("Location", "") or "")[:200]
            results.append((rp.status_code, len(rp.content), loc))
        return results

    headers_used = {}
    fingerprints = _probe_set(headers_used)
    if fingerprints and all(s == 400 for s, _, _ in fingerprints):
        headers_used = {"Host": "localhost"}
        fingerprints = _probe_set(headers_used)

    if not fingerprints:
        return {"ok": False, "found": [], "skipped_reason": f"Could not reach {base}"}

    def _is_soft_404(status, length, loc):
        for fs, fl, floc in fingerprints:
            if status == fs and abs(length - fl) < 96 and loc == floc:
                return True
        return False

    wordlist = (_AI_PATHS or _COMMON_DIRS)
    for path in wordlist:
        r = safe_get(f"{base}/{path}", req=req,
                     headers=headers_used or {}, allow_redirects=False)
        if r is None:
            continue
        if r.status_code == 404:
            continue
        loc = (r.headers.get("Location", "") or "")[:200]
        if _is_soft_404(r.status_code, len(r.content), loc):
            continue
        hit = {"path": "/" + path, "status": r.status_code, "length": len(r.content)}
        if loc:
            hit["redirect_to"] = loc
        found.append(hit)

    return {
        "ok":                True,
        "found":             found,
        "tested":            len(wordlist),
        "fingerprint_probes": len(fingerprints),
        "host_override":     headers_used.get("Host"),
        "engine":            "python-fuzz (3-probe soft-404 baseline + Host fallback)",
    }



# VLERR-WRAP-V1
@router.post("/api/recon/gobuster")
async def recon_gobuster(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await recon_gobuster_impl(req, _)
    except Exception as _e:
        return {"ok": False,
                 "skipped_reason": f"gobuster scanner failed: {type(_e).__name__}: {str(_e)[:200]}",
                 "error": str(_e)[:300]}

def register(app):
    app.include_router(router)
