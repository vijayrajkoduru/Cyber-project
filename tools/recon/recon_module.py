"""Recon module — 24 endpoints under /api/recon/* matching the React UI.

Each endpoint accepts {target} POST body, returns a tool-specific
JSON shape that the existing frontend's ReconModule renders.
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

router = APIRouter()


# ── WHOIS ──────────────────────────────────────────────────────
@router.post("/api/recon/whois")
async def recon_whois(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        w = whois_lib.whois(host)
    except Exception as e:
        return {"ok": False, "skipped_reason": f"WHOIS query failed: {e}"}

    def _first(v):
        return v[0] if isinstance(v, list) and v else v

    def _iso(d):
        d = _first(d)
        if isinstance(d, datetime.datetime):
            return d.isoformat()
        return str(d) if d else None

    return {
        "ok": True,
        "domain": host,
        "registrar": _first(w.registrar),
        "created": _iso(w.creation_date),
        "expires": _iso(w.expiration_date),
        "updated": _iso(w.updated_date),
        "name_servers": sorted({str(n).lower() for n in (w.name_servers or [])}),
        "registrant": _first(w.registrant_name) or _first(w.org),
        "country": _first(w.country),
    }


# ── DNS Records (typed dict) ───────────────────────────────────
@router.post("/api/recon/dns")
async def recon_dns(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    records = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5
            ans = resolver.resolve(host, rtype)
            records[rtype] = [r.to_text() for r in ans]
        except Exception:
            pass
    if not records:
        return {"ok": False, "skipped_reason": "No DNS records found for this target (private/local IP)."}
    return {"ok": True, "records": records}


# ── DNS Recon (flat list, more shape) ──────────────────────────
@router.post("/api/recon/dnsrecon")
async def recon_dnsrecon(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    records = []
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5
            ans = resolver.resolve(host, rtype)
            for r in ans:
                records.append({"type": rtype, "name": host, "address": r.to_text()})
        except Exception:
            pass
    return {"ok": True, "records": records}


# ── Subdomains (kept; crtsh does the heavy lifting) ────────────
@router.post("/api/recon/subdomains")
async def recon_subdomains(req: ScanRequest, _=Depends(verify_scan_quota)):
    return {"ok": True, "subdomains": [],
            "skipped_reason": "Use crt.sh tile for CT-based subdomains."}


# ── crt.sh Certificate Transparency ────────────────────────────
@router.post("/api/recon/crtsh")
async def recon_crtsh(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{host}&output=json",
            timeout=20,
            headers={"User-Agent": "VulnusLab/1.0"},
        )
        if r.status_code != 200:
            return {"ok": False, "subdomains": [],
                    "skipped_reason": f"crt.sh returned {r.status_code}"}
        data = r.json()
    except Exception as e:
        return {"ok": False, "subdomains": [],
                "skipped_reason": f"crt.sh query failed: {e}"}

    subs = set()
    for entry in data:
        for line in str(entry.get("name_value", "")).split("\n"):
            line = line.strip().lower().lstrip("*.")
            if line and line.endswith(host):
                subs.add(line)
    return {"ok": True, "subdomains": sorted(subs)}


# ── Amass-equivalent: 6 passive sources + DNS brute force, all parallel ──
_BRUTE_WORDLIST = [
    "www","mail","ftp","smtp","pop","imap","webmail","remote","admin",
    "blog","shop","store","api","api-dev","api-staging","api-prod",
    "app","apps","dev","test","staging","stage","beta","alpha",
    "preview","demo","qa","uat","sandbox",
    "cdn","static","assets","media","img","images","files","uploads",
    "secure","ssl","vpn","git","gitlab","jenkins",
    "ci","monitor","grafana","kibana","prometheus",
    "db","database","mysql","postgres","mongo",
    "backup","old","new","v1","v2","v3","internal",
    "support","help","docs","wiki","portal","dashboard",
    "auth","sso","login","account",
    "cpanel","panel","phpmyadmin",
    "mobile","m",
    "ns1","ns2","ns3","ns4","mx","mx1","mx2",
]


async def _resolve_brute(host, prefix):
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        await resolver.resolve(f"{prefix}.{host}", "A")
        return f"{prefix}.{host}"
    except Exception:
        return None


@router.post("/api/recon/amass")
async def recon_amass(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    all_subs = set()
    sources_hit = {}
    sources_failed = {}

    def _add_subs(names, source):
        before = len(all_subs)
        for name in names:
            name = str(name).strip().lower().lstrip("*.")
            if name and name.endswith(host) and not name.startswith("*"):
                all_subs.add(name)
        sources_hit[source] = len(all_subs) - before

    # 1. crt.sh
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{host}&output=json", timeout=10,
                         headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            names = []
            for e in r.json():
                names.extend(str(e.get("name_value", "")).split("\n"))
            _add_subs(names, "crt.sh")
    except Exception as e:
        sources_failed["crt.sh"] = str(e)[:80]

    # 2. CertSpotter
    try:
        r = requests.get(
            f"https://api.certspotter.com/v1/issuances?domain={host}&include_subdomains=true&expand=dns_names",
            timeout=10, headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            names = []
            for e in r.json():
                names.extend(e.get("dns_names", []))
            _add_subs(names, "certspotter")
    except Exception as e:
        sources_failed["certspotter"] = str(e)[:80]

    # 3. JLDC / Anubis
    try:
        r = requests.get(f"https://jldc.me/anubis/subdomains/{host}", timeout=10,
                         headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            _add_subs(r.json(), "jldc_anubis")
    except Exception as e:
        sources_failed["jldc_anubis"] = str(e)[:80]

    # 4. AlienVault OTX
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/passive_dns",
            timeout=10, headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            names = [e.get("hostname", "") for e in r.json().get("passive_dns", [])]
            _add_subs(names, "alienvault_otx")
    except Exception as e:
        sources_failed["alienvault_otx"] = str(e)[:80]

    # 5. HackerTarget
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={host}", timeout=10,
                         headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200 and "API count exceeded" not in r.text:
            names = [line.split(",")[0] for line in r.text.splitlines()]
            _add_subs(names, "hackertarget")
        elif "API count exceeded" in (r.text or ""):
            sources_failed["hackertarget"] = "rate limit"
    except Exception as e:
        sources_failed["hackertarget"] = str(e)[:80]

    # 6. RapidDNS (HTML parse)
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{host}?full=1", timeout=10,
                         headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            import re as _re
            esc_host = _re.escape(host)
            names = _re.findall(r"<td>([a-z0-9.-]+\." + esc_host + r")</td>", r.text.lower())
            _add_subs(names, "rapiddns")
    except Exception as e:
        sources_failed["rapiddns"] = str(e)[:80]

    # 7. DNS brute force — parallel resolution of common subdomain prefixes
    try:
        results = await asyncio.gather(*[_resolve_brute(host, p) for p in _BRUTE_WORDLIST])
        brute_found = [r for r in results if r]
        for name in brute_found:
            all_subs.add(name)
        sources_hit["dns_brute"] = len(brute_found)
    except Exception as e:
        sources_failed["dns_brute"] = str(e)[:80]

    return {
        "ok": True,
        "subdomains": sorted(all_subs),
        "total_subdomains": len(all_subs),
        "sources": sources_hit,
        "sources_failed": sources_failed,
        "engine": "pure-Python (6 passive sources + DNS brute, parallel)",
    }


# ── theHarvester-equivalent: pattern gen + target scrape + Wayback + HackerTarget ──
_COMMON_EMAIL_PREFIXES = [
    "info","contact","admin","support","sales","security","webmaster",
    "noreply","no-reply","hello","mail","email","abuse","postmaster",
    "team","office","press","hr","careers","jobs","help","feedback",
    "marketing","privacy","legal","dpo","compliance",
]

_CONTACT_PAGES = [
    "","/contact","/contact-us","/about","/about-us","/team","/staff",
    "/people","/imprint","/legal","/privacy","/terms","/support",
]


@router.post("/api/recon/harvester")
async def recon_harvester(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    emails = set()
    hosts = set()
    sources_hit = {}
    sources_failed = {}
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

    # 1. Pattern generation — common business email prefixes for the domain
    pre_count = len(emails)
    for p in _COMMON_EMAIL_PREFIXES:
        emails.add(f"{p}@{host}")
    sources_hit["pattern_generation"] = len(emails) - pre_count

    # 2. Scrape target's own pages for real emails
    try:
        base = web_url(req.target).rstrip("/")
        pre_count = len(emails)
        for p in _CONTACT_PAGES:
            r = safe_get(base + p, req=req, allow_redirects=True)
            if r is not None and r.status_code == 200:
                for match in email_pattern.findall(r.text or ""):
                    m = match.lower()
                    if host in m or m.endswith(f".{host}"):
                        emails.add(m)
        sources_hit["target_scrape"] = len(emails) - pre_count
    except Exception as e:
        sources_failed["target_scrape"] = str(e)[:80]

    # 3. Wayback Machine — fetch archived homepage and extract emails
    try:
        wb = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={host}&output=json&limit=5&filter=statuscode:200",
            timeout=10, headers={"User-Agent": "VulnusLab/1.0"},
        )
        if wb.status_code == 200:
            rows = wb.json()
            pre_count = len(emails)
            for row in rows[1:3]:
                if len(row) >= 3:
                    archive_url = f"http://web.archive.org/web/{row[1]}/{row[2]}"
                    try:
                        ar = requests.get(archive_url, timeout=10,
                                          headers={"User-Agent": "VulnusLab/1.0"})
                        if ar.status_code == 200:
                            for match in email_pattern.findall(ar.text):
                                m = match.lower()
                                if host in m:
                                    emails.add(m)
                    except Exception:
                        continue
            sources_hit["wayback"] = len(emails) - pre_count
    except Exception as e:
        sources_failed["wayback"] = str(e)[:80]

    # 4. HackerTarget hostsearch for hosts (hostname + ip pairs)
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={host}",
            timeout=10, headers={"User-Agent": "VulnusLab/1.0"},
        )
        if r.status_code == 200 and "API count exceeded" not in r.text:
            pre_count = len(hosts)
            for line in r.text.splitlines():
                parts = line.split(",")
                if len(parts) >= 2:
                    hostname = parts[0].strip().lower()
                    if hostname.endswith(host):
                        hosts.add(hostname)
            sources_hit["hackertarget_hosts"] = len(hosts) - pre_count
        elif "API count exceeded" in (r.text or ""):
            sources_failed["hackertarget_hosts"] = "rate limit"
    except Exception as e:
        sources_failed["hackertarget_hosts"] = str(e)[:80]

    return {
        "ok": True,
        "emails": sorted(emails),
        "hosts": sorted(hosts),
        "total_emails": len(emails),
        "total_hosts": len(hosts),
        "sources": sources_hit,
        "sources_failed": sources_failed,
        "engine": "pure-Python (pattern gen + target scrape + Wayback + HackerTarget)",
    }


# ── Shodan (paid API; key from frontend body) ──────────────────
@router.post("/api/recon/shodan")
async def recon_shodan(req: ScanRequest, _=Depends(verify_scan_quota)):
    api_key = getattr(req, "api_key", "") or ""
    if not api_key:
        return {"ok": False, "skipped_reason": "No Shodan API key configured — set in Settings"}
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return {"ok": False, "skipped_reason": f"Could not resolve {host}"}
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=15)
        if r.status_code != 200:
            return {"ok": False, "skipped_reason": f"Shodan API returned {r.status_code}"}
        d = r.json()
        return {
            "ok": True, "ip": d.get("ip_str", ip), "org": d.get("org"),
            "isp": d.get("isp"), "country": d.get("country_name"),
            "city": d.get("city"), "os": d.get("os"),
            "ports": d.get("ports", []),
        }
    except Exception as e:
        return {"ok": False, "skipped_reason": f"Shodan query failed: {e}"}


# ── Port-scan helpers ──────────────────────────────────────────
_PORT_CATALOG = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
    135:"MS RPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",
    587:"SMTP-submit",993:"IMAPS",995:"POP3S",1433:"MSSQL",1521:"Oracle",
    2375:"Docker API",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5672:"AMQP",
    5900:"VNC",6379:"Redis",8000:"HTTP-alt",8080:"HTTP-proxy",8443:"HTTPS-alt",
    8888:"HTTP-alt",9200:"Elasticsearch",11211:"Memcached",15672:"RabbitMQ UI",
    27017:"MongoDB",
}


async def _tcp_probe(host, port, timeout=1.5):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _scan_open_ports(host):
    ports = sorted(_PORT_CATALOG.keys())
    results = await asyncio.gather(*[_tcp_probe(host, p) for p in ports])
    return [p for p, ok in zip(ports, results) if ok]


@router.post("/api/recon/masscan")
async def recon_masscan(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "ports": [], "skipped_reason": f"Could not resolve {host}: {e}"}
    open_ports = await _scan_open_ports(ip)
    return {"ok": True, "ip": ip,
            "ports": [{"port": p, "proto": "tcp", "state": "open"} for p in open_ports],
            "engine": "python-asyncio"}


@router.post("/api/recon/nmap")
async def recon_nmap(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "ports": [], "skipped_reason": f"Could not resolve {host}: {e}"}
    open_ports = await _scan_open_ports(ip)
    return {"ok": True, "ip": ip,
            "ports": [{"port": p, "proto": "tcp", "state": "open",
                       "service": _PORT_CATALOG.get(p, "unknown")} for p in open_ports],
            "engine": "python-asyncio"}


@router.post("/api/recon/services")
async def recon_services(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "ports": [], "skipped_reason": f"Could not resolve {host}: {e}"}
    open_ports = await _scan_open_ports(ip)
    return {"ok": True,
            "ports": [{"port": p, "service": _PORT_CATALOG.get(p, "unknown"),
                       "version": None} for p in open_ports]}


@router.post("/api/recon/os")
async def recon_os(req: ScanRequest, _=Depends(verify_scan_quota)):
    return {"ok": True, "os": None,
            "skipped_reason": "Active OS fingerprinting needs raw sockets (Kali nmap)."}


async def _grab_banner(host, port, timeout=3.0):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        if port in (80, 8000, 8080, 8443, 8888):
            writer.write(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


@router.post("/api/recon/banner")
async def recon_banner(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "banners": {}, "skipped_reason": f"Could not resolve {host}: {e}"}
    open_ports = await _scan_open_ports(ip)
    banners = {}
    for p in open_ports[:10]:
        b = await _grab_banner(ip, p)
        if b:
            banners[p] = b
    return {"ok": True, "banners": banners}


# ── Gobuster (pure-Python dir bruteforce) ──────────────────────
_COMMON_DIRS = [
    # admin / login portals
    "admin","administrator","admin.php","admin/login","admin/index","login","login.php","signin","cpanel",
    "wp-admin","wp-login.php","phpmyadmin","pma","adminer","myadmin","manage","management","manager",
    "panel","controlpanel","dashboard","moderator","webadmin","sysadmin",
    # config + secrets
    ".env",".env.local",".env.production",".env.development",".env.staging",".env.backup",
    "config.php","config.json","config.yaml","config.yml","config.xml","configuration.php",
    "settings.php","settings.json","settings.py","appsettings.json","web.config","wp-config.php",
    ".aws/credentials",".aws/config",".ssh/id_rsa",".ssh/authorized_keys",
    "secrets.json","secrets.yml","credentials.json","credentials.txt",
    # version control + IDE
    ".git/config",".git/HEAD",".git/index",".gitignore",".gitlab-ci.yml",".github/workflows",
    ".svn/entries",".svn/wc.db",".hg/hgrc",".bzr/README",".DS_Store",
    ".vscode/settings.json",".idea/workspace.xml",
    # backup files
    "backup","backup.zip","backup.tar.gz","backup.tar","backup.sql","backup.rar","backup.7z",
    "site-backup.zip","www.zip","html.zip","public.zip","sql.zip","db.sql","db.zip",
    "dump.sql","mysql.sql","postgres.sql","mongodump",
    "wp-config.php.bak","config.php.bak","config.php~","index.php.bak","index.html.bak",
    # info disclosure files
    "phpinfo.php","info.php","test.php","p.php","i.php","x.php","debug.php","trace.php",
    "server-status","server-info","status","stats","statistics","metrics","health","healthcheck",
    "ping","heartbeat","alive","ready","probe",
    # API + docs
    "api","api/v1","api/v2","api/v3","api/docs","api-docs","swagger","swagger.json","swagger-ui",
    "openapi.json","openapi.yaml","redoc","graphql","graphql-playground","graphiql",
    "rest","rest/v1","actuator","actuator/health","actuator/env","actuator/metrics",
    # dev/staging leaks
    "dev","development","staging","stage","beta","test","testing","preview","sandbox",
    "demo","tmp","temp","old","new","backup-old","internal","intranet",
    # uploads / file paths
    "uploads","upload","files","file","download","downloads","docs","documents",
    "images","img","media","assets","static","public","private","data",
    # WordPress paths
    "wp-content","wp-includes","wp-content/uploads","wp-content/plugins","wp-content/themes",
    "wp-content/debug.log","wp-content/backup-db",
    # Drupal/Joomla
    "sites/default","sites/default/files","sites/default/settings.php",
    "administrator/index.php","joomla","drupal",
    # well-known + standard
    "robots.txt","sitemap.xml","sitemap_index.xml","sitemap.xml.gz","humans.txt","ads.txt",
    ".well-known/security.txt",".well-known/openid-configuration",".well-known/change-password",
    # auth tokens / JWT
    ".htaccess",".htpasswd",".bash_history",".profile",".bashrc",
    # logs
    "logs","log","error.log","access.log","debug.log","application.log","app.log",
    # rare-but-juicy
    "phpunit.xml","composer.json","composer.lock","package.json","package-lock.json","yarn.lock",
    "Gemfile","Gemfile.lock","requirements.txt","Pipfile","Pipfile.lock","go.mod","go.sum",
    "Dockerfile","docker-compose.yml","Vagrantfile","Makefile",
    "README.md","README.txt","CHANGELOG.md","LICENSE","TODO.txt",
    "console","actuator","jolokia","prometheus","grafana",
]


@router.post("/api/recon/gobuster")
async def recon_gobuster(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    found = []
    baseline = safe_get(f"{base}/{hashlib.sha1(req.target.encode()).hexdigest()[:12]}-404probe", req=req)
    if baseline is None:
        return {"ok": False, "found": [], "skipped_reason": f"Could not reach {base}"}
    bs, bl = baseline.status_code, len(baseline.content)
    for path in _COMMON_DIRS:
        r = safe_get(f"{base}/{path}", req=req, allow_redirects=False)
        if r is None:
            continue
        if r.status_code != 404 and (r.status_code != bs or abs(len(r.content) - bl) > 64):
            found.append({"path": "/" + path, "status": r.status_code, "length": len(r.content)})
    return {"ok": True, "found": found, "engine": "python-fuzz"}


# ── JS endpoint extractor ──────────────────────────────────────
@router.post("/api/recon/jsendpoints")
async def recon_jsendpoints(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(base, req=req, allow_redirects=True)
    if r is None:
        return {"ok": False, "endpoints": [], "skipped_reason": f"Could not reach {base}"}
    js_urls = re.findall(r'src=["\']([^"\']+\.js)', r.text)
    endpoints = set()
    for js_url in js_urls[:5]:
        full = js_url if js_url.startswith("http") else f"{base}/{js_url.lstrip('/')}"
        rjs = safe_get(full, req=req)
        if rjs is None:
            continue
        for m in re.findall(r'["\']/(api/[a-zA-Z0-9_/.-]+)', rjs.text):
            endpoints.add("/" + m)
    return {"ok": True, "endpoints": sorted(endpoints), "js_files": len(js_urls)}


# ── Wayback Machine ────────────────────────────────────────────
@router.post("/api/recon/wayback")
async def recon_wayback(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        r = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={host}/*&output=json&limit=200",
            timeout=15,
        )
        if r.status_code != 200:
            return {"ok": False, "urls": [], "skipped_reason": f"Wayback returned {r.status_code}"}
        rows = r.json()
        urls = [row[2] for row in rows[1:]] if rows and len(rows) > 1 else []
        return {"ok": True, "urls": urls[:200]}
    except Exception as e:
        return {"ok": False, "urls": [], "skipped_reason": f"Wayback query failed: {e}"}


# ── robots.txt + sitemap.xml + .well-known ─────────────────────
@router.post("/api/recon/robotsmap")
async def recon_robotsmap(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    disallow, sitemaps, well_known = [], [], []
    r = safe_get(f"{base}/robots.txt", req=req)
    if r is not None and r.status_code == 200:
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                p = line.split(":", 1)[1].strip()
                if p:
                    disallow.append(p)
            elif line.lower().startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
    if not sitemaps:
        rs = safe_get(f"{base}/sitemap.xml", req=req)
        if rs is not None and rs.status_code == 200:
            sitemaps.append(f"{base}/sitemap.xml")
    sec = safe_get(f"{base}/.well-known/security.txt", req=req)
    if sec is not None and sec.status_code == 200:
        well_known.append("/.well-known/security.txt")
    return {"ok": True, "disallow": disallow, "sitemaps": sitemaps, "well_known": well_known}


# ── BFS crawler (depth 1, same-origin) ─────────────────────────
@router.post("/api/recon/crawl")
async def recon_crawl(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(base, req=req)
    if r is None:
        return {"ok": False, "urls": [], "skipped_reason": f"Could not reach {base}"}
    links = set()
    host = recon_host(req.target)
    for m in re.findall(r'href=["\']([^"\']+)["\']', r.text):
        if m.startswith("http"):
            if recon_host(m) == host:
                links.add(m)
        elif m.startswith("/"):
            links.add(base + m)
    return {"ok": True, "urls": sorted(links)[:50]}


# ── Parameter discovery ────────────────────────────────────────
@router.post("/api/recon/params")
async def recon_params(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(base, req=req)
    if r is None:
        return {"ok": False, "params": [], "skipped_reason": f"Could not reach {base}"}
    params = set()
    for m in re.findall(r'<input[^>]+name=["\']([^"\']+)', r.text, re.I):
        params.add(m)
    for m in re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{0,30})=', r.text):
        params.add(m)
    return {"ok": True, "params": sorted(params)[:100]}


# ── Favicon fingerprint ────────────────────────────────────────
@router.post("/api/recon/favicon")
async def recon_favicon(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(f"{base}/favicon.ico", req=req)
    if r is None or r.status_code != 200 or not r.content:
        return {"ok": True, "favicon": None, "skipped_reason": "No favicon found at /favicon.ico"}
    return {"ok": True,
            "favicon": {"md5": hashlib.md5(r.content).hexdigest(),
                        "size": len(r.content)}}


# ── Cloud buckets (S3 / GCS guess+probe) ──────────────────────
@router.post("/api/recon/cloudbuckets")
async def recon_cloudbuckets(req: ScanRequest, _=Depends(verify_scan_quota)):
    name = recon_host(req.target).split(".")[0]
    _suffixes = ["", "-prod", "-staging", "-dev", "-test", "-backup", "-backups",
                 "-uploads", "-files", "-data", "-assets", "-media", "-images",
                 "-public", "-private", "-internal", "-archive", "-logs"]
    candidates = []
    for sfx in _suffixes:
        bn = name + sfx
        candidates.append(f"https://{bn}.s3.amazonaws.com")
        candidates.append(f"https://s3.amazonaws.com/{bn}")
        candidates.append(f"https://storage.googleapis.com/{bn}")
        candidates.append(f"https://{bn}.blob.core.windows.net")
        candidates.append(f"https://{bn}.digitaloceanspaces.com")
    # Parallel async HEAD probes with short timeout — 90 candidates resolve in ~5s total
    async def _probe_bucket(url):
        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=4)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.head(url, allow_redirects=False) as r:
                    return (url, r.status)
        except Exception:
            return (url, None)
    results = await asyncio.gather(*[_probe_bucket(u) for u in candidates])
    existing, open_buckets = [], []
    for url, status in results:
        if status in (200, 403):
            existing.append({"url": url, "status": status})
            if status == 200:
                open_buckets.append(url)
    return {"ok": True, "existing": existing, "open": open_buckets, "tested": len(candidates)}


# ── JS Secret Scanner (tight high-confidence patterns only) ──
_SECRET_PATTERNS = [
    ("AWS Access Key",       r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key",       r"(?i)aws(.{0,20})?(secret|priv)?(.{0,20})?[\"\'][0-9a-zA-Z/+]{40}[\"\']"),
    ("Google API Key",       r"AIza[0-9A-Za-z_-]{35}"),
    ("Google OAuth",         r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("Slack Token",          r"xox[baprs]-[0-9a-zA-Z]{10,}"),
    ("Slack Webhook",        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("GitHub PAT (classic)", r"ghp_[0-9A-Za-z]{36}"),
    ("GitHub PAT (fine)",    r"github_pat_[0-9A-Za-z_]{82}"),
    ("GitHub OAuth",         r"gho_[0-9A-Za-z]{36}"),
    ("GitHub App Token",     r"(ghu|ghs)_[0-9A-Za-z]{36}"),
    ("Stripe Live",          r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Restricted",    r"rk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable",   r"pk_live_[0-9a-zA-Z]{24,}"),
    ("Mailgun API",          r"key-[0-9a-zA-Z]{32}"),
    ("SendGrid API",         r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"),
    ("Twilio Account SID",   r"AC[a-z0-9]{32}"),
    ("Twilio API Key",       r"SK[a-z0-9]{32}"),
    ("Heroku API",           r"(?i)heroku.{0,20}?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"),
    ("Dropbox API",          r"sl\.[A-Za-z0-9_-]{135,}"),
    ("Discord Bot Token",    r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
    ("Discord Webhook",      r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
    ("OpenAI API Key",       r"sk-[A-Za-z0-9]{48}"),
    ("Anthropic API Key",    r"sk-ant-[A-Za-z0-9-_]{90,}"),
    ("Square OAuth",         r"sq0atp-[0-9A-Za-z-_]{22}"),
    ("RSA Private Key",      r"-----BEGIN RSA PRIVATE KEY-----"),
    ("SSH Private Key",      r"-----BEGIN (OPENSSH|DSA|EC|PGP) PRIVATE KEY-----"),
    ("JWT Token",            r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    ("Basic Auth in URL",    r"https?://[^/\s:@]+:[^/\s:@]{4,}@[^/\s]+"),
]


@router.post("/api/recon/secrets")
async def recon_secrets(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(base, req=req, allow_redirects=True)
    if r is None:
        return {"ok": False, "secrets": [], "skipped_reason": f"Could not reach {base}"}
    js_urls = re.findall(r'src=["\']([^"\']+\.js)', r.text)
    secrets, js_count = [], 0
    for js_url in js_urls[:5]:
        full = js_url if js_url.startswith("http") else f"{base}/{js_url.lstrip('/')}"
        rjs = safe_get(full, req=req)
        if rjs is None:
            continue
        js_count += 1
        for name, pattern in _SECRET_PATTERNS:
            for m in re.finditer(pattern, rjs.text):
                secrets.append({"type": name, "match": m.group(0)[:60], "file": full})
    return {"ok": True, "secrets": secrets, "js_files": js_count}


# ── ASN / IP Ownership ─────────────────────────────────────────
@router.post("/api/recon/asn")
async def recon_asn(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "skipped_reason": f"Could not resolve {host}: {e}"}
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if r.status_code != 200:
            return {"ok": False, "skipped_reason": f"ipinfo returned {r.status_code}"}
        d = r.json()
        return {"ok": True, "ip": ip, "asn": d.get("org", ""),
                "country": d.get("country"), "city": d.get("city"),
                "region": d.get("region"), "hostname": d.get("hostname")}
    except Exception as e:
        return {"ok": False, "skipped_reason": f"ASN lookup failed: {e}"}


# ── Free Shodan via InternetDB (no API key) ────────────────────
@router.post("/api/recon/internetdb")
async def recon_internetdb(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "skipped_reason": f"Could not resolve {host}: {e}"}
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if r.status_code == 404:
            return {"ok": True, "ip": ip, "skipped_reason": "No InternetDB record for this IP"}
        if r.status_code != 200:
            return {"ok": False, "skipped_reason": f"InternetDB returned {r.status_code}"}
        d = r.json()
        return {"ok": True, "ip": ip,
                "ports": d.get("ports", []), "cves": d.get("vulns", []),
                "hostnames": d.get("hostnames", []), "tags": d.get("tags", [])}
    except Exception as e:
        return {"ok": False, "skipped_reason": f"InternetDB query failed: {e}"}


# ── Subdomain Takeover Detection ──────────────────────────────
_TAKEOVER_SIGS = [
    ("github.io",                "There isn't a GitHub Pages site here",   "CRITICAL", "GitHub Pages"),
    ("s3.amazonaws.com",         "NoSuchBucket",                            "CRITICAL", "AWS S3"),
    ("herokuapp.com",            "No such app",                             "CRITICAL", "Heroku"),
    ("bitbucket.io",             "Repository not found",                    "CRITICAL", "Bitbucket"),
    ("tumblr.com",               "Whatever you were looking for",           "CRITICAL", "Tumblr"),
    ("wordpress.com",            "Do you want to register",                 "CRITICAL", "WordPress"),
    ("surge.sh",                 "project not found",                       "CRITICAL", "Surge.sh"),
    ("myshopify.com",            "Sorry, this shop is currently unavailable", "CRITICAL", "Shopify"),
    ("fastly.net",               "Fastly error: unknown domain",            "CRITICAL", "Fastly"),
    ("ghost.io",                 "The thing you were looking for is no longer here", "CRITICAL", "Ghost"),
    ("helpscoutdocs.com",        "No settings were found for this company", "CRITICAL", "Help Scout"),
    ("readme.io",                "Project doesnt exist",                    "CRITICAL", "Readme.io"),
    ("pingdom.com",              "Public Report Not Activated",             "HIGH",     "Pingdom"),
    ("getresponse.com",          "Unrecognized domain",                     "HIGH",     "GetResponse"),
    ("teamwork.com",             "Oops - We didn't find your site",         "HIGH",     "Teamwork"),
    ("wpengine.com",             "The site you were looking for",           "HIGH",     "WPEngine"),
    ("cargo.site",               "404 Not Found",                           "HIGH",     "Cargo"),
    ("strikinglydns.com",        "PAGE NOT FOUND",                          "HIGH",     "Strikingly"),
    ("tilda.ws",                 "Please renew your subscription",          "HIGH",     "Tilda"),
    ("uberflip.com",             "Non-Hub domain",                          "HIGH",     "Uberflip"),
    ("ngrok.io",                 "Tunnel .* not found",                     "HIGH",     "Ngrok"),
    ("pantheonsite.io",          "The gods are wise",                       "HIGH",     "Pantheon"),
    ("cloudfront.net",           "Bad request",                             "MEDIUM",   "CloudFront"),
    ("elasticbeanstalk.com",     "404 Not Found",                           "MEDIUM",   "Elastic Beanstalk"),
    ("azurewebsites.net",        "404 Web Site not found",                  "MEDIUM",   "Azure WebSites"),
]


async def _check_takeover(subdomain):
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        try:
            ans = await resolver.resolve(subdomain, "CNAME")
            cname = str(ans[0].target).rstrip(".").lower()
        except Exception:
            return None
        for pattern, fp, severity, service in _TAKEOVER_SIGS:
            if pattern in cname:
                try:
                    r = requests.get(
                        f"http://{subdomain}", timeout=8, allow_redirects=True,
                        headers={"User-Agent": "VulnusLab/1.0"},
                    )
                    body = (r.text or "")[:5000]
                    if fp.lower() in body.lower() or re.search(fp, body, re.I):
                        return {
                            "subdomain": subdomain, "cname": cname,
                            "service": service, "severity": severity,
                            "fingerprint": fp, "status_code": r.status_code,
                        }
                except Exception:
                    pass
        return None
    except Exception:
        return None


@router.post("/api/recon/subdomain_takeover")
async def recon_subdomain_takeover(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    all_subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{host}&output=json", timeout=15,
                         headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            for entry in r.json():
                for line in str(entry.get("name_value", "")).split("\n"):
                    line = line.strip().lower().lstrip("*.")
                    if line and line.endswith(host) and not line.startswith("*"):
                        all_subs.add(line)
    except Exception:
        pass
    all_subs.add(host)
    subs_to_check = sorted(all_subs)[:150]
    if not subs_to_check:
        return {"ok": True, "vulnerable": [], "checked": 0,
                "skipped_reason": "No subdomains discovered",
                "engine": "pure-Python (CNAME + HTTP fingerprint)"}
    results = await asyncio.gather(*[_check_takeover(s) for s in subs_to_check])
    vulnerable = [v for v in results if v is not None]
    return {
        "ok": True, "vulnerable": vulnerable,
        "total_vulnerable": len(vulnerable), "checked": len(subs_to_check),
        "services_checked": len(_TAKEOVER_SIGS),
        "engine": f"pure-Python (CNAME + HTTP fingerprint, {len(_TAKEOVER_SIGS)} services)",
    }


# ── WAF / CDN Fingerprint ─────────────────────────────────────
_WAF_CDN_SIGS = [
    ("Cloudflare",             "CDN+WAF",  [("header:server", r"^cloudflare"), ("header:cf-ray", r".+"), ("cookie:__cf_bm", r".+")]),
    ("AWS CloudFront",         "CDN",      [("header:server", r"^CloudFront"), ("header:x-amz-cf-id", r".+"), ("header:via", r"CloudFront")]),
    ("Akamai",                 "CDN+WAF",  [("header:server", r"AkamaiGHost"), ("header:x-akamai-transformed", r".+")]),
    ("Fastly",                 "CDN",      [("header:fastly-debug-path", r".+"), ("header:x-served-by", r"^cache-"), ("header:x-fastly", r".+")]),
    ("Imperva Incapsula",      "WAF",      [("header:x-cdn", r"Incapsula"), ("cookie:visid_incap", r".+"), ("cookie:incap_ses", r".+")]),
    ("Sucuri CloudProxy",      "WAF",      [("header:server", r"Sucuri"), ("header:x-sucuri-id", r".+"), ("header:x-sucuri-cache", r".+")]),
    ("F5 BIG-IP ASM",          "WAF",      [("cookie:bigipserver", r".+"), ("cookie:ts[0-9a-f]+", r".+"), ("header:x-wa-info", r".+")]),
    ("Citrix NetScaler",       "WAF",      [("header:via", r"NS-CACHE"), ("cookie:ns_af", r".+"), ("cookie:citrix_ns_id", r".+")]),
    ("Barracuda",              "WAF",      [("header:server", r"^barra"), ("cookie:barra_counter_session", r".+")]),
    ("Fortinet FortiWeb",      "WAF",      [("header:server", r"FortiWeb"), ("cookie:fortiwafsid", r".+")]),
    ("StackPath",              "CDN",      [("header:server", r"StackPath"), ("header:x-cdn", r"stackpath")]),
    ("DDoS-Guard",             "WAF",      [("header:server", r"ddos-guard"), ("cookie:__ddg", r".+")]),
    ("Edgio (Verizon)",        "CDN",      [("header:server", r"^ECS"), ("header:x-ec-debug", r".+"), ("header:x-edgio-cache", r".+")]),
    ("Distil Networks",        "WAF",      [("header:x-distil-cs", r".+")]),
    ("Yundun (Aliyun)",        "WAF",      [("header:server", r"Yundun"), ("cookie:yd_cookie", r".+")]),
    ("Aliyun OSS",             "CDN",      [("header:server", r"AliyunOSS")]),
    ("Reblaze",                "WAF",      [("header:x-reblaze", r".+"), ("cookie:rbzid", r".+")]),
    ("Sangfor",                "WAF",      [("header:x-sf-", r".+")]),
    ("Wallarm",                "WAF",      [("header:server", r"nginx-wallarm"), ("header:x-wallarm-flag", r".+")]),
    ("Wordfence",              "WAF",      [("header:server", r"^wordfence"), ("body", r"Generated by Wordfence")]),
    ("ModSecurity",            "WAF",      [("header:server", r"Mod_Security|NOYB"), ("header:x-mod-security", r".+")]),
    ("NAXSI",                  "WAF",      [("header:x-data-origin", r"naxsi")]),
    ("Squid Proxy",            "Proxy",    [("header:server", r"^squid"), ("header:x-squid-error", r".+")]),
    ("Varnish",                "CDN",      [("header:server", r"^Varnish"), ("header:via", r"varnish"), ("header:x-varnish", r".+")]),
    ("Bunny.net",              "CDN",      [("header:server", r"BunnyCDN"), ("header:cdn-pullzone", r".+")]),
    ("KeyCDN",                 "CDN",      [("header:server", r"keycdn"), ("header:x-cache", r"keycdn")]),
    ("CDN77",                  "CDN",      [("header:server", r"CDN77"), ("header:x-77-cache", r".+")]),
    ("Tencent Cloud",          "CDN",      [("header:server", r"tencent|tcloud"), ("header:x-nws-log-uuid", r".+")]),
    ("Baidu Yunjiasu",         "WAF",      [("header:server", r"yunjiasu"), ("header:x-yunjiasu", r".+")]),
    ("Microsoft Azure Front Door", "CDN",  [("header:x-azure-ref", r".+"), ("header:x-azure-fdid", r".+")]),
    ("Google Frontend",        "CDN",      [("header:server", r"^gws$|gfe"), ("header:via", r"google")]),
    ("CacheFly",               "CDN",      [("header:server", r"CacheFly"), ("header:x-cf-cache", r".+")]),
    ("Section.io",             "CDN",      [("header:section-io-id", r".+")]),
    ("Limelight",              "CDN",      [("header:server", r"Limelight"), ("header:x-llnw", r".+")]),
    ("Sucuri (legacy)",        "WAF",      [("header:server", r"Sucuri/Cloudproxy")]),
    ("PerimeterX",             "WAF",      [("header:server", r"^px"), ("cookie:_px", r".+"), ("body", r"perimeterx")]),
    ("Datadome",               "WAF",      [("header:server", r"DataDome"), ("cookie:datadome", r".+")]),
    ("Kona Site Defender",     "WAF",      [("header:server", r"Kona"), ("header:x-akamai-rate-control", r".+")]),
    ("AWS WAF",                "WAF",      [("header:x-amzn-trace-id", r"Root="), ("header:x-amz-rid", r".+"), ("body", r"AWS WAF|Request blocked")]),
    ("Google Cloud Armor",     "WAF",      [("header:via", r"^[\d.]+ google"), ("body", r"Google Cloud Armor")]),
]


@router.post("/api/recon/waf_cdn")
async def recon_waf_cdn(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    r = safe_get(url, req=req, allow_redirects=True)
    if r is None:
        return {"ok": False, "detected": [], "skipped_reason": f"Could not reach {url}",
                "engine": "pure-Python (40 signatures)"}

    headers_lower = {k.lower(): str(v) for k, v in r.headers.items()}
    cookies_lower = {c.name.lower(): c.value for c in r.cookies}
    body = (r.text or "")[:50000]

    detected = []
    for vendor, category, checks in _WAF_CDN_SIGS:
        matched_check = None
        for field, pattern in checks:
            if field.startswith("header:"):
                hname = field.split(":", 1)[1].lower()
                for hk, hv in headers_lower.items():
                    if hk == hname or (hname.endswith("-") and hk.startswith(hname)):
                        if re.search(pattern, hv, re.I):
                            matched_check = f"{field}: {hv[:60]}"
                            break
                if matched_check: break
            elif field.startswith("cookie:"):
                cname = field.split(":", 1)[1].lower()
                for ck, cv in cookies_lower.items():
                    if ck == cname or (cname.endswith("-") and ck.startswith(cname)):
                        matched_check = f"{field}: {(cv or '')[:40] if cv else 'set'}"
                        break
                if matched_check: break
            elif field == "body":
                if re.search(pattern, body, re.I):
                    matched_check = f"body matched: {pattern[:40]}"
                    break
        if matched_check:
            detected.append({"vendor": vendor, "category": category, "evidence": matched_check})

    return {
        "ok": True,
        "detected": detected,
        "total_detected": len(detected),
        "signatures_checked": len(_WAF_CDN_SIGS),
        "engine": f"pure-Python (passive: headers + cookies + body, {len(_WAF_CDN_SIGS)} signatures)",
    }


def register(app):
    app.include_router(router)
