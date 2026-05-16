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


# ── DNS Records (typed dict) ───────────────────────────────────


# ── DNS Recon (flat list, more shape) ──────────────────────────


# ── Subdomains: active DNS brute force (~250 high-signal prefixes) ──
_SUB_BRUTE_WORDLIST = [
    "www","mail","ftp","smtp","pop","imap","webmail","remote","ns1","ns2","ns3","ns4","ns5",
    "mx","mx1","mx2","mx3","dns","dns1","dns2","ldap",
    "dev","test","staging","stage","stg","beta","alpha","preview","demo","sandbox","qa","uat",
    "lab","labs","internal","intranet","preprod","pre-prod","production","prod",
    "admin","administrator","panel","cpanel","phpmyadmin","pma","auth","sso","login",
    "account","accounts","signup","register","oauth","saml","openid",
    "app","apps","application","api","api-v1","api-v2","api-v3","api1","api2","api3",
    "api-dev","api-staging","api-prod","api-internal","api-public","api-gateway",
    "cdn","static","assets","media","img","images","files","downloads","upload","uploads","videos","video",
    "m","mobile","wap","iphone","android",
    "us","uk","eu","asia","na","sa","africa","au","us-east","us-west","eu-west","eu-east","ap-south",
    "blog","shop","store","forum","wiki","kb","support","help","docs","documentation","portal",
    "dashboard","console","status","stats","metrics","monitor","monitoring",
    "git","gitlab","github","bitbucket","jenkins","ci","cd","build","deploy","registry","docker",
    "k8s","kubernetes","grafana","kibana","prometheus","alertmanager","sentry","datadog","splunk",
    "db","database","mysql","postgres","postgresql","mongo","mongodb","redis","memcache",
    "memcached","elasticsearch","es","cassandra",
    "vpn","secure","ssl","tls","ssh","rdp",
    "intra","ext","external","partners","partner","vendor","vendors","ticket","tickets","helpdesk",
    "news","ads","tracker","tracking","analytics","marketing","campaign","campaigns","newsletter",
    "checkout","payment","payments","billing","invoice","invoices","subscription","subscriptions",
    "hr","careers","jobs","recruiting","talent","ops","devops","sre","noc","soc",
    "email","mailing","outbound","smtp1","smtp2","mail2","webmail2","outlook",
    "old","new","legacy","v1","v2","v3","next","deprecated","archive","archives",
    "drupal","joomla","wordpress","wp",
    "auth-internal","auth-service","user-service","user-api","account-service","billing-service",
    "payment-service","order-service","search-service","notification-service","metrics-service",
    "server","server1","server2","host","host1","host2","node1","node2","node3","node4",
    "aws","gcp","azure","cloud","compute",
    "crm","sales","erp","salesforce","hubspot",
    "client","clients","customer","customers","user","users","guest","anonymous","public","private","vip",
    "security","audit","compliance","vault","keyvault",
    "it","tech","engineering","eng","dev-team",
    "feed","feeds","rss","atom",
    "proxy","gateway","router","firewall","fw","switch","ap","wifi",
    "loadbalancer","lb","haproxy","nginx","apache","iis",
    "elk","logstash","fluentd","rabbitmq","kafka","zookeeper","nats","consul","etcd","minio",
    "pci","stripe","paypal","square",
]


async def _resolve_sub_brute(host, prefix):
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        ans = await resolver.resolve(f"{prefix}.{host}", "A")
        return (f"{prefix}.{host}", str(ans[0]))
    except Exception:
        return None




# ── crt.sh Certificate Transparency ────────────────────────────


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




# ── Shodan (paid API; key from frontend body) ──────────────────


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










async def _grab_banner(host, port, timeout=3.0):
    is_https = port in (443, 8443)
    is_http  = port in (80, 8000, 8080, 8888) or is_https
    try:
        if is_https:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout,
            )
        if is_http:
            req = (f"GET / HTTP/1.0\r\n"
                   f"Host: {host}\r\n"
                   f"User-Agent: VulnusLab/1.0\r\n"
                   f"Accept: */*\r\n\r\n").encode()
            writer.write(req)
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
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




# ── Gobuster (pure-Python dir bruteforce) ──────────────────────
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




# ── JS endpoint extractor ──────────────────────────────────────


# ── Wayback Machine ────────────────────────────────────────────


# ── robots.txt + sitemap.xml + .well-known ─────────────────────


# ── BFS crawler (depth-3 recursive, same-origin, parallel async) ──
import aiohttp as _aiohttp_crawl

_INTERESTING_CRAWL = ["admin","login","config","backup","test","internal",
                       ".env",".git","api","swagger","console","dashboard","setup"]




# ── Parameter discovery — regex extract + Arjun-style reflection probe ──
_COMMON_PARAMS = [
    "id","user","username","page","query","search","q","url","redirect","return","next","filename",
    "file","path","name","email","type","category","action","method","token","key","api_key","auth",
    "session","sid","lang","locale","language","country","region","format","view","tab","sort","order",
    "limit","offset","start","end","from","to","since","until","date","callback","jsonp","output","debug",
    "test","admin","cmd","command","exec","system","data","value","param","arg","input","content",
    "title","message","comment","body","subject","ref","source","src","dest","destination",
]





def _murmur3_32(data, seed=0):
    """Pure-Python MurmurHash3 32-bit (Shodan favicon hash format)."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed
    rounded_end = (length // 4) * 4
    for i in range(0, rounded_end, 4):
        k1 = (data[i] & 0xff) | ((data[i+1] & 0xff) << 8) | ((data[i+2] & 0xff) << 16) | (data[i+3] << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = (((k1 << 15) | (k1 >> 17)) * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = length & 3
    if tail >= 3: k1 = (data[rounded_end + 2] & 0xff) << 16
    if tail >= 2: k1 |= (data[rounded_end + 1] & 0xff) << 8
    if tail >= 1:
        k1 |= (data[rounded_end] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = (((k1 << 15) | (k1 >> 17)) * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)
    if h1 >= 0x80000000:
        h1 = -(0x100000000 - h1)
    return h1


# ── Favicon fingerprint ────────────────────────────────────────


# ── Cloud buckets (S3 / GCS guess+probe) ──────────────────────


# ── JS Secret Scanner (tight high-confidence patterns only) ──
_SECRET_PATTERNS = [
    ("AWS Access Key",        r"AKIA[0-9A-Z]{16}"),
    ("AWS Session Token",     r"FQoG[A-Za-z0-9/+=]{50,}"),
    ("AWS Secret (in JS)",    r"(?i)aws(.{0,20})?(secret|priv|key)?(.{0,20})?[\"\'][0-9a-zA-Z/+]{40}[\"\']"),
    ("Google API Key",        r"AIza[0-9A-Za-z_-]{35}"),
    ("Google OAuth",          r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("Google Cloud Service Account", r"\"type\":\s*\"service_account\""),
    ("Firebase URL",          r"[a-z0-9.-]+\.firebaseio\.com"),
    ("Slack Token",           r"xox[baprs]-[0-9a-zA-Z]{10,}"),
    ("Slack Webhook",         r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("GitHub PAT (classic)",  r"ghp_[0-9A-Za-z]{36}"),
    ("GitHub PAT (fine)",     r"github_pat_[0-9A-Za-z_]{82}"),
    ("GitHub OAuth",          r"gho_[0-9A-Za-z]{36}"),
    ("GitHub App Token",      r"(ghu|ghs)_[0-9A-Za-z]{36}"),
    ("GitHub Refresh",        r"ghr_[0-9A-Za-z]{76}"),
    ("GitLab PAT",            r"glpat-[0-9a-zA-Z_-]{20}"),
    ("Bitbucket Client ID",   r"(?i)bitbucket(.{0,20})?[\"\'][0-9a-zA-Z]{32}[\"\']"),
    ("Stripe Live Secret",    r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Restricted",     r"rk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable",    r"pk_live_[0-9a-zA-Z]{24,}"),
    ("PayPal Braintree",      r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    ("Square OAuth",          r"sq0atp-[0-9A-Za-z-_]{22}"),
    ("Square Access Token",   r"sq0csp-[0-9A-Za-z-_]{43}"),
    ("Mailgun API",           r"key-[0-9a-zA-Z]{32}"),
    ("Mailchimp API",         r"[0-9a-f]{32}-us[0-9]{1,2}"),
    ("SendGrid API",          r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"),
    ("Twilio Account SID",    r"AC[a-z0-9]{32}"),
    ("Twilio API Key SID",    r"SK[a-z0-9]{32}"),
    ("Heroku API",            r"(?i)heroku.{0,20}?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"),
    ("Dropbox Long Token",    r"sl\.[A-Za-z0-9_-]{135,}"),
    ("Dropbox API",           r"(?i)dropbox.{0,20}?[a-z0-9]{15}"),
    ("Discord Bot Token",     r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
    ("Discord Webhook",       r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
    ("OpenAI API Key",        r"sk-[A-Za-z0-9]{48}"),
    ("OpenAI Project Key",    r"sk-proj-[A-Za-z0-9_-]{40,}"),
    ("Anthropic API Key",     r"sk-ant-[A-Za-z0-9-_]{90,}"),
    ("Hugging Face Token",    r"hf_[A-Za-z0-9]{30,}"),
    ("RSA Private Key",       r"-----BEGIN RSA PRIVATE KEY-----"),
    ("SSH Private Key",       r"-----BEGIN (OPENSSH|DSA|EC|PGP) PRIVATE KEY-----"),
    ("PKCS8 Private Key",     r"-----BEGIN PRIVATE KEY-----"),
    ("Encrypted Private Key", r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    ("Certificate",           r"-----BEGIN CERTIFICATE-----"),
    ("JWT Token",             r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    ("Basic Auth in URL",     r"https?://[^/\s:@]+:[^/\s:@]{4,}@[^/\s]+"),
    ("MongoDB URI",           r"mongodb(\+srv)?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("MySQL URI",             r"mysql://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("PostgreSQL URI",        r"postgres(ql)?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("Redis URI w/ pass",     r"redis://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("Datadog API Key",       r"(?i)datadog.{0,20}?[a-z0-9]{32}"),
    ("New Relic API Key",     r"NRAK-[A-Z0-9]{27}"),
    ("PagerDuty Service",     r"pdus[+_]?[0-9a-zA-Z]{32}"),
    ("Splunk Token",          r"splunk_[a-zA-Z0-9]{32}"),
    ("Atlassian API Token",   r"(?i)atlassian.{0,20}?[a-z0-9]{24}"),
    ("Algolia API Key",       r"(?i)algolia.{0,20}?[a-zA-Z0-9]{32}"),
    ("Cloudflare API Key",    r"(?i)cloudflare.{0,20}?[a-f0-9]{37}"),
    ("Cloudflare API Token",  r"(?i)cloudflare.{0,20}?[A-Za-z0-9_]{40,}"),
    ("Vercel Token",          r"(?i)vercel.{0,20}?[A-Za-z0-9]{24}"),
    ("Netlify Token",         r"(?i)netlify.{0,20}?[A-Za-z0-9_-]{38}"),
    ("npm Token",             r"npm_[A-Za-z0-9]{36}"),
    ("PyPI Token",            r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+"),
    ("Sentry DSN w/ secret",  r"https://[a-f0-9]+:[a-f0-9]+@[a-z0-9-]+\.ingest\.sentry\.io"),
    ("Asana Token",           r"(?i)asana.{0,20}?[0-9]/[0-9]{16,}:[a-z0-9]{32}"),
    ("Linear API Key",        r"lin_api_[A-Za-z0-9]{40}"),
    ("Notion API Token",      r"secret_[A-Za-z0-9]{43}"),
    ("Airtable API Key",      r"key[A-Za-z0-9]{14}"),
    ("Airtable PAT",          r"pat[A-Za-z0-9]{14}\.[a-f0-9]{64}"),
    ("Shopify API Token",     r"shpat_[a-f0-9]{32}"),
    ("Shopify Custom App",    r"shpca_[a-f0-9]{32}"),
    ("Shopify Shared Secret", r"shpss_[a-f0-9]{32}"),
    ("WordPress API Key",     r"(?i)wp-api.{0,20}?[a-zA-Z0-9]{32}"),
    ("CircleCI Token",        r"(?i)circle-token.{0,5}[a-f0-9]{40}"),
    ("Buildkite API",         r"(?i)buildkite.{0,20}?[a-z0-9]{40}"),
    ("Snyk API Key",          r"(?i)snyk.{0,20}?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("Postman API Key",       r"PMAK-[a-f0-9]{24}-[a-f0-9]{34}"),
    ("Telegram Bot Token",    r"[0-9]{8,10}:AA[A-Za-z0-9_-]{33}"),
    ("Adafruit IO Key",       r"(?i)adafruit.{0,20}?[a-z0-9]{32}"),
    ("DigitalOcean PAT",      r"dop_v1_[a-f0-9]{64}"),
    ("Linode API Token",      r"(?i)linode.{0,20}?[a-f0-9]{64}"),
    ("Hetzner API Token",     r"(?i)hcloud.{0,20}?[a-zA-Z0-9]{64}"),
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




# ── ASN / IP Ownership ─────────────────────────────────────────


# ── Free Shodan via InternetDB (no API key) ────────────────────


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
    ("agilecrm.com",             "Sorry, this page is no longer available",  "HIGH",     "Agile CRM"),
    ("activecampaign.com",       "Trying to access your account",             "HIGH",     "ActiveCampaign"),
    ("acquia-sites.com",         "The site you are looking for could not be found", "HIGH", "Acquia"),
    ("aftership.com",            "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist", "HIGH", "AfterShip"),
    ("animaapp.io",              "Oops, this page may have been moved or deleted", "MEDIUM", "Anima"),
    ("apigee.net",               "404 Not Found",                              "MEDIUM",   "Apigee"),
    ("aws.amazon.com/apprunner", "The page you are looking for cannot be found", "HIGH",   "AWS App Runner"),
    ("bigcartel.com",            "Oops! We couldn't find that page",          "HIGH",     "Big Cartel"),
    ("brightcove.net",           "Brightcove Error",                          "MEDIUM",   "Brightcove"),
    ("campaignmonitor.com",      "Double check the URL or",                   "HIGH",     "Campaign Monitor"),
    ("canny.io",                 "Company Not Found",                         "HIGH",     "Canny"),
    ("createsend.com",           "Domain has been disabled by the administrator", "HIGH", "Campaign Monitor (sendgrid)"),
    ("desk.com",                 "Sorry, We Couldn't Find That Page",         "HIGH",     "Desk"),
    ("flywheelsites.com",        "We're sorry, you've landed on a page that is hosted by Flywheel", "HIGH", "Flywheel"),
    ("freshdesk.com",            "May be this is still fresh!",               "HIGH",     "Freshdesk"),
    ("hatena.ne.jp",             "404 Blog is not found",                     "HIGH",     "Hatena Blog"),
    ("intercom.help",            "This page is reserved for artistic use",    "HIGH",     "Intercom"),
    ("kinsta.com",               "No Site For Domain",                        "HIGH",     "Kinsta"),
    ("launchrock.com",           "It looks like you may have taken a wrong turn",  "HIGH",  "LaunchRock"),
    ("mashery.com",              "Unrecognized domain",                       "HIGH",     "Mashery"),
    ("netlify.app",              "Not Found - Request ID:",                   "HIGH",     "Netlify"),
    ("ngrok.io",                 "Tunnel .* not found",                       "HIGH",     "Ngrok"),
    ("smartling.com",            "Domain is not configured",                  "HIGH",     "Smartling"),
    ("surveysparrow.com",        "Account not found",                         "HIGH",     "SurveySparrow"),
    ("thinkific.com",            "You may have mistyped the address",         "HIGH",     "Thinkific"),
    ("unbouncepages.com",        "The requested URL was not found on this server", "HIGH","Unbounce"),
    ("vend.com",                 "Looks like you've traveled too far into cyberspace", "HIGH", "Vend"),
    ("vercel.app",               "404: NOT_FOUND",                            "HIGH",     "Vercel"),
    ("webflow.io",               "The page you are looking for doesn't exist",  "HIGH",   "Webflow"),
    ("worksites.net",            "Hello! Sorry, but the webpage you requested",  "HIGH",  "Worksites"),
    ("zendesk.com",              "Help Center Closed",                        "HIGH",     "Zendesk"),
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
    ("Mod_Security (CRS)",     "WAF",      [("header:x-mod-security", r".+"), ("body", r"Mod_Security|NOYB")]),
    ("Anquanbao",              "WAF",      [("header:x-powered-by-anquanbao", r".+")]),
    ("BitNinja",               "WAF",      [("body", r"BitNinja|Security check by BitNinja")]),
    ("Bluedon IST",            "WAF",      [("header:server", r"bluedon")]),
    ("Comodo cWatch",          "WAF",      [("header:server", r"Protected by COMODO WAF")]),
    ("DOSarrest",              "WAF",      [("header:server", r"DOSarrest"), ("header:x-dis-request-id", r".+")]),
    ("DotDefender",            "WAF",      [("header:x-dotdefender-denied", r".+")]),
    ("eEye Digital Security",  "WAF",      [("header:server", r"SecureIIS")]),
    ("Greywizard",             "WAF",      [("header:server", r"greywizard")]),
    ("HyperGuard",             "WAF",      [("cookie:wlsessionkey", r".+")]),
    ("InstartLogic",           "WAF",      [("header:x-instart-request-id", r".+")]),
    ("ISA Server",             "WAF",      [("body", r"isaserror\.htm|Forefront TMG")]),
    ("Jiasule",                "WAF",      [("header:server", r"jiasule"), ("cookie:jsluid", r".+")]),
    ("KSWebShield",            "WAF",      [("header:server", r"KSWebShield")]),
    ("Mission Control",        "WAF",      [("header:server", r"Mission Control Application Shield")]),
    ("NetContinuum",           "WAF",      [("cookie:nci__sessionid", r".+")]),
    ("NewDefend",              "WAF",      [("header:server", r"NewDefend")]),
    ("NSFOCUS",                "WAF",      [("header:server", r"NSFocus")]),
    ("Powerful Firewall",      "WAF",      [("body", r"Powerful Firewall blocked")]),
    ("Profense",               "WAF",      [("header:server", r"profense"), ("cookie:profenceuserid", r".+")]),
    ("Safe3 Web Firewall",     "WAF",      [("header:x-powered-by", r"Safe3")]),
    ("SafeDog",                "WAF",      [("header:server", r"safedog"), ("header:x-powered-by", r"safedog")]),
    ("SecureSphere",           "WAF",      [("body", r"SecureSphere")]),
    ("USP-SES",                "WAF",      [("header:server", r"Secure Entry Server")]),
    ("WebKnight",              "WAF",      [("header:server", r"WebKnight")]),
]




# ── SSL / TLS Deep Scan ────────────────────────────────────────
import ssl as _ssl_mod


def _test_protocol(host, port, version_enum):
    try:
        ctx = _ssl_mod.SSLContext(_ssl_mod.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl_mod.CERT_NONE
        ctx.minimum_version = version_enum
        ctx.maximum_version = version_enum
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except Exception:
        return False




def register(app):
    app.include_router(router)
