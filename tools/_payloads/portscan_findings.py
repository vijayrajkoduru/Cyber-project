"""Port-scan findings rules — shared across the 5 Port-Scan family tools.

Tools that consume this library:
  portscan.py  (Fast Port Scan)   — top 40 service ports
  nmap.py      (Deep Port Scan)   — top 1000 + service detection layer
  services.py  (Service Detection) — version identification per port
  os.py        (OS Fingerprinting) — TTL/Window analysis
  banner.py    (Banner Grabbing)   — first-bytes-of-response per port

State shape:
  host, ip,
  ports_open (list of dicts: {port, service, severity, cwe?, banner?, version?}),
  ports_probed (int),
  scan_duration_seconds (float),
  open_count_summary (dict: {critical, high, medium, info}),
  os_hint (str | None),
  ttl (int | None),
  window_size (int | None),
  http_present (bool),
  https_present (bool),
  banners (dict port -> banner_text),
  versions (dict port -> version_string),
"""

# Service-category buckets — drives "what kind of attack surface" findings
_DATABASE_PORTS = {1433, 1521, 3306, 5432, 5984, 6379, 7474, 9200, 11211, 27017, 27018}
_ADMIN_PORTS = {22, 23, 3389, 5900, 5985, 5986, 8291}  # SSH/Telnet/RDP/VNC/WinRM
_DEVOPS_PORTS = {2375, 2376, 6443, 8080, 9000, 5601, 3000, 9090, 5672, 15672}
_FILE_SHARE_PORTS = {21, 139, 445, 2049}  # FTP/NetBIOS/SMB/NFS
_LEGACY_PROTO_PORTS = {23, 21, 110, 143}  # Telnet/FTP/POP3/IMAP (cleartext)


def rule_databases_exposed(s):
    open_db = [p for p in (s.get("ports_open") or [])
                if p.get("port") in _DATABASE_PORTS]
    if not open_db: return None
    names = ", ".join(f"{p['port']}/{p.get('service', '?')}" for p in open_db[:5])
    return {"name": f"Database ports exposed to internet ({len(open_db)})",
            "severity": "CRITICAL",
            "cwe": "CWE-668",
            "evidence": f"Open: {names}",
            "remediation": "Bind databases to localhost or VPN-only. Public DB exposure is the #1 cause of mass-breach incidents (Capital One, etc.). Use firewall rules to whitelist app-tier IPs only."}


def rule_admin_ports_exposed(s):
    open_admin = [p for p in (s.get("ports_open") or [])
                   if p.get("port") in _ADMIN_PORTS]
    if not open_admin: return None
    names = ", ".join(f"{p['port']}/{p.get('service', '?')}" for p in open_admin[:5])
    return {"name": f"Remote admin ports exposed ({len(open_admin)})",
            "severity": "HIGH",
            "cwe": "CWE-200",
            "evidence": f"Open: {names}",
            "remediation": "Restrict SSH/RDP/Telnet to bastion hosts or VPN. Enable MFA. Brute-force attempts against these ports are constant baseline noise."}


def rule_devops_panels_exposed(s):
    open_devops = [p for p in (s.get("ports_open") or [])
                    if p.get("port") in _DEVOPS_PORTS]
    if not open_devops: return None
    names = ", ".join(f"{p['port']}/{p.get('service', '?')}" for p in open_devops[:5])
    return {"name": f"DevOps/admin panels exposed ({len(open_devops)})",
            "severity": "HIGH",
            "cwe": "CWE-306",
            "evidence": f"Open: {names}",
            "remediation": "Jenkins/Kibana/Docker-API/etc. should NEVER be internet-facing. They're high-value targets with default-cred history. VPN-restrict immediately."}


def rule_file_shares_exposed(s):
    open_fs = [p for p in (s.get("ports_open") or [])
                if p.get("port") in _FILE_SHARE_PORTS]
    if not open_fs: return None
    names = ", ".join(f"{p['port']}/{p.get('service', '?')}" for p in open_fs[:5])
    return {"name": f"File-share ports exposed ({len(open_fs)})",
            "severity": "HIGH",
            "cwe": "CWE-668",
            "evidence": f"Open: {names}",
            "remediation": "FTP/SMB/NFS exposed to internet allows data exfiltration + ransomware staging. Block at firewall."}


def rule_legacy_cleartext(s):
    open_legacy = [p for p in (s.get("ports_open") or [])
                    if p.get("port") in _LEGACY_PROTO_PORTS]
    if not open_legacy: return None
    names = ", ".join(f"{p['port']}/{p.get('service', '?')}" for p in open_legacy[:3])
    return {"name": f"Cleartext legacy protocols ({len(open_legacy)})",
            "severity": "HIGH",
            "cwe": "CWE-319",
            "evidence": f"Open: {names}",
            "remediation": "Telnet/FTP/POP3/IMAP send credentials in plaintext. Migrate to SSH/SFTP/POP3S/IMAPS."}


def rule_total_open_count(s):
    n = len(s.get("ports_open") or [])
    if n == 0: return None
    return {"name": f"{n} open port(s) detected",
            "severity": "INFO",
            "evidence": f"Scanned {s.get('ports_probed', 0)} ports; "
                        f"{n} responded to TCP SYN"}


def rule_no_ports_open(s):
    if (s.get("ports_open") or []): return None
    if (s.get("ports_probed") or 0) == 0: return None
    return {"name": "No ports open from external probe",
            "severity": "POSITIVE",
            "evidence": "All probed ports returned RST or timed out — strong filtering or host offline",
            "remediation": "If you expected services to be reachable, check firewall + WAF rules. If this is intentional (origin behind CDN), this is the GOAL."}


def rule_http_no_https(s):
    if s.get("http_present") and not s.get("https_present"):
        return {"name": "HTTP exposed without HTTPS",
                "severity": "MEDIUM",
                "cwe": "CWE-319",
                "evidence": "Port 80 open, port 443 closed",
                "remediation": "Add TLS — Let's Encrypt is free + automatic. Redirect HTTP→HTTPS. Modern browsers warn on cleartext."}
    return None


def rule_https_present(s):
    if s.get("https_present"):
        return {"name": "HTTPS available on port 443",
                "severity": "POSITIVE",
                "evidence": "TLS/443 reachable"}
    return None


def rule_os_identified(s):
    os = s.get("os_hint")
    if not os: return None
    return {"name": f"OS hint via TCP/IP stack analysis: {os}",
            "severity": "INFO",
            "evidence": f"TTL={s.get('ttl', '?')}, Window={s.get('window_size', '?')}"}


def rule_banner_disclosed(s):
    banners = s.get("banners") or {}
    if not banners: return None
    # Banners that leak versions are mildly bad
    revealing = [p for p, b in banners.items()
                  if isinstance(b, str) and len(b) > 0
                  and any(kw in b.lower() for kw in ["server:", "version", "ssh-",
                                                       "smtp", "ftp", "imap", "pop3"])]
    if not revealing: return None
    return {"name": f"Service banners disclose product/version ({len(revealing)} port(s))",
            "severity": "LOW",
            "cwe": "CWE-200",
            "evidence": ", ".join(f"port {p}" for p in revealing[:5]),
            "remediation": "Configure services to hide version banners. Reduces fingerprinting accuracy for CVE matching."}


def rule_outdated_service_versions(s):
    versions = s.get("versions") or {}
    if not versions: return None
    # Flag very old OpenSSH / Apache / nginx
    flagged = []
    for port, ver in versions.items():
        v = str(ver).lower()
        if "openssh_5" in v or "openssh_6" in v:
            flagged.append((port, ver, "OpenSSH < 7 — multiple CVEs"))
        elif "apache/2.2" in v or "apache/2.0" in v:
            flagged.append((port, ver, "Apache 2.2 EOL"))
        elif "nginx/1.0" in v or "nginx/1.1" in v:
            flagged.append((port, ver, "nginx <1.18 EOL"))
        elif "iis/6" in v or "iis/7" in v:
            flagged.append((port, ver, "IIS legacy EOL"))
    if not flagged: return None
    return {"name": f"Outdated service versions detected ({len(flagged)})",
            "severity": "HIGH",
            "cwe": "CWE-1104",
            "evidence": "; ".join(f"port {p}: {v} — {reason}" for p, v, reason in flagged[:3]),
            "remediation": "Patch immediately. Outdated services accumulate known CVEs faster than the rest of your stack."}


PORTSCAN_FINDING_RULES = [
    rule_databases_exposed,
    rule_admin_ports_exposed,
    rule_devops_panels_exposed,
    rule_file_shares_exposed,
    rule_legacy_cleartext,
    rule_total_open_count,
    rule_no_ports_open,
    rule_http_no_https,
    rule_https_present,
    rule_os_identified,
    rule_banner_disclosed,
    rule_outdated_service_versions,
]


# ── Port catalog shared by all 5 family tools ──
PORT_CATALOG = {
    21:    ("FTP",            "HIGH",     "CWE-200"),
    22:    ("SSH",            "HIGH",     "CWE-200"),
    23:    ("Telnet",         "CRITICAL", "CWE-319"),
    25:    ("SMTP",           "LOW",      "CWE-200"),
    53:    ("DNS",            "INFO",     "CWE-200"),
    80:    ("HTTP",           "INFO",     None),
    110:   ("POP3",           "LOW",      "CWE-200"),
    111:   ("RPC",            "MEDIUM",   "CWE-200"),
    135:   ("MS RPC",         "HIGH",     "CWE-200"),
    139:   ("NetBIOS",        "HIGH",     "CWE-200"),
    143:   ("IMAP",           "LOW",      "CWE-200"),
    443:   ("HTTPS",          "INFO",     None),
    445:   ("SMB",            "HIGH",     "CWE-200"),
    465:   ("SMTPS",          "LOW",      None),
    587:   ("SMTP-submit",    "LOW",      None),
    993:   ("IMAPS",          "LOW",      None),
    995:   ("POP3S",          "LOW",      None),
    1433:  ("MSSQL",          "CRITICAL", "CWE-668"),
    1521:  ("Oracle",         "CRITICAL", "CWE-668"),
    1883:  ("MQTT",           "MEDIUM",   "CWE-306"),
    2049:  ("NFS",            "HIGH",     "CWE-668"),
    2375:  ("Docker API",     "CRITICAL", "CWE-306"),
    2376:  ("Docker API TLS", "CRITICAL", "CWE-306"),
    3000:  ("Grafana",        "HIGH",     "CWE-306"),
    3306:  ("MySQL",          "CRITICAL", "CWE-668"),
    3389:  ("RDP",            "HIGH",     "CWE-200"),
    5432:  ("PostgreSQL",     "CRITICAL", "CWE-668"),
    5601:  ("Kibana",         "HIGH",     "CWE-200"),
    5672:  ("AMQP",           "MEDIUM",   "CWE-306"),
    5900:  ("VNC",            "HIGH",     "CWE-306"),
    5984:  ("CouchDB",        "CRITICAL", "CWE-668"),
    6379:  ("Redis",          "CRITICAL", "CWE-668"),
    6443:  ("K8s API",        "CRITICAL", "CWE-306"),
    7474:  ("Neo4j",          "CRITICAL", "CWE-668"),
    8000:  ("HTTP-alt",       "INFO",     None),
    8080:  ("HTTP-proxy",     "INFO",     None),
    8443:  ("HTTPS-alt",      "INFO",     None),
    8888:  ("HTTP-alt",       "INFO",     None),
    9000:  ("HTTP-alt",       "INFO",     None),
    9090:  ("Prometheus",     "HIGH",     "CWE-200"),
    9200:  ("Elasticsearch",  "CRITICAL", "CWE-668"),
    9300:  ("ES transport",   "HIGH",     "CWE-668"),
    11211: ("Memcached",      "CRITICAL", "CWE-668"),
    15672: ("RabbitMQ UI",    "HIGH",     "CWE-200"),
    27017: ("MongoDB",        "CRITICAL", "CWE-668"),
    27018: ("MongoDB shard",  "CRITICAL", "CWE-668"),
}
