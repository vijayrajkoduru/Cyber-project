#!/usr/bin/env python3
"""
Run this on Kali to replace paid OSINT API calls with free Kali tools.
Usage: python3 patch_osint_free.py
"""
import re, shutil, os

TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")
shutil.copy(TARGET, TARGET + ".bak")

with open(TARGET, "r", encoding="utf-8") as f:
    src = f.read()

# ── 1. Remove paid API key globals ────────────────────────────
src = re.sub(
    r"\n# ── API KEYS.*?SECTRAILS_KEY.*?\n",
    "\n# ── API KEYS (optional — leave blank if not needed) ──────────────\n"
    "SHODAN_KEY     = os.getenv('SHODAN_KEY',     '')\n"
    "VIRUSTOTAL_KEY = os.getenv('VIRUSTOTAL_KEY', '')\n",
    src, flags=re.DOTALL
)

# ── 2. Replace osint_email_osint with free version ────────────
NEW_EMAIL = '''
@app.post("/api/osint/email_osint")
async def osint_email_osint(req: ScanRequest, token: str = Depends(verify_token)):
    """Email & subdomain harvesting using only free, no-key tools."""
    scan_id = str(_uuid.uuid4())
    domain = _recon_host(req.target) if req.target else req.target
    findings = []
    seen = set()

    def add(sev, title, detail):
        key = f"{title}|{detail}"
        if key not in seen:
            seen.add(key)
            findings.append({"severity": sev, "title": title, "detail": str(detail)[:200]})

    # ── theHarvester (free sources only, no API key needed) ──────
    result = await run_tool(
        ["theHarvester", "-d", domain, "-b",
         "crtsh,dnsdumpster,hackertarget,anubis,certspotter,rapiddns,otx,urlscan",
         "-l", "300"], timeout=120)
    raw = result.get("output","") + result.get("error","")
    for line in raw.splitlines():
        line = line.strip()
        if re.match(r"^[\\w\\.\\+\\-]+@[\\w\\.-]+\\.\\w{2,}$", line):
            add("HIGH", "Email Found (theHarvester)", line)
        elif "linkedin.com/in/" in line.lower():
            add("MEDIUM", "LinkedIn Profile", line)
        elif re.match(r"^\\d{1,3}(\\.\\d{1,3}){3}$", line):
            add("MEDIUM", "IP Address", line)
        elif re.match(r"^[\\w\\-]+\\.[\\w\\.-]+\\.[a-z]{2,}$", line) and domain.split(".")[-2] in line:
            add("MEDIUM", "Subdomain (theHarvester)", line)

    # ── subfinder — passive subdomain enumeration (free, built-in Kali) ──
    r2 = await run_tool(["subfinder", "-d", domain, "-silent", "-timeout", "30"], timeout=60)
    for line in (r2.get("output","")).splitlines():
        line = line.strip()
        if line and domain in line:
            add("MEDIUM", "Subdomain (subfinder)", line)

    # ── amass passive — subdomain enumeration (free) ──────────────
    r3 = await run_tool(["amass", "enum", "-passive", "-d", domain, "-timeout", "60"], timeout=90)
    for line in (r3.get("output","")).splitlines():
        line = line.strip()
        if line and domain in line and "." in line:
            add("MEDIUM", "Subdomain (amass)", line)

    # ── crt.sh certificate transparency (free public API) ─────────
    cert_data = _api_get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if cert_data and isinstance(cert_data, list):
        for c in cert_data[:50]:
            for n in c.get("name_value","").split("\\n"):
                n = n.replace("*.","").strip()
                if n and domain in n:
                    add("MEDIUM", "Subdomain (crt.sh)", n)

    # ── URLScan.io — free, no key needed ──────────────────────────
    us = _api_get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=20")
    if us and us.get("results"):
        for r in us["results"][:10]:
            pg = r.get("page",{})
            ip = pg.get("ip","")
            server = pg.get("server","")
            if ip: add("INFO", "IP (URLScan.io)", f"{domain} resolves to {ip}")
            if server: add("INFO", "Web Server", f"{server} detected via URLScan.io")

    # ── AlienVault OTX — free, no key needed ──────────────────────
    otx = _api_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
    if otx and otx.get("passive_dns"):
        for r in otx["passive_dns"][:10]:
            hostname = r.get("hostname","")
            address  = r.get("address","")
            if hostname and domain in hostname:
                add("MEDIUM", "Subdomain (OTX)", hostname)
            if address and re.match(r"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$", address):
                add("INFO", "IP Record (OTX)", f"{hostname} → {address}")

    # ── ipinfo.io — free, no key, 50k req/month ───────────────────
    # Resolve domain first
    r_host = await run_tool(["dig", "+short", domain, "A"], timeout=10)
    ips = [l.strip() for l in r_host.get("output","").splitlines() if re.match(r"\\d+\\.\\d+\\.\\d+\\.\\d+", l.strip())]
    for ip in ips[:3]:
        ip_info = _api_get(f"https://ipinfo.io/{ip}/json")
        if ip_info:
            org  = ip_info.get("org","")
            city = ip_info.get("city","")
            country = ip_info.get("country","")
            add("INFO", f"IP Info: {ip}", f"Org: {org} | Location: {city}, {country}")

    # ── VirusTotal free tier (500 req/day, no credit card) ─────────
    if VIRUSTOTAL_KEY:
        vt = _api_get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                      headers={"x-apikey": VIRUSTOTAL_KEY})
        if vt and vt.get("data"):
            attrs = vt["data"].get("attributes",{})
            malicious = attrs.get("last_analysis_stats",{}).get("malicious",0)
            rep = attrs.get("reputation",0)
            if malicious > 0:
                add("HIGH", "Malicious Domain (VirusTotal)", f"{malicious} engines flagged this domain")
            else:
                add("INFO", "VirusTotal Clean", f"Reputation: {rep} — no malicious flags")

    if not findings:
        findings.append({"severity":"INFO","title":"No OSINT data found",
            "detail":f"No subdomains/emails found for {domain}. Try a real company domain."})

    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw[:600],
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} OSINT item(s)"}
'''

# ── 3. Replace osint_recon_ng with free DNS deep-dive ─────────
NEW_RECON = '''
@app.post("/api/osint/recon_ng")
async def osint_recon_ng(req: ScanRequest, token: str = Depends(verify_token)):
    """Deep DNS + WHOIS + cert transparency — 100% free, no API keys."""
    scan_id = str(_uuid.uuid4())
    host = _recon_host(req.target) if req.target else req.target
    findings = []
    seen = set()

    def add(sev, title, detail):
        key = f"{title}|{detail}"
        if key not in seen:
            seen.add(key)
            findings.append({"severity": sev, "title": title, "detail": str(detail)[:200]})

    # ── dnsrecon — full DNS enumeration ───────────────────────────
    r1 = await run_tool(["dnsrecon", "-d", host, "-t", "std,axfr"], timeout=90)
    raw1 = r1.get("output","") + r1.get("error","")
    for line in raw1.splitlines():
        line = line.strip()
        m = re.search(r"(A|AAAA|MX|NS|TXT|SOA|CNAME)\\s+([\\w\\.-]+)\\s+([\\d\\.]+|[\\w\\.-]+)", line)
        if m:
            rtype, name, value = m.group(1), m.group(2), m.group(3)
            sev = "HIGH" if rtype == "MX" else "MEDIUM" if rtype in ("A","NS","AAAA") else "INFO"
            add(sev, f"DNS {rtype} Record", f"{name} → {value}")
        if "zone transfer" in line.lower() and "success" in line.lower():
            add("CRITICAL", "Zone Transfer ENABLED", f"DNS zone transfer allowed on {host} — exposes all records")
        if "axfr" in line.lower() and "[+]" in line:
            add("CRITICAL", "Zone Transfer Success", line.replace("[+]","").strip())

    # ── WHOIS registration data ────────────────────────────────────
    r2 = await run_tool(["whois", host], timeout=30)
    raw2 = r2.get("output","")
    important = ["Registrar:", "Creation Date:", "Expir", "Name Server:", "Registrant Org",
                 "Registrant Country", "Admin Email", "Tech Email"]
    for line in raw2.splitlines():
        for key in important:
            if key.lower() in line.lower() and ":" in line:
                parts = line.split(":", 1)
                val = parts[1].strip() if len(parts) > 1 else ""
                if val and len(val) > 2:
                    title_key = parts[0].strip().title()
                    sev = "HIGH" if "email" in key.lower() else "INFO"
                    add(sev, f"WHOIS: {title_key}", val[:120])
                break

    # ── dnsx — fast DNS probing (free, usually on Kali) ──────────
    r3 = await run_tool(["dnsx", "-d", host, "-a", "-aaaa", "-mx", "-ns", "-txt", "-silent"],
                        timeout=30)
    for line in (r3.get("output","")).splitlines():
        line = line.strip()
        if line and "[" in line:
            add("INFO", "DNS Record (dnsx)", line[:150])

    # ── Reverse DNS on discovered IPs ────────────────────────────
    r_dig = await run_tool(["dig", "+short", host, "A"], timeout=10)
    for ip in (r_dig.get("output","")).splitlines():
        ip = ip.strip()
        if re.match(r"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$", ip):
            add("MEDIUM", "IP Address", ip)
            r_rev = await run_tool(["dig", "+short", "-x", ip], timeout=10)
            rev = r_rev.get("output","").strip()
            if rev:
                add("INFO", "Reverse DNS", f"{ip} → {rev}")
            # nmap quick scan on discovered IP (free, real findings)
            r_nmap = await run_tool(["nmap", "-F", "--open", "-T4", ip], timeout=60)
            for nline in (r_nmap.get("output","")).splitlines():
                if "/tcp" in nline and "open" in nline:
                    port = nline.split("/")[0].strip()
                    svc = nline.split()[-1] if nline.split() else ""
                    sev = "HIGH" if port in ("21","22","23","3306","5432","6379","27017","445","3389") else "MEDIUM"
                    add(sev, f"Open Port {port}", f"{nline.strip()} on {ip}")

    # ── OTX reputation (free, no key) ─────────────────────────────
    otx = _api_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/general")
    if otx:
        pulse_count = otx.get("pulse_info",{}).get("count",0)
        if pulse_count > 0:
            add("HIGH", "Threat Intelligence (OTX)", f"{host} appears in {pulse_count} threat intelligence feeds")

    if not findings:
        findings.append({"severity":"INFO","title":"No records found","detail":f"No DNS records or WHOIS data found for {host}."})

    raw = raw1[:400] + "\\n" + raw2[:200]
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} host(s) found"}
'''

# Apply patches
import re

# Replace email_osint function
src = re.sub(
    r"@app\.post\(\"/api/osint/email_osint\"\).*?(?=\n@app\.|\n# ──)",
    NEW_EMAIL.strip() + "\n\n",
    src, flags=re.DOTALL
)

# Replace recon_ng function
src = re.sub(
    r"@app\.post\(\"/api/osint/recon_ng\"\).*?(?=\n@app\.|\n# ──)",
    NEW_RECON.strip() + "\n\n",
    src, flags=re.DOTALL
)

with open(TARGET, "w", encoding="utf-8") as f:
    f.write(src)

print("✅ Patch applied successfully!")
print("   Email Harvesting → theHarvester + subfinder + amass + crt.sh + OTX + URLScan + ipinfo")
print("   Recon-ng → dnsrecon + whois + nmap + dig + OTX (all free, all on Kali)")
print()
print("Now run:  uvicorn main:app --host 0.0.0.0 --port 8000 --reload")
