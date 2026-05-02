# ══════════════════════════════════════════════════════════════
#  RECON MODULE — PASTE THIS AT THE BOTTOM OF main.py ON KALI
#  10 endpoints for Information Gathering & Recon module
# ══════════════════════════════════════════════════════════════
# Make sure these imports are at the top of main.py (add if missing):
#   import re, json, subprocess, datetime, uuid
#   from urllib.parse import urlparse


# ── HELPER: extract plain host/domain from any target input ──
def _recon_host(target: str) -> str:
    t = target.strip()
    if t.startswith("http://") or t.startswith("https://"):
        return urlparse(t).hostname or t
    return t.split("/")[0].strip()


# ── 1. WHOIS ─────────────────────────────────────────────────
@app.post("/api/recon/whois")
async def recon_whois(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["whois", host], timeout=30)
    out = result.get("output", "")

    def _get(patterns, text):
        for p in patterns:
            m = re.search(p, text, re.IGNORECASE | re.MULTILINE)
            if m:
                return m.group(1).strip()
        return None

    registrar   = _get([r"Registrar:\s*(.+)", r"registrar:\s*(.+)"], out)
    created     = _get([r"Creation Date:\s*(.+)", r"Created:\s*(.+)", r"created:\s*(.+)"], out)
    expires     = _get([r"Expiry Date:\s*(.+)", r"Registry Expiry Date:\s*(.+)", r"expires:\s*(.+)"], out)
    updated     = _get([r"Updated Date:\s*(.+)", r"last-modified:\s*(.+)"], out)
    registrant  = _get([r"Registrant Name:\s*(.+)", r"Registrant Organization:\s*(.+)"], out)
    country     = _get([r"Registrant Country:\s*(.+)", r"country:\s*(.+)"], out)
    name_servers = re.findall(r"Name Server:\s*(.+)", out, re.IGNORECASE)
    name_servers = [ns.strip().lower() for ns in name_servers[:6]]

    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "whois", req.target, result)
    return {
        "scan_id":      scan_id,
        "target":       req.target,
        "domain":       host,
        "registrar":    registrar,
        "created":      created,
        "expires":      expires,
        "updated":      updated,
        "registrant":   registrant,
        "country":      country,
        "name_servers": name_servers,
        "raw_output":   out,
        "timestamp":    datetime.datetime.utcnow().isoformat()
    }


# ── 2. DNS RECORDS ────────────────────────────────────────────
@app.post("/api/recon/dns")
async def recon_dns(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        r = await run_tool(["dig", "+short", host, rtype], timeout=15)
        vals = [v.strip() for v in r["output"].splitlines() if v.strip()]
        if vals:
            records[rtype] = vals
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dns", req.target, {"records": records})
    return {
        "scan_id":   scan_id,
        "target":    req.target,
        "domain":    host,
        "records":   records,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


# ── 3. DNS RECON ──────────────────────────────────────────────
@app.post("/api/recon/dnsrecon")
async def recon_dnsrecon(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    out_file = f"/tmp/dnsrecon_{uuid.uuid4().hex}.json"
    result = await run_tool(
        ["dnsrecon", "-d", host, "-t", "std", "-j", out_file],
        timeout=60
    )
    records = []
    try:
        with open(out_file) as f:
            data = json.load(f)
        for rec in data:
            if isinstance(rec, dict) and rec.get("type") not in ("info",):
                records.append({
                    "type":    rec.get("type", ""),
                    "name":    rec.get("name", rec.get("target", "")),
                    "address": rec.get("address", rec.get("strings", rec.get("exchange", ""))),
                })
    except Exception:
        # fallback: parse text output
        for line in result.get("output", "").splitlines():
            m = re.match(r"\s*\[\*\]\s+(\w+)\s+(\S+)\s+(.*)", line)
            if m:
                records.append({"type": m.group(1), "name": m.group(2), "address": m.group(3).strip()})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dnsrecon", req.target, result)
    return {
        "scan_id":   scan_id,
        "target":    req.target,
        "domain":    host,
        "records":   records,
        "total":     len(records),
        "raw_output": result.get("output", ""),
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


# ── 4. SUBDOMAIN DISCOVERY ────────────────────────────────────
@app.post("/api/recon/subdomains")
async def recon_subdomains(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    out_file = f"/tmp/sublist3r_{uuid.uuid4().hex}.txt"
    result = await run_tool(
        ["sublist3r", "-d", host, "-o", out_file, "-t", "10"],
        timeout=120
    )
    subdomains = []
    try:
        with open(out_file) as f:
            subdomains = [l.strip() for l in f if l.strip()]
    except Exception:
        # fallback: parse stdout
        for line in result.get("output", "").splitlines():
            line = line.strip()
            if host in line and not line.startswith("[") and " " not in line:
                subdomains.append(line)
    subdomains = sorted(set(subdomains))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "subdomains", req.target, result)
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "domain":     host,
        "subdomains": subdomains,
        "total":      len(subdomains),
        "raw_output": result.get("output", ""),
        "timestamp":  datetime.datetime.utcnow().isoformat()
    }


# ── 5. OSINT HARVESTING ───────────────────────────────────────
@app.post("/api/recon/harvester")
async def recon_harvester(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(
        ["theHarvester", "-d", host, "-b", "bing,crtsh,dnsdumpster,hackertarget", "-l", "100"],
        timeout=120
    )
    out = result.get("output", "")
    emails, hosts = [], []

    # Parse emails
    in_emails = False
    for line in out.splitlines():
        line = line.strip()
        if "emails found" in line.lower() or "[*] emails" in line.lower():
            in_emails = True; continue
        if in_emails:
            if line.startswith("[") or not line:
                in_emails = False
            elif "@" in line:
                emails.append(line)

    # Parse hosts/IPs
    in_hosts = False
    for line in out.splitlines():
        line = line.strip()
        if "hosts found" in line.lower() or "[*] hosts" in line.lower() or "ips found" in line.lower():
            in_hosts = True; continue
        if in_hosts:
            if line.startswith("[") or not line:
                in_hosts = False
            elif line:
                hosts.append(line)

    # Fallback regex
    if not emails:
        emails = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", out)))
    if not hosts:
        hosts  = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out)))

    # Filter out theHarvester's own tool-author emails that appear in its header
    _tool_domains = {"edge-security.com"}
    emails = [e for e in emails if e.split("@")[-1].lower() not in _tool_domains]

    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "harvester", req.target, result)
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "domain":     host,
        "emails":     list(set(emails))[:50],
        "hosts":      list(set(hosts))[:50],
        "total":      len(emails) + len(hosts),
        "raw_output": out,
        "timestamp":  datetime.datetime.utcnow().isoformat()
    }


# ── 6. FAST PORT SCAN (masscan) ───────────────────────────────
@app.post("/api/recon/masscan")
async def recon_masscan(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    out_file = f"/tmp/masscan_{uuid.uuid4().hex}.json"
    result = await run_tool(
        ["masscan", host, "-p1-65535", "--rate=1000",
         "-oJ", out_file, "--wait", "3"],
        timeout=180
    )
    ports = []
    try:
        with open(out_file) as f:
            raw = f.read().strip().rstrip(",").strip()
            if not raw.startswith("["):
                raw = "[" + raw + "]"
            data = json.loads(raw)
        for entry in data:
            for p in entry.get("ports", []):
                ports.append({
                    "port":  p.get("port"),
                    "proto": p.get("proto", "tcp"),
                    "state": p.get("status", "open"),
                    "ip":    entry.get("ip", host)
                })
    except Exception:
        for line in result.get("output","").splitlines():
            m = re.search(r"Discovered open port (\d+)/(\w+)", line)
            if m:
                ports.append({"port": int(m.group(1)), "proto": m.group(2), "state": "open", "ip": host})
    ports.sort(key=lambda x: x.get("port", 0))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "masscan", req.target, result)
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "host":       host,
        "ports":      ports,
        "total":      len(ports),
        "raw_output": result.get("output",""),
        "timestamp":  datetime.datetime.utcnow().isoformat()
    }


# ── 7. DEEP PORT SCAN (nmap) ──────────────────────────────────
@app.post("/api/recon/nmap")
async def recon_nmap(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(
        ["nmap", "-sV", "-T4", "-p-", "--open", host],
        timeout=300
    )
    ports = _parse_nmap_ports(result.get("output", ""))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "nmap", req.target, result)
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "host":       host,
        "ports":      ports,
        "total":      len(ports),
        "raw_output": result.get("output",""),
        "timestamp":  datetime.datetime.utcnow().isoformat()
    }


# ── 8. SERVICE DETECTION (nmap -sV -sC) ──────────────────────
@app.post("/api/recon/services")
async def recon_services(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(
        ["nmap", "-sV", "-sC", "-T4", "--open", host],
        timeout=180
    )
    ports = _parse_nmap_ports(result.get("output", ""))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "services", req.target, result)
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "host":       host,
        "ports":      ports,
        "total":      len(ports),
        "raw_output": result.get("output",""),
        "timestamp":  datetime.datetime.utcnow().isoformat()
    }


# ── 9. OS FINGERPRINTING (nmap -O) ───────────────────────────
@app.post("/api/recon/os")
async def recon_os(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(
        ["nmap", "-O", "--osscan-guess", "-T4", host],
        timeout=120
    )
    out = result.get("output", "")
    os_name, accuracy = None, None
    matches = []

    for line in out.splitlines():
        # "OS details: Linux 4.15"
        m = re.match(r"OS details:\s*(.+)", line)
        if m:
            os_name = m.group(1).strip()
        # "Aggressive OS guesses: Linux 4.15 (97%)"
        m2 = re.match(r"Aggressive OS guesses:\s*(.+)", line)
        if m2:
            for item in m2.group(1).split(","):
                item = item.strip()
                acc = re.search(r"\((\d+)%\)", item)
                name = re.sub(r"\s*\(\d+%\)", "", item).strip()
                matches.append({"name": name, "accuracy": int(acc.group(1)) if acc else 0})
            if matches and not os_name:
                os_name = matches[0]["name"]
                accuracy = matches[0]["accuracy"]

    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "os", req.target, result)
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "host":       host,
        "os":         os_name,
        "accuracy":   accuracy,
        "matches":    matches[:5],
        "raw_output": out,
        "timestamp":  datetime.datetime.utcnow().isoformat()
    }


# ── 10. BANNER GRABBING (nmap --script banner) ────────────────
@app.post("/api/recon/banner")
async def recon_banner(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(
        ["nmap", "-sV", "--script", "banner", "-T4", "--open", host],
        timeout=120
    )
    out = result.get("output", "")
    banners = {}
    current_port = None
    for line in out.splitlines():
        pm = re.match(r"(\d+)/tcp\s+open", line)
        if pm:
            current_port = pm.group(1)
        # nmap outputs either "| banner: ..." or "|_banner: ..."
        bm = re.match(r"\|[_ ]\s*banner:\s*(.+)", line, re.IGNORECASE)
        if bm and current_port:
            banners[current_port] = bm.group(1).strip()

    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "banner", req.target, result)
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "host":       host,
        "banners":    banners,
        "total":      len(banners),
        "raw_output": out,
        "timestamp":  datetime.datetime.utcnow().isoformat()
    }


# ── 11. CERT TRANSPARENCY (crt.sh) ───────────────────────────
@app.post("/api/recon/crtsh")
async def recon_crtsh(req: ScanRequest, user=Depends(verify_token)):
    import urllib.request, ssl
    host = _recon_host(req.target)
    subdomains = []
    raw_output = ""
    try:
        url = f"https://crt.sh/?q=%25.{host}&output=json"
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(url, context=ctx, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        seen = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.splitlines():
                sub = sub.strip().lstrip("*.")
                if sub and host in sub and sub not in seen:
                    seen.add(sub)
                    subdomains.append(sub)
        raw_output = f"Found {len(subdomains)} subdomains via crt.sh"
    except Exception as e:
        raw_output = f"crt.sh error: {e}"
    subdomains = sorted(set(subdomains))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "crtsh", req.target, {"output": raw_output, "subdomains": subdomains})
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "domain":     host,
        "subdomains": subdomains,
        "total":      len(subdomains),
        "raw_output": raw_output,
        "timestamp":  datetime.datetime.utcnow().isoformat()
    }


# ── 12. DEEP SUBDOMAIN (amass) ────────────────────────────────
@app.post("/api/recon/amass")
async def recon_amass(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    out_file = f"/tmp/amass_{uuid.uuid4().hex}.txt"
    result = await run_tool(
        ["amass", "enum", "-passive", "-d", host, "-o", out_file],
        timeout=180
    )
    subdomains = []
    try:
        with open(out_file) as f:
            subdomains = [l.strip() for l in f if l.strip()]
    except Exception:
        for line in result.get("output", "").splitlines():
            line = line.strip()
            if host in line and " " not in line:
                subdomains.append(line)
    subdomains = sorted(set(subdomains))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "amass", req.target, result)
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "domain":     host,
        "subdomains": subdomains,
        "total":      len(subdomains),
        "raw_output": result.get("output", ""),
        "timestamp":  datetime.datetime.utcnow().isoformat()
    }


# ── 13. SHODAN LOOKUP ─────────────────────────────────────────
class ShodanRequest(BaseModel):
    target: str
    api_key: str = ""

@app.post("/api/recon/shodan")
async def recon_shodan(req: ShodanRequest, user=Depends(verify_token)):
    import socket, urllib.request, ssl
    host = _recon_host(req.target)
    api_key = req.api_key.strip()
    raw_output = ""
    result_data = {}

    if not api_key:
        return {
            "scan_id":    str(uuid.uuid4()),
            "target":     req.target,
            "host":       host,
            "error":      "No Shodan API key provided",
            "raw_output": "",
            "timestamp":  datetime.datetime.utcnow().isoformat()
        }

    try:
        ip = socket.gethostbyname(host)
        ctx = ssl.create_default_context()
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        with urllib.request.urlopen(url, context=ctx, timeout=20) as resp:
            data = json.loads(resp.read().decode())

        ports = [item.get("port") for item in data.get("data", []) if item.get("port")]
        vulns = list(data.get("vulns", {}).keys())
        hostnames = data.get("hostnames", [])
        org = data.get("org", "")
        isp = data.get("isp", "")
        country = data.get("country_name", "")
        city = data.get("city", "")
        os_name = data.get("os", "")
        last_update = data.get("last_update", "")

        result_data = {
            "ip":          ip,
            "ports":       sorted(set(ports)),
            "vulns":       vulns,
            "hostnames":   hostnames,
            "org":         org,
            "isp":         isp,
            "country":     country,
            "city":        city,
            "os":          os_name,
            "last_update": last_update,
            "services":    [
                {
                    "port":    item.get("port"),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "banner":  (item.get("data", "") or "")[:200],
                }
                for item in data.get("data", [])[:20]
            ]
        }
        raw_output = f"Shodan data for {ip}: {len(ports)} ports, {len(vulns)} CVEs"
    except Exception as e:
        raw_output = f"Shodan error: {e}"

    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "shodan", req.target, {"output": raw_output, **result_data})
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "host":       host,
        "raw_output": raw_output,
        "timestamp":  datetime.datetime.utcnow().isoformat(),
        **result_data
    }


# ── SHARED PARSER: nmap port table ───────────────────────────
def _parse_nmap_ports(output: str) -> list:
    ports = []
    for line in output.splitlines():
        # e.g.  22/tcp   open  ssh     OpenSSH 8.4p1
        m = re.match(r"(\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*)", line)
        if m:
            ports.append({
                "port":     int(m.group(1)),
                "protocol": m.group(2),
                "state":    m.group(3),
                "service":  m.group(4),
                "version":  m.group(5).strip(),
            })
    return ports
