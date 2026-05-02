# ══════════════════════════════════════════════════════════════
#  PASTE ALL OF THIS AT THE BOTTOM OF ~/main.py ON KALI
#  Install commix first: sudo apt install commix -y
# ══════════════════════════════════════════════════════════════


# ── COMMAND INJECTION (commix) ────────────────────────────────
@app.post("/api/scan/commix")
async def commix_scan(req: ScanRequest, user=Depends(verify_token)):
    cmd = ["commix", "--url", req.target, "--crawl=1", "--batch",
           "--level=1", "--timeout=10", "--output-dir=/tmp/commix_out"]
    result = await run_tool(cmd, timeout=180)
    out = result["output"].lower()
    vulnerable = ("is vulnerable" in out or "command injection" in out
                  or "[+]" in result["output"] and "parameter" in out)
    findings = []
    if vulnerable:
        findings.append({
            "detail": "OS Command Injection vulnerability detected",
            "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
            "cwe": "CWE-78", "cwe_name": "OS Command Injection",
            "owasp": "A03:2021 - Injection",
            "remediation": "Never pass user input to OS commands. Use safe APIs and input validation."
        })
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "commix", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "commix",
            "vulnerable": vulnerable, "findings": findings, "total": len(findings),
            "raw_output": result["output"], "command": result["cmd"],
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── PATH TRAVERSAL / LFI (curl) ───────────────────────────────
@app.post("/api/scan/lfi")
async def lfi_scan(req: ScanRequest, user=Depends(verify_token)):
    payloads = [
        "../../../../etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "../../../../windows/win.ini",
    ]
    params = ["file", "page", "path", "include", "load", "view", "doc", "template", "dir"]
    findings = []
    tested = 0
    for param in params[:5]:
        for payload in payloads[:3]:
            url = f"{req.target}?{param}={payload}"
            try:
                res = await run_tool(["curl", "-sk", "--max-time", "5", "-L", url], timeout=10)
                tested += 1
                out = res["output"]
                if ("root:x:" in out or "[extensions]" in out or
                        "for 16-bit app support" in out or "boot loader" in out.lower()):
                    findings.append({
                        "detail": f"LFI confirmed: ?{param}={payload}",
                        "severity": "CRITICAL", "cvss": "9.1", "cve": "N/A",
                        "cwe": "CWE-22", "cwe_name": "Path Traversal",
                        "owasp": "A01:2021 - Broken Access Control",
                        "remediation": "Validate all file path inputs. Use whitelist. Never allow ../ sequences."
                    })
                    break
            except Exception:
                pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "lfi", req.target, {"output": f"Tested {tested} combinations. Findings: {len(findings)}", "cmd": "curl LFI"})
    return {"scan_id": scan_id, "target": req.target, "tool": "lfi",
            "vulnerable": len(findings) > 0, "findings": findings, "total": len(findings),
            "tested": tested, "raw_output": f"Tested {tested} param/payload combinations",
            "command": "curl path traversal", "timestamp": datetime.datetime.utcnow().isoformat()}


# ── OPEN REDIRECT (curl) ──────────────────────────────────────
@app.post("/api/scan/openredirect")
async def openredirect_scan(req: ScanRequest, user=Depends(verify_token)):
    external = "https://evil.com"
    params = ["redirect", "url", "next", "return", "returnUrl", "goto",
              "dest", "destination", "link", "redir", "redirect_uri", "callback", "ref"]
    findings = []
    for param in params:
        url = f"{req.target}?{param}={external}"
        try:
            res = await run_tool(["curl", "-sk", "--max-time", "5", "-I", "-L", url], timeout=10)
            out = res["output"].lower()
            if "location: https://evil.com" in out or "location: http://evil.com" in out:
                findings.append({
                    "detail": f"Open redirect: ?{param}= forwards to external URLs",
                    "severity": "MEDIUM", "cvss": "6.1", "cve": "N/A",
                    "cwe": "CWE-601", "cwe_name": "Open Redirect",
                    "owasp": "A01:2021 - Broken Access Control",
                    "remediation": f"Whitelist allowed redirect URLs. Reject external domains in ?{param}="
                })
        except Exception:
            pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "openredirect", req.target, {"output": f"Tested {len(params)} params", "cmd": "curl open redirect"})
    return {"scan_id": scan_id, "target": req.target, "tool": "openredirect",
            "vulnerable": len(findings) > 0, "findings": findings, "total": len(findings),
            "raw_output": f"Tested {len(params)} redirect parameters",
            "command": "curl open redirect", "timestamp": datetime.datetime.utcnow().isoformat()}


# ── SENSITIVE FILE EXPOSURE (gobuster + ext wordlist) ─────────
@app.post("/api/scan/sensitivefiles")
async def sensitivefiles_scan(req: ScanRequest, user=Depends(verify_token)):
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    base = req.target.rstrip("/")
    cmd = ["gobuster", "dir", "-u", base, "-w", wordlist,
           "-x", "php,bak,zip,sql,log,env,conf,txt,xml,json,old,backup,swp,inc",
           "-t", "30", "--timeout", "10s", "-q", "-s", "200,301,302", "--no-error"]
    result = await run_tool(cmd, timeout=240)
    sensitive_patterns = [".env", ".git", "backup", ".bak", ".sql", "config",
                          "passwd", "shadow", "web.config", "phpinfo", ".zip",
                          ".tar", "debug", ".log", "admin", "install", "setup", ".inc"]
    findings = []
    discovered = []
    for line in result["output"].split("\n"):
        m = re.match(r"(/\S+)\s+\(Status:\s*(\d+)", line)
        if m:
            path, status = m.group(1), int(m.group(2))
            discovered.append({"path": path, "status": status})
            if any(pat in path.lower() for pat in sensitive_patterns):
                findings.append({
                    "detail": f"Sensitive file exposed: {path} (HTTP {status})",
                    "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                    "cwe": "CWE-538", "cwe_name": "Sensitive File Exposure",
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "remediation": f"Remove or restrict access to {path}. Add .htaccess deny rules."
                })
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "sensitivefiles", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "sensitivefiles",
            "vulnerable": len(findings) > 0, "findings": findings, "discovered": discovered,
            "total": len(findings), "raw_output": result["output"], "command": result["cmd"],
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── AUTH BRUTE FORCE (hydra) ──────────────────────────────────
@app.post("/api/scan/hydra")
async def hydra_scan(req: ScanRequest, user=Depends(verify_token)):
    host = extract_host(req.target)
    userlist = ["admin", "administrator", "root", "user", "test", "guest", "manager", "operator"]
    passlist = ["admin", "password", "123456", "admin123", "password123",
                "test", "root", "guest", "letmein", "qwerty", "abc123", "pass"]
    with open("/tmp/hydra_users.txt", "w") as f:
        f.write("\n".join(userlist))
    with open("/tmp/hydra_pass.txt", "w") as f:
        f.write("\n".join(passlist))
    cmd = ["hydra", "-L", "/tmp/hydra_users.txt", "-P", "/tmp/hydra_pass.txt",
           "-f", "-t", "4", "-timeout", "5", host, "http-get", "/",
           "-o", "/tmp/hydra_out.txt"]
    result = await run_tool(cmd, timeout=120)
    findings = []
    try:
        with open("/tmp/hydra_out.txt") as f:
            for line in f:
                if "login:" in line.lower() and "password:" in line.lower():
                    findings.append({
                        "detail": f"Weak credentials found: {line.strip()}",
                        "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                        "cwe": "CWE-521", "cwe_name": "Weak Password Requirements",
                        "owasp": "A07:2021 - Identification and Authentication Failures",
                        "remediation": "Enforce strong passwords. Implement account lockout after failed attempts."
                    })
    except Exception:
        pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "hydra", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "hydra",
            "vulnerable": len(findings) > 0, "findings": findings, "total": len(findings),
            "raw_output": result["output"], "command": result["cmd"],
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── SSRF TESTING (curl) ───────────────────────────────────────
@app.post("/api/scan/ssrf")
async def ssrf_scan(req: ScanRequest, user=Depends(verify_token)):
    internal_targets = ["http://127.0.0.1/", "http://localhost/",
                        "http://192.168.1.1/", "http://10.0.0.1/"]
    params = ["url", "path", "dest", "redirect", "uri", "load", "fetch", "src", "href", "link"]
    findings = []
    ssrf_indicators = ["root:", "private", "admin interface", "apache", "nginx",
                       "welcome to", "it works", "default page", "iis"]
    for param in params[:6]:
        for internal in internal_targets[:2]:
            url = f"{req.target}?{param}={internal}"
            try:
                res = await run_tool(["curl", "-sk", "--max-time", "5", url], timeout=10)
                if any(ind in res["output"].lower() for ind in ssrf_indicators):
                    findings.append({
                        "detail": f"SSRF vulnerability: ?{param}= fetched internal resource {internal}",
                        "severity": "HIGH", "cvss": "8.6", "cve": "N/A",
                        "cwe": "CWE-918", "cwe_name": "Server-Side Request Forgery",
                        "owasp": "A10:2021 - SSRF",
                        "remediation": "Validate URLs against allowlist. Block RFC1918 ranges. Disable internal redirects."
                    })
                    break
            except Exception:
                pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "ssrf", req.target, {"output": f"Tested {len(params)} params for SSRF", "cmd": "curl SSRF"})
    return {"scan_id": scan_id, "target": req.target, "tool": "ssrf",
            "vulnerable": len(findings) > 0, "findings": findings, "total": len(findings),
            "raw_output": f"Tested {min(6, len(params))} SSRF parameters",
            "command": "curl SSRF test", "timestamp": datetime.datetime.utcnow().isoformat()}


# ── XXE INJECTION (curl) ──────────────────────────────────────
@app.post("/api/scan/xxe")
async def xxe_scan(req: ScanRequest, user=Depends(verify_token)):
    xxe_payload = ('<?xml version="1.0"?><!DOCTYPE foo '
                   '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                   '<root><data>&xxe;</data></root>')
    endpoints = ["/", "/api", "/api/", "/upload", "/import", "/xml", "/soap", "/xmlrpc.php"]
    findings = []
    for endpoint in endpoints[:5]:
        url = req.target.rstrip("/") + endpoint
        try:
            res = await run_tool(
                ["curl", "-sk", "--max-time", "5", "-X", "POST",
                 "-H", "Content-Type: application/xml", "-d", xxe_payload, url],
                timeout=10)
            if "root:x:" in res["output"] or ("root:" in res["output"] and "/bin/" in res["output"]):
                findings.append({
                    "detail": f"XXE confirmed at {endpoint} — /etc/passwd content returned",
                    "severity": "CRITICAL", "cvss": "9.1", "cve": "N/A",
                    "cwe": "CWE-611", "cwe_name": "XML External Entity",
                    "owasp": "A03:2021 - Injection",
                    "remediation": "Disable XML external entity processing. Use safe XML parsers (defusedxml)."
                })
        except Exception:
            pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "xxe", req.target, {"output": f"XXE test complete. Findings: {len(findings)}", "cmd": "curl XXE"})
    return {"scan_id": scan_id, "target": req.target, "tool": "xxe",
            "vulnerable": len(findings) > 0, "findings": findings, "total": len(findings),
            "raw_output": f"Tested {min(5, len(endpoints))} XML endpoints",
            "command": "curl XXE", "timestamp": datetime.datetime.utcnow().isoformat()}


# ── CLICKJACKING (curl headers check) ────────────────────────
@app.post("/api/scan/clickjacking")
async def clickjacking_scan(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["curl", "-sk", "--max-time", "10", "-I", req.target], timeout=15)
    headers = result["output"].lower()
    findings = []
    has_xfo = "x-frame-options" in headers
    has_csp_frame = "frame-ancestors" in headers
    if not has_xfo and not has_csp_frame:
        findings.append({
            "detail": "Clickjacking: missing X-Frame-Options and CSP frame-ancestors headers",
            "severity": "MEDIUM", "cvss": "6.1", "cve": "N/A",
            "cwe": "CWE-1021", "cwe_name": "UI Redress Attack",
            "owasp": "A05:2021 - Security Misconfiguration",
            "remediation": "Add: X-Frame-Options: DENY  or  Content-Security-Policy: frame-ancestors 'self'"
        })
    elif has_xfo:
        m = re.search(r"x-frame-options:\s*(\S+)", headers)
        val = m.group(1) if m else ""
        if "allow-from" in val:
            findings.append({
                "detail": "Weak clickjacking protection: X-Frame-Options ALLOW-FROM is deprecated",
                "severity": "LOW", "cvss": "3.1", "cve": "N/A",
                "cwe": "CWE-1021", "cwe_name": "Weak Clickjacking Protection",
                "owasp": "A05:2021 - Security Misconfiguration",
                "remediation": "Replace ALLOW-FROM with CSP: frame-ancestors 'self'"
            })
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "clickjacking", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "clickjacking",
            "vulnerable": len(findings) > 0,
            "x_frame_options": has_xfo, "csp_frame_ancestors": has_csp_frame,
            "findings": findings, "total": len(findings),
            "raw_output": result["output"], "command": result["cmd"],
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── HTTP VERB TAMPERING (curl) ────────────────────────────────
@app.post("/api/scan/verbtamper")
async def verbtamper_scan(req: ScanRequest, user=Depends(verify_token)):
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD", "CONNECT"]
    dangerous = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}
    findings = []
    allowed_methods = []
    for method in methods:
        try:
            res = await run_tool(
                ["curl", "-sk", "--max-time", "5", "-X", method, "-I", req.target], timeout=10)
            m = re.search(r"HTTP/[\d.]+ (\d+)", res["output"])
            if m:
                status = int(m.group(1))
                if status not in [405, 501, 400, 403, 0]:
                    allowed_methods.append({"method": method, "status": status})
                    if method in dangerous:
                        findings.append({
                            "detail": f"Dangerous HTTP method allowed: {method} (HTTP {status})",
                            "severity": "HIGH" if method in ("PUT", "DELETE") else "MEDIUM",
                            "cvss": "7.5" if method in ("PUT", "DELETE") else "5.3",
                            "cve": "N/A", "cwe": "CWE-749",
                            "cwe_name": "Exposed Dangerous Method",
                            "owasp": "A05:2021 - Security Misconfiguration",
                            "remediation": f"Disable {method} in server config. Limit to GET/POST only."
                        })
        except Exception:
            pass
    scan_id = str(uuid.uuid4())
    out = "Allowed: " + str([m["method"] for m in allowed_methods])
    save_scan(scan_id, "verbtamper", req.target, {"output": out, "cmd": "curl verb tamper"})
    return {"scan_id": scan_id, "target": req.target, "tool": "verbtamper",
            "vulnerable": len(findings) > 0, "allowed_methods": allowed_methods,
            "findings": findings, "total": len(findings),
            "raw_output": out, "command": "curl HTTP verb tampering",
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── PARAMETER POLLUTION (arjun + curl) ───────────────────────
@app.post("/api/scan/pollution")
async def pollution_scan(req: ScanRequest, user=Depends(verify_token)):
    # Discover parameters
    cmd = ["arjun", "-u", req.target, "-m", "GET", "--stable",
           "-t", "5", "-oJ", "/tmp/arjun_pollution.json"]
    result = await run_tool(cmd, timeout=120)
    params = []
    try:
        with open("/tmp/arjun_pollution.json") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for _, p in data.items():
                if isinstance(p, list):
                    params.extend(p)
        elif isinstance(data, list):
            params = data
    except Exception:
        pass
    findings = []
    polluted = []
    for param in params[:5]:
        # HPP: duplicate param — second value should win; if both reflected it's polluted
        url = f"{req.target}?{param}=SAFE_VALUE&{param}=POLLUTED_INJECT"
        try:
            res = await run_tool(["curl", "-sk", "--max-time", "5", url], timeout=10)
            if "POLLUTED_INJECT" in res["output"] and "SAFE_VALUE" in res["output"]:
                polluted.append(param)
                findings.append({
                    "detail": f"HTTP Parameter Pollution: {param} — both values reflected in response",
                    "severity": "MEDIUM", "cvss": "5.3", "cve": "N/A",
                    "cwe": "CWE-235", "cwe_name": "Improper Handling of Extra Parameters",
                    "owasp": "A03:2021 - Injection",
                    "remediation": f"Accept only one value per parameter. Reject duplicate {param} params."
                })
        except Exception:
            pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "pollution", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "pollution",
            "vulnerable": len(findings) > 0, "parameters": params, "polluted": polluted,
            "findings": findings, "total": len(findings),
            "raw_output": result["output"], "command": result["cmd"],
            "timestamp": datetime.datetime.utcnow().isoformat()}
