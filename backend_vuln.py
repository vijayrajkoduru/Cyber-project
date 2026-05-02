# ══════════════════════════════════════════════════════════════
#  VULN SCAN MODULE — PASTE AT BOTTOM OF main.py ON KALI
#  9 endpoints for Vulnerability Scanning module
# ══════════════════════════════════════════════════════════════

import urllib.request as _ureq, ssl as _ssl

def _sev(text):
    t = text.lower()
    if any(k in t for k in ["sql injection","remote code","command injection","rce","shell","arbitrary file","traversal","authentication bypass"]):
        return "CRITICAL"
    if any(k in t for k in ["xss","cross-site script","csrf","open redirect","admin","backup","config","password","credentials","privilege"]):
        return "HIGH"
    if any(k in t for k in ["header missing","content-security","x-frame","referrer","hsts","strict-transport","deprecated","information disclosure","version"]):
        return "MEDIUM"
    if any(k in t for k in ["clickjack","cookie","cache","options","banner","server","mime"]):
        return "LOW"
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


# ── 1. NIKTO ─────────────────────────────────────────────────
@app.post("/api/scan/nikto")
async def scan_nikto(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["nikto", "-h", req.target, "-nointeractive"], timeout=120)
    out = result.get("output", "")
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue
        # skip header/info lines
        if any(s in line for s in ["Target IP","Target Hostname","Target Port","Start Time","End Time","host(s) tested","Nikto v","requests:"]):
            continue
        detail = re.sub(r"^\+\s*\[\d+\]\s*", "", line).strip().lstrip("+ ").strip()
        if not detail or len(detail) < 10:
            continue
        # Extract URL reference if present
        url_part = ""
        if "See:" in detail:
            parts = detail.split("See:")
            detail = parts[0].strip().rstrip(".")
            url_part = parts[1].strip() if len(parts) > 1 else ""
        findings.append({
            "severity":    _sev(detail),
            "detail":      detail,
            "remediation": _rem(detail),
            "reference":   url_part,
            "cwe":         "",
            "cvss":        "",
        })
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "nikto", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "findings": findings,
            "total": len(findings), "raw_output": out,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── 2. NUCLEI ────────────────────────────────────────────────
@app.post("/api/scan/nuclei")
async def scan_nuclei(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(
        ["nuclei", "-u", req.target, "-severity", "low,medium,high,critical",
         "-silent", "-no-color"],
        timeout=180
    )
    out = result.get("output", "")
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # nuclei format: [template-id] [protocol] [severity] URL - info
        m = re.match(r"\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(\S+)\s*(.*)", line)
        if m:
            sev = m.group(3).upper()
            detail = f"{m.group(1)}: {m.group(5).strip()}" if m.group(5).strip() else m.group(1)
            findings.append({
                "severity":    sev if sev in ("CRITICAL","HIGH","MEDIUM","LOW") else "MEDIUM",
                "detail":      detail,
                "remediation": _rem(detail),
                "cwe": "", "cvss": "",
            })
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "nuclei", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "findings": findings,
            "total": len(findings), "raw_output": out,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── 3. WPSCAN ────────────────────────────────────────────────
@app.post("/api/scan/wpscan")
async def scan_wpscan(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(
        ["wpscan", "--url", req.target, "--no-banner", "--random-user-agent"],
        timeout=120
    )
    out = result.get("output", "")
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("[!]") or line.startswith("[+] WordPress version"):
            detail = re.sub(r"^\[.+?\]\s*", "", line).strip()
            if detail:
                findings.append({
                    "severity": "HIGH" if "[!]" in line else "MEDIUM",
                    "detail": detail,
                    "remediation": _rem(detail),
                    "cwe": "", "cvss": "",
                })
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "wpscan", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "findings": findings,
            "total": len(findings), "raw_output": out,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── 4. SSLSCAN ───────────────────────────────────────────────
@app.post("/api/scan/ssl")
async def scan_ssl(req: ScanRequest, user=Depends(verify_token)):
    from urllib.parse import urlparse
    host = urlparse(req.target).hostname or req.target.split("/")[0]
    result = await run_tool(["sslscan", "--no-color", host], timeout=60)
    out = result.get("output", "")
    findings = []
    weak_protos = ["SSLv2","SSLv3","TLSv1.0","TLSv1.1"]
    for line in out.splitlines():
        for proto in weak_protos:
            if proto in line and "enabled" in line.lower():
                findings.append({
                    "severity": "HIGH",
                    "detail": f"Weak protocol enabled: {proto}",
                    "remediation": f"Disable {proto} — support TLS 1.2+ only",
                    "cwe": "CWE-326", "cvss": "7.5",
                })
        if "RC4" in line and "accepted" in line.lower():
            findings.append({"severity":"HIGH","detail":"Weak cipher RC4 accepted","remediation":"Disable RC4 ciphers","cwe":"CWE-327","cvss":"7.5"})
        if "NULL" in line and "accepted" in line.lower():
            findings.append({"severity":"CRITICAL","detail":"NULL cipher accepted — no encryption","remediation":"Disable NULL ciphers immediately","cwe":"CWE-327","cvss":"9.1"})
    if not out.strip() or "ERROR" in out.upper() or "unable" in out.lower():
        findings.append({"severity":"LOW","detail":"SSL/TLS not available on target (HTTP only)","remediation":"Consider enabling HTTPS with a valid certificate","cwe":"","cvss":""})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "ssl", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "findings": findings,
            "total": len(findings), "raw_output": out,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── 5. SECURITY HEADERS ──────────────────────────────────────
@app.post("/api/scan/headers")
async def scan_headers(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    raw_output = ""
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        _open = lambda u: _ureq.urlopen(u, timeout=15, context=ctx) if u.startswith("https") else _ureq.urlopen(u, timeout=15)
        r = _open(req.target)
        headers = dict(r.headers)
        raw_output = "\n".join(f"{k}: {v}" for k, v in headers.items())

        checks = [
            ("content-security-policy",    "MEDIUM", "Content-Security-Policy header missing",      "Add CSP header to prevent XSS",                        "CWE-1021"),
            ("strict-transport-security",  "MEDIUM", "HSTS header missing",                          "Add Strict-Transport-Security header",                  "CWE-319"),
            ("x-content-type-options",     "LOW",    "X-Content-Type-Options header missing",        "Add X-Content-Type-Options: nosniff",                   "CWE-693"),
            ("x-frame-options",            "MEDIUM", "X-Frame-Options / frame-ancestors missing",    "Add X-Frame-Options or CSP frame-ancestors directive",  "CWE-1021"),
            ("referrer-policy",            "LOW",    "Referrer-Policy header missing",               "Add Referrer-Policy: no-referrer-when-downgrade",       "CWE-200"),
            ("permissions-policy",         "LOW",    "Permissions-Policy header missing",            "Add Permissions-Policy to restrict browser features",   "CWE-693"),
        ]
        hl = {k.lower(): v for k, v in headers.items()}
        for hdr, sev, detail, rem, cwe in checks:
            if hdr not in hl:
                findings.append({"severity": sev, "detail": detail, "remediation": rem, "cwe": cwe, "cvss": ""})

        # Check for info disclosure
        server = hl.get("server", "")
        if server:
            findings.append({"severity":"LOW","detail":f"Server header discloses version: {server}","remediation":"Remove or genericise the Server header","cwe":"CWE-200","cvss":""})

    except Exception as e:
        raw_output = f"Error: {e}"
        findings.append({"severity":"LOW","detail":f"Could not retrieve headers: {e}","remediation":"Ensure target is reachable","cwe":"","cvss":""})

    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "headers", req.target, {"output": raw_output})
    return {"scan_id": scan_id, "target": req.target, "findings": findings,
            "total": len(findings), "raw_output": raw_output,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── 6. CORS ──────────────────────────────────────────────────
@app.post("/api/scan/cors")
async def scan_cors(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    raw_output = ""
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        req2 = _ureq.Request(req.target, headers={"Origin": "https://evil.com"})
        r = _ureq.urlopen(req2, timeout=15, context=ctx) if req.target.startswith("https") else _ureq.urlopen(req2, timeout=15)
        headers = dict(r.headers)
        raw_output = "\n".join(f"{k}: {v}" for k, v in headers.items())
        hl = {k.lower(): v for k, v in headers.items()}
        acao = hl.get("access-control-allow-origin", "")
        acac = hl.get("access-control-allow-credentials", "")
        if acao == "*":
            findings.append({"severity":"MEDIUM","detail":"CORS: Access-Control-Allow-Origin: * (wildcard)","remediation":"Restrict CORS to specific trusted origins","cwe":"CWE-942","cvss":"6.5"})
        if "evil.com" in acao:
            findings.append({"severity":"HIGH","detail":"CORS: Arbitrary origin reflected — possible CORS misconfiguration","remediation":"Validate Origin header against a whitelist","cwe":"CWE-942","cvss":"8.1"})
        if acac.lower() == "true" and ("evil.com" in acao or acao == "*"):
            findings.append({"severity":"CRITICAL","detail":"CORS: Credentials allowed with permissive origin — session hijack risk","remediation":"Never combine Access-Control-Allow-Credentials: true with wildcard or reflected origin","cwe":"CWE-942","cvss":"9.0"})
        if not findings:
            raw_output += "\nNo CORS misconfiguration detected."
    except Exception as e:
        raw_output = f"Error: {e}"
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "cors", req.target, {"output": raw_output})
    return {"scan_id": scan_id, "target": req.target, "findings": findings,
            "total": len(findings), "raw_output": raw_output,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── 7. COOKIE SECURITY ───────────────────────────────────────
@app.post("/api/scan/cookies")
async def scan_cookies(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    raw_output = ""
    try:
        import http.cookiejar
        jar = http.cookiejar.CookieJar()
        opener = _ureq.build_opener(_ureq.HTTPCookieProcessor(jar))
        opener.addheaders = [("User-Agent","Mozilla/5.0")]
        opener.open(req.target, timeout=15)
        for cookie in jar:
            raw_output += f"Cookie: {cookie.name} | secure={cookie.secure} | httponly={cookie.has_nonstandard_attr('httponly')} | samesite={cookie.get_nonstandard_attr('samesite','not set')}\n"
            if not cookie.secure:
                findings.append({"severity":"HIGH","detail":f"Cookie '{cookie.name}' missing Secure flag — can be sent over HTTP","remediation":"Set Secure flag on all cookies","cwe":"CWE-614","cvss":"7.5"})
            if not cookie.has_nonstandard_attr("httponly"):
                findings.append({"severity":"HIGH","detail":f"Cookie '{cookie.name}' missing HttpOnly flag — accessible via JavaScript","remediation":"Set HttpOnly flag to prevent XSS-based cookie theft","cwe":"CWE-1004","cvss":"7.5"})
            ss = cookie.get_nonstandard_attr("samesite","")
            if not ss:
                findings.append({"severity":"MEDIUM","detail":f"Cookie '{cookie.name}' missing SameSite attribute — CSRF risk","remediation":"Set SameSite=Strict or SameSite=Lax","cwe":"CWE-352","cvss":"6.5"})
        if not raw_output:
            raw_output = "No cookies set by target."
    except Exception as e:
        raw_output = f"Error: {e}"
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "cookies", req.target, {"output": raw_output})
    return {"scan_id": scan_id, "target": req.target, "findings": findings,
            "total": len(findings), "raw_output": raw_output,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── 8. CMS DETECTION ─────────────────────────────────────────
@app.post("/api/scan/cms")
async def scan_cms(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    raw_output = ""
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        r = _ureq.urlopen(req.target, timeout=15, context=ctx) if req.target.startswith("https") else _ureq.urlopen(req.target, timeout=15)
        body = r.read(65536).decode("utf-8", errors="ignore")
        headers = dict(r.headers)
        raw_output = f"Status: {r.status}\nHeaders: {headers}\n"

        cms_sigs = [
            ("WordPress",   ["/wp-content/", "/wp-includes/", "wp-json"],                  "HIGH",   "Update WordPress core, themes, and plugins regularly; use security hardening plugins"),
            ("Joomla",      ["content=\"Joomla", "/components/com_", "Joomla!"],            "HIGH",   "Keep Joomla updated; remove unused extensions; restrict admin path"),
            ("Drupal",      ["Drupal.settings","sites/all/","jQuery.extend(Drupal"],        "HIGH",   "Keep Drupal updated; apply security advisories promptly"),
            ("Magento",     ["Mage.Cookies","skin/frontend/","Magento"],                    "HIGH",   "Apply Magento security patches; enable 2FA on admin"),
            ("Django",      ["csrfmiddlewaretoken","__django","djdt-"],                     "MEDIUM", "Ensure DEBUG=False in production; review exposed admin URLs"),
            ("Laravel",     ["laravel_session","XSRF-TOKEN","Laravel"],                     "MEDIUM", "Keep Laravel updated; rotate APP_KEY; restrict debug mode"),
        ]
        for cms, sigs, sev, rem in cms_sigs:
            if any(s in body for s in sigs):
                raw_output += f"\nDetected: {cms}"
                findings.append({"severity": sev, "detail": f"CMS detected: {cms} — version details may be exposed", "remediation": rem, "cwe": "CWE-200", "cvss": ""})

        # Generator meta tag
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
        if m:
            raw_output += f"\nGenerator meta: {m.group(1)}"
            findings.append({"severity":"MEDIUM","detail":f"Generator meta tag exposes platform: {m.group(1)}","remediation":"Remove generator meta tag from HTML output","cwe":"CWE-200","cvss":""})

    except Exception as e:
        raw_output = f"Error: {e}"
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "cms", req.target, {"output": raw_output})
    return {"scan_id": scan_id, "target": req.target, "findings": findings,
            "total": len(findings), "raw_output": raw_output,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── 9. XSS TESTING ───────────────────────────────────────────
@app.post("/api/scan/xss")
async def scan_xss(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(
        ["nikto", "-h", req.target, "-Tuning", "4", "-nointeractive", "-no-color"],
        timeout=90
    )
    out = result.get("output", "")
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue
        if any(s in line for s in ["Target IP","Target Hostname","Start Time","End Time","host(s) tested","Nikto v","requests:"]):
            continue
        if any(k in line.lower() for k in ["xss","cross-site","script","inject","parameter"]):
            detail = re.sub(r"^\+\s*\[\d+\]\s*", "", line).strip().lstrip("+ ").strip()
            if "See:" in detail:
                detail = detail.split("See:")[0].strip().rstrip(".")
            findings.append({"severity":"HIGH","detail":detail,"remediation":"Sanitise all user input; implement Content-Security-Policy","cwe":"CWE-79","cvss":"6.1"})

    # Also run dalfox if available
    dalfox = await run_tool(["dalfox", "url", req.target, "--no-color", "--silence"], timeout=60)
    for line in dalfox.get("output","").splitlines():
        if "[V]" in line or "VULN" in line.upper():
            detail = line.strip().lstrip("[V] ")
            findings.append({"severity":"HIGH","detail":f"dalfox: {detail}","remediation":"Sanitise input and encode output; enforce CSP","cwe":"CWE-79","cvss":"6.1"})

    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "xss", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "findings": findings,
            "total": len(findings), "raw_output": out,
            "timestamp": datetime.datetime.utcnow().isoformat()}
