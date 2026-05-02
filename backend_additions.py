# ══════════════════════════════════════════════════════════════
#  PASTE THIS AT THE BOTTOM OF main.py ON YOUR KALI VM
#  Also apply the cookie_name fix shown below in /api/scan/cookies
# ══════════════════════════════════════════════════════════════

# ── COOKIE NAME FIX ───────────────────────────────────────────
# In your existing /api/scan/cookies endpoint, find this line:
#   cookies.append({"cookie":cookie_val,"issues":issues,"secure_score":...})
# Replace it with:
#   cookie_name = cookie_val.split("=")[0].split(";")[0].strip()
#   cookies.append({"name":cookie_name,"cookie":cookie_val,"issues":issues,"secure_score":...})


# ── NUCLEI ────────────────────────────────────────────────────
@app.post("/api/scan/nuclei")
async def nuclei_scan(req: ScanRequest, user=Depends(verify_token)):
    cmd = [
        "nuclei", "-u", req.target,
        "-severity", "critical,high,medium,low",
        "-c", "25",
        "-timeout", "10",
        "-no-color",
        "-jsonl"
    ]
    result = await run_tool(cmd, timeout=300)
    findings = []
    CVSS_MAP = {"critical": "9.8", "high": "7.5", "medium": "5.3", "low": "3.1"}
    OWASP_MAP = {"critical": "A06:2021 - Vulnerable Components", "high": "A05:2021 - Security Misconfiguration",
                 "medium": "A05:2021 - Security Misconfiguration", "low": "A05:2021 - Security Misconfiguration"}
    for line in result["output"].split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            info = data.get("info", {})
            sev  = info.get("severity", "info").lower()
            cves = info.get("classification", {}).get("cve-id") or []
            cwes = info.get("classification", {}).get("cwe-id") or []
            findings.append({
                "detail":      info.get("name", "Nuclei Finding") + (f" — {data.get('matched-at','')}" if data.get("matched-at") else ""),
                "severity":    sev.upper(),
                "cvss":        CVSS_MAP.get(sev, "0.0"),
                "cve":         cves[0] if cves else "N/A",
                "cwe":         cwes[0] if cwes else "N/A",
                "cwe_name":    "Security Vulnerability",
                "owasp":       OWASP_MAP.get(sev, "A05:2021 - Security Misconfiguration"),
                "remediation": info.get("remediation") or "Apply patch or update the affected component.",
                "template":    data.get("template-id", ""),
                "matched_at":  data.get("matched-at", "")
            })
        except Exception:
            pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "nuclei", req.target, result)
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "tool":       "nuclei",
        "findings":   findings,
        "total":      len(findings),
        "high":       len([f for f in findings if f["severity"] in ("CRITICAL","HIGH")]),
        "raw_output": result["output"],
        "command":    result["cmd"],
        "timestamp":  datetime.datetime.utcnow().isoformat()
    }


# ── FFUF ─────────────────────────────────────────────────────
@app.post("/api/scan/ffuf")
async def ffuf_scan(req: ScanRequest, user=Depends(verify_token)):
    host    = extract_host(req.target)
    mode    = req.options.get("mode", "dirs")
    wordlist = "/usr/share/wordlists/dirb/common.txt"

    if mode == "vhosts":
        cmd = ["ffuf", "-w", wordlist, "-u", req.target,
               "-H", f"Host: FUZZ.{host}", "-mc", "200,301,302,403",
               "-of", "json", "-o", "/tmp/ffuf_out.json", "-t", "50", "-timeout", "10", "-s"]
    elif mode == "params":
        url = req.target + ("?" if "?" not in req.target else "&") + "FUZZ=test"
        cmd = ["ffuf", "-w", wordlist, "-u", url,
               "-mc", "200,301,302", "-of", "json", "-o", "/tmp/ffuf_out.json",
               "-t", "50", "-timeout", "10", "-s"]
    else:
        base = req.target.rstrip("/")
        cmd = ["ffuf", "-w", wordlist, "-u", f"{base}/FUZZ",
               "-mc", "200,301,302,403", "-of", "json", "-o", "/tmp/ffuf_out.json",
               "-t", "50", "-timeout", "10", "-s"]

    result = await run_tool(cmd, timeout=300)
    discovered = []
    try:
        with open("/tmp/ffuf_out.json") as f:
            data = json.load(f)
        for r in data.get("results", []):
            word = r.get("input", {}).get("FUZZ", r.get("url", ""))
            discovered.append({
                "path":   word,
                "url":    r.get("url", ""),
                "status": r.get("status", 0),
                "size":   r.get("length", 0)
            })
    except Exception:
        for line in result["output"].split("\n"):
            m = re.match(r"\s+(\S+)\s+\[Status:\s*(\d+)", line)
            if m:
                discovered.append({"path": m.group(1), "status": int(m.group(2))})

    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "ffuf", req.target, result)
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "tool":       "ffuf",
        "mode":       mode,
        "discovered": discovered,
        "total":      len(discovered),
        "raw_output": result["output"],
        "command":    result["cmd"],
        "timestamp":  datetime.datetime.utcnow().isoformat()
    }


# ── WPSCAN ────────────────────────────────────────────────────
@app.post("/api/scan/wpscan")
async def wpscan_scan(req: ScanRequest, user=Depends(verify_token)):
    cmd = [
        "wpscan", "--url", req.target,
        "--no-update", "--random-user-agent",
        "--format", "json", "--output", "/tmp/wpscan_out.json"
    ]
    result = await run_tool(cmd, timeout=180)
    findings = []
    wp_version = "Unknown"
    try:
        with open("/tmp/wpscan_out.json") as f:
            data = json.load(f)
        wp_version = (data.get("version") or {}).get("number", "Unknown")
        for vuln in (data.get("vulnerabilities") or []):
            cves = (vuln.get("references") or {}).get("cve") or []
            findings.append({
                "detail":      vuln.get("title", "WordPress Core Vulnerability"),
                "severity":    "HIGH",
                "cvss":        "7.5",
                "cve":         cves[0] if cves else "N/A",
                "cwe":         "CWE-937",
                "cwe_name":    "Outdated Component",
                "owasp":       "A06:2021 - Vulnerable and Outdated Components",
                "remediation": "Update WordPress core to the latest version."
            })
        for pname, pdata in (data.get("plugins") or {}).items():
            for vuln in (pdata.get("vulnerabilities") or []):
                cves = (vuln.get("references") or {}).get("cve") or []
                findings.append({
                    "detail":      f"Plugin '{pname}': {vuln.get('title','Vulnerability')}",
                    "severity":    "HIGH",
                    "cvss":        "7.5",
                    "cve":         cves[0] if cves else "N/A",
                    "cwe":         "CWE-937",
                    "cwe_name":    "Outdated Component",
                    "owasp":       "A06:2021 - Vulnerable and Outdated Components",
                    "remediation": f"Update or remove plugin: {pname}"
                })
    except Exception:
        for line in result["output"].split("\n"):
            if "[!]" in line and "vulnerabilit" in line.lower():
                findings.append({
                    "detail": line.strip().replace("[!]","").strip(),
                    "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                    "cwe": "CWE-937", "cwe_name": "Outdated Component",
                    "owasp": "A06:2021 - Vulnerable and Outdated Components",
                    "remediation": "Update WordPress and all plugins."
                })

    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "wpscan", req.target, result)
    return {
        "scan_id":     scan_id,
        "target":      req.target,
        "tool":        "wpscan",
        "wp_version":  wp_version,
        "findings":    findings,
        "total":       len(findings),
        "raw_output":  result["output"],
        "command":     result["cmd"],
        "timestamp":   datetime.datetime.utcnow().isoformat()
    }


# ── ARJUN ─────────────────────────────────────────────────────
@app.post("/api/scan/arjun")
async def arjun_scan(req: ScanRequest, user=Depends(verify_token)):
    cmd = [
        "arjun", "-u", req.target,
        "-m", "GET,POST",
        "--stable",
        "-t", "10",
        "-oJ", "/tmp/arjun_out.json"
    ]
    result = await run_tool(cmd, timeout=180)
    parameters = []
    try:
        with open("/tmp/arjun_out.json") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for url, params in data.items():
                if isinstance(params, list):
                    parameters.extend(params)
        elif isinstance(data, list):
            parameters = data
    except Exception:
        for line in result["output"].split("\n"):
            if "[+]" in line and "parameter" in line.lower():
                params = re.findall(r"'(\w+)'", line)
                parameters.extend(params)
            m = re.search(r"Parameters found:\s*(.+)", line)
            if m:
                parameters.extend([p.strip() for p in m.group(1).split(",")])
    parameters = list(set(parameters))

    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "arjun", req.target, result)
    return {
        "scan_id":    scan_id,
        "target":     req.target,
        "tool":       "arjun",
        "parameters": parameters,
        "total":      len(parameters),
        "raw_output": result["output"],
        "command":    result["cmd"],
        "timestamp":  datetime.datetime.utcnow().isoformat()
    }
