"""§8 Password Attacks — 79 endpoints per module_playbooks/08_password.md.
8 sections: online attacks, offline cracking, stuffing/spray, hash ID,
wordlists/rules, cloud distributed cracking, OS extraction, modern auth bypass.

VL-FORGE 2026-05-30: 2 live probes for HTTP form posture (form discovery
+ rate-limit / lockout detection). Other techniques correctly stay
advisory (offline cracking, OS extraction, cloud GPU require non-external
resources).
"""
import urllib.request, urllib.error, urllib.parse
import time
from tools._pack_common import make_advisory_router, _adv_response
from tools._shared import wrap_finding


def _host(t):
    return t.split("://", 1)[-1].split("/")[0].split(":")[0].strip().lower() or t

def _http_get(url, timeout=4):
    try:
        r = urllib.request.Request(url, headers={"User-Agent":"VulnusLab/2.0"})
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", errors="ignore"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(4096).decode("utf-8", errors="ignore"), dict(e.headers) if e.headers else {}
        except Exception: return e.code, "", {}
    except Exception:
        return 0, "", {}

def _http_post_form(url, data, timeout=3):
    try:
        body = urllib.parse.urlencode(data).encode()
        r = urllib.request.Request(url, data=body, headers={
            "User-Agent":"VulnusLab/2.0",
            "Content-Type":"application/x-www-form-urlencoded"
        }, method="POST")
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read(2048).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(2048).decode("utf-8", errors="ignore")
        except Exception: return e.code, ""
    except Exception:
        return 0, ""

def _build(tool, target, findings, tested, summary):
    sev_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0,"POSITIVE":0}
    top = "INFO"
    for f in findings:
        if sev_order.get(f.get("severity","INFO"),0) > sev_order.get(top,0):
            top = f.get("severity","INFO")
    return {"tool":tool,"target":target,"scan_time":0,
            "vulnerable": top in ("CRITICAL","HIGH","MEDIUM"),
            "severity": top, "findings": findings,
            "tests_performed": tested, "tests_summary": summary, "raw_data": {}}


def _probe_login_form_brute(target, req):
    """Detect login forms + check basic posture (CSRF token, rate limit hints)."""
    base = f"https://{_host(target)}"
    paths = ["/login", "/signin", "/account/login", "/user/login",
              "/wp-login.php", "/admin/login", "/api/login", "/api/auth/login"]
    forms_found = []
    for p in paths:
        code, body, headers = _http_get(base + p, timeout=3)
        if code == 200 and ('<form' in body.lower() or '"password"' in body.lower()):
            has_csrf = any(s in body.lower() for s in ["csrf", "csrfmiddlewaretoken",
                                                          "authenticity_token", "x-xsrf"])
            forms_found.append({"path": p, "csrf": has_csrf})
    findings = []
    if forms_found:
        no_csrf = [f for f in forms_found if not f["csrf"]]
        if no_csrf:
            findings.append(wrap_finding(
                f"Login form(s) found WITHOUT CSRF tokens: {len(no_csrf)} — brute-force + CSRF risk",
                "HIGH", cvss="7.0", cwe="CWE-352",
                remediation="Add CSRF tokens to all auth forms; implement rate limit + lockout.",
                evidence_marker=", ".join(f["path"] for f in no_csrf)))
        else:
            findings.append(wrap_finding(
                f"Login form(s) with CSRF tokens detected at {len(forms_found)} path(s)",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Continue CSRF + add rate limit.",
                evidence_marker=", ".join(f["path"] for f in forms_found)))
    else:
        findings.append(wrap_finding(
            "No standard login forms detected",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue.",
            evidence_marker=f"Tested {len(paths)} paths"))
    return _build("hydra_http_form", target, findings, len(paths),
                   "Login form discovery + CSRF posture")


def _probe_login_rate_limit(target, req):
    """Burst 8 invalid login attempts; check for 429/lockout response."""
    base = f"https://{_host(target)}"
    # First find a form path
    form_path = None
    for p in ["/login", "/signin", "/wp-login.php", "/api/login", "/api/auth/login"]:
        code, body, _ = _http_get(base + p, timeout=3)
        if code in (200, 405) and ('form' in body.lower() or '"password"' in body.lower() or code == 405):
            form_path = p; break
    if not form_path:
        return _adv_response("password_spray_hydra", target,
            "No login form found — rate limit probe skipped",
            "INFO", "0.0", evidence="No form path detected")
    url = base + form_path
    codes = []
    start = time.time()
    for i in range(8):
        code, _ = _http_post_form(url,
            {"username": f"nonexistent_{i}", "password": "wrong",
             "user": f"nonexistent_{i}", "pass": "wrong", "email": f"x{i}@x.com"},
            timeout=3)
        codes.append(code)
        if code == 429: break
    elapsed = time.time() - start
    findings = []
    if 429 in codes:
        findings.append(wrap_finding(
            f"Rate limit ENFORCED on {form_path} — 429 after {codes.index(429)+1} attempts",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue rate-limiting; consider per-account lockout.",
            evidence_marker=f"Codes: {codes}"))
    elif all(c and c == codes[0] for c in codes):
        findings.append(wrap_finding(
            f"Rate limit NOT enforced on {form_path} — 8 invalid logins all returned {codes[0]}",
            "HIGH", cvss="7.5", cwe="CWE-307",
            remediation="Implement rate limit (e.g. 5 attempts / 15 min per IP+account) + CAPTCHA after N attempts.",
            evidence_marker=f"All 8 attempts: {codes[0]} in {elapsed:.1f}s"))
    else:
        findings.append(wrap_finding(
            f"Rate limit posture unclear — mixed codes",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Manual verification needed.",
            evidence_marker=f"Codes: {codes}"))
    return _build("password_spray_hydra", target, findings, 8,
                   "Login rate-limit burst probe")


PROBES = {
    "hydra_http_form":     _probe_login_form_brute,
    "password_spray_hydra": _probe_login_rate_limit,
}

TECHNIQUES = [
    # §1 Online Password Attacks (13)
    ("hydra_ssh", "Hydra SSH brute-force.", "HIGH", "7.0"),
    ("hydra_ftp", "Hydra FTP brute-force.", "HIGH", "7.0"),
    ("hydra_rdp", "Hydra RDP brute-force.", "HIGH", "7.0"),
    ("hydra_http_form", "Hydra HTTP-form brute-force.", "HIGH", "7.0"),
    ("hydra_http_basic", "Hydra HTTP-basic brute-force.", "HIGH", "7.0"),
    ("hydra_smb", "Hydra SMB brute-force.", "HIGH", "7.0"),
    ("hydra_imap", "Hydra IMAP brute-force.", "HIGH", "7.0"),
    ("hydra_pop3", "Hydra POP3 brute-force.", "HIGH", "7.0"),
    ("medusa_multi_proto", "Medusa multi-protocol brute-force.", "HIGH", "7.0"),
    ("ncrack_brute", "ncrack network auth brute-force.", "HIGH", "7.0"),
    ("patator_brute", "patator multi-purpose brute-force.", "HIGH", "7.0"),
    ("crackmapexec_auth", "Crackmapexec / NetExec auth probe.", "HIGH", "7.0"),
    ("manual_online_brute", "Manual online brute-force (analyst).", "INFO", "0.0"),
    # §2 Offline Hash Cracking (15)
    ("hashcat_dictionary", "hashcat dictionary attack.", "MEDIUM", "5.5"),
    ("hashcat_mask", "hashcat mask attack.", "MEDIUM", "5.5"),
    ("hashcat_rule_based", "hashcat rule-based attack.", "MEDIUM", "5.5"),
    ("hashcat_combinator", "hashcat combinator attack.", "MEDIUM", "5.5"),
    ("hashcat_hybrid", "hashcat hybrid attack.", "MEDIUM", "5.5"),
    ("hashcat_gpu_acceleration", "hashcat GPU acceleration (CUDA/OpenCL).", "MEDIUM", "5.0"),
    ("john_dictionary", "John the Ripper dictionary.", "MEDIUM", "5.5"),
    ("john_incremental", "John incremental mode.", "MEDIUM", "5.5"),
    ("john_external", "John external mode (custom).", "MEDIUM", "5.5"),
    ("crackstation_lookup", "CrackStation rainbow-table lookup.", "MEDIUM", "5.0"),
    ("hashes_com_lookup", "hashes.com lookup.", "MEDIUM", "5.0"),
    ("md5decrypt_lookup", "md5decrypt online lookup.", "MEDIUM", "5.0"),
    ("ophcrack_lm_ntlm", "Ophcrack LM/NTLM rainbow tables.", "MEDIUM", "5.5"),
    ("rainbowcrack_tables", "RainbowCrack rcrack rainbow tables.", "MEDIUM", "5.0"),
    ("manual_hash_crack", "Manual hash crack (analyst).", "INFO", "0.0"),
    # §3 Credential Stuffing & Spray (9)
    ("password_spray_hydra", "Password spray via hydra.", "HIGH", "7.5"),
    ("password_spray_kerberoast", "Password spray via Kerberos pre-auth.", "HIGH", "7.5"),
    ("password_spray_o365", "O365 password spray.", "HIGH", "7.5"),
    ("password_spray_okta", "Okta password spray.", "HIGH", "7.5"),
    ("credential_stuffing_burp", "Credential stuffing via Burp Intruder.", "HIGH", "7.5"),
    ("credential_stuffing_openbullet", "Credential stuffing via OpenBullet.", "HIGH", "7.5"),
    ("credential_stuffing_sentry_mba", "Credential stuffing via Sentry MBA.", "HIGH", "7.5"),
    ("breach_compilation_check", "haveibeenpwned breach compilation check.", "HIGH", "7.0"),
    ("manual_spray_design", "Manual spray pattern design (analyst).", "INFO", "0.0"),
    # §4 Hash Identification (8)
    ("hashid_basic", "hashid basic identification.", "INFO", "0.0"),
    ("hash_identifier_classify", "hash-identifier multi-class.", "INFO", "0.0"),
    ("hashcat_mode_lookup", "hashcat mode lookup.", "INFO", "0.0"),
    ("john_format_test", "John format test --list=formats.", "INFO", "0.0"),
    ("name_that_hash", "name-that-hash auto-detect.", "INFO", "0.0"),
    ("identify_jwt_header", "JWT alg identification from header.", "INFO", "0.0"),
    ("identify_bcrypt_costfactor", "bcrypt $2x$cost identification.", "INFO", "0.0"),
    ("identify_argon2_variant", "Argon2 variant + parameters identification.", "INFO", "0.0"),
    # §5 Wordlist & Rule Generation (10)
    ("cewl_target_specific", "cewl target-specific wordlist gen.", "INFO", "0.0"),
    ("crunch_combinator", "crunch wordlist combinator.", "INFO", "0.0"),
    ("cupp_personal", "CUPP personal-info wordlist.", "INFO", "0.0"),
    ("rockyou_baseline", "rockyou.txt baseline wordlist.", "INFO", "0.0"),
    ("seclists_categorized", "SecLists categorized wordlist library.", "INFO", "0.0"),
    ("hashcat_rule_best64", "hashcat rule best64.", "INFO", "0.0"),
    ("hashcat_rule_d3ad0ne", "hashcat rule d3ad0ne.", "INFO", "0.0"),
    ("custom_rule_authoring", "Custom hashcat rule authoring.", "INFO", "0.0"),
    ("mentalist_gui_rule", "Mentalist GUI rule generation.", "INFO", "0.0"),
    ("statsprocessor_markov", "statsprocessor Markov chain wordlist gen.", "INFO", "0.0"),
    # §6 Cloud Distributed Cracking (7)
    ("aws_gpu_p4d_advisory", "AWS GPU p4d instance cracking advisory.", "MEDIUM", "5.5"),
    ("azure_nv_a100_advisory", "Azure NVidia A100 cracking advisory.", "MEDIUM", "5.5"),
    ("gcp_t4_v100_advisory", "GCP T4/V100 cracking advisory.", "MEDIUM", "5.5"),
    ("vast_ai_advisory", "vast.ai GPU marketplace advisory.", "MEDIUM", "5.5"),
    ("paperspace_gradient_advisory", "Paperspace Gradient advisory.", "MEDIUM", "5.5"),
    ("runpod_advisory", "RunPod cracking advisory.", "MEDIUM", "5.5"),
    ("manual_cloud_orchestration", "Manual cloud cracking orchestration.", "INFO", "0.0"),
    # §7 OS-specific Password Extraction (11)
    ("windows_sam_dump", "Windows SAM dump.", "CRITICAL", "9.0"),
    ("windows_system_hive", "Windows SYSTEM hive dump.", "CRITICAL", "9.0"),
    ("windows_security_hive", "Windows SECURITY hive dump.", "CRITICAL", "9.0"),
    ("windows_lsass_dump", "Windows LSASS dump.", "CRITICAL", "9.5"),
    ("windows_ntds_dit", "Windows NTDS.dit dump (DC).", "CRITICAL", "9.5"),
    ("linux_etc_shadow", "/etc/shadow dump.", "CRITICAL", "9.0"),
    ("linux_etc_passwd", "/etc/passwd dump.", "HIGH", "7.5"),
    ("macos_keychain_dump", "macOS Keychain dump.", "HIGH", "8.0"),
    ("browser_passwords_dump", "Browser saved passwords dump.", "HIGH", "8.0"),
    ("network_pcap_credential_extract", "Network pcap credential extraction.", "HIGH", "7.5"),
    ("memory_credential_dump", "Memory credential dump (volatility).", "HIGH", "8.0"),
    # §8 Modern Auth Bypass (Passkey / MFA) (6)
    ("aitm_session_steal", "AiTM session cookie steal.", "CRITICAL", "9.0"),
    ("webauthn_resident_key_audit", "WebAuthn resident-key audit.", "MEDIUM", "5.5"),
    ("passkey_cross_device_sync_audit", "Passkey cross-device sync audit.", "MEDIUM", "5.5"),
    ("magic_link_entropy_audit", "Magic-link entropy audit.", "HIGH", "7.0"),
    ("oauth_device_code_phishing", "OAuth device-code phishing.", "HIGH", "7.5"),
    ("totp_secret_storage_audit", "TOTP secret storage audit.", "MEDIUM", "5.5"),
]

router = make_advisory_router("password", TECHNIQUES,
    playbook_ref="See module_playbooks/08_password.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
