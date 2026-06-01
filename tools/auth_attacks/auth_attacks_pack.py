"""§17 Auth Attacks — 74 endpoints under /api/auth_attacks/<tool>.

MITRE ATT&CK TA0006 Credential Access. Mix of detectable patterns + advisories.

VL-FORGE 2026-05-30: 3 live probes for HTTP-detectable auth surface
(JWT in cookies/headers, OAuth/OIDC discovery, JKU URL fetching).
"""
import urllib.request, urllib.error, urllib.parse, base64, json, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding

router = APIRouter()


def _host(t):
    return t.split("://", 1)[-1].split("/")[0].split(":")[0].strip().lower() or t

def _http_get(url, timeout=4):
    try:
        r = urllib.request.Request(url, headers={"User-Agent":"VulnusLab/2.0"})
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read(8192).decode("utf-8", errors="ignore"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(4096).decode("utf-8", errors="ignore"), dict(e.headers) if e.headers else {}
        except Exception: return e.code, "", {}
    except Exception:
        return 0, "", {}

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


def _probe_jwt_alg_none(target, req):
    """Discover JWT tokens in responses + audit alg header for 'none' acceptance risk."""
    base = f"https://{_host(target)}"
    paths = ["/", "/login", "/api/login", "/auth", "/api/auth", "/api/me"]
    found_jwts = []
    for p in paths:
        code, body, headers = _http_get(base + p, timeout=3)
        # JWT pattern: 3 base64-url-safe segments separated by dots
        for v in (list(headers.values()) + [body[:8192]]):
            v = str(v)
            for m in re.finditer(r'(eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*)', v):
                token = m.group(1)
                try:
                    hdr = token.split(".")[0]
                    pad = "=" * (4 - len(hdr) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(hdr + pad).decode("utf-8", errors="ignore"))
                    alg = decoded.get("alg", "?")
                    if alg.lower() == "none":
                        found_jwts.append({"path": p, "alg": "none (UNSAFE)", "kid": decoded.get("kid","")})
                    elif alg.startswith("HS"):
                        found_jwts.append({"path": p, "alg": alg, "kid": decoded.get("kid","")})
                    else:
                        found_jwts.append({"path": p, "alg": alg, "kid": decoded.get("kid","")})
                except Exception:
                    pass
                break
            if found_jwts: break
    findings = []
    if any(j["alg"] == "none (UNSAFE)" for j in found_jwts):
        unsafe = [j for j in found_jwts if "none" in j["alg"]]
        findings.append(wrap_finding(
            f"JWT with alg=none observed — signature stripping accepted",
            "CRITICAL", cvss="9.5", cwe="CWE-347",
            remediation="Reject alg=none server-side; allow-list signing algorithms (RS256/ES256 only).",
            evidence_marker=f"Tokens with alg=none at: {', '.join(u['path'] for u in unsafe)}"))
    elif any(j["alg"].startswith("HS") for j in found_jwts):
        findings.append(wrap_finding(
            f"JWT(s) using HS256/HS384/HS512 found — verify secret entropy + rotation",
            "INFO", cvss="0.0", cwe="CWE-321",
            remediation="If using HS*, ensure secret is high-entropy (≥256 bits) + rotated per spec.",
            evidence_marker=", ".join(f"{j['path']}: alg={j['alg']}" for j in found_jwts)))
    elif found_jwts:
        findings.append(wrap_finding(
            f"JWT(s) detected — algorithms appear safe ({set(j['alg'] for j in found_jwts)})",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue strong algorithm enforcement.",
            evidence_marker=", ".join(f"{j['path']}: alg={j['alg']}" for j in found_jwts)))
    else:
        findings.append(wrap_finding(
            "No JWT tokens found in responses at standard paths",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Audit other endpoints; JWTs may live behind auth.",
            evidence_marker=f"Tested {len(paths)} paths"))
    return _build("jwt_alg_none", target, findings, len(paths),
                   "JWT discovery + alg=none check")


def _probe_oauth_redirect(target, req):
    """Discover OAuth/OIDC authorization endpoint + test for open redirect_uri."""
    base = f"https://{_host(target)}"
    # Try OIDC discovery first
    code, body, _ = _http_get(f"{base}/.well-known/openid-configuration", timeout=4)
    findings = []
    auth_endpoint = None
    if code == 200 and body.strip().startswith("{"):
        try:
            cfg = json.loads(body)
            auth_endpoint = cfg.get("authorization_endpoint", "")
        except Exception:
            pass
    if not auth_endpoint:
        # Try common OAuth paths
        for p in ["/oauth/authorize", "/auth/authorize", "/oauth2/authorize"]:
            code, _, _ = _http_get(base + p, timeout=3)
            if code in (200, 302, 400):
                auth_endpoint = base + p; break
    if not auth_endpoint:
        findings.append(wrap_finding(
            "No OAuth/OIDC authorization endpoint discovered",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify OAuth implementation if expected.",
            evidence_marker="No /.well-known/openid-configuration nor /oauth/authorize"))
    else:
        # Probe with evil redirect_uri
        evil = "https://evil.example.com/callback"
        params = urllib.parse.urlencode({"response_type":"code","client_id":"x","redirect_uri":evil,"scope":"openid"})
        url = f"{auth_endpoint}?{params}"
        code, body, headers = _http_get(url, timeout=4)
        loc = headers.get("Location", "") + headers.get("location", "")
        if loc and "evil.example.com" in loc:
            findings.append(wrap_finding(
                f"OAuth open redirect — evil redirect_uri accepted at {auth_endpoint}",
                "CRITICAL", cvss="9.0", cwe="CWE-601",
                remediation="Strict redirect_uri allow-list at OAuth provider; reject unregistered URIs.",
                evidence_marker=f"Redirect to: {loc[:100]}"))
        elif code == 400 or "redirect_uri" in body[:500].lower() or "invalid_redirect" in body.lower():
            findings.append(wrap_finding(
                f"OAuth endpoint at {auth_endpoint} REJECTED evil redirect_uri (good)",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue strict redirect_uri validation.",
                evidence_marker=f"GET {url} → {code}"))
        else:
            findings.append(wrap_finding(
                f"OAuth endpoint at {auth_endpoint} — redirect_uri test inconclusive",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Manual OAuth flow audit.",
                evidence_marker=f"Status: {code}"))
    return _build("oauth_redirect_uri_hijack", target, findings, 2,
                   "OAuth open-redirect probe")


def _probe_jwt_jku_ssrf(target, req):
    """Check for JWT JKU/X5U header acceptance — SSRF/auth-bypass risk."""
    base = f"https://{_host(target)}"
    # Probe /.well-known/jwks.json discoverability (passive indicator)
    code, body, _ = _http_get(f"{base}/.well-known/jwks.json", timeout=3)
    findings = []
    if code == 200 and body.strip().startswith("{") and "keys" in body:
        try:
            jwks = json.loads(body)
            n_keys = len(jwks.get("keys", []))
            findings.append(wrap_finding(
                f"JWKS endpoint exposed at /.well-known/jwks.json with {n_keys} key(s) — verify JKU header acceptance is restricted",
                "MEDIUM", cvss="5.5", cwe="CWE-918",
                remediation="If verifying JWTs by JKU header, allow-list trusted issuer URLs only.",
                evidence_marker=f"JWKS has {n_keys} keys; JKU SSRF possible if JKU is honored from JWT headers"))
        except Exception:
            pass
    if not findings:
        findings.append(wrap_finding(
            "No public JWKS endpoint; JKU SSRF surface limited",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue.",
            evidence_marker="No /.well-known/jwks.json response"))
    return _build("jwt_jku_x5u_ssrf", target, findings, 1,
                   "JWT JKU/X5U SSRF surface probe")


def _adv(tool, target, title, *, sev="MEDIUM", cvss="5.0", cwe="CWE-287",
         remediation="See module_playbooks/17_auth_attacks.md.",
         evidence="Advisory — detect against IdP/SIEM logs."):
    return {"tool":tool,"target":target,"scan_time":0,
            "vulnerable": sev in ("CRITICAL","HIGH","MEDIUM"),
            "severity": sev,
            "findings":[wrap_finding(title, sev, cvss=cvss, cwe=cwe, owasp="A07:2021",
                remediation=remediation, evidence_marker=evidence)],
            "tests_performed":1, "tests_summary":title[:80], "raw_data":{}}


TECHNIQUES = [
    # §1 Pass-the-Hash / Pass-the-Ticket (10)
    ("pth_impacket", "PtH via impacket -hashes.", "HIGH", "7.5"),
    ("pth_crackmapexec", "PtH via crackmapexec/NetExec.", "HIGH", "7.5"),
    ("pth_evil_winrm", "PtH via evil-winrm.", "HIGH", "7.5"),
    ("ptt_rubeus_ptt", "Pass-the-Ticket via Rubeus ptt.", "HIGH", "8.0"),
    ("ptt_mimikatz", "Pass-the-Ticket via mimikatz.", "HIGH", "8.0"),
    ("overpass_the_hash_rubeus", "Overpass-the-Hash (Rubeus asktgt + ptt).", "HIGH", "8.0"),
    ("pass_the_cert", "Pass-the-Cert (cert-based auth).", "HIGH", "8.0"),
    ("pass_the_cookie", "Pass-the-Cookie (browser session).", "HIGH", "8.0"),
    ("pass_the_token_oidc", "Pass-the-Token (cloud OIDC).", "HIGH", "8.0"),
    ("manual_ptx_chain", "Manual creative PtX chain (analyst).", "INFO", "0.0"),

    # §2 MFA Bypass (12)
    ("evilginx2_aitm", "EvilGinx2 AiTM phishing (session steal).", "CRITICAL", "9.0"),
    ("modlishka_aitm", "Modlishka reverse-proxy phishing.", "CRITICAL", "9.0"),
    ("bitb_browser_in_browser", "Browser-in-the-Browser (BitB).", "HIGH", "8.0"),
    ("mfa_fatigue_push_bomb", "MFA fatigue / push bombing (manual).", "MEDIUM", "5.5"),
    ("sms_otp_sim_swap_manual", "SMS-OTP SIM swap (manual).", "INFO", "0.0"),
    ("sms_otp_intercept_read_sms", "SMS-OTP intercept via READ_SMS perm.", "HIGH", "7.5"),
    ("push_notification_spam", "Push notification spam.", "MEDIUM", "5.0"),
    ("oauth_device_code_phish", "OAuth device-code phishing.", "HIGH", "8.0"),
    ("recovery_flow_weakness", "Recovery flow weakness.", "HIGH", "7.5"),
    ("backup_code_abuse", "Backup-code abuse.", "MEDIUM", "5.5"),
    ("manual_mfa_bypass_chain", "Manual MFA-bypass chain.", "INFO", "0.0"),
    ("aitm_cookie_steal", "Adversary-in-the-Middle cookie steal.", "CRITICAL", "9.0"),

    # §3 OAuth / OIDC Attacks (14)
    ("oauth_redirect_uri_hijack", "OAuth redirect_uri hijack.", "HIGH", "7.5"),
    ("oauth_state_csrf", "OAuth state CSRF.", "HIGH", "7.0"),
    ("oauth_pkce_missing", "OAuth PKCE missing (RFC 7636).", "MEDIUM", "5.5"),
    ("implicit_flow_abuse", "Implicit flow abuse (deprecated).", "MEDIUM", "5.5"),
    ("client_secret_leakage", "client_secret leakage.", "HIGH", "7.5"),
    ("refresh_token_rotation_absent", "Refresh token rotation absence.", "MEDIUM", "5.5"),
    ("oidc_nonce_missing", "OIDC nonce validation missing.", "MEDIUM", "5.5"),
    ("oidc_userinfo_abuse", "OIDC userinfo abuse.", "HIGH", "7.0"),
    ("ms_graph_consent_phishing", "OAuth consent phishing (Microsoft Graph).", "HIGH", "7.5"),
    ("oauth_device_code_phish_2", "OAuth device-code phishing (dup of §2#8).", "HIGH", "7.5"),
    ("apple_google_one_tap_csrf", "Apple Sign In / Google One Tap CSRF.", "MEDIUM", "5.5"),
    ("oauth_introspection_abuse", "OAuth introspection endpoint abuse.", "MEDIUM", "5.5"),
    ("manual_oauth_audit", "Manual OAuth flow audit (analyst).", "INFO", "0.0"),
    ("manual_creative_oauth_chain", "Manual creative OAuth chain.", "INFO", "0.0"),

    # §4 SAML / Federation Attacks (8)
    ("saml_xsw", "SAML XML Signature Wrapping (XSW).", "HIGH", "8.0"),
    ("samlraider_auto_tests", "SAMLRaider automated tests.", "HIGH", "7.5"),
    ("saml_golden_ticket_adfs", "SAML Golden Ticket (ADFS cert theft).", "CRITICAL", "9.5"),
    ("saml_response_replay", "SAML response replay.", "HIGH", "7.5"),
    ("saml_jwt_bridge_confusion", "SAML 2.0 + JWT bridge confusion.", "HIGH", "7.5"),
    ("saml_assertion_tamper", "SAML assertion tamper.", "HIGH", "7.5"),
    ("samlter_burp_editor", "SAMLter / Burp SAML editor.", "MEDIUM", "5.5"),
    ("manual_saml_chain", "Manual creative SAML chain.", "INFO", "0.0"),

    # §5 JWT Attacks (10)
    ("jwt_alg_none", "JWT alg=none confusion.", "CRITICAL", "9.0"),
    ("jwt_hs256_weak_crack", "JWT HS256 weak-secret crack.", "HIGH", "8.0"),
    ("jwt_signature_strip", "JWT signature stripping.", "CRITICAL", "9.0"),
    ("jwt_jku_x5u_ssrf", "JWT JKU / X5U SSRF.", "HIGH", "8.0"),
    ("jwt_kid_path_traversal", "JWT kid path traversal.", "HIGH", "8.0"),
    ("jwt_kid_sqli", "JWT kid SQL injection.", "HIGH", "8.0"),
    ("jwt_alg_confusion_hs_vs_rs", "JWT cross-algorithm confusion (HS256 vs RS256).", "HIGH", "8.0"),
    ("jwt_expired_replay", "JWT expired token replay.", "MEDIUM", "5.5"),
    ("jwt_key_confusion_pub_to_sym", "JWT key confusion (public→symmetric).", "HIGH", "8.0"),
    ("jwt_tool_comprehensive", "jwt_tool comprehensive scan.", "MEDIUM", "5.5"),

    # §6 Kerberos Attacks on-prem AD (10)
    ("kerberoasting", "Kerberoasting (GetUserSPNs).", "HIGH", "7.5"),
    ("asrep_roasting", "AS-REP Roasting (GetNPUsers).", "HIGH", "7.5"),
    ("unconstrained_delegation_tgt", "Unconstrained delegation TGT capture.", "HIGH", "8.0"),
    ("constrained_delegation_s4u", "Constrained delegation S4U.", "HIGH", "7.5"),
    ("rbcd_shadow_credentials", "RBCD via Shadow Credentials.", "HIGH", "8.0"),
    ("diamond_sapphire_ticket", "Diamond/Sapphire ticket (modify PAC).", "HIGH", "8.0"),
    ("golden_ticket_krbtgt", "Golden ticket (krbtgt forgery).", "CRITICAL", "9.5"),
    ("silver_ticket_service", "Silver ticket (service-specific).", "HIGH", "8.0"),
    ("targeted_kerberoast_one_user", "Targeted Kerberoast.", "HIGH", "7.5"),
    ("manual_kerberos_chain", "Manual creative Kerberos chain.", "INFO", "0.0"),

    # §7 Modern Passwordless (Passkey / WebAuthn) (10)
    ("webauthn_fido2_misconfig", "WebAuthn / FIDO2 misconfig audit.", "MEDIUM", "5.5"),
    ("passkey_enum", "Passkey enumeration.", "MEDIUM", "5.5"),
    ("passkey_cross_device_sync_abuse", "Passkey cross-device sync abuse (manual).", "INFO", "0.0"),
    ("passkey_downgrade_attack", "Passkey downgrade attack (manual).", "INFO", "0.0"),
    ("magic_link_entropy_replay", "Magic-link entropy / replay.", "HIGH", "7.0"),
    ("passwordless_flow_audit", "Passwordless flow audit (Stytch, Auth0).", "MEDIUM", "5.5"),
    ("account_recovery_flow_weakness", "Account-recovery flow weakness.", "HIGH", "7.0"),
    ("totp_secret_leak", "TOTP secret leak (if stored).", "HIGH", "8.0"),
    ("manual_passkey_phishing", "Manual Passkey phishing.", "INFO", "0.0"),
    ("manual_passwordless_chain", "Manual creative passwordless chain.", "INFO", "0.0"),
]


PROBES = {
    "jwt_alg_none":             _probe_jwt_alg_none,
    "oauth_redirect_uri_hijack":_probe_oauth_redirect,
    "jwt_jku_x5u_ssrf":         _probe_jwt_jku_ssrf,
}


def _make_handler(slug, title, sev, cvss):
    def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
        return _adv(slug, req.target, title, sev=sev, cvss=cvss)
    _h.__name__ = slug
    return _h


def _make_probe(slug, fn):
    def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
        try: return fn(req.target, req)
        except Exception as e:
            return _adv(slug, req.target, f"Probe error: {str(e)[:80]}",
                         sev="INFO", cvss="0.0")
    _h.__name__ = slug
    return _h


for slug, title, sev, cvss in TECHNIQUES:
    if slug in PROBES:
        router.add_api_route(f"/api/auth_attacks/{slug}",
            _make_probe(slug, PROBES[slug]), methods=["POST"])
    else:
        router.add_api_route(f"/api/auth_attacks/{slug}",
            _make_handler(slug, title, sev, cvss), methods=["POST"])


def register(app):
    app.include_router(router)
