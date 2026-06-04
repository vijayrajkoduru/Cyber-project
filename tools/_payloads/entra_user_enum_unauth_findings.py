"""entra_user_enum_unauth - finding rules.

Severity model:
  HIGH     - many valid UPNs disclosed (5+) -> credential-stuffing surface
  MEDIUM   - 1-4 valid UPNs disclosed (information disclosure)
  INFO     - no input / httpx missing / throttled
  POSITIVE - probed users, zero existed (likely a properly scoped UPN
             space or wildcard-block; reduced enum surface)

CWE: CWE-204 Observable Response Discrepancy
MITRE: T1087.004 Cloud Account Discovery / T1589.002 Email Address Gathering
"""


def rule_high_disclosure(s):
    n = s.get("entra_user_enum_existing_count") or 0
    if n < 5:
        return None
    sample = ", ".join(r["upn"] for r in (s.get("entra_user_enum_existing") or [])[:5])
    return {
        "name": (f"Entra ID user enumeration: {n} valid UPN(s) disclosed via "
                 "GetCredentialType (unauthenticated)"),
        "severity": "HIGH", "cvss": "5.3",
        "cwe": "CWE-204", "owasp": "A07:2021",
        "mitre": "T1087.004",
        "evidence": (f"login.microsoftonline.com/common/GetCredentialType returned "
                     f"IfExistsResult=0/5/6 for {n} probed UPNs in tenant "
                     f"{s.get('entra_user_enum_tenant') or '<unknown>'}. "
                     f"Top valid UPNs: {sample}. This is the same enumeration "
                     "primitive used by o365creeper and AADInternals "
                     "Invoke-AADIntUserEnumerationAsOutsider."),
        "remediation": (
            "1. Enable smart lockout + risk-based Conditional Access to "
            "throttle enum from unknown IPs. "
            "2. Disable legacy Office desktop auth flows (ROPC). "
            "3. Deploy Continuous Access Evaluation (CAE) to revoke tokens "
            "on user-risk changes. "
            "4. Microsoft cannot fully suppress GetCredentialType (it's part "
            "of the sign-in UX), but you can break the attacker assumption by "
            "using non-guessable UPNs (UUID-style local parts) for privileged "
            "service accounts. "
            "5. Monitor sign-in logs for high-volume IfExistsResult=0 patterns "
            "via Microsoft Sentinel."),
    }


def rule_medium_disclosure(s):
    n = s.get("entra_user_enum_existing_count") or 0
    if n <= 0 or n >= 5:
        return None
    sample = ", ".join(r["upn"] for r in (s.get("entra_user_enum_existing") or [])[:5])
    return {
        "name": f"Entra ID user enumeration: {n} valid UPN(s) disclosed",
        "severity": "MEDIUM", "cvss": "4.3",
        "cwe": "CWE-204", "owasp": "A07:2021",
        "mitre": "T1087.004",
        "evidence": (f"GetCredentialType returned IfExistsResult=0/5/6 for {n} probed "
                     f"UPNs in tenant {s.get('entra_user_enum_tenant') or '<unknown>'}. "
                     f"Valid UPNs: {sample}. Unauthenticated information disclosure."),
        "remediation": ("See HIGH variant of this rule. Even small leaks chain "
                        "into MFA-fatigue / password-spray (MSOLSpray) attacks."),
    }


def rule_federated_tenant(s):
    fed = s.get("entra_user_enum_federated_count") or 0
    if fed <= 0:
        return None
    return {
        "name": f"Tenant uses federated authentication ({fed} federated UPN(s))",
        "severity": "INFO",
        "cwe": "CWE-200",
        "evidence": (f"GetCredentialType returned DomainType=4 (federated) for "
                     f"{fed} UPN(s). Tenant likely uses ADFS or third-party IDP. "
                     "Run adfs_extract_audit against the federation endpoint."),
        "remediation": ("Audit the federation IDP (ADFS / Okta / PingFederate) "
                        "for known issuance-policy vulns. Federated tenants are "
                        "the target of Solorigate / Storm-0558 token-forge classes."),
    }


def rule_throttled(s):
    t = s.get("entra_user_enum_throttled_count") or 0
    if t <= 0:
        return None
    return {
        "name": f"GetCredentialType throttled {t} request(s) — possible Smart Lockout",
        "severity": "POSITIVE",
        "evidence": (f"Microsoft rate-limited {t} probe(s) (HTTP 429 or "
                     "IfExistsResult=4). This indicates Smart Lockout / "
                     "Conditional Access throttling is active for the source IP."),
        "remediation": ("Maintain Smart Lockout. Consider Microsoft Entra "
                        "Identity Protection 'Risky sign-in' alerts to escalate "
                        "throttle events to your SOC."),
        "cwe": "CWE-307",
    }


def rule_no_input(s):
    if not s.get("entra_user_enum_no_input"):
        return None
    return {
        "name": "entra_user_enum_unauth skipped — no options.username_list",
        "severity": "INFO",
        "evidence": ("This probe requires options.username_list (newline-separated "
                     "UPNs) on the request. Without it no enumeration is performed."),
        "remediation": ("Re-run with a list of probable UPNs derived from OSINT "
                        "(LinkedIn, theHarvester, dehashed). Keep <=50 to avoid "
                        "Microsoft throttling and your own SOC noise."),
        "cwe": "N/A",
    }


def rule_httpx_missing(s):
    err = s.get("entra_user_enum_error") or ""
    if "httpx not installed" not in err:
        return None
    return {
        "name": "httpx not installed on scanner host",
        "severity": "INFO",
        "evidence": err,
        "remediation": "pip install httpx>=0.27",
        "cwe": "N/A",
    }


def rule_clean(s):
    if s.get("entra_user_enum_no_input") or s.get("entra_user_enum_error"):
        return None
    probed = s.get("entra_user_enum_probed") or 0
    existing = s.get("entra_user_enum_existing_count") or 0
    if probed <= 0 or existing > 0:
        return None
    return {
        "name": "Entra ID enum yielded zero valid UPNs",
        "severity": "POSITIVE",
        "evidence": (f"Submitted {probed} UPN(s) to GetCredentialType — none "
                     "existed in the tenant. Reduced enumeration surface."),
        "remediation": ("Continue using non-guessable service-account UPNs and "
                        "enforce Smart Lockout to suppress dictionary enum."),
        "cwe": "CWE-204",
    }


ENTRA_USER_ENUM_UNAUTH_FINDING_RULES = [
    rule_high_disclosure,
    rule_medium_disclosure,
    rule_federated_tenant,
    rule_throttled,
    rule_no_input,
    rule_httpx_missing,
    rule_clean,
]
