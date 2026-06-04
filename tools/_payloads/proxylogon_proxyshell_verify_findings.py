"""proxylogon_proxyshell_verify - findings rules.

Severity model:
  CRITICAL - ProxyLogon SSRF backend-redirection confirmed
  CRITICAL - ProxyShell path-confusion indicators observed
  HIGH     - OWA banner advertises an unpatched CU (KB5000871 / KB5003435 missing)
  INFO     - probe could not reach target / no version banner
  POSITIVE - probes returned the expected post-patch 401 / 404 with no indicators
"""


def rule_proxylogon_confirmed(s):
    if not s.get("pxlogon_proxylogon_hit"):
        return None
    backend = s.get("pxlogon_proxylogon_backend") or "(empty)"
    headers = s.get("pxlogon_proxylogon_headers_seen") or []
    return {
        "name": "ProxyLogon EXPLOITABLE - Exchange autodiscover SSRF accepts attacker-supplied backend",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cve":  "CVE-2021-26855",
        "cwe":  "CWE-918",
        "owasp": "A10:2021",
        "evidence": (
            f"POST {s.get('pxlogon_proxylogon_url', '?')} returned status "
            f"{s.get('pxlogon_proxylogon_status')} with backend redirection header "
            f"'{backend}' and Exchange routing headers exposed: {', '.join(headers)}. "
            "EPSS: 97.5% | CISA KEV: YES."
        ),
        "remediation": (
            "1. Apply the Exchange Cumulative Update + KB5000871 (March 2021 security "
            "update) immediately. Target builds: 15.2.792.10 (2019 CU8), 15.1.2176.9 "
            "(2016 CU19), 15.0.1497.12 (2013 CU23). "
            "2. Run the Microsoft Safety Scanner + Test-ProxyLogon.ps1 on every "
            "Exchange server to detect prior compromise (webshells under "
            "%ExchangeInstallPath%\\ClientAccess\\ECP\\auth, IIS logs for "
            "/owa/auth/Current/...aspx writes). "
            "3. Restrict autodiscover.json to authenticated tenants only via IIS URL "
            "Rewrite until the patch lands. "
            "4. Re-run this scan post-patch — the backend-redirection header should "
            "disappear and status should be 401/404."
        ),
    }


def rule_proxyshell_confirmed(s):
    if not s.get("pxlogon_proxyshell_hit"):
        return None
    indicators = s.get("pxlogon_proxyshell_indicators") or []
    return {
        "name": "ProxyShell EXPLOITABLE - Exchange autodiscover path-confusion exposes Mailbox routing",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cve":  "CVE-2021-34473",
        "cwe":  "CWE-22",
        "owasp": "A01:2021",
        "evidence": (
            f"GET {s.get('pxlogon_proxyshell_url', '?')} returned status "
            f"{s.get('pxlogon_proxyshell_status')} with Exchange-specific indicators: "
            f"{'; '.join(indicators)}. EPSS: 97.4% | CISA KEV: YES."
        ),
        "remediation": (
            "1. Apply Exchange CU + KB5003435 (May 2021 security update). Target "
            "builds: 15.2.858.5 (2019 CU10) or 15.1.2242.4 (2016 CU20) at minimum. "
            "ProxyShell chains 3 CVEs (CVE-2021-34473 + CVE-2021-34523 + "
            "CVE-2021-31207); the May SU + September SU together close all three. "
            "2. Run HAFNIUM IOC hunt: check %ExchangeInstallPath%\\Logging\\HttpProxy\\Autodiscover "
            "for unauthenticated autodiscover.json hits, especially with @-character "
            "URL patterns. "
            "3. Disable Exchange UM-driven autodiscover paths via "
            "Set-AutoDiscoverVirtualDirectory until patched. "
            "4. Re-run this scan post-patch — indicators should drop to 0."
        ),
    }


def rule_version_unpatched(s):
    if s.get("pxlogon_proxylogon_hit") or s.get("pxlogon_proxyshell_hit"):
        return None  # already CRITICAL above
    if not s.get("pxlogon_version_unpatched"):
        return None
    return {
        "name": (f"Exchange version {s.get('pxlogon_owa_version', '?')} advertises an "
                 "unpatched build (KB5000871 / KB5003435 missing)"),
        "severity": "HIGH",
        "cvss": "9.8",
        "cve":  "CVE-2021-26855, CVE-2021-34473",
        "cwe":  "CWE-1395",
        "owasp": "A06:2021",
        "evidence": (
            f"OWA logon page exposed X-OWA-Version = {s.get('pxlogon_owa_version')}. "
            "Probe responses were ambiguous (possible WAF / rate-limiter in front) "
            "but the advertised build precedes the ProxyLogon + ProxyShell fixes. "
            "EPSS for both: >97% | CISA KEV: YES."
        ),
        "remediation": (
            "Apply the latest Exchange CU + security updates (KB5000871 + KB5003435 + "
            "KB5004778 chain). Confirm with Get-ExchangeServer | fl Name, AdminDisplayVersion "
            "on every server, plus Test-ProxyLogon.ps1 + Test-ProxyShell.ps1. "
            "Then re-run this scan."
        ),
    }


def rule_network_error(s):
    if s.get("pxlogon_ran"):
        return None
    return {
        "name": "ProxyLogon/ProxyShell probe could not run",
        "severity": "INFO",
        "evidence": (
            f"Errors: owa={s.get('pxlogon_owa_error', '-')}; "
            f"proxylogon={s.get('pxlogon_proxylogon_error', '-')}; "
            f"proxyshell={s.get('pxlogon_proxyshell_error', '-')}; "
            f"no_target={s.get('pxlogon_no_target', False)}."
        ),
        "remediation": ("Confirm the Exchange server's OWA endpoint is reachable on "
                        "HTTPS and re-run. If the target is internal, run the scan "
                        "from a host with network access to the Exchange server."),
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if not s.get("pxlogon_ran"):
        return None
    if s.get("pxlogon_proxylogon_hit") or s.get("pxlogon_proxyshell_hit"):
        return None
    if s.get("pxlogon_version_unpatched"):
        return None
    if not (s.get("pxlogon_proxylogon_status") or s.get("pxlogon_proxyshell_status")):
        return None
    return {
        "name": "Exchange autodiscover passed ProxyLogon + ProxyShell verification",
        "severity": "POSITIVE",
        "cve":  "CVE-2021-26855, CVE-2021-34473",
        "cwe":  "CWE-918",
        "owasp": "A06:2021",
        "evidence": (
            f"OWA version {s.get('pxlogon_owa_version', 'unknown')}. ProxyLogon SSRF "
            f"returned {s.get('pxlogon_proxylogon_status')} with no backend "
            "redirection. ProxyShell path-confusion returned "
            f"{s.get('pxlogon_proxyshell_status')} with no Exchange indicators."
        ),
        "remediation": ("Keep Exchange on the latest CU + security updates; re-run "
                        "this scan after every Exchange patch Tuesday."),
    }


PROXYLOGON_PROXYSHELL_VERIFY_FINDING_RULES = [
    rule_proxylogon_confirmed,
    rule_proxyshell_confirmed,
    rule_version_unpatched,
    rule_network_error,
    rule_positive,
]
