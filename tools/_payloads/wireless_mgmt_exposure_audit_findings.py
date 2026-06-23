"""wireless_mgmt_exposure_audit - findings rules.

ZERO-FALSE-POSITIVE discipline:
  - A graded severity (MEDIUM/HIGH) is emitted ONLY when the probe matched a
    real wireless AP / WLAN-controller admin signature on a LIVE response from
    the internet-reachable target, OR telnet (cleartext mgmt) is actually
    reachable. Both are actively confirmed conditions.
  - Resolve failure, no reachable ports, or open-but-unidentified ports are all
    INFO / POSITIVE context — never a vulnerability.
"""


def rule_no_target(s):
    if not s.get("no_target"):
        return None
    return {"name": "No target supplied to wireless management-exposure audit",
            "severity": "INFO",
            "evidence": "ScanRequest.target was empty",
            "remediation": ("Provide the hostname or IP of the wireless AP / WLAN "
                            "controller management plane to audit its internet exposure."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_resolve_failed(s):
    host = s.get("resolve_failed")
    if not host:
        return None
    return {"name": f"Target '{host}' did not resolve",
            "severity": "INFO",
            "evidence": f"socket.gethostbyname('{host}') failed — host not resolvable from the scanner",
            "remediation": ("Confirm the management plane has a public DNS name / IP. "
                            "Internal-only controllers (RFC1918) are correctly not "
                            "reachable from external SaaS and should be audited via "
                            "an on-LAN agent."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_no_mgmt_ports(s):
    if not s.get("no_mgmt_ports_reachable"):
        return None
    ip = s.get("resolved_ip", "")
    return {"name": "No wireless-management ports reachable from the internet",
            "severity": "POSITIVE",
            "evidence": (f"Resolved to {ip}; none of the common AP/controller "
                         "management ports (80/443/8080/8443/4343/8291/22/23) "
                         "accepted a TCP connection"),
            "remediation": ("Good posture — the wireless management plane is not "
                            "directly internet-exposed. Keep AP/controller admin "
                            "interfaces on a management VLAN behind VPN/firewall; "
                            "never NAT them to the public internet."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_ap_admin_exposed(s):
    hits = s.get("ap_admin_exposed") or []
    if not hits:
        return None
    # Severity is graded by confirmed exposure of a vendor admin panel:
    #   - HTTP (cleartext) admin panel reachable -> HIGH (creds in the clear)
    #   - HTTPS admin panel reachable            -> MEDIUM (exposed surface)
    any_http = any(h.get("scheme") == "http" for h in hits)
    sev = "HIGH" if any_http else "MEDIUM"
    cvss = "7.4" if any_http else "5.3"
    vendors = sorted({h.get("vendor", "") for h in hits if h.get("vendor")})
    panel_lines = "; ".join(
        f"{h.get('url')} -> {h.get('vendor')} "
        f"(HTTP {h.get('status')}, Server: {h.get('server') or 'n/a'}"
        f"{', title=' + h.get('title') if h.get('title') else ''})"
        for h in hits
    )
    return {"name": ("Wireless AP / WLAN-controller admin panel exposed to the internet"
                     + (" over cleartext HTTP" if any_http else "")),
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-284", "owasp": "A05:2021",
            "verified_exploit": True,  # actively confirmed on a live response
            "evidence": (f"Confirmed wireless management interface(s) reachable from "
                         f"the public internet for vendor(s) {', '.join(vendors) or 'unknown'}: "
                         + panel_lines),
            "remediation": ("Remove the wireless AP/controller admin interface from the "
                            "public internet immediately. Place it on a dedicated "
                            "management VLAN reachable only via VPN/bastion; enforce "
                            "MFA + non-default credentials; disable cleartext HTTP "
                            "(redirect to HTTPS only); apply the vendor's latest "
                            "firmware (Cisco WLC / UniFi / Aruba / Ruckus / MikroTik "
                            "all have remote-admin CVEs). Restrict source IPs with an "
                            "ACL if remote admin is unavoidable.")}


def rule_telnet_mgmt(s):
    if not s.get("telnet_mgmt_reachable"):
        return None
    ip = s.get("resolved_ip", "")
    return {"name": "Cleartext Telnet management reachable on wireless infrastructure",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-319", "owasp": "A02:2021",
            "verified_exploit": True,  # TCP/23 actively accepted a connection
            "evidence": (f"TCP/23 (Telnet) accepted a connection on {ip} — wireless "
                         "AP/controller management credentials would traverse the "
                         "network in cleartext and are trivially sniffable"),
            "remediation": ("Disable Telnet on the AP/controller entirely and use SSHv2 "
                            "with key-based auth. Telnet on a wireless management plane "
                            "exposes admin credentials to passive interception and is a "
                            "PCI DSS 4.0 §2.2 / NIST SP 800-153 violation.")}


def rule_generic_marker_only(s):
    """A LIVE response contained only a GENERIC AP marker ("access point",
    "SSID", "wlan settings", ...) and no exact vendor signature. Such markers
    appear on countless unrelated pages, so this is NOT a confirmed wireless
    management plane — INFO context only, never graded."""
    hits = s.get("generic_ap_markers") or []
    if not hits:
        return None
    lines = "; ".join(
        f"{h.get('url')} (HTTP {h.get('status')}, "
        f"Server: {h.get('server') or 'n/a'}"
        f"{', title=' + h.get('title') if h.get('title') else ''})"
        for h in hits
    )
    return {"name": "Generic AP/Wi-Fi marker seen but no vendor admin panel confirmed",
            "severity": "INFO",
            "evidence": (f"Live response(s) contained only low-specificity wireless "
                         f"markers (e.g. 'access point' / 'SSID' / 'WLAN settings') with "
                         f"NO exact vendor fingerprint: {lines}. These strings appear on "
                         "many unrelated pages and do not confirm an exposed wireless "
                         "management plane."),
            "remediation": ("If any of these ports DO front wireless infrastructure, "
                            "firewall the admin interface off the public internet "
                            "regardless. Otherwise no action — no wireless exposure "
                            "was confirmed."),
            "cwe": "CWE-668", "owasp": "A05:2021"}


def rule_open_unidentified(s):
    """Ports reachable but NO wireless-admin signature matched. Context only —
    NEVER graded (could be any web service). INFO."""
    open_ports = s.get("open_mgmt_ports") or []
    if not open_ports:
        return None
    if s.get("ap_admin_exposed"):
        return None  # the graded rule already covers identified panels
    if s.get("generic_ap_markers"):
        return None  # covered by rule_generic_marker_only
    if s.get("telnet_mgmt_reachable"):
        return None  # telnet rule covers that case
    ports = ", ".join(str(p.get("port")) for p in open_ports)
    return {"name": "Management-range ports reachable but no wireless-admin panel confirmed",
            "severity": "INFO",
            "evidence": (f"Ports {ports} accepted TCP connections but no AP/controller "
                         "fingerprint matched the live responses — these may be unrelated "
                         "web/SSH services, not a wireless management plane"),
            "remediation": ("No wireless management exposure was confirmed. If these "
                            "ports DO belong to wireless infrastructure, ensure the admin "
                            "interface is firewalled off the public internet regardless."),
            "cwe": "CWE-668", "owasp": "A05:2021"}


WIRELESS_MGMT_EXPOSURE_AUDIT_FINDING_RULES = [
    rule_no_target,
    rule_resolve_failed,
    rule_no_mgmt_ports,
    rule_ap_admin_exposed,
    rule_telnet_mgmt,
    rule_generic_marker_only,
    rule_open_unidentified,
]
