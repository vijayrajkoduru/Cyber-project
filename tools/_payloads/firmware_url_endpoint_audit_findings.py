"""firmware_url_endpoint_audit - findings rules.

ZERO-FP contract: cleartext-transport severity fires only when a concrete
http/ftp/tftp/telnet endpoint was literally extracted from the firmware bytes.
URL inventory + public-IP + update-host enumeration are INFO.
"""


def rule_cleartext_endpoints(s):
    ct = s.get("fw_cleartext_endpoints") or []
    if not ct:
        return None
    # telnet:// + tftp:// are worse (no auth/no integrity at all)
    worst = [c for c in ct if c.get("scheme") in ("telnet", "tftp", "ftp")]
    sev = "MEDIUM" if worst else "LOW"
    cvss = "5.3" if worst else "3.7"
    sample = ", ".join(f"{c['scheme']}://…" for c in ct[:5])
    detail = ", ".join(c["url"] for c in (worst or ct)[:4])
    return {"name": f"{len(ct)} cleartext network endpoint(s) hardcoded in firmware",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-319", "owasp": "A02:2021",
            "evidence": f"Schemes: {sample}. e.g. {detail}",
            "remediation": ("The device will contact these endpoints over unencrypted transport "
                            "(http/ftp/tftp/telnet), exposing config, firmware updates, or shell "
                            "traffic to network MITM and downgrade. Move update/control channels to "
                            "HTTPS/SFTP/SSH with certificate or signature pinning. Remove telnet/"
                            "tftp entirely from production builds.")}


def rule_public_ips(s):
    ips = s.get("fw_public_ips") or []
    if not ips:
        return None
    return {"name": f"{len(ips)} hardcoded public IP address(es) in firmware",
            "severity": "INFO",
            "evidence": "Examples: " + ", ".join(ips[:8]),
            "remediation": ("Hardcoded routable IPs are fixed callback/update destinations that "
                            "cannot be re-pointed without a firmware reflash, and may indicate a "
                            "pinned cloud/C2 endpoint. Prefer DNS names with TLS so destinations "
                            "can rotate. Confirm each IP belongs to a sanctioned vendor service."),
            "cwe": "CWE-200"}


def rule_update_hosts(s):
    hosts = s.get("fw_update_hosts") or []
    if not hosts:
        return None
    return {"name": f"{len(hosts)} firmware update / OTA hostname(s) discovered",
            "severity": "INFO",
            "evidence": "Examples: " + ", ".join(hosts[:8]),
            "remediation": ("These are the device's update/provisioning endpoints. Verify the OTA "
                            "channel enforces TLS + signed-image verification, and that the update "
                            "domain is registered and not abandoned (a lapsed update domain is a "
                            "supply-chain hijack vector)."),
            "cwe": "CWE-200"}


def rule_url_inventory(s):
    total = s.get("fw_url_total") or 0
    if total <= 0:
        return None
    if s.get("fw_cleartext_endpoints"):
        # already covered by the graded finding; still record the breadth as INFO
        pass
    counts = s.get("fw_url_scheme_counts") or {}
    return {"name": f"Firmware contains {total} hardcoded URL(s)",
            "severity": "INFO",
            "evidence": "By scheme: " + ", ".join(f"{k}={v}" for k, v in counts.items()),
            "remediation": ("Review the extracted URL inventory for abandoned domains, third-party "
                            "analytics/telemetry endpoints, and any debug/staging hosts that should "
                            "not ship in production firmware."),
            "cwe": "CWE-200"}


FIRMWARE_URL_ENDPOINT_AUDIT_FINDING_RULES = [rule_cleartext_endpoints, rule_public_ips,
                                             rule_update_hosts, rule_url_inventory]
