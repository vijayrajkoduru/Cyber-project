"""monitor_mode_capability_audit - findings rules."""


def rule_iw_missing(s):
    if not s.get("iw_binary_missing"):
        return None
    return {"name": "iw binary not available on this scanner host",
            "severity": "INFO",
            "evidence": "shutil.which('iw') returned None and /sbin/iw is absent",
            "remediation": ("Wireless audits need the `iw` userspace utility plus a "
                            "monitor-mode capable USB Wi-Fi adapter passed through "
                            "to the scan container. Install via `apt install iw` and "
                            "run the scanner in agent mode on a host with a wireless NIC."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_no_wireless_interface(s):
    if not s.get("no_wireless_interface"):
        return None
    return {"name": "No wireless interface available on scanner host",
            "severity": "HIGH",
            "evidence": "iw dev returned an empty interface list — VPS / container has no Wi-Fi NIC",
            "remediation": ("Wireless attack surface CANNOT be audited from this host. "
                            "Deploy the VulnusLab agent on a workstation with a "
                            "monitor-mode capable adapter (Alfa AWUS036ACH, AWUS1900, "
                            "TP-Link TL-WN722N v1) and re-run with target=\"auto\"."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_iface_missing(s):
    name = s.get("requested_interface_missing")
    if not name:
        return None
    return {"name": f"Requested wireless interface '{name}' not found",
            "severity": "INFO",
            "evidence": f"`iw dev` did not list interface '{name}' on this host",
            "remediation": ("Verify the adapter is plugged in and recognized "
                            "(`ip link`, `dmesg | tail`). Use target=\"auto\" to let "
                            "the probe pick any available wireless interface."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_monitor_capable_present(s):
    if not s.get("monitor_capable_count"):
        return None
    ifs = s.get("wifi_interfaces") or []
    cap = [i["ifname"] for i in ifs if i.get("monitor_supported")]
    return {"name": "Monitor-mode capable wireless adapter detected",
            "severity": "POSITIVE",
            "evidence": "iw phy reports monitor mode supported on: " + ", ".join(cap),
            "remediation": ("Monitor mode is required for handshake capture / "
                            "deauth / KARMA / hcxdumptool. Keep the adapter "
                            "physically secured — anyone with shell + this NIC "
                            "can passively sniff Wi-Fi traffic."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_no_monitor_capable(s):
    ifs = s.get("wifi_interfaces") or []
    if not ifs:
        return None
    if s.get("monitor_capable_count"):
        return None
    names = ", ".join(i["ifname"] for i in ifs)
    return {"name": "Wireless interface(s) present but none support monitor mode",
            "severity": "MEDIUM",
            "evidence": f"iw phy info shows no 'monitor' in supported interface_modes for: {names}",
            "remediation": ("The on-board adapter (often Intel iwlwifi) cannot do "
                            "monitor mode reliably. Use an external chipset proven "
                            "for monitor mode (Atheros AR9271, MediaTek MT7612U, "
                            "RTL8812AU). Re-run audit after attaching one."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


MONITOR_MODE_CAPABILITY_AUDIT_FINDING_RULES = [
    rule_iw_missing,
    rule_no_wireless_interface,
    rule_iface_missing,
    rule_monitor_capable_present,
    rule_no_monitor_capable,
]
