"""wps_pin_audit - findings rules."""


def rule_reaver_missing(s):
    if not s.get("reaver_binary_missing"):
        return None
    return {"name": "reaver binary not available on scanner host",
            "severity": "INFO",
            "evidence": "shutil.which('reaver') returned None and /usr/sbin/reaver is absent",
            "remediation": ("Install reaver (`apt install reaver`) plus pixiewps "
                            "and run the scanner on an agent host with a "
                            "monitor-mode capable Wi-Fi adapter."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_no_monitor_interface(s):
    if not s.get("no_monitor_interface"):
        return None
    return {"name": "No monitor-mode interface supplied for WPS audit",
            "severity": "INFO",
            "evidence": "options.interface was empty",
            "remediation": ("Run monitor_mode_capability_audit first; then pass "
                            "options.interface=\"wlan0mon\" (the airmon-ng "
                            "monitor iface) plus options.channel."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_bad_bssid(s):
    bad = s.get("bad_bssid")
    if not bad and bad != "":
        return None
    if bad is None:
        return None
    return {"name": "Invalid or missing BSSID for WPS audit",
            "severity": "INFO",
            "evidence": f"ScanRequest.target='{bad}' is not a MAC address (AA:BB:CC:DD:EE:FF)",
            "remediation": ("WPS PIN audit needs the target AP's BSSID (MAC). "
                            "Get it from `airodump-ng wlan0mon` and pass via "
                            "ScanRequest.target."),
            "cwe": "CWE-20", "owasp": "A04:2021"}


def rule_perm_denied(s):
    if not s.get("reaver_permission_denied"):
        return None
    return {"name": "reaver requires elevated privileges",
            "severity": "INFO",
            "evidence": "exec failed with PermissionError",
            "remediation": ("Run as root or with CAP_NET_RAW + CAP_NET_ADMIN. "
                            "Docker scan backend needs --privileged + USB adapter "
                            "passthrough (`--device=/dev/bus/usb`)."),
            "cwe": "CWE-250", "owasp": "A04:2021"}


def rule_wps_enabled(s):
    a = s.get("wps_audit") or {}
    if not a.get("wps_enabled"):
        return None
    locked = a.get("wps_locked")
    if locked is True:
        sev, cvss = "MEDIUM", "5.3"
        ev_suffix = " (currently locked — temporary mitigation only)"
    else:
        sev, cvss = "HIGH", "7.5"
        ev_suffix = ""
    return {"name": "WPS (Wi-Fi Protected Setup) enabled on AP" + ev_suffix,
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": ("reaver M1 exchange succeeded against BSSID "
                         + str(s.get("bssid", "")) +
                         " — WPS is active and brute-forceable"),
            "remediation": ("DISABLE WPS in the router admin panel. Modern threat: "
                            "Pixie Dust (CVE-2018-2860 / Ralink, Broadcom, Realtek "
                            "chips) recovers the PIN in <10 min from a single M1/M3 "
                            "exchange. Even WPS PBC (push-button) is vulnerable to "
                            "concurrency races. If WPS must stay on, restrict to "
                            "physical-button mode + short window + AP-side rate limit.")}


def rule_pixie_dust_indicator(s):
    a = s.get("wps_audit") or {}
    if not a.get("pixie_dust_indicator"):
        return None
    return {"name": "AP appears vulnerable to Pixie Dust offline WPS attack",
            "severity": "HIGH", "cvss": "8.1",
            "cwe": "CWE-330", "owasp": "A02:2021",
            "evidence": ("reaver output references Pixie Dust / pixiewps for BSSID "
                         + str(s.get("bssid", "")) +
                         " — the AP leaked E-S1/E-S2 nonces"),
            "remediation": ("Pixie Dust exploits weak random-number generation in "
                            "Ralink/Broadcom/Realtek WPS chipsets — the registrar "
                            "nonces are predictable, allowing offline PIN recovery. "
                            "DISABLE WPS entirely and upgrade firmware. Replace "
                            "AP if vendor has not patched.")}


def rule_pin_recovered(s):
    a = s.get("wps_audit") or {}
    if not a.get("pin_recovered"):
        return None
    return {"name": "WPS PIN recovered — full AP compromise",
            "severity": "CRITICAL", "cvss": "9.8",
            "cwe": "CWE-330", "owasp": "A02:2021",
            "evidence": "reaver output contained 'WPS PIN: ' for BSSID " + str(s.get("bssid", "")),
            "remediation": ("CRITICAL — anyone in range can derive the WPA PSK from "
                            "the recovered WPS PIN. Disable WPS immediately, "
                            "rotate the WPA2-PSK to a 20+ char passphrase, and "
                            "force re-association of all clients. Schedule a "
                            "firmware update or AP replacement.")}


def rule_wps_disabled(s):
    a = s.get("wps_audit") or {}
    if a.get("wps_enabled") is False and not a.get("pin_recovered"):
        return {"name": "WPS not enabled on target AP",
                "severity": "POSITIVE",
                "evidence": "reaver did not negotiate an M1/M3 exchange — WPS is off",
                "remediation": ("Keep WPS disabled. Verify after every firmware "
                                "upgrade — some vendors silently re-enable WPS on update."),
                "cwe": "CWE-798", "owasp": "A07:2021"}
    return None


WPS_PIN_AUDIT_FINDING_RULES = [
    rule_reaver_missing,
    rule_no_monitor_interface,
    rule_bad_bssid,
    rule_perm_denied,
    rule_wps_enabled,
    rule_pixie_dust_indicator,
    rule_pin_recovered,
    rule_wps_disabled,
]
