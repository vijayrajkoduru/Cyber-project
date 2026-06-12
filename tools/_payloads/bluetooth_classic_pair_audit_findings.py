"""bluetooth_classic_pair_audit - findings rules."""


def rule_bluez_missing(s):
    if not s.get("bluez_missing"):
        return None
    return {"name": "bluez (bluetoothctl + hcitool) not installed",
            "severity": "INFO",
            "evidence": "shutil.which() returned None for bluetoothctl + hcitool",
            "remediation": ("Install bluez (`apt install bluez bluez-tools`) and "
                            "expose an HCI adapter to the scan container "
                            "(`--device=/dev/bus/usb` + `--privileged`)."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_no_adapter(s):
    if not s.get("no_bt_adapter"):
        return None
    return {"name": "No Bluetooth HCI adapter present on scanner host",
            "severity": "INFO",
            "evidence": "hciconfig returned no hciN device — the SCANNER host has no Bluetooth NIC. This is a scanner-platform limitation, NOT a finding about the target.",
            "remediation": ("BT-Classic audit needs an HCI adapter that supports "
                            "inquiry mode. Deploy the VulnusLab agent on a "
                            "workstation with a BT 5.0 USB dongle."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_adapter_missing(s):
    name = s.get("adapter_not_present")
    if not name:
        return None
    return {"name": f"Requested BT adapter '{name}' not present",
            "severity": "INFO",
            "evidence": f"hciconfig did not list '{name}'",
            "remediation": ("Pick from `hciconfig` output or use target=\"auto\". "
                            "Run `hciconfig hci0 up` to enable a powered-down adapter."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_sdptool_missing(s):
    if s.get("have_sdptool") is not False:
        return None
    if not s.get("btc_device_count"):
        return None
    return {"name": "sdptool absent — pairing-mode classification limited",
            "severity": "INFO",
            "evidence": "shutil.which('sdptool') returned None — only CoD heuristic used",
            "remediation": ("Install bluez-tools (`apt install bluez-tools`) for "
                            "Service Discovery Protocol probing. Without it, "
                            "Just-Works vs Legacy PIN cannot be distinguished."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_devices_seen(s):
    n = s.get("btc_device_count") or 0
    if n == 0:
        return None
    sample = ", ".join(
        f"{d['addr']} ({d.get('name') or d.get('device_class') or '?'})"
        for d in (s.get("btc_devices") or [])[:5]
    )
    return {"name": f"{n} Bluetooth Classic device(s) in discoverable mode",
            "severity": "MEDIUM" if n >= 3 else "LOW",
            "cvss": "5.3" if n >= 3 else "3.1",
            "cwe": "CWE-200", "owasp": "A01:2021",
            "evidence": f"BT-Classic inquiry returned: {sample}",
            "remediation": ("Disable discoverable mode on company-owned BT peripherals "
                            "when not actively pairing. Discoverable devices are "
                            "fingerprintable + targetable for BlueBorne (CVE-2017-0781), "
                            "BIAS (CVE-2020-10135), KNOB (CVE-2019-9506).")}


def rule_legacy_pin(s):
    n = s.get("btc_legacy_count") or 0
    if n == 0:
        return None
    return {"name": f"{n} device(s) using Legacy PIN pairing (pre-BT 2.1)",
            "severity": "HIGH", "cvss": "7.4",
            "cwe": "CWE-326", "owasp": "A02:2021",
            "evidence": ("SDP records reference 'PIN code' / 'Legacy' or CoD "
                         "indicates legacy headset/audio device"),
            "remediation": ("Replace pre-BT 2.1 peripherals with BT 4.2+ Secure "
                            "Connections devices. Legacy PIN pairing uses E0 cipher "
                            "(broken) + 4-digit PIN brute-forceable in seconds via "
                            "btcrack. Force `btmgmt sc-only on` adapter-side to "
                            "refuse legacy pairing on the host.")}


def rule_just_works(s):
    n = s.get("btc_just_works_count") or 0
    if n == 0:
        return None
    return {"name": f"{n} device(s) using Just Works pairing (no MITM protection)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-300", "owasp": "A07:2021",
            "evidence": "SDP records reference 'No Input No Output' IO capability",
            "remediation": ("Just Works pairing is vulnerable to MITM during initial "
                            "pairing (no out-of-band PIN compare). Where possible, "
                            "force Numeric Comparison or Passkey Entry pairing on "
                            "BT 4.2+ peripherals. For unattended devices (sensors), "
                            "pair only inside a Faraday-shielded enclosure.")}


def rule_secure_connections(s):
    n = s.get("btc_secure_count") or 0
    if n == 0:
        return None
    return {"name": f"{n} device(s) using BT Secure Connections",
            "severity": "POSITIVE",
            "evidence": "SDP records indicate Secure Simple Pairing / Secure Connections",
            "remediation": ("Keep enforcing Secure Connections Only mode "
                            "(`btmgmt sc-only on`) for all paired devices. Audit "
                            "after every firmware update — some peripherals "
                            "silently downgrade after factory reset."),
            "cwe": "CWE-326", "owasp": "A02:2021"}


BLUETOOTH_CLASSIC_PAIR_AUDIT_FINDING_RULES = [
    rule_bluez_missing,
    rule_no_adapter,
    rule_adapter_missing,
    rule_sdptool_missing,
    rule_devices_seen,
    rule_legacy_pin,
    rule_just_works,
    rule_secure_connections,
]
