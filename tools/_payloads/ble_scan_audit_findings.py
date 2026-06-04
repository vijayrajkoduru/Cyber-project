"""ble_scan_audit - findings rules."""


def rule_bluez_missing(s):
    if not s.get("bluez_missing"):
        return None
    return {"name": "bluez stack (bluetoothctl + hcitool) not installed",
            "severity": "INFO",
            "evidence": "shutil.which('bluetoothctl') and 'hcitool' both returned None",
            "remediation": ("Install bluez (`apt install bluez bluez-tools`) and "
                            "pass an HCI adapter through to the scan container "
                            "(`--device=/dev/bus/usb` plus `--privileged`)."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_no_adapter(s):
    if not s.get("no_bt_adapter"):
        return None
    return {"name": "No Bluetooth HCI adapter present on scanner host",
            "severity": "HIGH",
            "evidence": "hciconfig returned no hciN device — scan host has no Bluetooth NIC",
            "remediation": ("Bluetooth audits CANNOT run on a VPS without a USB BT "
                            "adapter. Deploy the VulnusLab agent on a workstation "
                            "with built-in BT (or a USB BT 5.0 dongle, e.g. CSR8510)."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_adapter_missing(s):
    name = s.get("adapter_not_present")
    if not name:
        return None
    return {"name": f"Requested BT adapter '{name}' not present",
            "severity": "INFO",
            "evidence": f"hciconfig did not list '{name}'",
            "remediation": ("Use target=\"auto\" or pick from hciconfig output. "
                            "`hciconfig hci0 up` may be required to enable the adapter."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_no_devices_seen(s):
    if s.get("bluez_missing") or s.get("no_bt_adapter"):
        return None
    if (s.get("ble_device_count") or 0) > 0:
        return None
    if not s.get("adapters"):
        return None
    return {"name": "No BLE devices observed in scan window",
            "severity": "POSITIVE",
            "evidence": f"BLE scan over {s.get('scan_duration_sec', 0)}s returned 0 advertisements",
            "remediation": ("Continue restricting BLE-discoverable mode on company "
                            "devices to active-pair-only windows. Re-run with "
                            "longer scan_duration (30-60s) at peak office hours."),
            "cwe": "CWE-200", "owasp": "A01:2021"}


def rule_devices_seen(s):
    count = s.get("ble_device_count") or 0
    if count == 0:
        return None
    devices = s.get("ble_devices") or []
    sample = ", ".join(f"{d['addr']} ({d['name']})" for d in devices[:5])
    return {"name": f"{count} BLE device(s) discoverable in range",
            "severity": "MEDIUM" if count >= 5 else "LOW",
            "cvss": "4.3" if count >= 5 else "3.1",
            "cwe": "CWE-200", "owasp": "A01:2021",
            "evidence": "BLE scan enumerated devices: " + (sample if sample else "(see Intel)"),
            "remediation": ("Every advertising device is fingerprintable + "
                            "trackable. For corporate fleet: disable BLE-advertising "
                            "for peripherals when not actively pairing. Use BLE "
                            "address randomization (Resolvable Private Addresses).")}


def rule_legacy_advertiser(s):
    legacy = s.get("ble_legacy_count") or 0
    if legacy == 0:
        return None
    return {"name": f"{legacy} BLE device(s) advertising legacy / pre-4.2 pairing",
            "severity": "HIGH", "cvss": "6.8",
            "cwe": "CWE-326", "owasp": "A02:2021",
            "evidence": ("Device names referenced legacy/v2.0/v2.1 — vulnerable to "
                         "BIAS (Bluetooth Impersonation Attacks, CVE-2020-10135), "
                         "KNOB (Key Negotiation Of Bluetooth, CVE-2019-9506)"),
            "remediation": ("Upgrade affected peripherals to BT 4.2+ Secure "
                            "Connections (LE Secure Connections, P-256 ECDH). "
                            "Disable legacy pairing in adapter config: "
                            "`btmgmt sc on` + `btmgmt sc-only on`.")}


def rule_anonymous_advertiser(s):
    anon = s.get("ble_anon_count") or 0
    if anon == 0:
        return None
    return {"name": f"{anon} BLE device(s) advertising without a name",
            "severity": "LOW", "cvss": "3.1",
            "cwe": "CWE-200", "owasp": "A01:2021",
            "evidence": "Anonymous advertisers detected — could be unmanaged devices",
            "remediation": ("Verify each anonymous MAC against the corporate asset "
                            "list. Unknown advertisers may be rogue trackers, "
                            "AirTags, or attacker tools (BlueDucky, BadBLE).")}


BLE_SCAN_AUDIT_FINDING_RULES = [
    rule_bluez_missing,
    rule_no_adapter,
    rule_adapter_missing,
    rule_no_devices_seen,
    rule_devices_seen,
    rule_legacy_advertiser,
    rule_anonymous_advertiser,
]
