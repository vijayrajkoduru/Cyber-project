"""ble_attack_surface — findings rules."""


def rule_positive_emit(s):
    if s.get("ble_attack_surface_total"):
        return None
    return {"name": "No BLE (Bluetooth Low Energy) attack surface",
            "severity": "POSITIVE",
            "evidence": f"manifest + {s.get('files_scanned', 0)} smali files scanned - no BLUETOOTH* perms / BluetoothLeScanner APIs",
            "remediation": "App does not use BLE. No BLE pentest tooling needed.",
            "cwe": "CWE-200", "owasp": "M3:2023"}


def rule_ble_surface_present(s):
    perms = s.get("ble_permissions") or []
    apis = s.get("ble_api_hits") or {}
    if not (perms or apis):
        return None
    return {"name": "BLE attack surface present",
            "severity": "INFO",
            "cwe": "CWE-300", "owasp": "M3:2023",
            "evidence": f"Permissions: {', '.join(p.split('.')[-1] for p in perms)}; APIs: {', '.join(list(apis.keys())[:5])}",
            "remediation": "Plan a BLE-specific pentest: Ubertooth One / nRF52840 dongle for sniffing, gatttool / btlejack for replay. Verify the app validates GATT characteristic responses cryptographically + uses LE Secure Connections (LE SC) pairing."}


BLE_ATTACK_SURFACE_FINDING_RULES = [
    rule_positive_emit,
    rule_ble_surface_present,
]
