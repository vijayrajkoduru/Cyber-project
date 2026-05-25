"""websocket_grpc_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("websocket_grpc_audit_total"):
        return None
    return {"name": "No WebSocket / gRPC / MQTT transports detected - REST/HTTP only",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned",
            "remediation": "Standard Burp testing covers all traffic. No additional tooling needed.",
            "cwe": "CWE-200", "owasp": "M3:2023"}


def rule_protocols_present(s):
    protos = s.get("protocols_detected") or {}
    if not protos:
        return None
    ws_uris = s.get("websocket_uris") or []
    mqtt_uris = s.get("mqtt_uris") or []
    grpc_hosts = s.get("grpc_hosts") or []
    return {"name": f"Non-REST transports: {len(protos)} ({', '.join(list(protos.keys())[:3])})",
            "severity": "INFO",
            "cwe": "CWE-200", "owasp": "M3:2023",
            "evidence": f"WS URIs: {len(ws_uris)}; MQTT URIs: {len(mqtt_uris)}; gRPC hosts: {len(grpc_hosts)}",
            "remediation": "Standard Burp doesn't intercept these by default. WebSocket: enable Burp's WS view + retest. gRPC: use grpc-web proxy + Burp. MQTT: use mitmproxy --mode reverse:mqtt:// or MQTT-PWN."}


def rule_cleartext_ws(s):
    """ws:// (not wss://) = HTTP-grade leakage."""
    ws_uris = s.get("websocket_uris") or []
    cleartext = [u for u in ws_uris if u.startswith("ws://")]
    if not cleartext:
        return None
    return {"name": f"{len(cleartext)} cleartext WebSocket URI(s) (ws://)",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-319", "owasp": "M3:2023",
            "evidence": "URIs: " + "; ".join(cleartext[:5]),
            "remediation": "Replace ws:// with wss://. WebSockets over plain HTTP are sniffable on hostile Wi-Fi just like HTTP."}


WEBSOCKET_GRPC_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_protocols_present,
    rule_cleartext_ws,
]
