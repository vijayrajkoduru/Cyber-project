"""websocket_origin_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("websocket_origin_audit_total"):
        return None
    return {"name": "WebSocket usage looks clean",
            "severity": "POSITIVE",
            "evidence": (f"WS users={len(s.get('ws_users') or [])} "
                         f"Origin set={s.get('ws_origin_set_callers', 0)} "
                         f"TLS verify={s.get('ws_tls_verify_callers', 0)}"),
            "remediation": "Continue setting Origin header explicitly + verifying TLS on every wss:// connect.",
            "cwe": "CWE-319", "owasp": "M3:2023"}


def rule_plain_ws(s):
    pl = s.get("plain_ws_urls") or []
    if not pl:
        return None
    return {"name": f"Plain ws:// WebSocket in {len(pl)} class(es)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-319", "owasp": "M3:2023",
            "evidence": "Files: " + ", ".join(pl[:6]),
            "remediation": "Use wss:// only. Plain ws:// is the WebSocket equivalent of HTTP - MITM reads + injects messages."}


def rule_no_origin(s):
    if not s.get("ws_users") or s.get("ws_origin_set_callers", 0) > 0:
        return None
    return {"name": f"WebSocket connections ({len(s.get('ws_users') or [])}) without explicit Origin header",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-352", "owasp": "M3:2023",
            "evidence": "No Origin header / Sec-WebSocket-Origin set on WS handshake",
            "remediation": "Set Origin header before connect; server should validate against an allowlist (Cross-Site WebSocket Hijacking defense)."}


WEBSOCKET_ORIGIN_AUDIT_FINDING_RULES = [rule_positive_emit, rule_plain_ws, rule_no_origin]
