"""websocket_endpoint_discovery — findings (⭐ Recon §5 #84)."""
def rule_positive_emit(s):
    if s.get("websocket_endpoint_discovery_total"): return None
    return {"name": "No WebSocket endpoints discovered on common paths", "severity": "POSITIVE",
            "evidence": "no HTTP 101 Switching Protocols response on any probed path",
            "remediation": "Maintain — apps without WebSockets have a smaller real-time attack surface.",
            "cwe": "CWE-200", "owasp": "API3:2023"}

def rule_ws_endpoint(s):
    eps = s.get("ws_endpoints") or []
    if not eps: return None
    return {"name": f"WebSocket endpoint(s) discovered — {len(eps)} URL(s)", "severity": "INFO",
            "cwe": "CWE-200", "owasp": "API3:2023",
            "evidence": "; ".join(e["url"] for e in eps[:5]),
            "remediation": "Audit each WS endpoint for: (1) Origin validation, (2) post-upgrade auth, (3) message-level input validation, (4) rate limiting."}

WEBSOCKET_ENDPOINT_DISCOVERY_FINDING_RULES = [rule_positive_emit, rule_ws_endpoint]
