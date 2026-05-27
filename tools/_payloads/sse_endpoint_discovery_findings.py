"""sse_endpoint_discovery — findings (⭐ Recon §5 #85)."""
def rule_positive_emit(s):
    if s.get("sse_endpoint_discovery_total"): return None
    return {"name": "No SSE endpoints detected on common paths", "severity": "POSITIVE",
            "evidence": "no text/event-stream Content-Type on any probed path",
            "remediation": "Maintain — apps without SSE have one fewer real-time attack surface.",
            "cwe": "CWE-200", "owasp": "API3:2023"}

def rule_sse_endpoint(s):
    eps = s.get("sse_endpoints") or []
    if not eps: return None
    return {"name": f"SSE endpoint(s) discovered — {len(eps)} URL(s)", "severity": "INFO",
            "cwe": "CWE-200", "owasp": "API3:2023",
            "evidence": "; ".join(e["url"] for e in eps[:5]),
            "remediation": "Audit each SSE endpoint for: (1) Origin validation, (2) auth on initial GET, (3) per-user rate limit, (4) sensitive-data filtering in event payload."}

SSE_ENDPOINT_DISCOVERY_FINDING_RULES = [rule_positive_emit, rule_sse_endpoint]
