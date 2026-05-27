"""grpc_reflection_discovery — findings (⭐ Recon §5 #83)."""
def rule_positive_emit(s):
    if s.get("grpc_reflection_discovery_total"): return None
    return {"name": "No gRPC services detected on common ports", "severity": "POSITIVE",
            "evidence": "no HTTP/2 ALPN match on 50051 / 9090 / 8443 / 443 / 80 / 9091",
            "remediation": "Continue exposing gRPC only on internal networks if used.",
            "cwe": "CWE-200", "owasp": "API3:2023"}

def rule_grpc_endpoint(s):
    eps = s.get("grpc_endpoints") or []
    if not eps: return None
    detail = "; ".join(f"port {e['port']}{' (TLS)' if e['tls'] else ''}{' alpn=' + e['alpn'] if e.get('alpn') else ''}" for e in eps[:5])
    return {"name": f"gRPC service(s) detected — {len(eps)} endpoint(s)", "severity": "INFO",
            "cwe": "CWE-200", "owasp": "API3:2023", "evidence": detail,
            "remediation": "Audit whether gRPC Server Reflection is enabled. Use `grpcurl -plaintext <host>:<port> list`. Disable reflection in production."}

GRPC_REFLECTION_DISCOVERY_FINDING_RULES = [rule_positive_emit, rule_grpc_endpoint]
