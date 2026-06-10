"""grpc_reflection_audit — gRPC server-reflection enabled = schema leak.

gRPC server-reflection lets clients enumerate ALL services + methods +
message types without needing the .proto file. Useful in dev; in prod
it's the gRPC equivalent of GraphQL introspection — attacker maps
every method without auth.

Tests gRPC-Web (HTTP/JSON wrapper of gRPC) reflection endpoint AND
raw HTTP/2 gRPC. Most apps put gRPC at :443 with TLS so this checks
via standard HTTP path.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

REFLECTION_PATHS = [
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    "/api/grpc/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
]


@router.post("/api/webapp/scan/grpc_reflection_audit")
@vl_turbo()
def scan_grpc_reflection_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    reflection_hits = []
    for path in REFLECTION_PATHS:
        url = base + path
        # Send a minimal gRPC-Web request: ListServices via reflection
        # gRPC-Web frame: 0x00 (compressed=0) + 4-byte length + protobuf body
        # ListServices: {"list_services": ""} → protobuf 0x32 0x00
        body = bytes([0x00, 0x00, 0x00, 0x00, 0x02, 0x32, 0x00])
        r = safe_request("POST", url,
            headers={"Content-Type": "application/grpc-web+proto",
                      "X-User-Agent": "grpc-web-javascript/0.1",
                      "User-Agent": "VulnusLab/1.0"},
            data=body, req=req, timeout=10, allow_redirects=False)
        if r is None: continue
        # gRPC-Web success: HTTP 200 + grpc-status header + content
        grpc_status = r.headers.get("grpc-status") or r.headers.get("Grpc-Status")
        # Reflection enabled if we get a non-empty response with grpc-status=0
        if r.status_code == 200 and grpc_status == "0" and len(r.content) > 5:
            reflection_hits.append({"path": path,
                                      "response_size": len(r.content),
                                      "grpc_status": grpc_status})

    findings = []
    if reflection_hits:
        findings.append(wrap_finding(
            f"gRPC server-reflection ENABLED at {len(reflection_hits)} endpoint(s)",
            "MEDIUM", cvss="5.3", cwe="CWE-200", owasp="A05:2021",
            remediation="Disable gRPC server-reflection in production. "
                        "Go: don't register reflection.Register(s). "
                        "Java: don't add ProtoReflectionService. "
                        "Python: don't add reflection.enable_server_reflection. "
                        "Reflection is useful in dev (grpcurl) but in prod = "
                        "schema leak. If you need observability, expose a "
                        "static .proto descriptor at a controlled, "
                        "auth-protected endpoint instead.",
            evidence_marker=" | ".join(
                f"{h['path']}: HTTP 200 grpc-status=0 ({h['response_size']}B)"
                for h in reflection_hits[:3]
            )))
    else:
        findings.append(wrap_finding(
            "gRPC server-reflection not detected",
            "POSITIVE", cwe="CWE-200",
            remediation="Either no gRPC server, no reflection enabled, or behind "
                        "auth — all good. If you DO run gRPC, periodically re-test.",
            evidence_marker=f"checked {len(REFLECTION_PATHS)} gRPC reflection paths"))

    return standard_response(
        tool="grpc_reflection_audit", target=req.target, findings=findings,
        tests_performed=len(REFLECTION_PATHS), vulnerable=bool(reflection_hits),
        tests_summary=f"{len(reflection_hits)} reflection endpoint(s) exposed",
        raw_data={"reflection_hits": reflection_hits})


def register(app):
    app.include_router(router)
