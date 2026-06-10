"""tomcat_ajp_exposure — Tomcat AJP port (8009) public-internet exposure.

Apache JServ Protocol (AJP, default :8009) is the binary backchannel
between front-end (Apache/nginx) and Tomcat. NEVER meant to be
internet-exposed. CVE-2020-1938 (Ghostcat) lets attacker read arbitrary
files in webapp and potentially RCE if app accepts file uploads.

Probes the target's hostname on AJP port. If TCP connects + binary
response, AJP exposed.
"""
import socket
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
AJP_PORT = 8009


@router.post("/api/webapp/scan/tomcat_ajp_exposure")
@vl_turbo()
@vl_verify()
def scan_tomcat_ajp_exposure(req: ScanRequest, payload=Depends(verify_scan_quota)):
    parsed = urlparse(web_url(req.target))
    host = parsed.hostname or req.target
    findings = []
    try:
        sock = socket.create_connection((host, AJP_PORT), timeout=5)
        # Send minimal AJP ping: magic 0x12 0x34 + length + 0x0a
        ajp_ping = b"\x12\x34\x00\x01\x0a"
        sock.sendall(ajp_ping)
        resp = b""
        try:
            sock.settimeout(3)
            resp = sock.recv(64)
        except Exception: pass
        sock.close()
        # AJP response starts with 0xAB 0x00
        if resp.startswith(b"\xab\x00"):
            findings.append(wrap_finding(
                f"AJP port {AJP_PORT} EXPOSED on internet — Ghostcat (CVE-2020-1938)",
                "CRITICAL", cvss="9.8", cwe="CWE-200", owasp="A05:2021",
                remediation="DO NOT expose AJP (port 8009) to the internet. AJP "
                            "trusts ANY caller — Ghostcat lets attacker read "
                            "WEB-INF/web.xml and other webapp internals. Bind "
                            "AJP to 127.0.0.1 only: in Tomcat conf/server.xml "
                            "set <Connector port='8009' address='127.0.0.1' "
                            "secretRequired='true' secret='...' />. Better: "
                            "disable AJP entirely if not using mod_jk.",
                evidence_marker=f"AJP ping → {resp[:8].hex()} (CONFIRMED)"))
        else:
            findings.append(wrap_finding(
                f"Port {AJP_PORT} open but not AJP protocol",
                "INFO", cwe="CWE-200",
                remediation="Some other service on this port.",
                evidence_marker=f"TCP {host}:{AJP_PORT} connected, no AJP response"))
    except (ConnectionRefusedError, socket.timeout, OSError):
        findings.append(wrap_finding(
            f"AJP port {AJP_PORT} not exposed",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain. AJP should remain firewalled to internal-only.",
            evidence_marker=f"TCP {host}:{AJP_PORT} not reachable"))
    return standard_response(
        tool="tomcat_ajp_exposure", target=req.target, findings=findings,
        tests_performed=1,
        vulnerable=any(f.get("severity") == "CRITICAL" for f in findings),
        tests_summary="AJP probe",
        raw_data={"host": host, "port": AJP_PORT})


def register(app):
    app.include_router(router)
