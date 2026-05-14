"""Port scan — TCP connect scan against common service ports.

Active verification: full TCP handshake to each catalog port. A port
is reported OPEN only on successful connect. Severity reflects the
risk of internet exposure for the identified service:

  CRITICAL — exposed databases / cache / queues / Docker API / Telnet
  HIGH     — remote admin (SSH/RDP/VNC), file shares (SMB/FTP/NFS)
  MEDIUM   — message brokers / IoT protocols
  LOW      — mail / auxiliary
  INFO     — public web (80,443,8080,8443) — excluded from findings
"""
import asyncio
import socket
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host,
    wrap_finding, standard_response,
)

router = APIRouter()


PORT_CATALOG = {
    21:    ("FTP",            "HIGH",     "CWE-200"),
    22:    ("SSH",            "HIGH",     "CWE-200"),
    23:    ("Telnet",         "CRITICAL", "CWE-319"),
    25:    ("SMTP",           "LOW",      "CWE-200"),
    53:    ("DNS",            "INFO",     "CWE-200"),
    80:    ("HTTP",           "INFO",     None),
    110:   ("POP3",           "LOW",      "CWE-200"),
    135:   ("MS RPC",         "HIGH",     "CWE-200"),
    139:   ("NetBIOS",        "HIGH",     "CWE-200"),
    143:   ("IMAP",           "LOW",      "CWE-200"),
    443:   ("HTTPS",          "INFO",     None),
    445:   ("SMB",            "HIGH",     "CWE-200"),
    465:   ("SMTPS",          "LOW",      None),
    587:   ("SMTP-submit",    "LOW",      None),
    993:   ("IMAPS",          "LOW",      None),
    995:   ("POP3S",          "LOW",      None),
    1433:  ("MSSQL",          "CRITICAL", "CWE-668"),
    1521:  ("Oracle",         "CRITICAL", "CWE-668"),
    1883:  ("MQTT",           "MEDIUM",   "CWE-306"),
    2049:  ("NFS",            "HIGH",     "CWE-668"),
    2375:  ("Docker API",     "CRITICAL", "CWE-306"),
    2376:  ("Docker API TLS", "CRITICAL", "CWE-306"),
    3306:  ("MySQL",          "CRITICAL", "CWE-668"),
    3389:  ("RDP",            "HIGH",     "CWE-200"),
    5432:  ("PostgreSQL",     "CRITICAL", "CWE-668"),
    5601:  ("Kibana",         "HIGH",     "CWE-200"),
    5672:  ("AMQP",           "MEDIUM",   "CWE-306"),
    5900:  ("VNC",            "HIGH",     "CWE-306"),
    5984:  ("CouchDB",        "CRITICAL", "CWE-668"),
    6379:  ("Redis",          "CRITICAL", "CWE-668"),
    7474:  ("Neo4j",          "CRITICAL", "CWE-668"),
    8000:  ("HTTP-alt",       "INFO",     None),
    8080:  ("HTTP-proxy",     "INFO",     None),
    8443:  ("HTTPS-alt",      "INFO",     None),
    8888:  ("HTTP-alt",       "INFO",     None),
    9000:  ("HTTP-alt",       "INFO",     None),
    9200:  ("Elasticsearch",  "CRITICAL", "CWE-668"),
    9300:  ("ES transport",   "HIGH",     "CWE-668"),
    11211: ("Memcached",      "CRITICAL", "CWE-668"),
    15672: ("RabbitMQ UI",    "HIGH",     "CWE-200"),
    27017: ("MongoDB",        "CRITICAL", "CWE-668"),
    27018: ("MongoDB shard",  "CRITICAL", "CWE-668"),
}


async def _probe(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        fut = asyncio.open_connection(host, port)
        _, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


@router.post("/api/scan/portscan")
async def scan_portscan(req: ScanRequest, _=Depends(verify_scan_quota)):
    target = recon_host(req.target)

    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        return standard_response(
            tool="portscan", target=target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"DNS resolution failed for {target}: {e}",
        )

    ports = sorted(PORT_CATALOG.keys())
    results = await asyncio.gather(*[_probe(ip, p) for p in ports])
    open_ports = [p for p, ok in zip(ports, results) if ok]

    findings = []
    for port in open_ports:
        svc, sev, cwe = PORT_CATALOG[port]
        if sev == "INFO":
            continue
        kw = {
            "evidence_marker": f"{target} ({ip}):{port}/tcp OPEN",
            "tests_performed": 1,
        }
        if cwe:
            kw["cwe"] = cwe
        if sev == "CRITICAL":
            kw["owasp"] = "A05:2021"
            kw["remediation"] = (
                f"{svc} on port {port}/tcp is exposed to the public internet. "
                "Bind to localhost or restrict access via firewall / security group; "
                "require authentication and TLS for management interfaces."
            )
        elif sev == "HIGH":
            kw["remediation"] = (
                f"{svc} on port {port}/tcp is reachable from the internet. "
                "Restrict access to a bastion / VPN and enforce MFA."
            )
        else:
            kw["remediation"] = (
                f"{svc} on port {port}/tcp is reachable. "
                "Confirm exposure is intentional and protected."
            )
        findings.append(wrap_finding(
            f"{svc} exposed on port {port}/tcp",
            sev, **kw,
        ))

    return standard_response(
        tool="portscan", target=target, findings=findings,
        tests_performed=len(ports),
        tests_summary=f"Probed {len(ports)} common service ports; {len(open_ports)} open",
        raw_data={
            "ip": ip,
            "ports_probed": ports,
            "ports_open": [
                {"port": p, "service": PORT_CATALOG[p][0],
                 "severity": PORT_CATALOG[p][1]}
                for p in open_ports
            ],
        },
    )


def register(app):
    app.include_router(router)
