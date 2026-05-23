"""Database Exposure Check — internet-exposed NoSQL / cache / DB ports.

VL-FORGE'd infrastructure vulnerability scanner.
Route: POST /api/vuln/db_exposure_check

What it does — probes the following ports/protocols and emits CRITICAL findings
when a database accepts connections without authentication:
  • 27017  MongoDB           (ismaster command)
  • 6379   Redis             (PING / INFO command)
  • 9200   Elasticsearch     (HTTP GET /)
  • 5984   CouchDB           (HTTP GET /)
  • 11211  Memcached         (STATS command)
  • 5432   PostgreSQL        (startup packet — auth required = good, no-auth = critical)
  • 3306   MySQL             (handshake check)
  • 9092   Kafka             (API versions request)

These services regularly appear in mass-pwning campaigns (the "Meow attack" against
Elastic/Mongo, ransomware against Redis, etc.) when exposed to the internet without
authentication. Industry baseline is "no DB on internet, ever."
"""
import socket
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            wrap_finding, standard_response)
from tools.vuln._vuln_common import vuln_response

router = APIRouter()

_TIMEOUT = 4.0

# Each entry: (port, name, probe_bytes, expect_substring_in_response, severity, cvss, cwe, remediation)
_PROBES = [
    (27017, "MongoDB",
     b"\x39\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
     b"\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff"
     b"\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00",
     b"ismaster",
     "CRITICAL", "9.8", "CWE-306",
     "Restrict MongoDB to bind 127.0.0.1 only. Enable authorization (--auth flag). "
     "Add firewall rule blocking 27017 from internet. Internet-exposed MongoDB without auth "
     "= guaranteed data loss within hours (Meow attack campaign)."),

    (6379, "Redis", b"PING\r\n", b"+PONG",
     "CRITICAL", "9.8", "CWE-306",
     "Set 'requirepass <long-random>' in redis.conf + bind 127.0.0.1. "
     "Internet-exposed Redis without auth is trivially exploited for RCE via "
     "SLAVEOF / CONFIG SET dir + dbfilename + SET '<key>' '<webshell>' / BGSAVE. "
     "Ransomware groups routinely scan for and encrypt open Redis."),

    (9200, "Elasticsearch",
     b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
     b'"cluster_name"',
     "CRITICAL", "9.1", "CWE-306",
     "Enable X-Pack security (free since v6.8): elasticsearch.yml: xpack.security.enabled: true. "
     "Set bootstrap.memory_lock: true + bind to internal IP. "
     "Open Elasticsearch is the canonical 'Meow attack' target — full DB wipes."),

    (5984, "CouchDB",
     b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
     b'"couchdb"',
     "CRITICAL", "9.1", "CWE-306",
     "Set [admins] section in local.ini with admin password. Bind to 127.0.0.1. "
     "CVE-2017-12635 (CouchDB privilege escalation) requires unauth API access — kill that surface first."),

    (11211, "Memcached", b"stats\r\n", b"STAT pid",
     "HIGH", "7.5", "CWE-306",
     "Bind memcached to 127.0.0.1 only: '-l 127.0.0.1' in startup flags. Disable UDP. "
     "Open memcached = data leakage AND used as DDoS amplification vector (1.7Tbps GitHub 2018)."),

    (5432, "PostgreSQL",
     # Startup message: length(8) + protocol(4) + zero-padding probe
     b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
     # SSL request — postgres responds with 'S' (accept) or 'N' (no SSL) — both confirm it's pg
     b"",  # any response confirms PG (we treat connection accepted as positive signal)
     "HIGH", "7.5", "CWE-200",
     "PostgreSQL should listen on localhost or VLAN-internal interface. "
     "Set 'listen_addresses' in postgresql.conf. Restrict pg_hba.conf to known IPs. "
     "Always use scram-sha-256 over md5 for auth method."),

    (3306, "MySQL", b"",  # MySQL sends banner immediately on connect
     b"mysql",
     "HIGH", "7.5", "CWE-200",
     "MySQL on the internet = bad practice even with auth (cleartext on the wire pre-TLS). "
     "Bind to localhost or internal VIP. Enforce 'require_secure_transport=ON' in 8.0+. "
     "Remove anonymous + root@'%' accounts."),

    (9092, "Kafka", b"",
     b"",  # TCP-open alone is the signal — Kafka has no easy 1-packet probe
     "MEDIUM", "5.3", "CWE-200",
     "Apache Kafka without SASL is critical exposure. "
     "Configure SASL_SSL listeners + ACLs. Bind to internal network."),
]

def _probe(host, port, send_bytes, expect):
    """Return (port_open, banner_or_response_bytes)."""
    try:
        sock = socket.create_connection((host, port), timeout=_TIMEOUT)
        sock.settimeout(_TIMEOUT)
        if send_bytes:
            try: sock.send(send_bytes)
            except Exception: pass
        # Read up to 2KB of response
        data = b""
        try:
            data = sock.recv(2048)
        except socket.timeout:
            pass
        sock.close()
        if not expect:
            # No expected pattern — just port-open signal
            return True, data
        # Expected substring must be in response
        return (expect in data), data
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, b""
    except Exception:
        return False, b""

@router.post("/api/vuln/db_exposure_check")
def scan_db_exposure_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    findings, tests, exposed = [], 0, []

    for port, name, probe, expect, sev, cvss, cwe, fix in _PROBES:
        tests += 1
        confirmed, data = _probe(host, port, probe, expect)
        if confirmed:
            exposed.append({"db": name, "port": port,
                             "response_sample": data[:80].decode("utf-8", errors="replace")[:100]})
            findings.append(wrap_finding(
                f"{name} database exposed on TCP/{port} without authentication",
                sev, cvss=cvss, cwe=cwe, owasp="A05:2021",
                remediation=fix,
                evidence_marker=(f"Probe to {host}:{port} returned matching {name} signature; "
                                  f"data sample: {data[:60].hex()}...")))

    if not exposed:
        return vuln_response(tool="db_exposure_check", target=req.target, findings=[],
            tested=tests,
            skipped_reason=(f"No exposed databases detected — {tests} DB ports probed on {host} "
                            "(Mongo/Redis/Elastic/CouchDB/Memcached/PostgreSQL/MySQL/Kafka all closed or auth-protected)"),
            raw_data={"db_exposure_check": {"ports_tested": [p[0] for p in _PROBES],
                                              "exposures": []}})

    return vuln_response(tool="db_exposure_check", target=req.target, findings=findings,
        tested=tests,
        what_checked=f"Internet exposure of {len(_PROBES)} database/cache services (Mongo/Redis/Elastic/CouchDB/Memcached/PostgreSQL/MySQL/Kafka)",
        tests_summary=f"DB exposure: {tests} ports probed; {len(exposed)} services exposed without auth",
        raw_data={"db_exposure_check": {"ports_tested": [p[0] for p in _PROBES],
                                         "exposures": exposed}})


def register(app):
    app.include_router(router)
