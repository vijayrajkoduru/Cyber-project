"""Exposed unauthenticated datastores (Redis/Memcached/Elasticsearch/CouchDB/MongoDB).
VL-FORGE Vuln tier1 - playbook §1 #11/#12."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import tcp_probe

router = APIRouter()

_PROBES = [
    ("redis", 6379, b"PING\r\n", b"PONG"),
    ("memcached", 11211, b"stats\r\n", b"STAT "),
    ("elastic", 9200, b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", b"cluster_name"),
    ("couchdb", 5984, b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", b"couchdb"),
    ("mongo", 27017, b"", b""),
]


async def gather(ctx):
    host = str(ctx.host)

    async def _p(name, port, payload, marker):
        op, data = await asyncio.to_thread(tcp_probe, host, port, payload, 512, 4)
        return name, port, op, (bool(marker) and marker in data)

    results = await asyncio.gather(*[_p(*p) for p in _PROBES])
    tested = 0
    for name, port, op, unauth in results:
        tested += 1
        if op:
            ctx.source(f"tcp-{port}")
            ctx.state[f"{name}_open"] = True
            ctx.state[f"{name}_unauth"] = unauth
    ctx.state["tested"] = tested


def _r_redis(s):
    if not s.get("redis_open"):
        return None
    if s.get("redis_unauth"):
        return {"name": "Redis exposed WITHOUT authentication (6379)", "severity": "CRITICAL", "cvss": 9.8,
                "cwe": "CWE-306", "evidence": "PING returned +PONG with no AUTH",
                "remediation": "Bind to localhost, set requirepass, enable protected-mode."}
    return {"name": "Redis port 6379 reachable", "severity": "MEDIUM", "cwe": "CWE-668",
            "evidence": "TCP 6379 open", "remediation": "Restrict 6379 to trusted hosts; require AUTH."}


def _r_memcached(s):
    if not s.get("memcached_open"):
        return None
    if s.get("memcached_unauth"):
        return {"name": "Memcached exposed WITHOUT auth (11211)", "severity": "HIGH", "cvss": 7.5,
                "cwe": "CWE-306", "evidence": "stats returned STAT lines",
                "remediation": "Bind to localhost; enable SASL; firewall 11211 (UDP amplification risk)."}
    return {"name": "Memcached port 11211 reachable", "severity": "MEDIUM", "cwe": "CWE-668",
            "evidence": "TCP 11211 open", "remediation": "Restrict 11211."}


def _r_elastic(s):
    if not s.get("elastic_open"):
        return None
    if s.get("elastic_unauth"):
        return {"name": "Elasticsearch exposed WITHOUT auth (9200)", "severity": "HIGH", "cvss": 7.5,
                "cwe": "CWE-306", "evidence": "cluster info returned unauthenticated",
                "remediation": "Enable security/auth; firewall 9200."}
    return {"name": "Elasticsearch port 9200 reachable", "severity": "MEDIUM", "cwe": "CWE-668",
            "evidence": "TCP 9200 open", "remediation": "Restrict 9200; require auth."}


def _r_couchdb(s):
    if not s.get("couchdb_open"):
        return None
    unauth = s.get("couchdb_unauth")
    return {"name": "CouchDB exposed (5984)" + (" - unauthenticated" if unauth else ""),
            "severity": "HIGH" if unauth else "MEDIUM", "cwe": "CWE-306",
            "evidence": "TCP 5984 responded", "remediation": "Require admin auth; firewall 5984."}


def _r_mongo(s):
    if not s.get("mongo_open"):
        return None
    return {"name": "MongoDB port 27017 reachable", "severity": "MEDIUM", "cwe": "CWE-668",
            "evidence": "TCP 27017 open - verify authorization is enabled",
            "remediation": "Enable authorization; bind to localhost; firewall 27017."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1:
        return None
    if any(s.get(f"{n}_open") for n in ("redis", "memcached", "elastic", "couchdb", "mongo")):
        return None
    return {"name": "No exposed datastores detected", "severity": "POSITIVE",
            "evidence": "Redis/Memcached/Elasticsearch/CouchDB/MongoDB ports closed or filtered."}


FINDING_RULES = [_r_redis, _r_memcached, _r_elastic, _r_couchdb, _r_mongo, _r_clean]
INTEL_FIELDS = [("Datastore ports probed", "tested")]


@router.post("/api/vuln/exposed_datastores")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="exposed_datastores",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
