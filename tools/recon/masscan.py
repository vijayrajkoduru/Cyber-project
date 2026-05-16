"""recon_masscan -- isolated tool (Kali-style architecture).

Route: /api/recon/masscan
Split from recon_module.py monolith by scripts/split_recon_module.py.
Failure here is quarantined by the healing autoloader -- other tools unaffected.
"""

import asyncio
import base64
import datetime
import hashlib
import re
import socket
from typing import Optional
import requests
import dns.resolver
import dns.asyncresolver
import whois as whois_lib
from fastapi import APIRouter, Depends
from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host, safe_get, web_url,
)
import aiohttp as _aiohttp_crawl
import ssl as _ssl_mod

from fastapi import APIRouter, Depends

router = APIRouter()

_PORT_CATALOG = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
    135:"MS RPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",
    587:"SMTP-submit",993:"IMAPS",995:"POP3S",1433:"MSSQL",1521:"Oracle",
    2375:"Docker API",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5672:"AMQP",
    5900:"VNC",6379:"Redis",8000:"HTTP-alt",8080:"HTTP-proxy",8443:"HTTPS-alt",
    8888:"HTTP-alt",9200:"Elasticsearch",11211:"Memcached",15672:"RabbitMQ UI",
    27017:"MongoDB",
}

async def _scan_open_ports(host):
    ports = sorted(_PORT_CATALOG.keys())
    results = await asyncio.gather(*[_tcp_probe(host, p) for p in ports])
    return [p for p, ok in zip(ports, results) if ok]

async def _tcp_probe(host, port, timeout=1.5):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

@router.post("/api/recon/masscan")
async def recon_masscan(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "ports": [], "skipped_reason": f"Could not resolve {host}: {e}"}
    open_ports = await _scan_open_ports(ip)
    return {"ok": True, "ip": ip,
            "ports": [{"port": p, "proto": "tcp", "state": "open"} for p in open_ports],
            "engine": "python-asyncio"}


def register(app):
    app.include_router(router)
