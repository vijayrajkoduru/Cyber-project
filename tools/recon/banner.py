"""recon_banner -- isolated tool (Kali-style architecture).

Route: /api/recon/banner
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

async def _grab_banner(host, port, timeout=3.0):
    is_https = port in (443, 8443)
    is_http  = port in (80, 8000, 8080, 8888) or is_https
    try:
        if is_https:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout,
            )
        if is_http:
            req = (f"GET / HTTP/1.0\r\n"
                   f"Host: {host}\r\n"
                   f"User-Agent: VulnusLab/1.0\r\n"
                   f"Accept: */*\r\n\r\n").encode()
            writer.write(req)
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""

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

@router.post("/api/recon/banner")
async def recon_banner(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "banners": {}, "skipped_reason": f"Could not resolve {host}: {e}"}
    open_ports = await _scan_open_ports(ip)
    banners = {}
    for p in open_ports[:10]:
        b = await _grab_banner(ip, p)
        if b:
            banners[p] = b
    return {"ok": True, "banners": banners}


def register(app):
    app.include_router(router)
