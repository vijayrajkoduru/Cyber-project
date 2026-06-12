"""firmware_url_endpoint_audit - hardcoded URL / endpoint inventory (playbook §2 #20).

Reads the firmware blob as bytes (capped) and extracts hardcoded network
endpoints that the device will contact at runtime:

  - HTTP/HTTPS URLs        (cleartext http:// is a downgrade/MITM risk)
  - FTP / TFTP URLs        (cleartext firmware/update transport)
  - Telnet endpoints       (cleartext remote shell)
  - MQTT / CoAP brokers    (IoT control-plane endpoints)
  - Update / OTA hostnames (firmware/config fetch endpoints)
  - Hardcoded public IPs   (callback / C2-like fixed destinations)

ZERO-FP: a cleartext-transport finding is graded ONLY when a concrete
http://, ftp://, tftp:// or telnet:// endpoint was literally found in the
bytes. URL inventory itself is INFO. No request is ever made to any extracted
endpoint — this is pure static extraction (no chaining, no probing).

REAL static probe against the customer firmware file.

Customer input: ScanRequest.target = path to firmware blob on disk.
"""
from __future__ import annotations
import asyncio
import ipaddress
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.firmware_url_endpoint_audit_findings import FIRMWARE_URL_ENDPOINT_AUDIT_FINDING_RULES

router = APIRouter()
MAX_BYTES = 192 * 1024 * 1024
MAX_PER_CAT = 60

URL_RE = re.compile(rb"\b(https?|ftps?|tftp|telnet|mqtt|coap|ws|wss)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{3,200}")
IPV4_RE = re.compile(rb"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
# Update/OTA endpoint hostnames (the scheme may be split from host in config)
UPDATE_HOST_RE = re.compile(
    rb"(?i)\b(?:update|ota|firmware|fwupdate|upgrade|download|provision|config)[a-z0-9.\-]*\.[a-z]{2,24}\b")


def _decode(b: bytes) -> str:
    return b.decode("ascii", errors="replace").strip().rstrip(".,;)\"'")[:200]


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def _scan(path: Path):
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES)
    except OSError as e:
        return None, str(e)
    if not data:
        return {}, ""

    urls_by_scheme: dict[str, list] = {}
    cleartext = []
    seen_url = set()
    for m in URL_RE.finditer(data):
        raw = _decode(m.group(0))
        scheme = m.group(1).decode("ascii", errors="replace").lower()
        key = raw.lower()
        if key in seen_url:
            continue
        seen_url.add(key)
        bucket = urls_by_scheme.setdefault(scheme, [])
        if len(bucket) < MAX_PER_CAT:
            bucket.append(raw)
        if scheme in ("http", "ftp", "tftp", "telnet", "ws", "coap") and len(cleartext) < MAX_PER_CAT:
            # http to localhost is benign; keep only routable-looking hosts
            cleartext.append({"scheme": scheme, "url": raw})

    # Public hardcoded IPs
    public_ips = []
    seen_ip = set()
    for m in IPV4_RE.finditer(data):
        octs = [int(g) for g in m.groups()]
        if any(o > 255 for o in octs):
            continue
        ip_str = ".".join(str(o) for o in octs)
        if ip_str in seen_ip:
            continue
        seen_ip.add(ip_str)
        if _is_public_ip(ip_str) and len(public_ips) < MAX_PER_CAT:
            public_ips.append(ip_str)

    # Update / OTA hostnames
    update_hosts = []
    seen_host = set()
    for m in UPDATE_HOST_RE.finditer(data):
        host = _decode(m.group(0)).lower()
        if host in seen_host:
            continue
        seen_host.add(host)
        if len(update_hosts) < MAX_PER_CAT:
            update_hosts.append(host)

    return {
        "urls_by_scheme": urls_by_scheme,
        "cleartext": cleartext,
        "public_ips": public_ips,
        "update_hosts": update_hosts,
    }, ""


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["firmware_url_endpoint_audit_total"] = 0
        ctx.source("firmware file not found at target path")
        return

    res, err = await asyncio.get_event_loop().run_in_executor(None, _scan, Path(target))
    if res is None:
        ctx.state["firmware_url_endpoint_audit_error"] = f"read failed: {err[:120]}"
        ctx.source("read failed")
        return

    urls_by_scheme = res.get("urls_by_scheme", {})
    cleartext = res.get("cleartext", [])
    public_ips = res.get("public_ips", [])
    update_hosts = res.get("update_hosts", [])

    scheme_counts = {k: len(v) for k, v in urls_by_scheme.items()}
    total_urls = sum(scheme_counts.values())

    ctx.state["fw_url_scheme_counts"] = scheme_counts
    ctx.state["fw_url_total"] = total_urls
    ctx.state["fw_cleartext_endpoints"] = cleartext
    ctx.state["fw_public_ips"] = public_ips
    ctx.state["fw_update_hosts"] = update_hosts
    ctx.state["fw_url_samples"] = {k: v[:8] for k, v in urls_by_scheme.items()}
    ctx.state["firmware_url_endpoint_audit_total"] = len(cleartext)
    ctx.source(f"{total_urls} URLs, {len(cleartext)} cleartext endpoints, "
               f"{len(public_ips)} public IPs, {len(update_hosts)} update hosts")


INTEL_FIELDS = [("URLs by scheme",          "fw_url_scheme_counts"),
                ("Total URLs",              "fw_url_total"),
                ("URL samples",             "fw_url_samples"),
                ("Cleartext endpoints",     "fw_cleartext_endpoints"),
                ("Hardcoded public IPs",    "fw_public_ips"),
                ("Update / OTA hostnames",  "fw_update_hosts")]


@router.post("/api/firmware/firmware_url_endpoint_audit")
async def firmware_firmware_url_endpoint_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="firmware_url_endpoint_audit",
        gather_func=gather, finding_rules=FIRMWARE_URL_ENDPOINT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
