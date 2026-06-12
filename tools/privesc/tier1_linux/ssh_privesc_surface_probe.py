"""ssh_privesc_surface_probe - SSH banner grab + privesc-surface baseline.

REAL, credential-LESS remote probe. Opens a TCP connection to the SSH port
and reads the protocol banner the server volunteers (RFC 4253 — the server
sends its identification string BEFORE any authentication). From that banner
we parse:

  - the OpenSSH version (e.g. "OpenSSH_7.2p2")     -> EOL check (floor 7.4)
  - the OS distro tag (e.g. "Ubuntu-4ubuntu2.10")  -> fingerprint context

A graded severity (LOW) is emitted ONLY when an OpenSSH version was ACTUALLY
parsed from the banner AND it is below the maintained floor (7.4). That is a
direct observation of an unmaintained SSH stack, so the finding is stamped
verified_exploit=True — it does NOT assert any specific privesc CVE.

Everything else in this module's catalogue (LinPEAS, SUID/caps, sudo policy,
kernel CVEs) requires an authenticated on-host foothold and is surfaced as
honest [ADVISORY-BY-DESIGN] INFO — never a graded severity. See
tools/_payloads/ssh_privesc_surface_probe_findings.py.

This probe reads ONLY the banner. It does NOT authenticate, send payloads,
exploit, or chain into another scanner. On any error it degrades to a clean
INFO via the finding rules.

Customer input via ScanRequest.options:
  - target              = host/IP (ctx.host)
  - options.port        = SSH port override (default 22)
  - options.timeout_sec = TCP/banner read cap (default 8, clamped 3..20)
"""
from __future__ import annotations
import asyncio
import re
import socket
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.ssh_privesc_surface_probe_findings import (
    SSH_PRIVESC_SURFACE_PROBE_FINDING_RULES,
)

router = APIRouter()

DEFAULT_TIMEOUT = 8
# OpenSSH maintained floor. Releases below 7.4 (Dec 2016) are end-of-life and
# their base OS image is almost certainly unpatched (kernel/sudo/polkit too).
OPENSSH_EOL_FLOOR = (7, 4)

# RFC 4253 server-id: "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10"
_RE_OPENSSH = re.compile(r"OpenSSH[_-](\d+)\.(\d+)(?:p(\d+))?", re.IGNORECASE)
# Trailing comment after the software string carries the distro tag.
_RE_DISTRO_TAG = re.compile(r"OpenSSH[_-][\w.]+\s+([\w.\-+~]+)", re.IGNORECASE)


class SshPrivescSurfaceProbeRequest(ScanRequest):
    options: Optional[dict] = None


def _grab_banner(target: str, port: int, timeout: float) -> str:
    """Open a TCP socket and read the SSH identification string the server
    volunteers before auth. Blocking — call inside run_in_executor.

    Returns the decoded banner (possibly empty). Raises on connect/timeout
    so the caller can record a clean error.
    """
    sock = socket.create_connection((target, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        chunks = []
        # The banner is a single CRLF-terminated line, but some servers emit
        # pre-auth notices first; read a bounded amount and stop at the first
        # SSH- line.
        deadline_bytes = 4096
        total = 0
        while total < deadline_bytes:
            try:
                data = sock.recv(512)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if b"\n" in data:
                break
        raw = b"".join(chunks).decode("utf-8", errors="ignore")
        for line in raw.splitlines():
            if line.startswith("SSH-"):
                return line.strip()
        return raw.strip()
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _parse_openssh_version(banner: str) -> Optional[tuple[int, int, int]]:
    m = _RE_OPENSSH.search(banner or "")
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    return (major, minor, patch)


def _parse_distro_tag(banner: str) -> str:
    m = _RE_DISTRO_TAG.search(banner or "")
    return m.group(1)[:80] if m else ""


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["sshpe_no_target"] = True
        ctx.source("no-target")
        return

    opts = ctx.state.get("_options") or {}
    port = int(opts.get("port") or 22)
    timeout = min(max(float(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 3), 20)
    ctx.state["sshpe_target"] = f"{target}:{port}"

    loop = asyncio.get_event_loop()
    try:
        banner = await asyncio.wait_for(
            loop.run_in_executor(None, _grab_banner, target, port, timeout),
            timeout=timeout + 5,
        )
    except asyncio.TimeoutError:
        ctx.state["sshpe_error"] = f"SSH banner read timed out after {timeout}s"
        ctx.state["sshpe_ran"] = True
        ctx.source(f"timeout @ {timeout}s")
        return
    except Exception as e:
        ctx.state["sshpe_error"] = str(e)[:200]
        ctx.state["sshpe_ran"] = True
        ctx.source(f"connect failed: {str(e)[:80]}")
        return

    ctx.state["sshpe_ran"] = True

    if not banner or not banner.startswith("SSH-"):
        ctx.state["sshpe_error"] = (
            f"no SSH identification string (read: '{banner[:80]}')"
            if banner else "no SSH identification string received"
        )
        ctx.source("no SSH banner")
        return

    ctx.state["sshpe_banner"] = banner[:200]

    ver = _parse_openssh_version(banner)
    if ver:
        ctx.state["sshpe_openssh_version"] = f"{ver[0]}.{ver[1]}" + (
            f"p{ver[2]}" if ver[2] else ""
        )
        # EOL ONLY when a real version was parsed AND it is below the floor.
        if (ver[0], ver[1]) < OPENSSH_EOL_FLOOR:
            ctx.state["sshpe_openssh_eol"] = True

    distro = _parse_distro_tag(banner)
    if distro:
        ctx.state["sshpe_distro_tag"] = distro

    ctx.source(
        f"SSH banner: {banner[:60]} (OpenSSH="
        f"{ctx.state.get('sshpe_openssh_version', 'unparsed')}, "
        f"eol={bool(ctx.state.get('sshpe_openssh_eol'))})"
    )


INTEL_FIELDS = [
    ("SSH target",          "sshpe_target"),
    ("SSH banner",          "sshpe_banner"),
    ("OpenSSH version",     "sshpe_openssh_version"),
    ("OpenSSH end-of-life", "sshpe_openssh_eol"),
    ("OS distro tag",       "sshpe_distro_tag"),
]


@router.post("/api/privesc/ssh_privesc_surface_probe")
async def privesc_ssh_privesc_surface_probe(req: SshPrivescSurfaceProbeRequest,
                                            _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="ssh_privesc_surface_probe",
        gather_func=_gather_with_options,
        finding_rules=SSH_PRIVESC_SURFACE_PROBE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
