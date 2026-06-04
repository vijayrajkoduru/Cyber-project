"""suid_binary_audit - SUID enum + GTFOBins cross-reference (playbook §4 #52).

SSHes to ctx.host with customer-supplied creds, runs
`find / -perm -4000 -type f 2>/dev/null` to enumerate SUID-root binaries,
then cross-references each binary's basename against the local GTFOBins
mirror at /opt/gtfobins/_gtfobins/<binary>.md. Any GTFOBins match = CRITICAL
(instant root); non-default SUIDs not in the safe baseline = HIGH.

Customer input via ScanRequest.options:
  - target              = SSH host/IP (ctx.host)
  - options.username    = SSH username (required)
  - options.password    = SSH password (required OR options.ssh_key)
  - options.ssh_key     = OpenSSH/PEM private key string (alt to password)
  - options.port        = SSH port override (default 22)
  - options.timeout_sec = wall-clock cap (default 60)
"""
from __future__ import annotations
import asyncio
import io
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.suid_binary_audit_findings import (
    SUID_BINARY_AUDIT_FINDING_RULES,
    SAFE_SUID_BASENAMES,
)

router = APIRouter()

GTFOBINS_DIR = "/opt/gtfobins/_gtfobins"
DEFAULT_TIMEOUT = 60


class SuidBinaryAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _gtfobins_index() -> set[str]:
    """Set of GTFOBins binary names from /opt/gtfobins/_gtfobins/*.md.
    Files are named after the binary (e.g. find.md, vim.md). Returns
    lowercased basenames without the .md extension."""
    p = Path(GTFOBINS_DIR)
    if not p.is_dir():
        return set()
    return {f.stem.lower() for f in p.glob("*.md") if f.is_file()}


def _connect(target: str, port: int, username: str, password: Optional[str],
             ssh_key: Optional[str], timeout: int):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = {
        "hostname": target, "port": port, "username": username,
        "timeout": min(timeout, 30), "auth_timeout": min(timeout, 30),
        "banner_timeout": min(timeout, 30),
        "look_for_keys": False, "allow_agent": False,
    }
    if ssh_key:
        key_obj = None
        for keycls in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key, paramiko.DSSKey):
            try:
                key_obj = keycls.from_private_key(io.StringIO(ssh_key))
                break
            except Exception:
                continue
        if not key_obj:
            raise ValueError("ssh_key did not parse")
        kw["pkey"] = key_obj
    else:
        kw["password"] = password
    client.connect(**kw)
    return client


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["suid_no_target"] = True
        ctx.source("no-target")
        return

    try:
        import paramiko  # noqa: F401
    except ImportError:
        ctx.state["suid_ssh_error"] = "paramiko not installed"
        ctx.source("paramiko missing")
        return

    opts = ctx.state.get("_options") or {}
    username = (opts.get("username") or "").strip()
    password = opts.get("password") or ""
    ssh_key = (opts.get("ssh_key") or "").strip()

    if not username or (not password and not ssh_key):
        ctx.state["suid_no_creds"] = True
        ctx.source("missing username + password/ssh_key")
        return

    port = int(opts.get("port") or 22)
    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 15), 180)

    loop = asyncio.get_event_loop()
    client = None
    try:
        client = await loop.run_in_executor(
            None,
            lambda: _connect(target, port, username, password or None,
                              ssh_key or None, timeout),
        )
    except Exception as e:
        ctx.state["suid_ssh_error"] = str(e)[:200]
        ctx.source(f"SSH connect failed: {str(e)[:80]}")
        return

    try:
        # Enumerate SUID binaries; -xdev keeps it bounded by skipping bind-mounts.
        cmd = ("find / -xdev \\( -path /proc -o -path /sys -o -path /dev \\) "
               "-prune -o -perm -4000 -type f -print 2>/dev/null")

        def _run():
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            out = stdout.read()
            err = stderr.read()
            try: stdin.close()
            except Exception: pass
            return out, err

        try:
            stdout_b, _ = await asyncio.wait_for(
                loop.run_in_executor(None, _run),
                timeout=timeout + 15,
            )
        except asyncio.TimeoutError:
            ctx.state["suid_ssh_error"] = f"SUID find timed out after {timeout}s"
            ctx.source(f"timeout @ {timeout}s")
            return

        out = (stdout_b or b"").decode("utf-8", errors="ignore")
        suid_paths = [line.strip() for line in out.splitlines()
                       if line.strip().startswith("/")]

        gtfo = _gtfobins_index()
        if not gtfo:
            ctx.state["suid_gtfobins_db_missing"] = True

        gtfobins_hits: list[dict] = []
        unusual: list[str] = []
        for path in suid_paths:
            base = os.path.basename(path).lower()
            if gtfo and base in gtfo:
                gtfobins_hits.append({"binary": base, "path": path})
            elif base not in SAFE_SUID_BASENAMES:
                unusual.append(path)

        ctx.state["suid_paths"] = suid_paths[:200]
        ctx.state["suid_total_found"] = len(suid_paths)
        ctx.state["suid_gtfobins_hits"] = gtfobins_hits[:200]
        ctx.state["suid_unusual"] = unusual[:200]
        ctx.source(
            f"SUID inventory: {len(suid_paths)} found, "
            f"{len(gtfobins_hits)} GTFOBins-exploitable, "
            f"{len(unusual)} non-default"
        )

    finally:
        try:
            client.close()
        except Exception:
            pass


INTEL_FIELDS = [
    ("SUID binaries found",   "suid_total_found"),
    ("All SUID paths",        "suid_paths"),
    ("GTFOBins-exploitable",  "suid_gtfobins_hits"),
    ("Unusual (non-default)", "suid_unusual"),
]


@router.post("/api/privesc/suid_binary_audit")
async def privesc_suid_binary_audit(req: SuidBinaryAuditRequest,
                                     _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="suid_binary_audit",
        gather_func=_gather_with_options,
        finding_rules=SUID_BINARY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
