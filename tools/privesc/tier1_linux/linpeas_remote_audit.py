"""linpeas_remote_audit - SSH upload + execute LinPEAS (playbook §1 #1).

Uses paramiko to SSH to ctx.host with customer-supplied creds, uploads
/opt/peass-ng/linPEAS/linpeas.sh to /tmp/.vlp_linpeas.sh, runs `bash
/tmp/.vlp_linpeas.sh -a` (all-checks mode), parses output for
HIGH-severity findings, and deletes the upload in a finally block.

Customer input via ScanRequest.options:
  - target              = SSH host/IP (ctx.host)
  - options.username    = SSH username (required)
  - options.password    = SSH password (required OR provide ssh_key)
  - options.ssh_key     = OpenSSH/PEM private key as string (alternative to password)
  - options.port        = SSH port override (default 22)
  - options.timeout_sec = wall-clock cap for LinPEAS (default 300)
"""
from __future__ import annotations
import asyncio
import io
import os
import re
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.linpeas_remote_audit_findings import (
    LINPEAS_REMOTE_AUDIT_FINDING_RULES,
)

router = APIRouter()

LINPEAS_SCRIPT_PATH = "/opt/peass-ng/linPEAS/linpeas.sh"
REMOTE_UPLOAD_PATH = "/tmp/.vlp_linpeas.sh"
DEFAULT_TIMEOUT = 300


class LinpeasRemoteAuditRequest(ScanRequest):
    options: Optional[dict] = None


# LinPEAS uses ANSI color codes + "[+]" markers. RED entries = HIGH/CRITICAL.
# Reference: https://github.com/peass-ng/PEASS-ng/blob/master/linPEAS/builder/linpeas_parts/
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mK]")
_RED_TAG = "\x1b[1;31m"     # LinPEAS uses bold-red for HIGH
_YELLOW_RED = "\x1b[1;93;41m"  # very-high-confidence findings


# Critical patterns we extract independent of color codes (color codes can
# strip if customer's SSH stream filters them).
_CRITICAL_PATTERNS = [
    (r"shadow.*writable",             "World-writable /etc/shadow"),
    (r"sudo.*NOPASSWD.*\(ALL\)",      "sudo NOPASSWD: ALL grant"),
    (r"docker\.sock.*0[67]7",         "Exposed Docker socket (group read/write)"),
    (r"docker\.sock.*world.writable", "World-writable Docker socket"),
    (r"polkit.*pwnkit",               "PwnKit-vulnerable polkit (CVE-2021-4034)"),
    (r"dirty.?pipe",                  "Kernel vulnerable to DirtyPipe (CVE-2022-0847)"),
    (r"PRELOAD.*env_keep",            "sudoers env_keep retains LD_PRELOAD"),
    (r"capabilities.*cap_setuid",     "cap_setuid+ep granted to non-root binary"),
    (r"capabilities.*cap_sys_admin",  "cap_sys_admin granted to non-root binary"),
]
_HIGH_PATTERNS = [
    (r"PATH.*writable",               "Writable directory in $PATH"),
    (r"no_root_squash",               "NFS export with no_root_squash"),
    (r"PASS=|PASSWORD=|secret=",      "Cleartext credentials in env/cron"),
    (r"\.ssh/id_rsa.*readable",       "SSH private key readable by non-owner"),
    (r"GTFOBins.*found",              "GTFOBins-exploitable SUID binary present"),
    (r"AWS_SECRET|AWS_ACCESS_KEY",    "Cleartext AWS credentials in environment"),
]
_MEDIUM_PATTERNS = [
    (r"kernel.*outdated|old.kernel",  "Outdated kernel version"),
    (r"cron.*writable",               "Writable cron job file"),
    (r"smb.*null",                    "SMB null session permitted"),
]


def _scan_patterns(text: str, patterns: list, severity: str) -> list[dict]:
    out = []
    lower = text.lower()
    for pat, title in patterns:
        if re.search(pat, lower, re.IGNORECASE):
            out.append({"severity": severity, "title": title, "pattern": pat})
    return out


def _connect(target: str, port: int, username: str, password: Optional[str],
             ssh_key: Optional[str], timeout: int):
    """Build a paramiko SSHClient + connect. Returns the client or raises."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kw = {
        "hostname": target,
        "port": port,
        "username": username,
        "timeout": min(timeout, 30),
        "auth_timeout": min(timeout, 30),
        "banner_timeout": min(timeout, 30),
        "look_for_keys": False,
        "allow_agent": False,
    }
    if ssh_key:
        # ssh_key is a private key string; load via StringIO for any format
        key_obj = None
        for keycls in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key, paramiko.DSSKey):
            try:
                key_obj = keycls.from_private_key(io.StringIO(ssh_key))
                break
            except Exception:
                continue
        if not key_obj:
            raise ValueError("ssh_key string did not parse as RSA/ECDSA/Ed25519/DSS")
        connect_kw["pkey"] = key_obj
    else:
        connect_kw["password"] = password
    client.connect(**connect_kw)
    return client


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["linpeas_no_target"] = True
        ctx.source("no-target")
        return

    try:
        import paramiko  # noqa: F401
    except ImportError:
        ctx.state["linpeas_ssh_error"] = "paramiko not installed"
        ctx.source("paramiko missing")
        return

    opts = ctx.state.get("_options") or {}
    username = (opts.get("username") or "").strip()
    password = opts.get("password") or ""
    ssh_key = (opts.get("ssh_key") or "").strip()

    if not username or (not password and not ssh_key):
        ctx.state["linpeas_no_creds"] = True
        ctx.source("missing username + password/ssh_key")
        return

    if not os.path.exists(LINPEAS_SCRIPT_PATH):
        ctx.state["linpeas_script_missing"] = True
        ctx.source(f"{LINPEAS_SCRIPT_PATH} missing")
        return

    port = int(opts.get("port") or 22)
    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 60), 600)
    ctx.state["linpeas_host"] = f"{username}@{target}:{port}"

    # Connect (in a thread — paramiko is blocking).
    loop = asyncio.get_event_loop()
    client = None
    try:
        client = await loop.run_in_executor(
            None,
            lambda: _connect(target, port, username, password or None,
                              ssh_key or None, timeout),
        )
    except Exception as e:
        ctx.state["linpeas_ssh_error"] = str(e)[:200]
        ctx.source(f"SSH connect failed: {str(e)[:80]}")
        return

    try:
        # Upload LinPEAS via SFTP.
        sftp = await loop.run_in_executor(None, client.open_sftp)
        try:
            await loop.run_in_executor(
                None, sftp.put, LINPEAS_SCRIPT_PATH, REMOTE_UPLOAD_PATH)
            await loop.run_in_executor(
                None, sftp.chmod, REMOTE_UPLOAD_PATH, 0o755)
        finally:
            try:
                await loop.run_in_executor(None, sftp.close)
            except Exception:
                pass

        # Run LinPEAS with -a flag (all checks). Pipe through cat to neutralize
        # tty/color terminal detection that can hang under exec_command.
        cmd = f"bash {REMOTE_UPLOAD_PATH} -a -N 2>/dev/null | head -c 2000000"

        def _run():
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout, get_pty=False)
            stdout_bytes = stdout.read()
            stderr_bytes = stderr.read()
            try: stdin.close()
            except Exception: pass
            return stdout_bytes, stderr_bytes

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                loop.run_in_executor(None, _run),
                timeout=timeout + 30,
            )
        except asyncio.TimeoutError:
            ctx.state["linpeas_ssh_error"] = f"linpeas execution timed out after {timeout}s"
            ctx.source(f"timeout @ {timeout}s")
            return

        out = (stdout_b or b"").decode("utf-8", errors="ignore")
        err = (stderr_b or b"").decode("utf-8", errors="ignore")
        if not out and err:
            ctx.state["linpeas_ssh_error"] = f"linpeas stderr: {err[:200]}"
            ctx.source("linpeas wrote nothing to stdout")
            return

        # Parse for severity-tagged findings.
        findings: list[dict] = []
        findings.extend(_scan_patterns(out, _CRITICAL_PATTERNS, "CRITICAL"))
        findings.extend(_scan_patterns(out, _HIGH_PATTERNS, "HIGH"))
        findings.extend(_scan_patterns(out, _MEDIUM_PATTERNS, "MEDIUM"))

        # Also count LinPEAS-tagged red lines (95% red bold = HIGH-severity).
        red_lines = sum(1 for line in out.splitlines() if _RED_TAG in line)
        very_high_lines = sum(1 for line in out.splitlines() if _YELLOW_RED in line)

        ctx.state["linpeas_findings"] = findings
        ctx.state["linpeas_output_bytes"] = len(out)
        ctx.state["linpeas_red_lines"] = red_lines
        ctx.state["linpeas_very_high_lines"] = very_high_lines
        ctx.state["linpeas_ran"] = True
        ctx.source(f"LinPEAS -a complete: {len(out)} bytes, {len(findings)} parsed findings, "
                   f"{red_lines} red lines, {very_high_lines} very-high")

    finally:
        # Always delete the uploaded script.
        try:
            client.exec_command(f"rm -f {REMOTE_UPLOAD_PATH}", timeout=15)
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass


INTEL_FIELDS = [
    ("LinPEAS target host",   "linpeas_host"),
    ("Output bytes",          "linpeas_output_bytes"),
    ("Red (HIGH) lines",      "linpeas_red_lines"),
    ("Very-high lines",       "linpeas_very_high_lines"),
    ("Parsed findings",       "linpeas_findings"),
]


@router.post("/api/privesc/linpeas_remote_audit")
async def privesc_linpeas_remote_audit(req: LinpeasRemoteAuditRequest,
                                        _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="linpeas_remote_audit",
        gather_func=_gather_with_options,
        finding_rules=LINPEAS_REMOTE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
