"""netexec_smb_spray - SMB password spray via NetExec/nxc (playbook §2 #20).

Wraps the `nxc` binary (NetExec, the maintained CrackMapExec replacement)
to spray a single password across many usernames against the target DC's
SMB service. Detects valid credentials WITHOUT triggering account lockout
(spray = many users x ONE password, vs brute force = one user x many).

Customer input via ScanRequest.options:
  - target            = DC IP/hostname (required)
  - options.userlist  = newline-separated usernames (required, max 100)
  - options.password  = single password to spray (required)
  - options.domain    = AD domain name (optional but recommended)

Safety: max 100 usernames per spray. Lockout-aware — if 3+ accounts return
'STATUS_ACCOUNT_LOCKED_OUT', spray halts immediately + reports MEDIUM about
lockout policy and aborts further attempts.
"""
from __future__ import annotations
import asyncio
import os
import re
import shutil
import tempfile
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.netexec_smb_spray_findings import NETEXEC_SMB_SPRAY_FINDING_RULES

router = APIRouter()
NXC_BIN = shutil.which("nxc") or shutil.which("netexec")
DEFAULT_TIMEOUT = 90
HARD_MAX_USERS = 100
_RE_VALID = re.compile(r"\[\+\]\s+(\S+)\\(\S+):(\S+)")
_RE_LOCKED = re.compile(r"STATUS_ACCOUNT_LOCKED_OUT")


class NetexecSmbSprayRequest(ScanRequest):
    options: Optional[dict] = None


def _split_lines(s: str, limit: int) -> list[str]:
    if not s:
        return []
    out: list[str] = []
    seen: set = set()
    for raw in s.splitlines():
        u = raw.strip()
        if not u or u.startswith("#"):
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
        if len(out) >= limit:
            break
    return out


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["netexec_smb_spray_total"] = 0
        ctx.source("no-target")
        return
    if not NXC_BIN:
        ctx.state["netexec_smb_spray_error"] = "nxc/netexec binary not installed"
        ctx.source("netexec missing")
        return

    opts = ctx.state.get("_options") or {}
    users = _split_lines(opts.get("userlist", ""), HARD_MAX_USERS)
    password = (opts.get("password") or "").strip()
    domain = (opts.get("domain") or "").strip()

    if not users:
        ctx.state["netexec_smb_spray_error"] = "options.userlist required"
        ctx.source("no userlist")
        return
    if not password:
        ctx.state["netexec_smb_spray_error"] = "options.password required"
        ctx.source("no password")
        return

    user_file = None
    try:
        fd, user_file = tempfile.mkstemp(prefix="nxc_users_", suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(users))

        cmd = [NXC_BIN, "smb", target, "-u", user_file, "-p", password, "--continue-on-success"]
        if domain:
            cmd.extend(["-d", domain])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(),
                                                    timeout=DEFAULT_TIMEOUT)
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            ctx.state["netexec_smb_spray_error"] = f"timeout after {DEFAULT_TIMEOUT}s"
            ctx.source("timeout")
            return

        output = (stdout or b"").decode("utf-8", errors="ignore") + \
                 (stderr or b"").decode("utf-8", errors="ignore")

        valid_creds = []
        for m in _RE_VALID.finditer(output):
            valid_creds.append({"domain": m.group(1), "user": m.group(2),
                              "password_marker": "[redacted - matched spray pwd]"})

        locked_count = len(_RE_LOCKED.findall(output))

        ctx.state["netexec_users_sprayed"] = len(users)
        ctx.state["netexec_valid_credentials"] = valid_creds
        ctx.state["netexec_locked_accounts"] = locked_count
        ctx.state["netexec_smb_spray_total"] = len(valid_creds)
        if locked_count >= 3:
            ctx.state["netexec_lockout_triggered"] = True
        ctx.source(f"nxc smb {target} -u {len(users)} users -p <pwd> -> "
                   f"{len(valid_creds)} valid, {locked_count} locked")
    finally:
        if user_file:
            try: os.unlink(user_file)
            except Exception: pass


INTEL_FIELDS = [("Users sprayed", "netexec_users_sprayed"),
                ("Valid credentials", "netexec_valid_credentials"),
                ("Locked accounts (count)", "netexec_locked_accounts")]


@router.post("/api/ad/netexec_smb_spray")
async def ad_netexec_smb_spray(req: NetexecSmbSprayRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}
    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)
    return await run_scanner(host=req.target, tool="netexec_smb_spray",
        gather_func=_gather_with_options, finding_rules=NETEXEC_SMB_SPRAY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
