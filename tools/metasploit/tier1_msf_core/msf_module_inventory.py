"""msf_module_inventory - Metasploit Framework module inventory probe
(playbook §1/§2/§3/§4 health check, MITRE ATT&CK T1595.002).

What it does:
  Runs `msfconsole -q -x "search type:auxiliary; exit" --quiet` against
  the scanner-host's Metasploit Framework install and parses the output
  to extract the number of auxiliary modules available + a sample of
  recent additions. Used by customers to verify their MSF installation
  is healthy and current (Rapid7 ships ~50 new modules per quarter).

  If msfconsole is not installed on the scanner host the probe returns
  an INFO finding telling the customer how to install Metasploit
  Framework rather than silently failing.

Customer input via ScanRequest.options:
  - timeout_sec   wall-clock cap for msfconsole boot (default 90s)

This probe is host-side: the target field is recorded for the report
but msfconsole runs on the scanner host (no traffic to target).
"""
from __future__ import annotations
import asyncio
import os
import re
import shutil
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.msf_module_inventory_findings import (
    MSF_MODULE_INVENTORY_FINDING_RULES,
)

router = APIRouter()
MSFCONSOLE_BIN = shutil.which("msfconsole")
DEFAULT_TIMEOUT = 90
HARD_MAX_TIMEOUT = 180
SAMPLE_MODULES = 10


class MsfModuleInventoryRequest(ScanRequest):
    options: Optional[dict] = None


# msfconsole search output lines look like:
#  #   Name                                          Disclosure Date  Rank    Check  Description
#  --  ----                                          ---------------  ----    -----  -----------
#  0   auxiliary/admin/2wire/xslt_password_reset     2007-08-15       normal  No     ...
_RE_MODULE_LINE = re.compile(
    r"^\s*\d+\s+(?P<name>auxiliary/\S+)\s+",
)
# Matches summary line "Total modules: 1234" or "Interact with a module..." absent
_RE_TOTAL = re.compile(r"^\s*Total\s+modules?\s*:\s*(?P<n>\d+)", re.I)


async def gather(ctx: ScanContext):
    if not MSFCONSOLE_BIN:
        ctx.state["msf_module_inventory_binary_missing"] = True
        ctx.source("msfconsole missing")
        return

    opts = ctx.state.get("_options") or {}
    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 30), HARD_MAX_TIMEOUT)

    # -q quiet (no banner), -x command, --quiet suppress more chatter
    cmd = [
        MSFCONSOLE_BIN,
        "-q",
        "-x", "search type:auxiliary; exit",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "TERM": "dumb"},
        )
    except Exception as e:
        ctx.state["msf_module_inventory_error"] = f"spawn failed: {str(e)[:200]}"
        ctx.source("spawn error")
        return

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout,
        )
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        ctx.state["msf_module_inventory_error"] = f"msfconsole timeout after {timeout}s"
        ctx.source(f"timeout @ {timeout}s")
        return

    stdout = (stdout_b or b"").decode("utf-8", errors="ignore")
    stderr = (stderr_b or b"").decode("utf-8", errors="ignore")

    if "database not connected" in (stdout + stderr).lower():
        ctx.state["msf_module_inventory_db_not_connected"] = True

    module_names: list[str] = []
    total_line_seen: Optional[int] = None
    for line in stdout.splitlines():
        m = _RE_MODULE_LINE.match(line)
        if m:
            n = m.group("name").strip()
            if n and n not in module_names:
                module_names.append(n)
            continue
        t = _RE_TOTAL.match(line)
        if t:
            try:
                total_line_seen = int(t.group("n"))
            except Exception:
                pass

    total = total_line_seen if total_line_seen is not None else len(module_names)
    sample = module_names[: SAMPLE_MODULES]

    ctx.state["msf_module_inventory_total"] = total
    ctx.state["msf_module_inventory_sample"] = sample
    ctx.state["msf_module_inventory_msfconsole_path"] = MSFCONSOLE_BIN
    if proc.returncode and proc.returncode != 0 and not module_names:
        ctx.state["msf_module_inventory_error"] = (
            f"msfconsole exit {proc.returncode}; stderr head: {stderr[:200]}"
        )
    ctx.source(
        f"msfconsole -q search type:auxiliary -> {total} module(s), "
        f"{len(sample)} sampled"
    )


INTEL_FIELDS = [
    ("Auxiliary modules found",   "msf_module_inventory_total"),
    ("Sample modules",            "msf_module_inventory_sample"),
    ("msfconsole path",           "msf_module_inventory_msfconsole_path"),
]


@router.post("/api/metasploit/msf_module_inventory")
async def metasploit_msf_module_inventory(
    req: MsfModuleInventoryRequest, _=Depends(verify_scan_quota),
):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target or "scanner-host",
        tool="msf_module_inventory",
        gather_func=_gather_with_options,
        finding_rules=MSF_MODULE_INVENTORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
