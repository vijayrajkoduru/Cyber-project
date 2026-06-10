"""msf_auxiliary_scan - run a Metasploit auxiliary scanner module
(playbook §1, MITRE ATT&CK T1595.001 / T1046).

What it does:
  Drives `msfconsole -q -x "use <module>; set RHOSTS <target>; <extra>;
  run; exit"` against the customer-supplied target. Default module is
  `auxiliary/scanner/smb/smb_version` (a safe, read-only banner probe).
  The customer can override which auxiliary module runs via
  `options.module` plus any module-specific SET pairs in
  `options.module_options` (a dict). The probe whitelists `auxiliary/`
  modules only - exploit, post, encoder, and payload modules are
  rejected at the entry point.

Customer input via ScanRequest.options:
  - module           auxiliary module path (default "auxiliary/scanner/smb/smb_version")
  - RHOSTS           target list (default = ScanRequest.target)
  - RPORT            module RPORT override (optional)
  - module_options   dict of "SET <name> <value>" pairs (THREADS, etc.)
  - timeout_sec      wall-clock cap (default 120s)
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
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.msf_auxiliary_scan_findings import (
    MSF_AUXILIARY_SCAN_FINDING_RULES,
)

router = APIRouter()
MSFCONSOLE_BIN = shutil.which("msfconsole")
DEFAULT_MODULE = "auxiliary/scanner/smb/smb_version"
DEFAULT_TIMEOUT = 120
HARD_MAX_TIMEOUT = 300
HARD_MAX_SET_PAIRS = 12

# Sanitise module path - whitelist auxiliary/* only.
_RE_MODULE_OK = re.compile(r"^auxiliary/[A-Za-z0-9_/-]+$")
# Match msfconsole result lines: "[+]", "[*]", "[-]" prefix + text.
_RE_RESULT = re.compile(
    r"^\s*\[(?P<sym>[+*\-])\]\s+(?P<text>.+?)\s*$"
)
# Sanitise SET option name + value (alphanum / dot / underscore / dash only).
_RE_SET_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_RE_SET_VAL = re.compile(r"^[A-Za-z0-9_.,:/\-]{1,128}$")


class MsfAuxiliaryScanRequest(ScanRequest):
    options: Optional[dict] = None


def _build_resource_script(module: str, rhosts: str,
                            rport: Optional[str],
                            extras: dict) -> str:
    lines = [f"use {module}"]
    lines.append(f"set RHOSTS {rhosts}")
    if rport:
        lines.append(f"set RPORT {rport}")
    for k, v in (extras or {}).items():
        if not _RE_SET_NAME.match(str(k)):
            continue
        if not _RE_SET_VAL.match(str(v)):
            continue
        lines.append(f"set {k} {v}")
    lines.append("run")
    lines.append("exit")
    return "; ".join(lines)


async def gather(ctx: ScanContext):
    if not MSFCONSOLE_BIN:
        ctx.state["msf_auxiliary_scan_binary_missing"] = True
        ctx.source("msfconsole missing")
        return

    target = ctx.host
    if not target:
        ctx.state["msf_auxiliary_scan_no_target"] = True
        ctx.source("no target")
        return

    opts = ctx.state.get("_options") or {}
    module = (opts.get("module") or DEFAULT_MODULE).strip()
    if not _RE_MODULE_OK.match(module):
        ctx.state["msf_auxiliary_scan_invalid_module"] = module
        ctx.source(f"module rejected: {module[:60]}")
        return

    rhosts = (opts.get("RHOSTS") or opts.get("rhosts") or target).strip()
    rport = opts.get("RPORT") or opts.get("rport")
    rport_str = str(rport).strip() if rport else None
    if rport_str and not _RE_SET_VAL.match(rport_str):
        rport_str = None

    extras = opts.get("module_options") or {}
    if isinstance(extras, dict):
        # Clamp number of extra SET pairs
        extras = dict(list(extras.items())[:HARD_MAX_SET_PAIRS])
    else:
        extras = {}

    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 30), HARD_MAX_TIMEOUT)

    script = _build_resource_script(module, rhosts, rport_str, extras)
    cmd = [MSFCONSOLE_BIN, "-q", "-x", script]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "TERM": "dumb"},
        )
    except Exception as e:
        ctx.state["msf_auxiliary_scan_error"] = f"spawn failed: {str(e)[:200]}"
        ctx.source("spawn error")
        return

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout,
        )
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        ctx.state["msf_auxiliary_scan_error"] = f"msfconsole timeout after {timeout}s"
        ctx.source(f"timeout @ {timeout}s")
        return

    stdout = (stdout_b or b"").decode("utf-8", errors="ignore")
    stderr = (stderr_b or b"").decode("utf-8", errors="ignore")

    successes: list[str] = []
    informational: list[str] = []
    failures: list[str] = []
    for line in stdout.splitlines():
        m = _RE_RESULT.match(line)
        if not m:
            continue
        sym = m.group("sym")
        text = m.group("text").strip()
        if not text:
            continue
        if sym == "+" and len(successes) < 40:
            successes.append(text[:240])
        elif sym == "*" and len(informational) < 40:
            informational.append(text[:240])
        elif sym == "-" and len(failures) < 40:
            failures.append(text[:240])

    ctx.state["msf_auxiliary_scan_module"] = module
    ctx.state["msf_auxiliary_scan_target"] = rhosts
    ctx.state["msf_auxiliary_scan_rport"] = rport_str
    ctx.state["msf_auxiliary_scan_successes"] = successes
    ctx.state["msf_auxiliary_scan_informational"] = informational
    ctx.state["msf_auxiliary_scan_failures"] = failures
    ctx.state["msf_auxiliary_scan_total"] = len(successes)
    if proc.returncode and proc.returncode != 0 and not successes and not informational:
        ctx.state["msf_auxiliary_scan_error"] = (
            f"msfconsole exit {proc.returncode}; stderr head: {stderr[:200]}"
        )
    ctx.source(
        f"msfconsole {module} -> {len(successes)} success, "
        f"{len(informational)} info, {len(failures)} failure"
    )


INTEL_FIELDS = [
    ("Module run",                "msf_auxiliary_scan_module"),
    ("Target RHOSTS",             "msf_auxiliary_scan_target"),
    ("Target RPORT",              "msf_auxiliary_scan_rport"),
    ("Findings [+]",              "msf_auxiliary_scan_successes"),
    ("Informational [*]",         "msf_auxiliary_scan_informational"),
    ("Failures [-]",              "msf_auxiliary_scan_failures"),
]


@router.post("/api/metasploit/msf_auxiliary_scan")
async def metasploit_msf_auxiliary_scan(
    req: MsfAuxiliaryScanRequest, _=Depends(verify_scan_quota),
):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="msf_auxiliary_scan",
        gather_func=_gather_with_options,
        finding_rules=MSF_AUXILIARY_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
