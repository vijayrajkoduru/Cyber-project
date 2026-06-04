"""msfdb_status_audit - msfdb PostgreSQL backend health check
(playbook §6 Database Integration, MITRE ATT&CK n/a - configuration audit).

What it does:
  Runs `msfdb status` to verify that the Metasploit Framework's local
  PostgreSQL database is initialised and reachable. Customers rely on
  msfdb to persist hosts/services/vulns/creds/loot tables across
  msfconsole sessions; a broken msfdb is the #1 reason real-world MSF
  workflows silently lose state.

  When msfdb status reports the DB is running we follow up with
  `msfconsole -q -x "db_status; hosts; services; exit"` to pull a count
  of the persisted host + service rows. INFO if the DB is healthy
  (with the row counts), MEDIUM if msfdb is installed but not
  initialised, INFO if msfdb binary is missing.

Customer input via ScanRequest.options:
  - timeout_sec   wall-clock cap (default 60s)
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
from tools._payloads.msfdb_status_audit_findings import (
    MSFDB_STATUS_AUDIT_FINDING_RULES,
)

router = APIRouter()
MSFDB_BIN = shutil.which("msfdb")
MSFCONSOLE_BIN = shutil.which("msfconsole")
DEFAULT_TIMEOUT = 60
HARD_MAX_TIMEOUT = 120

# msfdb status output:
#   Database started
#   Database stopped
#   No configuration file found
_RE_DB_RUNNING = re.compile(r"\bdatabase\s+started\b", re.I)
_RE_DB_STOPPED = re.compile(r"\bdatabase\s+stopped\b", re.I)
_RE_DB_NOT_INIT = re.compile(r"no\s+configuration\s+file", re.I)
_RE_DB_CONNECTED = re.compile(r"connected\s+to\s+(?P<db>\S+)", re.I)
_RE_DB_NOT_CONNECTED = re.compile(r"database\s+not\s+connected", re.I)
# hosts table footer e.g. "Hosts\n=====\n... \nIPv4 ... \n\n[1 of 1]" - we count
# data rows between header rule and trailing blank.


class MsfdbStatusAuditRequest(ScanRequest):
    options: Optional[dict] = None


async def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "TERM": "dumb"},
        )
    except Exception as e:
        return (-1, "", f"spawn failed: {str(e)[:200]}")
    try:
        out_b, err_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout,
        )
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        return (-1, "", f"timeout after {timeout}s")
    return (
        proc.returncode if proc.returncode is not None else -1,
        (out_b or b"").decode("utf-8", errors="ignore"),
        (err_b or b"").decode("utf-8", errors="ignore"),
    )


def _count_table_rows(out: str, section_header: str) -> Optional[int]:
    """Count data rows in an msfconsole table section.

    msfconsole prints sections like:

        Hosts
        =====
        address  mac  name  os_name  ...
        -------  ---  ----  -------  ...
        10.0.0.1 ...  ...   ...      ...
        10.0.0.2 ...  ...   ...      ...

    We locate the header by name, advance past the header rule, and
    count non-empty lines until the next blank line or next section.
    """
    lines = out.splitlines()
    n = len(lines)
    for i, line in enumerate(lines):
        if line.strip().lower() == section_header.lower():
            # Look for the ===== rule on the next non-blank line.
            j = i + 1
            while j < n and not lines[j].strip():
                j += 1
            if j >= n or set(lines[j].strip()) != {"="}:
                continue
            # Skip the column header line + the ----- rule under it.
            j += 1
            if j < n and lines[j].strip():
                j += 1  # column header
            while j < n and set(lines[j].strip()) <= {"-", " "} and lines[j].strip():
                j += 1
            # Count data rows until blank or next ===== section
            rows = 0
            while j < n:
                row = lines[j].strip()
                if not row:
                    break
                if set(row) == {"="}:
                    break
                rows += 1
                j += 1
            return rows
    return None


async def gather(ctx: ScanContext):
    if not MSFDB_BIN:
        ctx.state["msfdb_status_audit_binary_missing"] = True
        ctx.source("msfdb missing")
        return

    opts = ctx.state.get("_options") or {}
    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 15), HARD_MAX_TIMEOUT)

    rc, out, err = await _run([MSFDB_BIN, "status"], timeout=timeout)
    if rc == -1 and "timeout" in err.lower():
        ctx.state["msfdb_status_audit_error"] = err
        ctx.source(err)
        return
    combined = out + "\n" + err

    db_running = bool(_RE_DB_RUNNING.search(combined))
    db_stopped = bool(_RE_DB_STOPPED.search(combined))
    db_not_init = bool(_RE_DB_NOT_INIT.search(combined))

    ctx.state["msfdb_status_audit_msfdb_path"] = MSFDB_BIN
    ctx.state["msfdb_status_audit_status_text"] = (out or err or "").strip()[:1024]
    ctx.state["msfdb_status_audit_db_running"] = db_running
    ctx.state["msfdb_status_audit_db_stopped"] = db_stopped and not db_running
    ctx.state["msfdb_status_audit_db_not_initialised"] = db_not_init

    # If DB is reportedly running, ask msfconsole how many rows are persisted.
    if db_running and MSFCONSOLE_BIN:
        rc2, out2, err2 = await _run(
            [MSFCONSOLE_BIN, "-q", "-x", "db_status; hosts; services; exit"],
            timeout=timeout,
        )
        combined2 = out2 + "\n" + err2
        connected = bool(_RE_DB_CONNECTED.search(combined2))
        not_connected = bool(_RE_DB_NOT_CONNECTED.search(combined2))
        ctx.state["msfdb_status_audit_db_connected_from_msfconsole"] = connected
        ctx.state["msfdb_status_audit_db_not_connected_from_msfconsole"] = not_connected
        host_rows = _count_table_rows(out2, "Hosts")
        svc_rows = _count_table_rows(out2, "Services")
        ctx.state["msfdb_status_audit_host_rows"] = host_rows if host_rows is not None else 0
        ctx.state["msfdb_status_audit_service_rows"] = svc_rows if svc_rows is not None else 0

    ctx.source(
        f"msfdb status -> running={db_running}, "
        f"stopped={db_stopped and not db_running}, "
        f"not_initialised={db_not_init}"
    )


INTEL_FIELDS = [
    ("msfdb path",                 "msfdb_status_audit_msfdb_path"),
    ("msfdb status",               "msfdb_status_audit_status_text"),
    ("DB running",                 "msfdb_status_audit_db_running"),
    ("DB connected (msfconsole)",  "msfdb_status_audit_db_connected_from_msfconsole"),
    ("Persisted hosts rows",       "msfdb_status_audit_host_rows"),
    ("Persisted services rows",    "msfdb_status_audit_service_rows"),
]


@router.post("/api/metasploit/msfdb_status_audit")
async def metasploit_msfdb_status_audit(
    req: MsfdbStatusAuditRequest, _=Depends(verify_scan_quota),
):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target or "scanner-host",
        tool="msfdb_status_audit",
        gather_func=_gather_with_options,
        finding_rules=MSFDB_STATUS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
