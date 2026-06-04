"""lateral_pivot_signal_check - PtH / PtT lateral-movement signal generator
   (playbook §5 #52 trusted-vendor sim + §7 #71 EDR alert tuning + §8 lateral).

Generates LOUD lateral-movement telemetry against a customer-supplied
internal IP. Uses impacket's psexec / wmiexec / smbexec primitives with
a BOGUS NT hash so the authentication WILL FAIL but the attempt will
emit:
  - Windows Event 4624 (logon attempt, type 3 network)
  - Windows Event 4625 (failed logon)
  - Windows Event 4648 (logon attempt with explicit credentials)
  - Windows Event 5140 (network share access)

Customer input via ScanRequest.options:
  - options.lateral_target    - customer LAN IP that runs Windows (required)
  - options.lateral_domain    - AD domain for the spray (default "WORKGROUP")
  - options.lateral_user      - username to use (default "Administrator")
  - options.lateral_nt_hash   - 32-hex NT hash (defaults to a known-bogus hash)
  - options.lateral_methods   - comma list: psexec,wmiexec,smbexec (default all)
  - options.lateral_timeout_sec - per-method cap (default 12, max 30)

Safety:
  - Hash is deliberately invalid (AAD3B... well-known empty-LM + zeros)
    so success would be a CRITICAL finding; expectation is auth-failure.
  - Probe runs ONLY against customer-supplied IP (no auto-discovery).
  - Does NOT attempt to execute payload binaries on success path; we abort
    immediately after we get auth response.

MITRE techniques: T1078 (Valid Accounts), T1550.002 (Pass the Hash),
                  T1570 (Lateral Tool Transfer), T1021.002 (SMB/Admin Shares),
                  T1021.006 (WinRM).
"""
from __future__ import annotations
import asyncio
import os
import re
import shutil
import time
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.lateral_pivot_signal_check_findings import (
    LATERAL_PIVOT_SIGNAL_CHECK_FINDING_RULES,
)

router = APIRouter()
DEFAULT_TIMEOUT = 12
HARD_MAX_TIMEOUT = 30

# Well-known invalid NT hash (LM empty + NT empty hash). Will NEVER auth.
DEFAULT_BOGUS_HASH = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

# Method -> impacket binary lookup
IMPACKET_BINS = {
    "psexec":  "impacket-psexec",
    "wmiexec": "impacket-wmiexec",
    "smbexec": "impacket-smbexec",
}


class LateralPivotSignalRequest(ScanRequest):
    options: Optional[dict] = None


def _resolve_bin(method: str) -> Optional[str]:
    """Find impacket-<method>. Falls back to <method>.py if needed."""
    primary = IMPACKET_BINS.get(method)
    if primary:
        path = shutil.which(primary)
        if path:
            return path
    # Fallback: try plain <method>.py (older impacket installs)
    return shutil.which(f"{method}.py")


def _parse_auth_outcome(stdout: str, stderr: str) -> str:
    """Classify auth outcome from impacket output."""
    s = (stdout + " " + stderr).lower()
    if "status_logon_failure" in s or "logon failure" in s:
        return "AUTH_FAILED_AS_EXPECTED"
    if "status_account_locked_out" in s or "account locked" in s:
        return "AUTH_LOCKED"
    if "status_password_expired" in s:
        return "AUTH_EXPIRED"
    if "status_invalid_logon_hours" in s:
        return "AUTH_HOURS"
    if "connection refused" in s or "no route to host" in s:
        return "NETWORK_UNREACHABLE"
    if "operation timed out" in s or "timeout" in s:
        return "NETWORK_TIMEOUT"
    if "status_logon_type_not_granted" in s:
        return "AUTH_TYPE_REJECTED"
    if "[*] " in s and "shell" in s:
        # Anomaly - hash actually worked! That means customer has the well-known
        # empty hash configured as a real password.
        return "AUTH_SUCCEEDED_CRITICAL"
    if "smbexception" in s or "smbsession" in s:
        return "AUTH_FAILED_AS_EXPECTED"
    return "INCONCLUSIVE"


async def _run_impacket(method: str, bin_path: str, target: str, domain: str,
                          user: str, nt_hash: str, timeout: int) -> dict:
    """Execute impacket-<method> with -hashes against target. Capture output."""
    # Common arg style: impacket-psexec -hashes LM:NT 'DOMAIN/user@target'
    creds = f"{domain}/{user}@{target}"
    # We pipe `exit` so impacket exits if it somehow got a shell.
    cmd = [bin_path, "-hashes", nt_hash, creds]
    start = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=b"exit\n"), timeout=timeout
            )
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            return {
                "method": method, "elapsed_ms": round((time.time() - start) * 1000),
                "outcome": "NETWORK_TIMEOUT", "rc": -1,
                "stdout_preview": "", "stderr_preview": f"timeout after {timeout}s",
            }
        rc = proc.returncode if proc.returncode is not None else -1
        stdout = (stdout_b or b"").decode("utf-8", errors="ignore")
        stderr = (stderr_b or b"").decode("utf-8", errors="ignore")
        outcome = _parse_auth_outcome(stdout, stderr)
        return {
            "method": method,
            "elapsed_ms": round((time.time() - start) * 1000),
            "outcome": outcome,
            "rc": rc,
            "stdout_preview": stdout.strip()[:240],
            "stderr_preview": stderr.strip()[:240],
        }
    except Exception as e:
        return {
            "method": method, "elapsed_ms": round((time.time() - start) * 1000),
            "outcome": f"ERR:{type(e).__name__}", "rc": -1,
            "stdout_preview": "", "stderr_preview": str(e)[:240],
        }


_RE_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    target = (opts.get("lateral_target") or "").strip()
    domain = (opts.get("lateral_domain") or "WORKGROUP").strip() or "WORKGROUP"
    user = (opts.get("lateral_user") or "Administrator").strip() or "Administrator"
    nt_hash = (opts.get("lateral_nt_hash") or DEFAULT_BOGUS_HASH).strip()
    methods_raw = (opts.get("lateral_methods") or "psexec,wmiexec,smbexec").strip()
    timeout = min(max(int(opts.get("lateral_timeout_sec") or DEFAULT_TIMEOUT), 4),
                   HARD_MAX_TIMEOUT)

    if not target:
        ctx.state["lateral_pivot_total"] = 0
        ctx.state["lateral_input_missing"] = True
        ctx.source("missing lateral_target")
        return
    # Must be IPv4 LAN-like (10/172.16-31/192.168/127) -- soft check
    if not _RE_IPV4.match(target):
        ctx.state["lateral_pivot_total"] = 0
        ctx.state["lateral_input_invalid"] = "lateral_target must be IPv4"
        ctx.source("lateral_target not IPv4")
        return

    methods = [m.strip().lower() for m in methods_raw.split(",") if m.strip()]
    methods = [m for m in methods if m in IMPACKET_BINS]
    if not methods:
        methods = ["psexec", "wmiexec", "smbexec"]

    results: list[dict] = []
    missing_bins: list[str] = []
    for method in methods:
        bin_path = _resolve_bin(method)
        if not bin_path:
            missing_bins.append(method)
            results.append({
                "method": method, "outcome": "BINARY_MISSING",
                "rc": -1, "elapsed_ms": 0,
                "stderr_preview": f"impacket-{method} not in PATH",
            })
            continue
        r = await _run_impacket(method, bin_path, target, domain, user, nt_hash, timeout)
        results.append(r)

    outcomes = [r["outcome"] for r in results]
    auth_failures = sum(1 for o in outcomes if o == "AUTH_FAILED_AS_EXPECTED")
    crit_success = any(o == "AUTH_SUCCEEDED_CRITICAL" for o in outcomes)
    network_issues = sum(1 for o in outcomes
                         if o in ("NETWORK_UNREACHABLE", "NETWORK_TIMEOUT"))

    # Redact the hash so it doesn't appear in customer PDF
    hash_redacted = (nt_hash[:8] + "..." + nt_hash[-4:]) if len(nt_hash) > 14 else "***"

    ctx.state["lateral_pivot_target"]        = target
    ctx.state["lateral_pivot_domain"]        = domain
    ctx.state["lateral_pivot_user"]          = user
    ctx.state["lateral_pivot_hash_redacted"] = hash_redacted
    ctx.state["lateral_pivot_methods_run"]   = methods
    ctx.state["lateral_pivot_results"]       = results
    ctx.state["lateral_pivot_total"]         = len(results)
    ctx.state["lateral_pivot_auth_failures"] = auth_failures
    ctx.state["lateral_pivot_critical"]      = crit_success
    ctx.state["lateral_pivot_network_issues"] = network_issues
    ctx.state["lateral_pivot_missing_bins"]  = missing_bins
    ctx.source(f"lateral pivot signals -> {target} as {domain}/{user} ; "
                f"{len(results)} method(s) -> "
                f"{auth_failures} expected-fail / {network_issues} network / "
                f"{'CRITICAL_SUCCESS' if crit_success else 'no-anomaly'}")


INTEL_FIELDS = [
    ("Lateral target IP",       "lateral_pivot_target"),
    ("Domain used",             "lateral_pivot_domain"),
    ("Username used",           "lateral_pivot_user"),
    ("NT hash (redacted)",      "lateral_pivot_hash_redacted"),
    ("Methods exercised",       "lateral_pivot_methods_run"),
    ("Attempts total",          "lateral_pivot_total"),
    ("Auth-failures (expected)","lateral_pivot_auth_failures"),
    ("Network-unreachable",     "lateral_pivot_network_issues"),
    ("Method results",          "lateral_pivot_results"),
]


@router.post("/api/red_team/lateral_pivot_signal_check")
async def red_team_lateral_pivot_signal_check(req: LateralPivotSignalRequest,
                                                _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="lateral_pivot_signal_check",
        gather_func=_gather_with_options,
        finding_rules=LATERAL_PIVOT_SIGNAL_CHECK_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
