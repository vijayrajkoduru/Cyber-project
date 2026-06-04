"""etw_bypass_detection_test - ETW patch detection probe.

What it does:
  Connects to a Windows target over WinRM (pywinrm) and runs PowerShell
  that submits the PUBLIC EventTracing-for-Windows (ETW) patch primitive:

      $EventProvider = [System.Diagnostics.Eventing.EventProvider]
      $field = $EventProvider.GetField('m_enabled','NonPublic,Instance')
      # Just READING m_enabled triggers the EDR rule on most products
      # We do NOT call SetValue(...) so no ETW providers are actually disabled.

  Then submits a Reflection-based ETW lookup against `EtwEventWrite` in
  ntdll.dll - which most EDRs hook with an inline jmp to ETWTI.

  The probe evaluates:
    a. PS execution succeeded with no AMSI/EDR block      -> HIGH
       (the EDR is not detecting the classic ETW patch chain).
    b. PS was blocked by AMSI or terminated by the EDR    -> POSITIVE.
    c. PS ran but EDR generated a real-time event channel -> POSITIVE
       (the customer's IR team will see this in Sysmon Operational logs;
        we can't see it from the scanner but we surface the technique
        as an INFO so the IR review confirms the alert fired).

What this probe is NOT:
  - Not an actual ETW disable (we never call SetValue($null, 0)).
  - Not silenced TraceLogging - only the LOOKUP is exercised.

MITRE: T1562.006 (Indicator Blocking - ETW)
CWE  : CWE-693 (Protection Mechanism Failure)

Customer input via ScanRequest.options:
  - username      Windows account (DOMAIN\\user or .\\local) (required)
  - password      account password (required)
  - port          WinRM port (default 5985 / 5986)
  - use_ssl       bool (default false)
  - timeout_sec   per-cmd cap (default 30)
"""
from __future__ import annotations
import asyncio
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.etw_bypass_detection_test_findings import (
    ETW_BYPASS_DETECTION_TEST_FINDING_RULES,
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


# Reflection access to EventProvider.m_enabled (the public ETW patch
# primitive). We deliberately do NOT call SetValue($null, 0); we only
# RESOLVE the field handle. Most EDR rules trigger on the reflection
# pattern itself (e.g. CrowdStrike rule "RR_ETW_RING0_PATCH_ATTEMPT").
PS_STEP_ETW_PROBE = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Output '== ETW-BEGIN =='
try {
    $provider = [System.Diagnostics.Eventing.EventProvider]
    Write-Output ('ETW-TYPE-OK|' + $provider.FullName)
    $f = $provider.GetField('m_enabled','NonPublic,Instance')
    if ($f) {
        Write-Output ('ETW-FIELD-OK|' + $f.Name + '|' + $f.FieldType.Name)
    } else { Write-Output 'ETW-NO-FIELD' }
    # Now resolve EtwEventWrite via P/Invoke signature - very common
    # detection rule (looking for LoadLibrary('ntdll') + GetProcAddress
    # of EtwEventWrite without execution).
    $sig = @'
using System;
using System.Runtime.InteropServices;
public class VLEtwProbe {
    [DllImport("ntdll.dll")]
    public static extern IntPtr EtwEventWrite(IntPtr a, IntPtr b, uint c, IntPtr d);
}
'@
    Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue
    if ([VLEtwProbe]) { Write-Output 'ETW-PINVOKE-COMPILED' }
} catch {
    Write-Output ('ETW-EXCEPTION|' + $_.Exception.GetType().FullName + '|' + $_.Exception.Message)
}
Write-Output '== ETW-END =='
""".strip()

# Baseline shell test, run first so we can tell apart "EDR killed bypass"
# from "WinRM session was broken before bypass ran".
PS_STEP_BASELINE = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Output '== BASELINE-BEGIN =='
$null = Get-Process -Name powershell -ErrorAction SilentlyContinue
Write-Output 'BASELINE-OK'
Write-Output '== BASELINE-END =='
""".strip()


def _do_winrm(host, port, use_ssl, user, password, timeout):
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
            ("etw",      PS_STEP_ETW_PROBE),
        ):
            try:
                r = s.run_ps(script)
                out[label] = {
                    "stdout": (r.std_out or b"").decode("utf-8", errors="replace"),
                    "stderr": (r.std_err or b"").decode("utf-8", errors="replace"),
                    "rc": r.status_code,
                }
            except Exception as e:
                out[label] = {"_step_error": str(e)[:300]}
        return out
    except Exception as e:
        msg = str(e)
        low = msg.lower()
        if "401" in msg or "unauthorized" in low or "authentication failed" in low:
            return {"_auth_failed": True, "_msg": msg[:300]}
        return {"_conn_error": msg[:300]}


def _evaluate(steps: dict) -> dict:
    out = {
        "baseline_ok": False,
        "etw_type_resolved": False,
        "etw_field_resolved": False,
        "etw_pinvoke_compiled": False,
        "etw_blocked": False,
        "etw_signature_hit": False,
        "raw_summary": [],
    }
    base = steps.get("baseline") or {}
    if "BASELINE-OK" in (base.get("stdout") or ""):
        out["baseline_ok"] = True

    etw = steps.get("etw") or {}
    so = etw.get("stdout") or ""
    se = etw.get("stderr") or ""
    if "ETW-TYPE-OK" in so:
        out["etw_type_resolved"] = True
    if "ETW-FIELD-OK" in so:
        out["etw_field_resolved"] = True
    if "ETW-PINVOKE-COMPILED" in so:
        out["etw_pinvoke_compiled"] = True

    low = (so + " " + se).lower()
    if ("amsiscanbuffer" in low or
        "this script contains malicious content" in low or
        "blocked by your antivirus" in low or
        "etweventwrite is disabled" in low or
        (etw.get("rc") and etw.get("rc") != 0 and
         ("etw" in low or "amsi" in low or "denied" in low))):
        out["etw_blocked"] = True
        out["etw_signature_hit"] = True

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
        ctx.state["etw_bypass_detection_test_total"] = 0
        ctx.source("no-target")
        return
    if not _WINRM_OK:
        ctx.state["etw_bypass_detection_test_error"] = "pywinrm not installed"
        ctx.source("pywinrm missing")
        return

    opts = ctx.state.get("_options") or {}
    user = (opts.get("username") or "").strip()
    password = opts.get("password") or ""
    if not user or not password:
        ctx.state["etw_bypass_detection_test_total"] = 0
        ctx.state["etw_bypass_creds_missing"] = True
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
        ctx.state["etw_bypass_detection_test_error"] = "winrm timeout"
        ctx.state["etw_bypass_detection_test_total"] = 0
        ctx.source("winrm timeout")
        return

    if result.get("_auth_failed"):
        ctx.state["etw_bypass_winrm_auth_failed"] = True
        ctx.state["etw_bypass_detection_test_total"] = 0
        ctx.source("winrm auth failed")
        return
    if result.get("_conn_error"):
        ctx.state["etw_bypass_detection_test_error"] = f"winrm: {result['_conn_error']}"
        ctx.state["etw_bypass_detection_test_total"] = 0
        ctx.source("winrm connect error")
        return

    evald = _evaluate(result)
    ctx.state["etw_bypass_baseline_ok"]      = evald["baseline_ok"]
    ctx.state["etw_bypass_type_resolved"]    = evald["etw_type_resolved"]
    ctx.state["etw_bypass_field_resolved"]   = evald["etw_field_resolved"]
    ctx.state["etw_bypass_pinvoke_compiled"] = evald["etw_pinvoke_compiled"]
    ctx.state["etw_bypass_blocked"]          = evald["etw_blocked"]
    ctx.state["etw_bypass_signature_hit"]    = evald["etw_signature_hit"]
    ctx.state["etw_bypass_summary"]          = evald["raw_summary"]
    ctx.state["etw_bypass_detection_test_total"] = 1
    ctx.source(
        f"winrm://{user}@{target}:{port} -> "
        f"field={'OK' if evald['etw_field_resolved'] else '-'} "
        f"pinvoke={'OK' if evald['etw_pinvoke_compiled'] else '-'} "
        f"edr={'BLOCKED' if evald['etw_blocked'] else 'NOT-BLOCKED'}"
    )


INTEL_FIELDS = [
    ("WinRM port",                "etw_bypass_target_port"),
    ("Baseline shell",            "etw_bypass_baseline_ok"),
    ("EventProvider resolved",    "etw_bypass_type_resolved"),
    ("m_enabled field resolved",  "etw_bypass_field_resolved"),
    ("P/Invoke EtwEventWrite",    "etw_bypass_pinvoke_compiled"),
    ("Blocked by EDR",            "etw_bypass_blocked"),
    ("Step summary",              "etw_bypass_summary"),
]


class EtwBypassRequest(ScanRequest):
    options: Optional[dict] = None


@router.post("/api/av_evasion/etw_bypass_detection_test")
async def av_evasion_etw_bypass_detection_test(
    req: EtwBypassRequest, _=Depends(verify_scan_quota),
):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        use_ssl = bool(options.get("use_ssl"))
        ctx.state["etw_bypass_target_port"] = int(
            options.get("port") or (DEFAULT_PORT_HTTPS if use_ssl else DEFAULT_PORT_HTTP)
        )
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="etw_bypass_detection_test",
        gather_func=_gather_with_options,
        finding_rules=ETW_BYPASS_DETECTION_TEST_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
