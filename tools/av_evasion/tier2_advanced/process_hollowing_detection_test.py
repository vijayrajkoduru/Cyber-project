"""process_hollowing_detection_test - Process Hollowing API-pattern detection.

What it does:
  Pushes a benign PowerShell + P/Invoke script over WinRM that performs
  the canonical "process hollowing" API call sequence (T1055.012):

      1. CreateProcessW("C:\\Windows\\System32\\notepad.exe",
                        ..., CREATE_SUSPENDED, ...)
      2. ZwUnmapViewOfSection(hProcess, lpBaseAddress)
      3. WriteProcessMemory(hProcess, lpBaseAddress, original_bytes, ...)
         <-- We write back the ORIGINAL section. No shellcode is injected.
      4. ResumeThread(hThread)
      5. TerminateProcess(hProcess, 0)
         <-- Closed immediately after resume so no notepad windows linger.

  Most modern EDRs (CrowdStrike, SentinelOne, Defender ATP) detect the
  CreateProcess(SUSPENDED) + ZwUnmapViewOfSection + WriteProcessMemory +
  ResumeThread call sequence as a process-hollowing indicator,
  REGARDLESS of the payload written to the target memory. This probe
  exercises that detection chain without any malicious side-effect.

What this probe is NOT:
  - Not a malicious payload injection. WriteProcessMemory writes back
    the bytes that ZwUnmapViewOfSection just unmapped (the original
    notepad image section).
  - notepad is created suspended, immediately resumed, then terminated;
    no UI is shown and no persistence is established.

MITRE: T1055.012 (Process Injection: Process Hollowing)
CWE  : CWE-693 (Protection Mechanism Failure)

Customer input via ScanRequest.options:
  - username      Windows account (required)
  - password      account password (required)
  - port          WinRM port (default 5985 / 5986)
  - use_ssl       bool (default false)
  - timeout_sec   per-cmd cap (default 60)
"""
from __future__ import annotations
import asyncio
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.process_hollowing_detection_test_findings import (
    PROCESS_HOLLOWING_DETECTION_TEST_FINDING_RULES,
)

router = APIRouter()

try:
    import winrm   # noqa: F401
    _WINRM_OK = True
except Exception:
    _WINRM_OK = False

DEFAULT_PORT_HTTP = 5985
DEFAULT_PORT_HTTPS = 5986
DEFAULT_TIMEOUT = 60

# Canonical process-hollowing call sequence. Notepad is suspended,
# we read+rewrite its first page (no mutation), resume, terminate.
# This triggers the EDR API-pattern rule without any payload execution.
PS_HOLLOWING_PROBE = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Output '== HOLLOW-BEGIN =='

$sig = @'
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
public class VLHollow {
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public uint cb; public string lpReserved; public string lpDesktop;
        public string lpTitle; public uint dwX; public uint dwY; public uint dwXSize;
        public uint dwYSize; public uint dwXCountChars; public uint dwYCountChars;
        public uint dwFillAttribute; public uint dwFlags; public ushort wShowWindow;
        public ushort cbReserved2; public IntPtr lpReserved2;
        public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess; public IntPtr hThread;
        public uint dwProcessId; public uint dwThreadId;
    }
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessW(
        string app, string cmd, IntPtr pAttr, IntPtr tAttr, bool inh,
        uint flags, IntPtr env, string dir,
        ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("ntdll.dll")]
    public static extern uint NtUnmapViewOfSection(IntPtr p, IntPtr addr);
    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr p, IntPtr addr,
        byte[] buf, uint size, out uint read);
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr p, IntPtr addr,
        byte[] buf, uint size, out uint written);
    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr h);
    [DllImport("kernel32.dll")]
    public static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}
'@

try {
    Add-Type -TypeDefinition $sig -ErrorAction Stop
    Write-Output 'HOLLOW-PINVOKE-COMPILED'

    $si = New-Object VLHollow+STARTUPINFO
    $si.cb = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($si)
    $pi = New-Object VLHollow+PROCESS_INFORMATION

    # CREATE_SUSPENDED = 0x4
    $ok = [VLHollow]::CreateProcessW(
        'C:\Windows\System32\notepad.exe', $null,
        [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x4,
        [IntPtr]::Zero, $null, [ref]$si, [ref]$pi)
    if (-not $ok) {
        Write-Output ('HOLLOW-CREATE-FAILED|' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
    } else {
        Write-Output ('HOLLOW-CREATE-OK|pid=' + $pi.dwProcessId)

        # Read first 4 KB of the notepad image section.
        $imageBase = [IntPtr]0x400000
        $buf = New-Object byte[] 4096
        $read = 0
        $rok = [VLHollow]::ReadProcessMemory($pi.hProcess, $imageBase, $buf, 4096, [ref]$read)
        Write-Output ('HOLLOW-READ|ok=' + $rok + '|bytes=' + $read)

        # ZwUnmapViewOfSection - canonical EDR detection point #1
        $unmap = [VLHollow]::NtUnmapViewOfSection($pi.hProcess, $imageBase)
        Write-Output ('HOLLOW-UNMAP|status=0x' + $unmap.ToString('X8'))

        # WriteProcessMemory of the SAME bytes back - canonical detection #2
        # (no mutation of the section - this is a SAFE probe)
        $written = 0
        $wok = [VLHollow]::WriteProcessMemory($pi.hProcess, $imageBase, $buf, 4096, [ref]$written)
        Write-Output ('HOLLOW-WRITE|ok=' + $wok + '|bytes=' + $written)

        # ResumeThread - canonical detection #3
        $resume = [VLHollow]::ResumeThread($pi.hThread)
        Write-Output ('HOLLOW-RESUME|prev=' + $resume)

        # TerminateProcess so no notepad UI lingers.
        $null = [VLHollow]::TerminateProcess($pi.hProcess, 0)
        $null = [VLHollow]::CloseHandle($pi.hThread)
        $null = [VLHollow]::CloseHandle($pi.hProcess)
        Write-Output 'HOLLOW-TERMINATED'
    }
} catch {
    Write-Output ('HOLLOW-EXCEPTION|' + $_.Exception.GetType().FullName + '|' + $_.Exception.Message)
}
Write-Output '== HOLLOW-END =='
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
        r = s.run_ps(PS_HOLLOWING_PROBE)
        return {
            "stdout": (r.std_out or b"").decode("utf-8", errors="replace"),
            "stderr": (r.std_err or b"").decode("utf-8", errors="replace"),
            "rc": r.status_code,
        }
    except Exception as e:
        msg = str(e)
        low = msg.lower()
        if "401" in msg or "unauthorized" in low or "authentication failed" in low:
            return {"_auth_failed": True, "_msg": msg[:300]}
        return {"_conn_error": msg[:300]}


def _evaluate(result: dict) -> dict:
    out = {
        "pinvoke_compiled": False,
        "create_ok": False,
        "create_pid": None,
        "read_ok": False,
        "unmap_attempted": False,
        "write_ok": False,
        "resume_ok": False,
        "terminated": False,
        "blocked_by_edr": False,
        "raw_summary": "",
    }
    so = result.get("stdout") or ""
    se = result.get("stderr") or ""
    if "HOLLOW-PINVOKE-COMPILED" in so:
        out["pinvoke_compiled"] = True
    for line in so.splitlines():
        if line.startswith("HOLLOW-CREATE-OK"):
            out["create_ok"] = True
            for p in line.split("|"):
                if p.startswith("pid="):
                    try: out["create_pid"] = int(p.split("=", 1)[1])
                    except Exception: pass
        elif line.startswith("HOLLOW-READ|ok=True"):
            out["read_ok"] = True
        elif line.startswith("HOLLOW-UNMAP"):
            out["unmap_attempted"] = True
        elif line.startswith("HOLLOW-WRITE|ok=True"):
            out["write_ok"] = True
        elif line.startswith("HOLLOW-RESUME"):
            out["resume_ok"] = True
        elif "HOLLOW-TERMINATED" in line:
            out["terminated"] = True

    low = (so + " " + se).lower()
    if ("blocked by your antivirus" in low or
        "trojan" in low or
        "malicious behaviour" in low or
        "malwareprotection" in low or
        "operation did not complete successfully because the file contains a virus" in low or
        (result.get("rc") and result.get("rc") != 0 and
         ("denied" in low or "blocked" in low or "malicious" in low))):
        out["blocked_by_edr"] = True

    out["raw_summary"] = (
        f"rc={result.get('rc')} "
        f"stdout-tail={(so or '')[-200:].replace(chr(10), ' ')} "
        f"stderr-head={(se or '')[:120].replace(chr(10), ' ')}"
    )[:400]
    return out


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["process_hollowing_detection_test_total"] = 0
        ctx.source("no-target")
        return
    if not _WINRM_OK:
        ctx.state["process_hollowing_detection_test_error"] = "pywinrm not installed"
        ctx.source("pywinrm missing")
        return

    opts = ctx.state.get("_options") or {}
    user = (opts.get("username") or "").strip()
    password = opts.get("password") or ""
    if not user or not password:
        ctx.state["process_hollowing_detection_test_total"] = 0
        ctx.state["process_hollowing_creds_missing"] = True
        ctx.source("missing WinRM creds")
        return

    use_ssl = bool(opts.get("use_ssl"))
    port = int(opts.get("port") or (DEFAULT_PORT_HTTPS if use_ssl else DEFAULT_PORT_HTTP))
    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 15), 180)

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_do_winrm, target, port, use_ssl, user, password, timeout),
            timeout=timeout * 4,
        )
    except asyncio.TimeoutError:
        ctx.state["process_hollowing_detection_test_error"] = "winrm timeout"
        ctx.state["process_hollowing_detection_test_total"] = 0
        ctx.source("winrm timeout")
        return

    if result.get("_auth_failed"):
        ctx.state["process_hollowing_winrm_auth_failed"] = True
        ctx.state["process_hollowing_detection_test_total"] = 0
        ctx.source("winrm auth failed")
        return
    if result.get("_conn_error"):
        ctx.state["process_hollowing_detection_test_error"] = f"winrm: {result['_conn_error']}"
        ctx.state["process_hollowing_detection_test_total"] = 0
        ctx.source("winrm connect error")
        return

    evald = _evaluate(result)
    ctx.state["process_hollowing_pinvoke_compiled"] = evald["pinvoke_compiled"]
    ctx.state["process_hollowing_create_ok"]        = evald["create_ok"]
    ctx.state["process_hollowing_create_pid"]       = evald["create_pid"]
    ctx.state["process_hollowing_read_ok"]          = evald["read_ok"]
    ctx.state["process_hollowing_unmap_attempted"]  = evald["unmap_attempted"]
    ctx.state["process_hollowing_write_ok"]         = evald["write_ok"]
    ctx.state["process_hollowing_resume_ok"]        = evald["resume_ok"]
    ctx.state["process_hollowing_terminated"]       = evald["terminated"]
    ctx.state["process_hollowing_blocked_by_edr"]   = evald["blocked_by_edr"]
    ctx.state["process_hollowing_summary"]          = evald["raw_summary"]
    ctx.state["process_hollowing_detection_test_total"] = 1
    ctx.source(
        f"winrm://{user}@{target}:{port} -> "
        f"create={'OK' if evald['create_ok'] else 'FAIL'} "
        f"unmap={'OK' if evald['unmap_attempted'] else 'FAIL'} "
        f"resume={'OK' if evald['resume_ok'] else 'FAIL'} "
        f"edr={'BLOCKED' if evald['blocked_by_edr'] else 'NOT-BLOCKED'}"
    )


INTEL_FIELDS = [
    ("WinRM port",              "process_hollowing_target_port"),
    ("P/Invoke compiled",       "process_hollowing_pinvoke_compiled"),
    ("CreateProcess SUSPENDED", "process_hollowing_create_ok"),
    ("Suspended PID",           "process_hollowing_create_pid"),
    ("ReadProcessMemory",       "process_hollowing_read_ok"),
    ("ZwUnmapViewOfSection",    "process_hollowing_unmap_attempted"),
    ("WriteProcessMemory",      "process_hollowing_write_ok"),
    ("ResumeThread",            "process_hollowing_resume_ok"),
    ("TerminateProcess",        "process_hollowing_terminated"),
    ("Blocked by EDR",          "process_hollowing_blocked_by_edr"),
    ("Run summary",             "process_hollowing_summary"),
]


class ProcessHollowingRequest(ScanRequest):
    options: Optional[dict] = None


@router.post("/api/av_evasion/process_hollowing_detection_test")
async def av_evasion_process_hollowing_detection_test(
    req: ProcessHollowingRequest, _=Depends(verify_scan_quota),
):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        use_ssl = bool(options.get("use_ssl"))
        ctx.state["process_hollowing_target_port"] = int(
            options.get("port") or (DEFAULT_PORT_HTTPS if use_ssl else DEFAULT_PORT_HTTP)
        )
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="process_hollowing_detection_test",
        gather_func=_gather_with_options,
        finding_rules=PROCESS_HOLLOWING_DETECTION_TEST_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
