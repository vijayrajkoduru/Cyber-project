"""direct_syscall_detection_test - inline syscall detection probe.

What it does:
  Pushes a benign PowerShell + P/Invoke probe over WinRM that allocates
  a small RW page via NtAllocateVirtualMemory using a DIRECT SYSCALL
  (inline `syscall` assembly instruction), bypassing ntdll.dll user-mode
  hooks that most EDRs install for monitoring.

  Two implementation paths are attempted:

    1. PRIMARY: assemble a tiny 11-byte shellcode stub that performs
       `mov r10, rcx ; mov eax, <syscall_id> ; syscall ; ret`, install
       it into RWX memory via VirtualAlloc, and invoke it via a delegate.
       If the customer's EDR detects RWX allocation or the syscall stub
       pattern, this attempt is killed.

    2. FALLBACK: P/Invoke NtAllocateVirtualMemory directly out of
       ntdll.dll (no inline syscall). This is the BASELINE path and
       always succeeds on a healthy box; it lets us prove the allocation
       primitive is reachable so we can attribute any failure of #1 to
       EDR detection rather than to a coding bug.

  All allocations are 4 KB, marked RW (or RWX for the syscall stub),
  and immediately FREED via NtFreeVirtualMemory. No code is executed
  inside the allocations beyond the 11-byte stub itself, which only
  allocates + frees memory.

What this probe is NOT:
  - Not a payload-stager (no shellcode is run inside the allocations).
  - Not a privilege-escalation primitive (NtAllocateVirtualMemory in
    the current process does not need SE_DEBUG_NAME).

MITRE: T1106 (Native API) +
       T1620 (Reflective Code Loading) - because direct syscalls are
       used to evade userland hooks
CWE  : CWE-693 (Protection Mechanism Failure)

Customer input via ScanRequest.options:
  - username      Windows account (required)
  - password      account password (required)
  - port          WinRM port (default 5985 / 5986)
  - use_ssl       bool (default false)
  - timeout_sec   per-cmd cap (default 45)
"""
from __future__ import annotations
import asyncio
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.direct_syscall_detection_test_findings import (
    DIRECT_SYSCALL_DETECTION_TEST_FINDING_RULES,
)

router = APIRouter()

try:
    import winrm   # noqa: F401
    _WINRM_OK = True
except Exception:
    _WINRM_OK = False

DEFAULT_PORT_HTTP = 5985
DEFAULT_PORT_HTTPS = 5986
DEFAULT_TIMEOUT = 45


# PowerShell probe:
#   - Compile P/Invoke for VirtualAlloc, VirtualFree, NtAllocateVirtualMemory,
#     NtFreeVirtualMemory, GetModuleHandle, GetProcAddress.
#   - Resolve the SSN (syscall number) of NtAllocateVirtualMemory by
#     reading the first 8 bytes of its export from ntdll.dll. On modern
#     Win10/Win11 the pattern is `4C 8B D1 B8 <SSN:DWORD> F6 04 25 ...`.
#   - Build an 11-byte stub: mov r10, rcx ; mov eax, <SSN> ; syscall ; ret
#   - Allocate RWX, copy the stub in, invoke as a delegate, allocate
#     4 KB via the inline syscall, then free + cleanup.
#   - Also run the BASELINE P/Invoke path so we can prove the API is
#     reachable when the direct syscall path fails.
PS_SYSCALL_PROBE = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Output '== SYSCALL-BEGIN =='

$sig = @'
using System;
using System.Runtime.InteropServices;
public class VLSys {
    public const uint MEM_COMMIT          = 0x1000;
    public const uint MEM_RESERVE         = 0x2000;
    public const uint MEM_RELEASE         = 0x8000;
    public const uint PAGE_READWRITE      = 0x04;
    public const uint PAGE_EXECUTE_RW     = 0x40;

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size,
        uint allocType, uint protect);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualFree(IntPtr addr, UIntPtr size, uint freeType);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr h, string proc);
    [DllImport("ntdll.dll")]
    public static extern uint NtAllocateVirtualMemory(IntPtr hProc,
        ref IntPtr baseAddr, IntPtr zeroBits, ref UIntPtr regionSize,
        uint allocType, uint protect);
    [DllImport("ntdll.dll")]
    public static extern uint NtFreeVirtualMemory(IntPtr hProc,
        ref IntPtr baseAddr, ref UIntPtr regionSize, uint freeType);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate uint NtAllocDel(IntPtr hProc, ref IntPtr baseAddr,
        IntPtr zeroBits, ref UIntPtr regionSize, uint allocType, uint protect);
}
'@
try {
    Add-Type -TypeDefinition $sig -ErrorAction Stop
    Write-Output 'SYSCALL-PINVOKE-COMPILED'

    # ---------- Baseline P/Invoke NtAllocateVirtualMemory ----------
    $base1 = [IntPtr]::Zero
    $sz1 = [UIntPtr]::new(4096)
    $st1 = [VLSys]::NtAllocateVirtualMemory(
        [IntPtr]-1, [ref]$base1, [IntPtr]::Zero, [ref]$sz1,
        [VLSys]::MEM_COMMIT -bor [VLSys]::MEM_RESERVE, [VLSys]::PAGE_READWRITE)
    Write-Output ('SYSCALL-BASELINE|status=0x' + $st1.ToString('X8') + '|addr=' + $base1.ToString())
    if ($base1 -ne [IntPtr]::Zero) {
        $null = [VLSys]::NtFreeVirtualMemory(
            [IntPtr]-1, [ref]$base1, [ref]$sz1, [VLSys]::MEM_RELEASE)
    }

    # ---------- Resolve SSN of NtAllocateVirtualMemory ----------
    $ntdll = [VLSys]::GetModuleHandle('ntdll.dll')
    $proc  = [VLSys]::GetProcAddress($ntdll, 'NtAllocateVirtualMemory')
    if ($ntdll -eq [IntPtr]::Zero -or $proc -eq [IntPtr]::Zero) {
        Write-Output 'SYSCALL-NO-NTDLL'
    } else {
        # Read first 8 bytes - expect 4C 8B D1 B8 ?? ?? ?? ?? (mov r10,rcx; mov eax,SSN)
        $prologue = New-Object byte[] 8
        [System.Runtime.InteropServices.Marshal]::Copy($proc, $prologue, 0, 8)
        $hex = ($prologue | ForEach-Object { $_.ToString('X2') }) -join ' '
        Write-Output ('SYSCALL-PROLOGUE|' + $hex)
        $ssn = $null
        if ($prologue[0] -eq 0x4C -and $prologue[1] -eq 0x8B -and
            $prologue[2] -eq 0xD1 -and $prologue[3] -eq 0xB8) {
            $ssn = [BitConverter]::ToUInt32($prologue, 4)
            Write-Output ('SYSCALL-SSN|' + $ssn)
        } else {
            Write-Output 'SYSCALL-SSN-PATTERN-MISMATCH'
        }

        if ($ssn -ne $null) {
            # 11-byte syscall stub: mov r10,rcx ; mov eax,SSN ; syscall ; ret
            $stub = New-Object byte[] 11
            $stub[0]=0x4C; $stub[1]=0x8B; $stub[2]=0xD1
            $stub[3]=0xB8
            $ssnBytes = [BitConverter]::GetBytes([uint32]$ssn)
            for ($i=0; $i -lt 4; $i++) { $stub[4+$i] = $ssnBytes[$i] }
            $stub[8]=0x0F; $stub[9]=0x05; $stub[10]=0xC3

            $rwx = [VLSys]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new(4096),
                [VLSys]::MEM_COMMIT -bor [VLSys]::MEM_RESERVE, [VLSys]::PAGE_EXECUTE_RW)
            if ($rwx -eq [IntPtr]::Zero) {
                Write-Output ('SYSCALL-RWX-FAILED|err=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
            } else {
                [System.Runtime.InteropServices.Marshal]::Copy($stub, 0, $rwx, 11)
                Write-Output ('SYSCALL-STUB-WRITTEN|rwx=' + $rwx.ToString())

                $del = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
                    $rwx, [type]([VLSys+NtAllocDel]))
                $base2 = [IntPtr]::Zero
                $sz2 = [UIntPtr]::new(4096)
                $st2 = $del.Invoke([IntPtr]-1, [ref]$base2, [IntPtr]::Zero, [ref]$sz2,
                    [VLSys]::MEM_COMMIT -bor [VLSys]::MEM_RESERVE, [VLSys]::PAGE_READWRITE)
                Write-Output ('SYSCALL-DIRECT|status=0x' + $st2.ToString('X8') + '|addr=' + $base2.ToString())
                if ($base2 -ne [IntPtr]::Zero) {
                    $null = [VLSys]::NtFreeVirtualMemory(
                        [IntPtr]-1, [ref]$base2, [ref]$sz2, [VLSys]::MEM_RELEASE)
                }
                $null = [VLSys]::VirtualFree($rwx, [UIntPtr]::Zero, [VLSys]::MEM_RELEASE)
                Write-Output 'SYSCALL-CLEANUP-OK'
            }
        }
    }
} catch {
    Write-Output ('SYSCALL-EXCEPTION|' + $_.Exception.GetType().FullName + '|' + $_.Exception.Message)
}
Write-Output '== SYSCALL-END =='
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
        r = s.run_ps(PS_SYSCALL_PROBE)
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
        "baseline_ok": False,
        "baseline_status": None,
        "ssn_resolved": False,
        "ssn_value": None,
        "stub_written": False,
        "direct_syscall_ok": False,
        "direct_status": None,
        "cleanup_ok": False,
        "blocked_by_edr": False,
        "raw_summary": "",
    }
    so = result.get("stdout") or ""
    se = result.get("stderr") or ""
    if "SYSCALL-PINVOKE-COMPILED" in so:
        out["pinvoke_compiled"] = True
    for line in so.splitlines():
        if line.startswith("SYSCALL-BASELINE"):
            for p in line.split("|"):
                if p.startswith("status="):
                    out["baseline_status"] = p.split("=", 1)[1]
                if p.startswith("addr=") and p.split("=", 1)[1] not in ("0", "0x0"):
                    out["baseline_ok"] = True
        elif line.startswith("SYSCALL-SSN|"):
            out["ssn_resolved"] = True
            try: out["ssn_value"] = int(line.split("|", 1)[1])
            except Exception: pass
        elif "SYSCALL-STUB-WRITTEN" in line:
            out["stub_written"] = True
        elif line.startswith("SYSCALL-DIRECT"):
            for p in line.split("|"):
                if p.startswith("status="):
                    out["direct_status"] = p.split("=", 1)[1]
                if p.startswith("addr=") and p.split("=", 1)[1] not in ("0", "0x0"):
                    out["direct_syscall_ok"] = True
        elif "SYSCALL-CLEANUP-OK" in line:
            out["cleanup_ok"] = True

    low = (so + " " + se).lower()
    if ("blocked by your antivirus" in low or
        "this script contains malicious content" in low or
        "malwareprotection" in low or
        "trojan" in low or
        (result.get("rc") and result.get("rc") != 0 and
         ("denied" in low or "blocked" in low or "malicious" in low or "amsi" in low))):
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
        ctx.state["direct_syscall_detection_test_total"] = 0
        ctx.source("no-target")
        return
    if not _WINRM_OK:
        ctx.state["direct_syscall_detection_test_error"] = "pywinrm not installed"
        ctx.source("pywinrm missing")
        return

    opts = ctx.state.get("_options") or {}
    user = (opts.get("username") or "").strip()
    password = opts.get("password") or ""
    if not user or not password:
        ctx.state["direct_syscall_detection_test_total"] = 0
        ctx.state["direct_syscall_creds_missing"] = True
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
        ctx.state["direct_syscall_detection_test_error"] = "winrm timeout"
        ctx.state["direct_syscall_detection_test_total"] = 0
        ctx.source("winrm timeout")
        return

    if result.get("_auth_failed"):
        ctx.state["direct_syscall_winrm_auth_failed"] = True
        ctx.state["direct_syscall_detection_test_total"] = 0
        ctx.source("winrm auth failed")
        return
    if result.get("_conn_error"):
        ctx.state["direct_syscall_detection_test_error"] = f"winrm: {result['_conn_error']}"
        ctx.state["direct_syscall_detection_test_total"] = 0
        ctx.source("winrm connect error")
        return

    evald = _evaluate(result)
    ctx.state["direct_syscall_pinvoke_compiled"] = evald["pinvoke_compiled"]
    ctx.state["direct_syscall_baseline_ok"]      = evald["baseline_ok"]
    ctx.state["direct_syscall_baseline_status"]  = evald["baseline_status"]
    ctx.state["direct_syscall_ssn_resolved"]     = evald["ssn_resolved"]
    ctx.state["direct_syscall_ssn_value"]        = evald["ssn_value"]
    ctx.state["direct_syscall_stub_written"]     = evald["stub_written"]
    ctx.state["direct_syscall_direct_ok"]        = evald["direct_syscall_ok"]
    ctx.state["direct_syscall_direct_status"]    = evald["direct_status"]
    ctx.state["direct_syscall_cleanup_ok"]       = evald["cleanup_ok"]
    ctx.state["direct_syscall_blocked_by_edr"]   = evald["blocked_by_edr"]
    ctx.state["direct_syscall_summary"]          = evald["raw_summary"]
    ctx.state["direct_syscall_detection_test_total"] = 1
    ctx.source(
        f"winrm://{user}@{target}:{port} -> "
        f"baseline={'OK' if evald['baseline_ok'] else 'FAIL'} "
        f"ssn={evald['ssn_value'] or '-'} "
        f"direct={'OK' if evald['direct_syscall_ok'] else 'FAIL'} "
        f"edr={'BLOCKED' if evald['blocked_by_edr'] else 'NOT-BLOCKED'}"
    )


INTEL_FIELDS = [
    ("WinRM port",                "direct_syscall_target_port"),
    ("P/Invoke compiled",         "direct_syscall_pinvoke_compiled"),
    ("Baseline NtAlloc",          "direct_syscall_baseline_ok"),
    ("Baseline status",           "direct_syscall_baseline_status"),
    ("SSN resolved",              "direct_syscall_ssn_resolved"),
    ("Syscall number (SSN)",      "direct_syscall_ssn_value"),
    ("Inline stub written",       "direct_syscall_stub_written"),
    ("Direct syscall allocation", "direct_syscall_direct_ok"),
    ("Direct syscall status",     "direct_syscall_direct_status"),
    ("Cleanup",                   "direct_syscall_cleanup_ok"),
    ("Blocked by EDR",            "direct_syscall_blocked_by_edr"),
    ("Run summary",               "direct_syscall_summary"),
]


class DirectSyscallRequest(ScanRequest):
    options: Optional[dict] = None


@router.post("/api/av_evasion/direct_syscall_detection_test")
async def av_evasion_direct_syscall_detection_test(
    req: DirectSyscallRequest, _=Depends(verify_scan_quota),
):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        use_ssl = bool(options.get("use_ssl"))
        ctx.state["direct_syscall_target_port"] = int(
            options.get("port") or (DEFAULT_PORT_HTTPS if use_ssl else DEFAULT_PORT_HTTP)
        )
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="direct_syscall_detection_test",
        gather_func=_gather_with_options,
        finding_rules=DIRECT_SYSCALL_DETECTION_TEST_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
