"""encoded_shellcode_detection_test - base64 shellcode decode detection probe.

What it does:
  Generates a 256-byte BENIGN x86_64 payload:

      0x90 * 253   (NOP sled)
      0x31 0xC0    (xor eax, eax)
      0xC3         (ret)

  Base64-encodes the payload (becomes a ~344-char string) and sends it
  to a Windows target over WinRM (pywinrm). On the target PowerShell:

    [byte[]]$bytes = [Convert]::FromBase64String('<344-char blob>')
    Write-Output ('LEN=' + $bytes.Length)
    Write-Output ('B0=0x' + $bytes[0].ToString('X2'))

  The shellcode is DECODED but NEVER executed:
    - No VirtualAlloc()
    - No CreateThread / NtCreateThreadEx
    - No Marshal::Copy into RWX memory

  We're testing whether the customer's AV/EDR catches the decode at the
  static-scan layer (i.e. signature-matches the base64 blob in transit
  or in PowerShell's AMSI hook), versus only catching it at execution.

What this probe is NOT:
  - Not an exploit payload (NOP+xor+ret is provably inert).
  - No code is executed on the target.

MITRE: T1027 (Obfuscated Files or Information) +
       T1027.002 (Software Packing) +
       T1027.013 (Encrypted/Encoded Files)
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
import base64
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.encoded_shellcode_detection_test_findings import (
    ENCODED_SHELLCODE_DETECTION_TEST_FINDING_RULES,
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


def _build_benign_shellcode() -> bytes:
    """256 bytes: 253 NOPs + xor eax,eax + ret. Provably inert."""
    return b"\x90" * 253 + b"\x31\xC0\xC3"


def _ps_decode_only(b64: str) -> str:
    """Return a PS one-liner that decodes the base64 to a byte[] and
    writes the length + first byte to stdout. NO execution."""
    return (
        r"$ErrorActionPreference = 'SilentlyContinue'" "\n"
        r"Write-Output '== DECODE-BEGIN =='" "\n"
        r"try {" "\n"
        r"    [byte[]]$bytes = [Convert]::FromBase64String('" + b64 + r"')" "\n"
        r"    Write-Output ('LEN=' + $bytes.Length)" "\n"
        r"    Write-Output ('B0=0x' + $bytes[0].ToString('X2'))" "\n"
        r"    Write-Output ('B253=0x' + $bytes[253].ToString('X2'))" "\n"
        r"    Write-Output ('B255=0x' + $bytes[255].ToString('X2'))" "\n"
        r"    Write-Output 'DECODE-OK-NOT-EXECUTED'" "\n"
        r"} catch {" "\n"
        r"    Write-Output ('DECODE-EXCEPTION|' + $_.Exception.GetType().FullName + '|' + $_.Exception.Message)" "\n"
        r"}" "\n"
        r"Write-Output '== DECODE-END =='" "\n"
    )


def _do_winrm(host, port, use_ssl, user, password, timeout, ps_script):
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
        r = s.run_ps(ps_script)
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
        "decode_ok": False,
        "decoded_len": 0,
        "first_byte": None,
        "decode_blocked": False,
        "av_signature_hit": False,
        "raw_summary": "",
    }
    so = result.get("stdout") or ""
    se = result.get("stderr") or ""
    for line in so.splitlines():
        if line.startswith("LEN="):
            try:
                out["decoded_len"] = int(line.split("=", 1)[1])
            except Exception:
                pass
        elif line.startswith("B0="):
            out["first_byte"] = line.split("=", 1)[1].strip()
        elif "DECODE-OK-NOT-EXECUTED" in line:
            out["decode_ok"] = True

    low = (so + " " + se).lower()
    blocked = False
    if "amsiscanbuffer" in low: blocked = True
    elif "this script contains malicious content" in low: blocked = True
    elif "blocked by your antivirus" in low: blocked = True
    elif "operation did not complete successfully because" in low: blocked = True
    elif "trojan" in low or "virus" in low: blocked = True
    elif (result.get("rc") and result.get("rc") != 0 and
          ("amsi" in low or "av" in low or "blocked" in low or "malicious" in low)):
        blocked = True
    if blocked:
        out["decode_blocked"] = True
        out["av_signature_hit"] = True

    out["raw_summary"] = (
        f"rc={result.get('rc')} "
        f"stdout-head={(so or '')[:120].replace(chr(10), ' ')} "
        f"stderr-head={(se or '')[:120].replace(chr(10), ' ')}"
    )[:300]
    return out


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["encoded_shellcode_detection_test_total"] = 0
        ctx.source("no-target")
        return
    if not _WINRM_OK:
        ctx.state["encoded_shellcode_detection_test_error"] = "pywinrm not installed"
        ctx.source("pywinrm missing")
        return

    opts = ctx.state.get("_options") or {}
    user = (opts.get("username") or "").strip()
    password = opts.get("password") or ""
    if not user or not password:
        ctx.state["encoded_shellcode_detection_test_total"] = 0
        ctx.state["encoded_shellcode_creds_missing"] = True
        ctx.source("missing WinRM creds")
        return

    use_ssl = bool(opts.get("use_ssl"))
    port = int(opts.get("port") or (DEFAULT_PORT_HTTPS if use_ssl else DEFAULT_PORT_HTTP))
    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 10), 120)

    shellcode = _build_benign_shellcode()
    b64 = base64.b64encode(shellcode).decode("ascii")
    ctx.state["encoded_shellcode_payload_bytes"] = len(shellcode)
    ctx.state["encoded_shellcode_b64_chars"] = len(b64)

    ps_script = _ps_decode_only(b64)
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_do_winrm, target, port, use_ssl, user, password, timeout, ps_script),
            timeout=timeout * 4,
        )
    except asyncio.TimeoutError:
        ctx.state["encoded_shellcode_detection_test_error"] = "winrm timeout"
        ctx.state["encoded_shellcode_detection_test_total"] = 0
        ctx.source("winrm timeout")
        return

    if result.get("_auth_failed"):
        ctx.state["encoded_shellcode_winrm_auth_failed"] = True
        ctx.state["encoded_shellcode_detection_test_total"] = 0
        ctx.source("winrm auth failed")
        return
    if result.get("_conn_error"):
        ctx.state["encoded_shellcode_detection_test_error"] = f"winrm: {result['_conn_error']}"
        ctx.state["encoded_shellcode_detection_test_total"] = 0
        ctx.source("winrm connect error")
        return

    evald = _evaluate(result)
    ctx.state["encoded_shellcode_decode_ok"]        = evald["decode_ok"]
    ctx.state["encoded_shellcode_decoded_len"]      = evald["decoded_len"]
    ctx.state["encoded_shellcode_first_byte"]       = evald["first_byte"]
    ctx.state["encoded_shellcode_blocked"]          = evald["decode_blocked"]
    ctx.state["encoded_shellcode_signature_hit"]    = evald["av_signature_hit"]
    ctx.state["encoded_shellcode_summary"]          = evald["raw_summary"]
    ctx.state["encoded_shellcode_detection_test_total"] = 1
    ctx.source(
        f"winrm://{user}@{target}:{port} -> "
        f"payload={len(shellcode)}B/{len(b64)}c base64 "
        f"decode={'OK' if evald['decode_ok'] else 'BLOCKED'}"
    )


INTEL_FIELDS = [
    ("WinRM port",            "encoded_shellcode_target_port"),
    ("Payload size (bytes)",  "encoded_shellcode_payload_bytes"),
    ("Base64 length (chars)", "encoded_shellcode_b64_chars"),
    ("Decoded length",        "encoded_shellcode_decoded_len"),
    ("First byte (hex)",      "encoded_shellcode_first_byte"),
    ("Decode succeeded",      "encoded_shellcode_decode_ok"),
    ("Blocked by AV",         "encoded_shellcode_blocked"),
    ("Run summary",           "encoded_shellcode_summary"),
]


class EncodedShellcodeRequest(ScanRequest):
    options: Optional[dict] = None


@router.post("/api/av_evasion/encoded_shellcode_detection_test")
async def av_evasion_encoded_shellcode_detection_test(
    req: EncodedShellcodeRequest, _=Depends(verify_scan_quota),
):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        use_ssl = bool(options.get("use_ssl"))
        ctx.state["encoded_shellcode_target_port"] = int(
            options.get("port") or (DEFAULT_PORT_HTTPS if use_ssl else DEFAULT_PORT_HTTP)
        )
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="encoded_shellcode_detection_test",
        gather_func=_gather_with_options,
        finding_rules=ENCODED_SHELLCODE_DETECTION_TEST_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
