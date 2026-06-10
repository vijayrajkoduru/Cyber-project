"""winpeas_check - WinRM upload + execute WinPEAS (playbook §2 #19).

Uses the pywinrm Python library to connect to ctx.host (Windows target)
via WinRM (default port 5985 HTTP). Uploads
/opt/peass-ng/winPEAS/winPEASexe/binaries/Release/x64/winPEASany.exe to
C:\\Windows\\Temp\\vlp_winpeas.exe (chunked base64 PowerShell write),
executes it, parses output for HIGH/CRITICAL findings, deletes the upload.

Customer input via ScanRequest.options:
  - target              = Windows host/IP (ctx.host)
  - options.username    = Windows username (required; may be DOMAIN\\user or user@domain)
  - options.password    = Windows password (required)
  - options.winrm_port  = WinRM port override (default 5985 HTTP, 5986 HTTPS)
  - options.use_ssl     = bool, default False (set True for 5986)
  - options.timeout_sec = wall-clock cap (default 300)
  - options.transport   = pywinrm transport: ntlm (default), kerberos, basic
"""
from __future__ import annotations
import asyncio
import base64
import os
import re
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.winpeas_check_findings import (
    WINPEAS_CHECK_FINDING_RULES,
)

router = APIRouter()

WINPEAS_BIN_PATH = "/opt/peass-ng/winPEAS/winPEASexe/binaries/Release/x64/winPEASany.exe"
REMOTE_WIN_PATH = r"C:\Windows\Temp\vlp_winpeas.exe"
DEFAULT_TIMEOUT = 300


class WinpeasCheckRequest(ScanRequest):
    options: Optional[dict] = None


# WinPEAS color tagging: it emits "[+]" markers + RED bold for HIGH/CRITICAL.
# We can't reliably keep colors over WinRM, so we pattern-match.
_CRITICAL_PATTERNS = [
    (r"AlwaysInstallElevated.*=.*1",     "AlwaysInstallElevated MSI install elevated"),
    (r"writable.*service.*binary",       "Writable service binary"),
    (r"cmdkey.*persists",                "Stored credentials in cmdkey vault"),
    (r"unattend\.xml.*found",            "Unattend.xml with cleartext credential"),
    (r"sysprep\.xml.*found",             "Sysprep.xml with cleartext credential"),
    (r"unquoted.*service.*path.*writable", "Unquoted service path + writable dir"),
]
_HIGH_PATTERNS = [
    (r"authenticated.users.*full.control", "Authenticated Users : Full Control on service ACL"),
    (r"everyone.*write",                 "Everyone : Write granted on sensitive object"),
    (r"unquoted.*service.*path",         "Unquoted service path"),
    (r"autorun.*world.writable",         "World-writable autorun registry key"),
    (r"weak.*registry.*permission",      "Weak registry permission on service key"),
    (r"LAPS.*not.*installed",            "LAPS not deployed (no local admin rotation)"),
    (r"Defender.*disabled",              "Windows Defender disabled"),
]
_MEDIUM_PATTERNS = [
    (r"SMBv1.*enabled",                  "SMBv1 protocol still enabled"),
    (r"smb1.*enabled",                   "SMBv1 protocol still enabled"),
    (r"password.*never.*expires",        "User account with PasswordNeverExpires"),
    (r"weak.*password.*policy",          "Weak password policy"),
    (r"stale.*user",                     "Stale local user account"),
]


def _scan_patterns(text: str, patterns: list, severity: str) -> list[dict]:
    out = []
    low = text.lower()
    for pat, title in patterns:
        if re.search(pat, low, re.IGNORECASE):
            out.append({"severity": severity, "title": title, "pattern": pat})
    return out


def _build_session(target: str, port: int, username: str, password: str,
                   use_ssl: bool, transport: str, timeout: int):
    """Build a pywinrm Session. Raises ImportError/ValueError on bad input."""
    import winrm
    scheme = "https" if use_ssl else "http"
    endpoint = f"{scheme}://{target}:{port}/wsman"
    return winrm.Session(
        endpoint,
        auth=(username, password),
        transport=transport,
        server_cert_validation="ignore",
        read_timeout_sec=timeout + 30,
        operation_timeout_sec=timeout,
    )


def _run_ps(session, ps_command: str):
    """Run a PowerShell command through pywinrm. Returns (stdout, stderr, rc)."""
    res = session.run_ps(ps_command)
    return (
        (res.std_out or b"").decode("utf-8", errors="ignore"),
        (res.std_err or b"").decode("utf-8", errors="ignore"),
        int(res.status_code or 0),
    )


def _upload_via_chunks(session, local_path: str, remote_path: str, chunk: int = 32768) -> int:
    """Upload local binary to remote path via base64 chunked PowerShell.
    First chunk truncates with WriteAllBytes; subsequent chunks append via
    [IO.File]::Open with FileMode.Append (cast as int 6).
    Reference pattern: impacket smbexec / pywinrm community gist."""
    written = 0
    first = True
    with open(local_path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            b64 = base64.b64encode(block).decode("ascii")
            if first:
                # Truncate + write first chunk in one call.
                ps = (
                    f"$b = [Convert]::FromBase64String('{b64}'); "
                    f"[IO.File]::WriteAllBytes('{remote_path}', $b)"
                )
            else:
                # Append via [System.IO.File]::AppendAllBytes equivalent.
                # PowerShell has no AppendAllBytes < .NET 4.5, so use a
                # FileStream opened in Append mode (enum value 6).
                ps = (
                    f"$b = [Convert]::FromBase64String('{b64}'); "
                    f"$f = New-Object System.IO.FileStream("
                    f"'{remote_path}', [System.IO.FileMode]::Append); "
                    f"$f.Write($b, 0, $b.Length); $f.Close(); $f.Dispose()"
                )
            out, err, rc = _run_ps(session, ps)
            if rc != 0:
                raise RuntimeError(f"upload chunk rc={rc} err={err[:200]}")
            written += len(block)
            first = False
    return written


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["winpeas_no_target"] = True
        ctx.source("no-target")
        return

    try:
        import winrm  # noqa: F401
    except ImportError:
        ctx.state["winpeas_pywinrm_missing"] = True
        ctx.source("pywinrm missing")
        return

    opts = ctx.state.get("_options") or {}
    username = (opts.get("username") or "").strip()
    password = opts.get("password") or ""

    if not username or not password:
        ctx.state["winpeas_no_creds"] = True
        ctx.source("missing username + password")
        return

    if not os.path.exists(WINPEAS_BIN_PATH):
        ctx.state["winpeas_binary_missing"] = True
        ctx.source(f"{WINPEAS_BIN_PATH} missing")
        return

    use_ssl = bool(opts.get("use_ssl"))
    port = int(opts.get("winrm_port") or (5986 if use_ssl else 5985))
    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 60), 600)
    transport = (opts.get("transport") or "ntlm").lower()
    if transport not in ("ntlm", "kerberos", "basic", "credssp", "plaintext"):
        transport = "ntlm"

    ctx.state["winpeas_host"] = f"{username}@{target}:{port} ({transport})"

    loop = asyncio.get_event_loop()
    session = None
    try:
        session = await loop.run_in_executor(
            None,
            lambda: _build_session(target, port, username, password,
                                    use_ssl, transport, timeout),
        )
    except Exception as e:
        ctx.state["winpeas_winrm_error"] = str(e)[:200]
        ctx.source(f"WinRM session build failed: {str(e)[:80]}")
        return

    try:
        # Smoke-test the WinRM session.
        try:
            out, err, rc = await asyncio.wait_for(
                loop.run_in_executor(None, _run_ps, session, "$PSVersionTable.PSVersion"),
                timeout=30,
            )
            if rc != 0:
                ctx.state["winpeas_winrm_error"] = f"smoke-test rc={rc} err={err[:200]}"
                ctx.source(f"WinRM smoke-test failed: {err[:80]}")
                return
        except asyncio.TimeoutError:
            ctx.state["winpeas_winrm_error"] = "WinRM smoke-test timed out after 30s"
            ctx.source("WinRM smoke-test timed out")
            return

        # Upload WinPEAS.
        try:
            written = await asyncio.wait_for(
                loop.run_in_executor(
                    None, _upload_via_chunks, session, WINPEAS_BIN_PATH, REMOTE_WIN_PATH,
                ),
                timeout=timeout,
            )
            ctx.state["winpeas_upload_bytes"] = written
        except Exception as e:
            ctx.state["winpeas_winrm_error"] = f"upload failed: {str(e)[:200]}"
            ctx.source(f"upload failed: {str(e)[:80]}")
            return

        # Execute WinPEAS. notcolor stops ANSI codes (some terminals show garbage).
        ps_run = (
            f"& '{REMOTE_WIN_PATH}' notcolor quiet 2>&1 | Out-String"
        )
        try:
            stdout, stderr, rc = await asyncio.wait_for(
                loop.run_in_executor(None, _run_ps, session, ps_run),
                timeout=timeout + 30,
            )
        except asyncio.TimeoutError:
            ctx.state["winpeas_winrm_error"] = f"WinPEAS exec timed out after {timeout}s"
            ctx.source(f"WinPEAS exec timeout @ {timeout}s")
            return

        if rc != 0 and not stdout:
            ctx.state["winpeas_winrm_error"] = f"WinPEAS rc={rc} err={stderr[:200]}"
            ctx.source(f"WinPEAS rc={rc}")
            return

        # Parse for severity-tagged findings.
        findings: list[dict] = []
        findings.extend(_scan_patterns(stdout, _CRITICAL_PATTERNS, "CRITICAL"))
        findings.extend(_scan_patterns(stdout, _HIGH_PATTERNS, "HIGH"))
        findings.extend(_scan_patterns(stdout, _MEDIUM_PATTERNS, "MEDIUM"))

        ctx.state["winpeas_findings"] = findings
        ctx.state["winpeas_output_bytes"] = len(stdout)
        ctx.state["winpeas_ran"] = True
        ctx.source(
            f"WinPEAS complete: {len(stdout)} bytes, "
            f"{len(findings)} parsed findings"
        )

    finally:
        # Always attempt cleanup; ignore failures.
        try:
            cleanup_ps = (
                f"if (Test-Path '{REMOTE_WIN_PATH}') "
                f"{{ Remove-Item -Force '{REMOTE_WIN_PATH}' }}"
            )
            await asyncio.wait_for(
                loop.run_in_executor(None, _run_ps, session, cleanup_ps),
                timeout=20,
            )
        except Exception:
            pass


INTEL_FIELDS = [
    ("WinPEAS target host",    "winpeas_host"),
    ("Upload bytes",           "winpeas_upload_bytes"),
    ("Output bytes",           "winpeas_output_bytes"),
    ("Parsed findings",        "winpeas_findings"),
]


@router.post("/api/privesc/winpeas_check")
async def privesc_winpeas_check(req: WinpeasCheckRequest,
                                 _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="winpeas_check",
        gather_func=_gather_with_options,
        finding_rules=WINPEAS_CHECK_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
