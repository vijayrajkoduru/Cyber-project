"""atomic_red_team_runner - subset of Atomic Red Team tests via SSH/WinRM
   (playbook §2 #11/12 #15/17/19 + §6 #67).

Picks 10 LOW-risk-but-LOUD Atomic Red Team tests across MITRE techniques
and executes each on a customer-supplied host:
  - target = atomic host (Linux SSH or Windows WinRM)
  - options.atomic_user        - SSH/WinRM username (required)
  - options.atomic_password    - SSH/WinRM password (required when no key)
  - options.atomic_ssh_key     - PEM-formatted SSH private key (Linux)
  - options.atomic_os          - "linux" (default) or "windows"
  - options.atomic_port        - 22 (Linux SSH) / 5985 (Windows WinRM)
  - options.atomic_timeout_sec - wall-clock cap per test (default 25)

The runner does NOT exploit anything — each test is a single deterministic
command (echo / mkdir / encoded PowerShell / non-destructive registry-write)
chosen so it generates a known telemetry signature without touching data.

MITRE techniques covered:
  T1003.001 LSASS access (read-only handle; no dump)
  T1027.005 Indicator removal: base64-encoded payload string echo'd
  T1053.005 Scheduled Task creation + immediate delete
  T1059.001 PowerShell encoded command (Linux: bash -c echoed base64)
  T1547.001 Registry Run key write + immediate delete (Windows)
  T1059.004 Unix Shell: nohup + disown pattern
  T1071.001 Web Protocols: curl HEAD to known C2 IP (cloudflare)
  T1082 System Information Discovery: hostnamectl / systeminfo
  T1087.001 Local Account Discovery: net user / cat /etc/passwd | head
  T1105 Ingress Tool Transfer: curl GET to public binary URL (HEAD only)

Outputs:
  INFO finding per test executed (technique ID + command + exit code)
  Single roll-up: total tests, technique coverage, customer detection ask.
"""
from __future__ import annotations
import asyncio
import io
import os
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.atomic_red_team_runner_findings import ATOMIC_RED_TEAM_RUNNER_FINDING_RULES

router = APIRouter()
DEFAULT_TIMEOUT = 25
HARD_MAX_TIMEOUT = 60


class AtomicRedTeamRunnerRequest(ScanRequest):
    options: Optional[dict] = None


# ── Atomic Red Team test catalogue (LOW-risk, LOUD telemetry) ──────
# Each entry: (atomic_id, technique_id, name, linux_cmd, windows_cmd)
# Commands are single-line + idempotent. Linux uses bash, Windows uses
# powershell.exe -Enc / cmd.exe single liners.
ATOMIC_TESTS_LINUX = [
    ("ART-T1003.001-L1", "T1003.001", "LSASS-like /proc read (cred dump sim)",
     "test -r /proc/1/maps && head -c 8 /proc/1/maps > /dev/null && echo 'lsass-sim-ok'"),
    ("ART-T1027.005-L1", "T1027.005", "Base64-obfuscated string emit",
     "echo -n 'aWQgPSAxOyBjbWQgPSBldmlsKCk7Cg==' | base64 -d > /dev/null && echo 'obf-ok'"),
    ("ART-T1053.005-L1", "T1053.005", "Cron job add+remove (scheduled task)",
     "( crontab -l 2>/dev/null; echo '# vl-art-test' ) | crontab - && crontab -l | grep -v 'vl-art-test' | crontab -"),
    ("ART-T1059.001-L1", "T1059.001", "Encoded shell exec (bash -c base64)",
     "bash -c \"$(echo -n 'ZWNobyAndmwtYXJ0LXNoZWxsLW9rJw==' | base64 -d)\""),
    ("ART-T1059.004-L1", "T1059.004", "nohup + disown background pattern",
     "nohup bash -c 'sleep 1' >/dev/null 2>&1 & disown 2>/dev/null; echo 'nohup-ok'"),
    ("ART-T1082-L1",     "T1082",     "System info discovery (uname/hostnamectl)",
     "uname -a; ( hostnamectl 2>/dev/null || cat /etc/os-release )"),
    ("ART-T1087.001-L1", "T1087.001", "Local account enumeration",
     "getent passwd | head -n 5"),
    ("ART-T1105-L1",     "T1105",     "Tool transfer simulation (HEAD only)",
     "curl -sS -m 8 -I https://www.cloudflare.com/ | head -n 1"),
    ("ART-T1071.001-L1", "T1071.001", "C2-like Web Protocols HEAD",
     "curl -sS -m 8 -I https://1.1.1.1/cdn-cgi/trace | head -n 1"),
    ("ART-T1547.001-L1", "T1547.001", "Autostart-like file create+delete",
     "f=$(mktemp /tmp/.vl-art-XXXX); echo '#vl-art-autostart' > \"$f\" && rm -f \"$f\" && echo 'autostart-ok'"),
]

# Windows variants (executed via WinRM)
ATOMIC_TESTS_WINDOWS = [
    ("ART-T1003.001-W1", "T1003.001", "LSASS handle open (read-only, no dump)",
     "powershell.exe -NoProfile -Command \"$p=Get-Process lsass -ErrorAction SilentlyContinue; if($p){Write-Output 'lsass-handle-ok'} else {Write-Output 'no-lsass'}\""),
    ("ART-T1027.005-W1", "T1027.005", "Base64-obfuscated string decode",
     "powershell.exe -NoProfile -Command \"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('dmwtYXJ0LW9iZi1vaw==')) | Out-Null; Write-Output 'obf-ok'\""),
    ("ART-T1053.005-W1", "T1053.005", "Scheduled task create+delete",
     "schtasks /Create /TN VL-ART-TEST /TR cmd.exe /SC ONCE /ST 23:59 /F >nul 2>&1 & schtasks /Delete /TN VL-ART-TEST /F >nul 2>&1 & echo schtask-ok"),
    ("ART-T1059.001-W1", "T1059.001", "PowerShell encoded command",
     # base64 of: Write-Output 'vl-art-ps-ok'
     "powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHYAbAAtAGEAcgB0AC0AcABzAC0AbwBrACcA"),
    ("ART-T1059.004-W1", "T1059.004", "WSL/cmd background pattern",
     "cmd.exe /c \"start /B cmd /c exit 0 & echo bg-ok\""),
    ("ART-T1082-W1",     "T1082",     "System info discovery (systeminfo)",
     "cmd.exe /c \"systeminfo | findstr /R /C:\\\"OS Name\\\" /C:\\\"OS Version\\\"\""),
    ("ART-T1087.001-W1", "T1087.001", "Local user enumeration (net user)",
     "cmd.exe /c \"net user\""),
    ("ART-T1105-W1",     "T1105",     "Tool transfer simulation (HEAD only)",
     "powershell.exe -NoProfile -Command \"(Invoke-WebRequest -UseBasicParsing -Method Head -TimeoutSec 8 -Uri 'https://www.cloudflare.com/').StatusCode\""),
    ("ART-T1071.001-W1", "T1071.001", "C2-like Web Protocols HEAD",
     "powershell.exe -NoProfile -Command \"(Invoke-WebRequest -UseBasicParsing -Method Head -TimeoutSec 8 -Uri 'https://1.1.1.1/cdn-cgi/trace').StatusCode\""),
    ("ART-T1547.001-W1", "T1547.001", "Registry Run key write+delete",
     "cmd.exe /c \"reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v VL_ART_TEST /t REG_SZ /d notepad.exe /f >nul && reg delete HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v VL_ART_TEST /f >nul && echo runkey-ok\""),
]


def _build_ssh_client(host: str, port: int, user: str, password: Optional[str],
                      key_text: Optional[str]):
    """Build paramiko client. Returns (client, error_str)."""
    try:
        import paramiko  # type: ignore
    except Exception as e:
        return None, f"paramiko import failed: {e}"
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(hostname=host, port=port, username=user, timeout=10,
                      banner_timeout=10, auth_timeout=10, allow_agent=False,
                      look_for_keys=False)
        if key_text:
            pkey = None
            for cls in ("RSAKey", "Ed25519Key", "ECDSAKey", "DSSKey"):
                try:
                    klass = getattr(paramiko, cls)
                    pkey = klass.from_private_key(io.StringIO(key_text))
                    break
                except Exception:
                    continue
            if pkey is None:
                return None, "ssh key parse failed"
            kwargs["pkey"] = pkey
        else:
            kwargs["password"] = password or ""
        client.connect(**kwargs)
        return client, None
    except Exception as e:
        return None, f"ssh connect failed: {type(e).__name__}: {str(e)[:120]}"


def _ssh_exec(client, cmd: str, timeout: int) -> tuple[int, str, str]:
    try:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="ignore")[:512]
        err = stderr.read().decode("utf-8", errors="ignore")[:512]
        return rc, out, err
    except Exception as e:
        return -1, "", f"{type(e).__name__}: {str(e)[:200]}"


def _winrm_exec(host: str, port: int, user: str, password: str,
                 cmd: str, timeout: int) -> tuple[int, str, str]:
    """Execute a command via pywinrm. Returns (rc, stdout, stderr)."""
    try:
        import winrm  # type: ignore  # pywinrm
    except Exception as e:
        return -1, "", f"pywinrm not installed: {e}"
    try:
        scheme = "https" if port == 5986 else "http"
        endpoint = f"{scheme}://{host}:{port}/wsman"
        session = winrm.Session(endpoint, auth=(user, password),
                                 transport="ntlm",
                                 server_cert_validation="ignore",
                                 read_timeout_sec=timeout + 5,
                                 operation_timeout_sec=timeout)
        # Strip leading shell prefix if cmd already includes it
        if cmd.lower().startswith("powershell.exe"):
            ps_body = cmd.split(" ", 1)[1] if " " in cmd else ""
            r = session.run_ps(ps_body)
        elif cmd.lower().startswith("cmd.exe /c"):
            r = session.run_cmd(cmd.split("/c", 1)[1].strip(' "'))
        else:
            r = session.run_cmd(cmd)
        rc = int(r.status_code)
        out = (r.std_out or b"").decode("utf-8", errors="ignore")[:512]
        err = (r.std_err or b"").decode("utf-8", errors="ignore")[:512]
        return rc, out, err
    except Exception as e:
        return -1, "", f"{type(e).__name__}: {str(e)[:200]}"


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["atomic_runner_total"] = 0
        ctx.source("no-target")
        return

    opts = ctx.state.get("_options") or {}
    user = (opts.get("atomic_user") or "").strip()
    password = (opts.get("atomic_password") or "").strip()
    key_text = (opts.get("atomic_ssh_key") or "").strip()
    os_kind = (opts.get("atomic_os") or "linux").strip().lower()
    timeout = min(max(int(opts.get("atomic_timeout_sec") or DEFAULT_TIMEOUT), 5),
                   HARD_MAX_TIMEOUT)
    default_port = 5985 if os_kind == "windows" else 22
    port = int(opts.get("atomic_port") or default_port)

    if not user or (not password and not key_text):
        ctx.state["atomic_runner_total"] = 0
        ctx.state["atomic_input_missing"] = True
        ctx.source("missing atomic_user / atomic_password|atomic_ssh_key")
        return

    tests = ATOMIC_TESTS_WINDOWS if os_kind == "windows" else ATOMIC_TESTS_LINUX
    ctx.state["atomic_runner_os"] = os_kind
    ctx.state["atomic_runner_port"] = port
    ctx.state["atomic_runner_target"] = target
    results: list[dict] = []
    technique_ids: set[str] = set()

    if os_kind == "linux":
        client, err = await asyncio.to_thread(
            _build_ssh_client, target, port, user, password or None, key_text or None
        )
        if not client:
            ctx.state["atomic_runner_total"] = 0
            ctx.state["atomic_connect_error"] = err
            ctx.source(f"ssh connect failed: {err[:80]}")
            return
        try:
            for atomic_id, tech, name, cmd in tests:
                rc, out, errout = await asyncio.to_thread(_ssh_exec, client, cmd, timeout)
                ok = (rc == 0)
                results.append({
                    "atomic_id": atomic_id,
                    "technique": tech,
                    "name": name,
                    "cmd_preview": cmd[:140],
                    "rc": rc,
                    "executed": ok,
                    "stdout_preview": (out.strip() or "")[:160],
                    "stderr_preview": (errout.strip() or "")[:160],
                })
                if ok:
                    technique_ids.add(tech)
        finally:
            try: client.close()
            except Exception: pass
    else:  # windows -> WinRM
        for atomic_id, tech, name, cmd in tests:
            rc, out, errout = await asyncio.to_thread(
                _winrm_exec, target, port, user, password, cmd, timeout
            )
            ok = (rc == 0)
            results.append({
                "atomic_id": atomic_id,
                "technique": tech,
                "name": name,
                "cmd_preview": cmd[:140],
                "rc": rc,
                "executed": ok,
                "stdout_preview": (out.strip() or "")[:160],
                "stderr_preview": (errout.strip() or "")[:160],
            })
            if ok:
                technique_ids.add(tech)

    executed = sum(1 for r in results if r["executed"])
    ctx.state["atomic_runner_results"] = results
    ctx.state["atomic_runner_total"] = executed
    ctx.state["atomic_runner_planned"] = len(results)
    ctx.state["atomic_runner_techniques"] = sorted(technique_ids)
    ctx.source(f"atomic runner {os_kind}://{target}:{port} -> "
                f"{executed}/{len(results)} tests executed; "
                f"{len(technique_ids)} MITRE techniques touched")


INTEL_FIELDS = [
    ("Target OS",              "atomic_runner_os"),
    ("Target host",            "atomic_runner_target"),
    ("Target port",            "atomic_runner_port"),
    ("Tests planned",          "atomic_runner_planned"),
    ("Tests executed",         "atomic_runner_total"),
    ("MITRE techniques hit",   "atomic_runner_techniques"),
]


@router.post("/api/red_team/atomic_red_team_runner")
async def red_team_atomic_runner(req: AtomicRedTeamRunnerRequest,
                                  _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="atomic_red_team_runner",
        gather_func=_gather_with_options,
        finding_rules=ATOMIC_RED_TEAM_RUNNER_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
