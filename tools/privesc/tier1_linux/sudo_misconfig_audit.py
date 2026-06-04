"""sudo_misconfig_audit - sudo policy + sudoers parse (playbook §4 #48-50).

SSHes to ctx.host, runs `sudo -n -l` (passwordless `sudo -l` — succeeds if
the customer's user has NOPASSWD entries) and parses:
  - NOPASSWD entries (split into GTFOBins-binary hits vs other)
  - `Defaults env_keep+=` for LD_PRELOAD / LD_LIBRARY_PATH
  - sudo (ALL) NOPASSWD: ALL grants
  - wildcards in command paths (cp /tmp/* etc.)

If the customer also supplies options.use_password=true, the probe will
attempt `sudo -S -l` with the SSH password to additionally read
/etc/sudoers + /etc/sudoers.d/* (otherwise it sticks to the safer -n path).

Customer input via ScanRequest.options:
  - target              = SSH host/IP
  - options.username    = SSH username (required)
  - options.password    = SSH password (required OR options.ssh_key)
  - options.ssh_key     = OpenSSH/PEM private key string
  - options.port        = SSH port override (default 22)
  - options.timeout_sec = wall-clock cap (default 30)
  - options.use_password = bool, if true also runs `sudo -S` to read sudoers
"""
from __future__ import annotations
import asyncio
import io
import re
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.sudo_misconfig_audit_findings import (
    SUDO_MISCONFIG_AUDIT_FINDING_RULES,
)

router = APIRouter()

GTFOBINS_SUDO_DIR = "/opt/gtfobins/_gtfobins"
DEFAULT_TIMEOUT = 30


class SudoMisconfigAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _gtfobins_sudo_index() -> set[str]:
    """GTFOBins binaries that have a 'Sudo' section in their .md file.
    We approximate by scanning each .md for the literal '### Sudo' header
    and returning the lowercased basename of matching files."""
    p = Path(GTFOBINS_SUDO_DIR)
    if not p.is_dir():
        return set()
    out: set[str] = set()
    for f in p.glob("*.md"):
        try:
            txt = f.read_text(encoding="utf-8", errors="ignore")
            if "### Sudo" in txt or "functions:\n  sudo:" in txt or "  sudo:" in txt:
                out.add(f.stem.lower())
        except Exception:
            continue
    return out


def _connect(target: str, port: int, username: str, password: Optional[str],
             ssh_key: Optional[str], timeout: int):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = {
        "hostname": target, "port": port, "username": username,
        "timeout": min(timeout, 30), "auth_timeout": min(timeout, 30),
        "banner_timeout": min(timeout, 30),
        "look_for_keys": False, "allow_agent": False,
    }
    if ssh_key:
        key_obj = None
        for keycls in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key, paramiko.DSSKey):
            try:
                key_obj = keycls.from_private_key(io.StringIO(ssh_key))
                break
            except Exception:
                continue
        if not key_obj:
            raise ValueError("ssh_key did not parse")
        kw["pkey"] = key_obj
    else:
        kw["password"] = password
    client.connect(**kw)
    return client


_RE_NOPASSWD_LINE = re.compile(r"NOPASSWD\s*:\s*(.+?)(?:$|\s*#)", re.IGNORECASE)
_RE_ENV_KEEP = re.compile(r"Defaults\s*\+?env_keep\s*\+?=\s*(.+)", re.IGNORECASE)
_RE_WILDCARD = re.compile(r"(/[^\s,]+\*[^\s,]*)")
_RE_ALL_NOPASSWD = re.compile(
    r"\(\s*ALL\s*[:,]?\s*ALL\s*\)\s*NOPASSWD\s*:\s*ALL", re.IGNORECASE,
)


def _parse_sudo_output(text: str, gtfo_sudo: set[str]) -> dict:
    """Extract NOPASSWD, env_keep, wildcards from sudo -l / sudoers output."""
    out: dict = {
        "nopasswd_other": [],
        "gtfobins_nopasswd": [],
        "env_keep_preload": False,
        "all_nopasswd": False,
        "wildcards": [],
    }

    # Detect ALL passwordless first (the catch-all worst case).
    if _RE_ALL_NOPASSWD.search(text):
        out["all_nopasswd"] = True

    # NOPASSWD entries: each line is `NOPASSWD: /path/to/binary [args]`.
    for m in _RE_NOPASSWD_LINE.finditer(text):
        cmd_spec = m.group(1).strip()
        if cmd_spec.lower() == "all":
            out["all_nopasswd"] = True
            continue
        # First token before space is the binary path.
        first = cmd_spec.split()[0] if cmd_spec else ""
        if not first:
            continue
        binary = first.rsplit("/", 1)[-1].lower()
        entry = {"binary": binary, "spec": cmd_spec[:200]}
        if gtfo_sudo and binary in gtfo_sudo:
            out["gtfobins_nopasswd"].append(entry)
        else:
            out["nopasswd_other"].append(entry)
        # Wildcard check on this spec.
        if "*" in cmd_spec:
            out["wildcards"].extend(_RE_WILDCARD.findall(cmd_spec))

    # env_keep with dangerous variables.
    for m in _RE_ENV_KEEP.finditer(text):
        body = m.group(1).strip().lower()
        if "ld_preload" in body or "ld_library_path" in body:
            out["env_keep_preload"] = True
            break

    # Defaults pass — pull any wildcard in any command path not already in spec.
    for w in _RE_WILDCARD.findall(text):
        if w not in out["wildcards"]:
            out["wildcards"].append(w)

    # De-dup binaries by name (keep first).
    seen = set()
    out["nopasswd_other"] = [x for x in out["nopasswd_other"]
                              if not (x["binary"] in seen or seen.add(x["binary"]))]
    seen2 = set()
    out["gtfobins_nopasswd"] = [x for x in out["gtfobins_nopasswd"]
                                 if not (x["binary"] in seen2 or seen2.add(x["binary"]))]
    out["wildcards"] = out["wildcards"][:30]
    return out


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["sudo_no_target"] = True
        ctx.source("no-target")
        return

    try:
        import paramiko  # noqa: F401
    except ImportError:
        ctx.state["sudo_ssh_error"] = "paramiko not installed"
        ctx.source("paramiko missing")
        return

    opts = ctx.state.get("_options") or {}
    username = (opts.get("username") or "").strip()
    password = opts.get("password") or ""
    ssh_key = (opts.get("ssh_key") or "").strip()

    if not username or (not password and not ssh_key):
        ctx.state["sudo_no_creds"] = True
        ctx.source("missing username + password/ssh_key")
        return

    port = int(opts.get("port") or 22)
    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 10), 120)
    use_password = bool(opts.get("use_password"))

    loop = asyncio.get_event_loop()
    client = None
    try:
        client = await loop.run_in_executor(
            None,
            lambda: _connect(target, port, username, password or None,
                              ssh_key or None, timeout),
        )
    except Exception as e:
        ctx.state["sudo_ssh_error"] = str(e)[:200]
        ctx.source(f"SSH connect failed: {str(e)[:80]}")
        return

    try:
        # 1. Passwordless `sudo -n -l` — reads what we can without prompting.
        def _run_cmd(cmd: str, in_str: Optional[str] = None):
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            if in_str:
                try:
                    stdin.write(in_str)
                    stdin.channel.shutdown_write()
                except Exception:
                    pass
            o = stdout.read()
            e = stderr.read()
            try: stdin.close()
            except Exception: pass
            return o, e

        try:
            out_n, _err_n = await asyncio.wait_for(
                loop.run_in_executor(None, _run_cmd, "sudo -n -l 2>&1 || true"),
                timeout=timeout + 10,
            )
        except asyncio.TimeoutError:
            ctx.state["sudo_ssh_error"] = "sudo -n -l timed out"
            ctx.source("timeout")
            return

        sudo_n_text = (out_n or b"").decode("utf-8", errors="ignore")
        sudo_text_combined = sudo_n_text

        # 2. If options.use_password, ALSO try `sudo -S -l` + read /etc/sudoers.
        if use_password and password:
            try:
                out_pw, _ = await asyncio.wait_for(
                    loop.run_in_executor(
                        None, _run_cmd, "sudo -S -l 2>/dev/null", password + "\n",
                    ),
                    timeout=timeout + 10,
                )
                pw_text = (out_pw or b"").decode("utf-8", errors="ignore")
                if pw_text.strip():
                    sudo_text_combined += "\n" + pw_text
            except asyncio.TimeoutError:
                pass
            # Try to cat /etc/sudoers + /etc/sudoers.d/* with sudo.
            try:
                out_su, _ = await asyncio.wait_for(
                    loop.run_in_executor(
                        None, _run_cmd,
                        "sudo -S cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null",
                        password + "\n",
                    ),
                    timeout=timeout + 10,
                )
                su_text = (out_su or b"").decode("utf-8", errors="ignore")
                if su_text.strip():
                    sudo_text_combined += "\n" + su_text
            except asyncio.TimeoutError:
                pass

        # 3. Parse the combined output.
        gtfo_sudo = _gtfobins_sudo_index()
        parsed = _parse_sudo_output(sudo_text_combined, gtfo_sudo)

        ctx.state["sudo_raw_excerpt"] = sudo_text_combined[:4000]
        ctx.state["sudo_gtfobins_nopasswd"] = parsed["gtfobins_nopasswd"]
        ctx.state["sudo_nopasswd_other"] = parsed["nopasswd_other"]
        ctx.state["sudo_env_keep_preload"] = parsed["env_keep_preload"]
        ctx.state["sudo_all_nopasswd"] = parsed["all_nopasswd"]
        ctx.state["sudo_wildcards"] = parsed["wildcards"]
        ctx.state["sudo_audit_ran"] = True
        ctx.source(
            f"sudo audit: NOPASSWD(all)={parsed['all_nopasswd']}, "
            f"NOPASSWD(GTFO)={len(parsed['gtfobins_nopasswd'])}, "
            f"NOPASSWD(other)={len(parsed['nopasswd_other'])}, "
            f"env_keep_preload={parsed['env_keep_preload']}, "
            f"wildcards={len(parsed['wildcards'])}"
        )

    finally:
        try:
            client.close()
        except Exception:
            pass


INTEL_FIELDS = [
    ("Sudo NOPASSWD: ALL",      "sudo_all_nopasswd"),
    ("env_keep LD_PRELOAD",     "sudo_env_keep_preload"),
    ("GTFOBins NOPASSWD hits",  "sudo_gtfobins_nopasswd"),
    ("Other NOPASSWD entries",  "sudo_nopasswd_other"),
    ("Wildcards in sudoers",    "sudo_wildcards"),
    ("sudo output excerpt",     "sudo_raw_excerpt"),
]


@router.post("/api/privesc/sudo_misconfig_audit")
async def privesc_sudo_misconfig_audit(req: SudoMisconfigAuditRequest,
                                        _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="sudo_misconfig_audit",
        gather_func=_gather_with_options,
        finding_rules=SUDO_MISCONFIG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
