"""handshake_crack_audit - offline WPA/WPA2 key recovery from an uploaded capture.

This is the HOSTED half of the wireless methodology. Live RF steps (monitor
mode, scan, deauth, handshake/PMKID capture) happen ON-SITE via the VulnusLab
Wi-Fi capture agent (agents/wifi_capture_agent.py), which needs a monitor-mode
adapter near the AP. The agent uploads the resulting capture here; this host
performs only the compute-only offline crack against a wordlist and reports.

Flow:
  1. POST /api/wireless/handshake_crack/upload  (multipart file) -> capture_path
  2. POST /api/wireless/handshake_crack  with options.capture_path  -> findings

Request body (ScanRequest):
  target                       = SSID or BSSID label for the report (free text)
  options.capture_path         = path returned by the upload route (REQUIRED)
  options.bssid                = target AP BSSID, avoids interactive net-select
  options.wordlist             = wordlist name under an allowed dir (optional)

Security:
  - capture_path must resolve inside the wireless_captures upload dir
    (is_contained_artifact) - no arbitrary file read.
  - wordlist path is restricted to known wordlist dirs.
  - The cracker runs with a wall-clock timeout and non-interactive stdin.
"""
from __future__ import annotations
import asyncio
import contextvars
import os
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile

from tools._shared import (ScanRequest, verify_scan_quota, writable_base,
                           is_contained_artifact)
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.handshake_crack_audit_findings import (
    HANDSHAKE_CRACK_AUDIT_FINDING_RULES,
)

router = APIRouter()

UPLOAD_DIR = writable_base("VL_UPLOAD_DIR", "/uploads") / "wireless_captures"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_BYTES = 60 * 1024 * 1024          # 60 MB - captures are small
CRACK_TIMEOUT = 900                          # 15 min wall-clock cap

# Capture extensions we accept + route to a cracker.
_PCAP_EXT = (".cap", ".pcap", ".pcapng")     # aircrack-ng handles these
_HASH_EXT = (".22000", ".hccapx", ".hc22000")  # hashcat mode 22000

# Allowed wordlist directories (prevents pointing the cracker at arbitrary files).
_WORDLIST_DIRS = ("/opt/seclists", "/usr/share/wordlists", "/opt/wordlists")
# Default wordlist candidates, first existing wins.
_DEFAULT_WORDLISTS = (
    "/usr/share/wordlists/rockyou.txt",
    "/opt/seclists/Passwords/Leaked-Databases/rockyou.txt",
    "/opt/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "/opt/seclists/Passwords/darkweb2017-top10000.txt",
)

_REQ_OPTS: contextvars.ContextVar = contextvars.ContextVar("hs_crack_opts", default={})


def _resolve_wordlist(name: str | None) -> str | None:
    """Return a safe wordlist path. A caller-supplied name is only honoured
    when it resolves inside an allowed wordlist dir; otherwise fall back to a
    bundled default. Returns None if nothing usable exists."""
    if name:
        try:
            p = Path(name).resolve()
            for root in _WORDLIST_DIRS:
                rr = Path(root).resolve()
                if (p == rr or p.is_relative_to(rr)) and p.is_file():
                    return str(p)
        except Exception:
            pass
    for cand in _DEFAULT_WORDLISTS:
        if os.path.isfile(cand):
            return cand
    return None


async def _run(cmd: list[str], *, timeout: int, stdin_data: bytes | None = None):
    """Run a subprocess with a wall-clock cap. Returns (rc, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(
            proc.communicate(input=stdin_data), timeout=timeout)
        return proc.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        return 124, "", f"cracker exceeded {timeout}s wall-clock cap"
    except Exception as e:
        return 1, "", str(e)


def _parse_aircrack_key(stdout: str) -> str | None:
    """aircrack-ng prints 'KEY FOUND! [ passphrase ]' on success."""
    marker = "KEY FOUND!"
    if marker in stdout:
        tail = stdout.split(marker, 1)[1]
        if "[" in tail and "]" in tail:
            return tail.split("[", 1)[1].split("]", 1)[0].strip()
    return None


async def gather(ctx: ScanContext):
    opts = _REQ_OPTS.get() or {}
    capture_path = str(opts.get("capture_path") or "").strip()
    bssid = str(opts.get("bssid") or "").strip()

    have_aircrack = bool(shutil.which("aircrack-ng"))
    have_hashcat = bool(shutil.which("hashcat"))
    if not have_aircrack and not have_hashcat:
        ctx.state["cracker_missing"] = True
        ctx.state["skipped_reason"] = ("no WPA cracker (aircrack-ng / hashcat) on "
                                       "the analysis host")
        ctx.source("cracker missing")
        return

    if not capture_path:
        ctx.state["no_capture"] = "options.capture_path was empty"
        ctx.state["skipped_reason"] = "no capture uploaded for offline crack"
        ctx.source("no capture")
        return

    # Path containment: the capture MUST live inside the wireless upload dir.
    if not is_contained_artifact(capture_path) or not os.path.isfile(capture_path):
        ctx.state["no_capture"] = "capture_path is not an uploaded capture file"
        ctx.state["skipped_reason"] = "capture_path rejected (not a contained upload)"
        ctx.source("bad capture path")
        return

    wordlist = _resolve_wordlist(opts.get("wordlist"))
    if not wordlist:
        ctx.state["no_handshake"] = "no wordlist available on the analysis host"
        ctx.state["skipped_reason"] = "no wordlist available for the crack"
        ctx.source("no wordlist")
        return
    ctx.state["wordlist_name"] = os.path.basename(wordlist)

    ext = Path(capture_path).suffix.lower()

    if ext in _HASH_EXT and have_hashcat:
        # hashcat mode 22000 (WPA-PBKDF2-PMKID+EAPOL). --potfile-disable keeps
        # runs independent; -a 0 straight dictionary; --quiet trims noise.
        rc, out, err = await _run(
            ["hashcat", "-m", "22000", "-a", "0", "--potfile-disable",
             "--quiet", capture_path, wordlist],
            timeout=CRACK_TIMEOUT)
        ctx.state["crack_ran"] = True
        ctx.source("hashcat")
        # hashcat prints "<hash>:<plain>" for a cracked line.
        key = None
        for line in out.splitlines():
            if ":" in line and line.strip() and not line.startswith(("Session", "Status")):
                key = line.rsplit(":", 1)[-1].strip() or None
                if key:
                    break
        if key:
            ctx.state["recovered_key"] = key
        elif "Exhausted" in out or "Exhausted" in err or rc in (0, 1):
            pass
        return

    if have_aircrack:
        cmd = ["aircrack-ng", "-w", wordlist]
        if bssid:
            cmd += ["-b", bssid]
        cmd.append(capture_path)
        # Feed "1\n" on stdin so a single-network capture auto-selects without
        # an interactive prompt when no BSSID was supplied.
        rc, out, err = await _run(cmd, timeout=CRACK_TIMEOUT,
                                  stdin_data=b"1\n" if not bssid else b"")
        ctx.state["crack_ran"] = True
        ctx.source("aircrack-ng")
        low = (out + err).lower()
        if "no valid wpa handshakes" in low or "no networks found" in low:
            ctx.state["no_handshake"] = "aircrack-ng found no usable WPA handshake in the capture"
            return
        key = _parse_aircrack_key(out)
        if key:
            ctx.state["recovered_key"] = key
        return

    # Capture type with no matching cracker available.
    ctx.state["no_handshake"] = f"no cracker available for capture type '{ext}'"


INTEL_FIELDS = [("SSID", "ssid"),
                ("Wordlist", "wordlist_name"),
                ("Cracker", "crack_ran")]


@router.post("/api/wireless/handshake_crack/upload")
async def handshake_crack_upload(request: Request, file: UploadFile = File(...),
                                 payload=Depends(verify_scan_quota)):
    """Receive a WPA handshake (.cap/.pcap/.pcapng) or PMKID (.22000/.hccapx)
    capture produced by the on-site agent. Validate extension + size, store.

    Records the operator's on-site authorization acknowledgment (sent by the
    agent as X-VL-Authorization-* headers) to the audit trail, mirroring the
    SCAN-AUTHZ-V1 consent model for live scans."""
    try:
        from tools.auth._db import record_audit
        _ack = (request.headers.get("x-vl-authorization-ack") or "").lower() == "true"
        _scope = (request.headers.get("x-vl-authorization-scope") or "")[:200]
        record_audit("wireless.capture_upload",
                     actor_id=(payload or {}).get("sub"),
                     actor_name=(payload or {}).get("username"),
                     target=(file.filename or "capture"),
                     ip=(request.client.host if request and request.client else None),
                     detail=f"ack={_ack} scope={_scope}")
    except Exception:
        pass
    name = file.filename or "capture.cap"
    ext = Path(name).suffix.lower()
    if ext not in (_PCAP_EXT + _HASH_EXT):
        raise HTTPException(status_code=400,
            detail=f"Unsupported capture type '{ext}'. Expected one of "
                   f"{', '.join(_PCAP_EXT + _HASH_EXT)}")
    scan_id = uuid.uuid4().hex[:12]
    safe_name = "".join(c for c in name if c.isalnum() or c in "._-")[:80] or "capture.cap"
    out_path = UPLOAD_DIR / f"{scan_id}_{safe_name}"
    total = 0
    with out_path.open("wb") as f:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                f.close()
                out_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413,
                    detail=f"Capture exceeds {MAX_UPLOAD_BYTES} bytes")
            f.write(chunk)
    return {"scan_id": scan_id, "capture_path": str(out_path),
            "filename": safe_name, "size": total}


@router.post("/api/wireless/handshake_crack")
async def wireless_handshake_crack(req: ScanRequest, request: Request,
                                   _=Depends(verify_scan_quota)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    _REQ_OPTS.set(body.get("options") or {})
    return await run_scanner(host=req.target, tool="handshake_crack_audit",
        gather_func=gather, finding_rules=HANDSHAKE_CRACK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
