"""john_hash_audit - offline hash crack via John the Ripper (playbook §2 #16).

Wraps the Kali-installed `john` binary to audit a customer-supplied
batch of password hashes against a default wordlist (john's built-in
or rockyou if present). Customer never receives the cracked cleartext -
the response reports only counts + the redacted hash prefix so the
finding pack remains safe for inclusion in a customer PDF.

Customer input via ScanRequest.options:
  - options.hashes       = newline-separated raw hashes (required, max 200)
  - options.hash_format  = john --format value (required, e.g. "NT",
                            "md5crypt", "sha512crypt", "raw-md5", "raw-sha1",
                            "raw-sha256", "Raw-MD5", "Raw-SHA1", "krb5tgs",
                            "ntlmv2", "bcrypt")
  - options.timeout_sec  = wall-clock cap (default 90, max 240)
  - options.wordlist_path = override default wordlist (must exist on disk)
"""
from __future__ import annotations
import asyncio
import hashlib
import os
import re
import shutil
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.john_hash_audit_findings import JOHN_HASH_AUDIT_FINDING_RULES

router = APIRouter()
JOHN_BIN = shutil.which("john")
DEFAULT_TIMEOUT = 90
HARD_MAX_HASHES = 200

# Wordlist preference order (first one that exists wins)
_CANDIDATE_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/john/password.lst",
    "/usr/share/wordlists/john.lst",
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
]

# Allowed john format identifiers (whitelist so customer can't pass arbitrary --format=anything)
_ALLOWED_FORMATS = {
    "nt", "ntlm",
    "raw-md5", "raw-md4", "raw-sha1", "raw-sha224", "raw-sha256",
    "raw-sha384", "raw-sha512",
    "md5", "md5crypt", "md5crypt-long",
    "sha512crypt", "sha256crypt",
    "bcrypt", "bcrypt-opencl",
    "des", "descrypt",
    "lm",
    "netntlm", "netntlmv2", "ntlmv2",
    "krb5tgs", "krb5pa-sha1", "krb5asrep",
    "mssql", "mssql05", "mssql12",
    "mysql", "mysql-sha1",
    "phpass", "wpapsk",
    "pkzip", "rar", "7z", "zip",
}


class JohnHashAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _resolve_wordlist(override: str) -> Optional[str]:
    if override:
        if os.path.isfile(override) and os.access(override, os.R_OK):
            return override
        return None
    for p in _CANDIDATE_WORDLISTS:
        if os.path.isfile(p) and os.access(p, os.R_OK):
            return p
    return None


def _split_hashes(s: str, limit: int) -> list[str]:
    if not s:
        return []
    out: list[str] = []
    for raw in s.splitlines():
        v = raw.strip()
        if not v or v.startswith("#"):
            continue
        if v in out:
            continue
        out.append(v)
        if len(out) >= limit:
            break
    return out


def _hash_prefix(h: str) -> str:
    """Customer-safe identifier: first 12 chars + sha256 fingerprint last 6."""
    h = h.strip()
    head = h[:12]
    fp = hashlib.sha256(h.encode("utf-8", errors="ignore")).hexdigest()[:6]
    return f"{head}... [fp:{fp}]"


# john --show output (terse, --pot=tmp): "hash:cracked_pw"
_RE_CRACKED = re.compile(r"^(?P<hash>[^:\s]+):(?P<pwd>.*)$")


async def gather(ctx: ScanContext):
    if not JOHN_BIN:
        ctx.state["john_hash_audit_error"] = "john binary not installed"
        ctx.source("john missing")
        return

    opts = ctx.state.get("_options") or {}
    hashes_raw = (opts.get("hashes") or "").strip()
    hash_format = (opts.get("hash_format") or "").strip().lower()
    if not hashes_raw or not hash_format:
        missing = []
        if not hashes_raw: missing.append("hashes")
        if not hash_format: missing.append("hash_format")
        ctx.state["john_input_missing"] = missing
        ctx.state["john_hash_audit_total"] = 0
        ctx.source(f"missing options: {', '.join(missing)}")
        return
    if hash_format not in _ALLOWED_FORMATS:
        ctx.state["john_format_invalid"] = hash_format
        ctx.state["john_hash_audit_total"] = 0
        ctx.source(f"invalid hash_format: {hash_format}")
        return

    hashes = _split_hashes(hashes_raw, HARD_MAX_HASHES)
    if not hashes:
        ctx.state["john_input_missing"] = ["hashes empty after dedupe"]
        ctx.state["john_hash_audit_total"] = 0
        ctx.source("empty hash list")
        return

    wordlist = _resolve_wordlist(opts.get("wordlist_path") or "")
    if not wordlist:
        ctx.state["john_no_wordlist"] = True
        ctx.state["john_hash_audit_total"] = 0
        ctx.source("no wordlist available on scanner host")
        return

    timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 15), 240)

    hash_path: Optional[str] = None
    pot_path: Optional[str] = None
    session_dir: Optional[str] = None
    try:
        session_dir = tempfile.mkdtemp(prefix="vl_john_")
        # John needs both a hash file and an isolated pot file so we don't
        # taint the global pot or leak results to the next scan.
        hash_path = os.path.join(session_dir, "hashes.txt")
        pot_path = os.path.join(session_dir, "john.pot")
        with open(hash_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(hashes) + "\n")
        # Touch pot file
        open(pot_path, "w").close()

        # First pass: run the crack with wordlist + default rules.
        crack_cmd = [
            JOHN_BIN,
            f"--format={hash_format}",
            f"--wordlist={wordlist}",
            "--rules=Single",
            f"--pot={pot_path}",
            f"--session={session_dir}/sess",
            hash_path,
        ]
        stderr_b: bytes = b""
        proc = await asyncio.create_subprocess_exec(
            *crack_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "HOME": session_dir},
        )
        try:
            _stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            # Don't return - still try --show on whatever cracked before timeout
            ctx.state["john_crack_timed_out"] = True

        crack_stderr = (stderr_b or b"").decode("utf-8", errors="ignore")
        if crack_stderr and "Unknown ciphertext format" in crack_stderr:
            ctx.state["john_format_unknown_in_engine"] = hash_format

        # Second pass: --show to enumerate cracks (pot has lines "hash:pw")
        show_cmd = [
            JOHN_BIN,
            f"--format={hash_format}",
            f"--pot={pot_path}",
            "--show",
            hash_path,
        ]
        proc2 = await asyncio.create_subprocess_exec(
            *show_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "HOME": session_dir},
        )
        try:
            show_stdout_b, show_stderr_b = await asyncio.wait_for(
                proc2.communicate(), timeout=20)
        except asyncio.TimeoutError:
            try: proc2.kill()
            except Exception: pass
            show_stdout_b, show_stderr_b = b"", b""

        show_stdout = (show_stdout_b or b"").decode("utf-8", errors="ignore")

        cracked_hashes_redacted: list[str] = []
        # john --show output ends with summary "N password hashes cracked, M left"
        for line in show_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if "password hash" in line.lower() and "cracked" in line.lower():
                # summary line - skip
                continue
            m = _RE_CRACKED.match(line)
            if not m:
                continue
            h = m.group("hash")
            # Cleartext is captured by the regex but DELIBERATELY discarded here
            # so it cannot leak into ctx.state / response / PDF.
            cracked_hashes_redacted.append(_hash_prefix(h))

        ctx.state["john_hash_audit_format"] = hash_format
        ctx.state["john_hash_audit_wordlist"] = os.path.basename(wordlist)
        ctx.state["john_hash_audit_hashes_in"] = len(hashes)
        ctx.state["john_cracked_hashes_redacted"] = cracked_hashes_redacted
        ctx.state["john_hash_audit_total"] = len(cracked_hashes_redacted)
        if ctx.state.get("john_crack_timed_out"):
            ctx.source(f"john --format={hash_format} timed out @ {timeout}s; "
                       f"partial: {len(cracked_hashes_redacted)}/{len(hashes)} cracked")
        else:
            ctx.source(f"john --format={hash_format} -> "
                       f"{len(cracked_hashes_redacted)}/{len(hashes)} cracked")
    except Exception as e:
        ctx.state["john_hash_audit_error"] = f"unexpected error: {type(e).__name__}: {str(e)[:120]}"
        ctx.source(f"error: {ctx.state['john_hash_audit_error']}")
    finally:
        if session_dir:
            try: shutil.rmtree(session_dir, ignore_errors=True)
            except Exception: pass


INTEL_FIELDS = [
    ("Hash format",         "john_hash_audit_format"),
    ("Wordlist used",       "john_hash_audit_wordlist"),
    ("Hashes submitted",    "john_hash_audit_hashes_in"),
    ("Cracked count",       "john_hash_audit_total"),
    ("Cracked (redacted)",  "john_cracked_hashes_redacted"),
]


@router.post("/api/password/john_hash_audit")
async def password_john_hash_audit(req: JohnHashAuditRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target or "offline-audit",
        tool="john_hash_audit",
        gather_func=_gather_with_options,
        finding_rules=JOHN_HASH_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
