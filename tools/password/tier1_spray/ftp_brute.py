"""ftp_brute - FTP password spray (VL-METHOD methodology).

Created 2026-06-05, modeled exactly on hydra_ssh_spray.py reference
scanner. Implements the VL-METHOD 7-step pentest pattern for FTP:

  1. PRE-FLIGHT  - Is FTP/21 reachable? If not, skip with SKIPPED status.

  2. FINGERPRINT - ftplib welcome-banner grab. Captures the raw 220
                    banner, normalises server name (ProFTPD/vsftpd/
                    FileZilla/etc) and checks if anonymous login is
                    enabled. Result drives wordlist + finding rules.

  3. QUICK PROBE - Try 5 known-bad defaults BEFORE customer's full
                    wordlist (anonymous/anonymous@example.com, ftp/ftp,
                    admin/admin, root/root, test/test). Uses ftplib
                    direct (pure Python stdlib, no extra deps) with
                    a 4s per-attempt timeout.

  4. DEEP SCAN   - Only runs if quick_probe found something OR customer
                    set options.always_deep=True. Pure-Python ftplib
                    loop over userlist x passlist (capped 10 x 25 = 250
                    attempts) - simpler and more reliable for FTP than
                    spawning hydra/medusa.

  5. VERIFY      - Re-confirm each valid credential with a SEPARATE
                    ftplib connection running `LIST` to confirm real
                    directory access. confidence=CONFIRMED if LIST
                    succeeds, SUSPECTED if auth OK but LIST fails.
                    verification_method=ftplib_second_login_list.

  6. PRIVILEGE   - Try to STOR a tiny test file:
                    write succeeds -> privilege='admin' (file_write_capable)
                    Otherwise try RETR /etc/passwd:
                    read succeeds  -> privilege='user'
                    Otherwise       -> privilege='guest'.
                   Test file is removed on success (best-effort).

  7. CHAIN       - For CONFIRMED admin, suggest dropzone audit + lateral
                    pivot scanners. For CONFIRMED user, suggest directory
                    traversal audit. Empty otherwise.

Customer input via ScanRequest.options:
  - target              = FTP host/IP (required - taken from req.target)
  - options.userlist    = newline-separated usernames (for deep_scan)
  - options.passlist    = newline-separated passwords (for deep_scan)
  - options.port        = FTP port override (default 21)
  - options.always_deep = bool, force deep_scan even if quick_probe empty
  - options.timeout_sec = wall-clock cap for deep_scan (default 90)

Safety guard: deep_scan hard-clamped to 10 users x 25 passwords (250
attempts) per run. Quick-probe is fixed at 5 well-known pairs only.
"""
from __future__ import annotations

import asyncio
import ftplib
import socket
import time
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.ftp_brute_findings import FTP_BRUTE_FINDING_RULES, INTEL_FIELDS

router = APIRouter()
DEFAULT_TIMEOUT = 90
HARD_MAX_USERS = 10
HARD_MAX_PASSWORDS = 25
PER_ATTEMPT_TIMEOUT = 4.0
TEST_FILE_NAME = ".vlpwd_test"
TEST_FILE_CONTENT = b"vulnuslab-write-probe\n"

# Top-5 FTP credential pairs. anonymous + ftp/ftp account for most
# misconfigured public FTP servers; admin/root/test catch generic
# bad-default deployments.
QUICK_PROBE_DEFAULTS = [
    ("anonymous", "anonymous@example.com"),
    ("ftp", "ftp"),
    ("admin", "admin"),
    ("root", "root"),
    ("test", "test"),
]


class FtpBruteRequest(ScanRequest):
    options: Optional[dict] = None


def _split_lines(s: str, limit: int) -> list[str]:
    """Trim + dedupe + clamp a newline-separated user/pass string."""
    if not s:
        return []
    seen: list[str] = []
    for raw in s.splitlines():
        v = raw.strip()
        if not v or v in seen:
            continue
        seen.append(v)
        if len(seen) >= limit:
            break
    return seen


def _redact(pwd: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction: length + last 3 chars only.
    When show_plaintext=True (customer scanning own infra), returns the
    actual plaintext password instead of the marker. Default behavior
    (False) keeps the marker so multi-tenant reports never leak creds."""
    if not pwd: return "len=0"
    pwd = pwd.strip()
    if show_plaintext:
        return pwd
    if len(pwd) <= 3: return f"len={len(pwd)} ***"
    return f"len={len(pwd)} ***{pwd[-3:]}"


def _detect_server(banner: str) -> str:
    """Map raw 220 welcome banner to a normalized server name."""
    if not banner:
        return ""
    low = banner.lower()
    if "proftpd" in low: return "ProFTPD"
    if "vsftpd" in low: return "vsftpd"
    if "filezilla" in low: return "FileZilla"
    if "pure-ftpd" in low: return "Pure-FTPd"
    if "microsoft ftp" in low or "iis" in low: return "Microsoft IIS FTP"
    if "wu-ftpd" in low: return "WU-FTPD"
    if "serv-u" in low: return "Serv-U"
    return ""


def _ftp_connect_login(host: str, port: int, user: str, pwd: str,
                        timeout: float) -> ftplib.FTP:
    """Blocking helper: open a single ftplib connection and login.
    Caller is responsible for ftp.quit()/close(). Raises on any failure."""
    ftp = ftplib.FTP(timeout=timeout)
    ftp.connect(host=host, port=port, timeout=timeout)
    ftp.login(user=user, passwd=pwd)
    return ftp


# ═══════════════════════════════════════════════════════════════════
#  FtpBrute - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class FtpBrute(MethodologyScanner):
    name = "ftp_brute"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        target = ctx.host
        opts = ctx.state.get("_options") or {}
        clean_host, port = helpers.resolve_port(
            target, opts, primary_port=21, valid_ports=(2121, 2200, 990))
        ctx.state["target_host"] = clean_host
        ctx.state["target_port"] = port
        if not clean_host:
            ctx.state["skipped_reason"] = "no target supplied"
            ctx.state["port_reachable"] = False
            return False
        reachable = await helpers.port_open(clean_host, port, timeout=3.0)
        ctx.state["port_reachable"] = reachable
        if not reachable:
            ctx.state["skipped_reason"] = f"FTP/{port} on {clean_host} not reachable (port closed or filtered)"
            return False
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 21)
        loop = asyncio.get_event_loop()

        def _grab() -> dict:
            out = {"banner": "", "server": "", "allows_anonymous": False}
            ftp = None
            try:
                ftp = ftplib.FTP(timeout=PER_ATTEMPT_TIMEOUT)
                welcome = ftp.connect(host=target, port=port,
                                       timeout=PER_ATTEMPT_TIMEOUT)
                out["banner"] = (welcome or ftp.welcome or "").strip()
                out["server"] = _detect_server(out["banner"])
            except Exception:
                pass
            # Probe anonymous separately so a banner-only grab still
            # populates banner+server even if anonymous attempt times out.
            try:
                if ftp is not None:
                    try: ftp.quit()
                    except Exception:
                        try: ftp.close()
                        except Exception: pass
            finally:
                ftp = None
            try:
                ftp2 = ftplib.FTP(timeout=PER_ATTEMPT_TIMEOUT)
                ftp2.connect(host=target, port=port,
                              timeout=PER_ATTEMPT_TIMEOUT)
                ftp2.login(user="anonymous", passwd="anonymous@example.com")
                out["allows_anonymous"] = True
                try: ftp2.quit()
                except Exception:
                    try: ftp2.close()
                    except Exception: pass
            except Exception:
                pass
            return out

        fp = await loop.run_in_executor(None, _grab)
        ctx.state["fingerprint"] = fp

    # ── STAGE 3: QUICK PROBE (5 known defaults) ──────────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 21)
        opts = ctx.state.get("_options") or {}
        show = bool(opts.get("show_plaintext"))
        loop = asyncio.get_event_loop()

        def _try_pair(user: str, pwd: str) -> bool:
            ftp = None
            try:
                ftp = _ftp_connect_login(target, port, user, pwd,
                                          PER_ATTEMPT_TIMEOUT)
                return True
            except Exception:
                return False
            finally:
                if ftp is not None:
                    try: ftp.quit()
                    except Exception:
                        try: ftp.close()
                        except Exception: pass

        findings: list[dict] = []
        for i, (user, pwd) in enumerate(QUICK_PROBE_DEFAULTS):
            ok = await loop.run_in_executor(None, _try_pair, user, pwd)
            if not ok:
                continue
            findings.append({
                "id": f"quick_{i}",
                "kind": "default_credential",
                "user": user,
                "password_marker": _redact(pwd, show_plaintext=show),
                "_pwd_private": pwd,
                "discovery_method": "quick_probe_known_defaults",
            })

        ctx.state["quick_probe_attempts"] = len(QUICK_PROBE_DEFAULTS)
        ctx.state["quick_probe_hits"] = len(findings)
        return findings

    # ── STAGE 4: DEEP SCAN (full ftplib spray, gated) ────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 21)
        opts = ctx.state.get("_options") or {}
        show = bool(opts.get("show_plaintext"))
        userlist_raw = (opts.get("userlist") or "").strip()
        passlist_raw = (opts.get("passlist") or "").strip()
        if not userlist_raw or not passlist_raw:
            ctx.state["deep_skipped"] = "userlist/passlist not supplied"
            return []
        max_users = min(int(opts.get("max_users") or HARD_MAX_USERS), HARD_MAX_USERS)
        max_pass = min(int(opts.get("max_passwords") or HARD_MAX_PASSWORDS), HARD_MAX_PASSWORDS)
        users = _split_lines(userlist_raw, max_users)
        passwords = _split_lines(passlist_raw, max_pass)
        if not users or not passwords:
            ctx.state["deep_skipped"] = "empty wordlists after dedupe"
            return []
        timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 15), 240)
        loop = asyncio.get_event_loop()

        # De-dup pairs we already proved in quick_probe so we don't
        # double-charge the deep-scan attempt counter.
        already_hit: set[tuple[str, str]] = set()
        for f in (ctx.state.get("_quick_findings") or []):
            already_hit.add((f.get("user", ""), f.get("_pwd_private", "")))

        def _try_pair(user: str, pwd: str) -> bool:
            ftp = None
            try:
                ftp = _ftp_connect_login(target, port, user, pwd,
                                          PER_ATTEMPT_TIMEOUT)
                return True
            except Exception:
                return False
            finally:
                if ftp is not None:
                    try: ftp.quit()
                    except Exception:
                        try: ftp.close()
                        except Exception: pass

        findings: list[dict] = []
        attempts = 0
        t_start = time.time()
        for user in users:
            if (time.time() - t_start) > timeout:
                ctx.state["deep_skipped"] = f"deep_scan timeout @ {timeout}s"
                break
            for pwd in passwords:
                if (time.time() - t_start) > timeout:
                    ctx.state["deep_skipped"] = f"deep_scan timeout @ {timeout}s"
                    break
                if (user, pwd) in already_hit:
                    continue
                attempts += 1
                try:
                    ok = await asyncio.wait_for(
                        loop.run_in_executor(None, _try_pair, user, pwd),
                        timeout=PER_ATTEMPT_TIMEOUT + 1.0)
                except asyncio.TimeoutError:
                    ok = False
                if ok:
                    findings.append({
                        "id": f"deep_{len(findings)}",
                        "kind": "spray_credential",
                        "user": user,
                        "password_marker": _redact(pwd, show_plaintext=show),
                        "_pwd_private": pwd,
                        "discovery_method": "ftplib_deep_spray",
                    })
                    # Move on to next user once we hit (-f equivalent)
                    break

        ctx.state["ftp_deep_attempts"] = attempts
        ctx.state["ftp_users_tried"] = len(users)
        ctx.state["ftp_passwords_tried"] = len(passwords)
        return findings

    # ── STAGE 5: VERIFY (re-login + LIST) ────────────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # VL-FOUNDRY evidence surfacing: stamp a concrete, per-finding
        # evidence string onto the methodology finding object. This rides
        # into the report via the methodology_findings intel field; it adds
        # no new finding and changes no severity (advisory-by-design safe).
        finding["evidence_marker"] = (
            f"{finding.get('discovery_method') or finding.get('kind') or 'probe'}"
            f" -> verifying {finding.get('kind') or 'finding'} for "
            f"{finding.get('user') or finding.get('attack_label') or ctx.host}")
        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 21)
        user = finding.get("user", "")
        pwd = finding.get("_pwd_private", "")
        loop = asyncio.get_event_loop()

        def _verify_login_list() -> tuple[bool, bool]:
            ftp = None
            try:
                ftp = _ftp_connect_login(target, port, user, pwd,
                                          PER_ATTEMPT_TIMEOUT)
                listing: list[str] = []
                try:
                    ftp.retrlines("LIST", listing.append)
                    return (True, True if listing or True else False)
                except Exception:
                    return (True, False)
            except Exception:
                return (False, False)
            finally:
                if ftp is not None:
                    try: ftp.quit()
                    except Exception:
                        try: ftp.close()
                        except Exception: pass

        auth_ok, list_ok = await loop.run_in_executor(None, _verify_login_list)

        if auth_ok and list_ok:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "ftplib_second_login_list"
        elif auth_ok:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "ftplib_second_login_list"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "ftplib_second_login_failed"
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        # Only run privilege probes for CONFIRMED findings - SUSPECTED
        # didn't pass LIST so file ops will fail uniformly anyway.
        if finding.get("confidence") != "CONFIRMED":
            finding["privilege_level"] = "unknown"
            return finding

        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 21)
        user = finding.get("user", "")
        pwd = finding.get("_pwd_private", "")
        loop = asyncio.get_event_loop()

        def _try_stor_and_cleanup() -> bool:
            import io as _io
            ftp = None
            try:
                ftp = _ftp_connect_login(target, port, user, pwd,
                                          PER_ATTEMPT_TIMEOUT)
                buf = _io.BytesIO(TEST_FILE_CONTENT)
                ftp.storbinary(f"STOR {TEST_FILE_NAME}", buf)
                # Best-effort cleanup
                try: ftp.delete(TEST_FILE_NAME)
                except Exception: pass
                return True
            except Exception:
                return False
            finally:
                if ftp is not None:
                    try: ftp.quit()
                    except Exception:
                        try: ftp.close()
                        except Exception: pass

        def _try_retr_passwd() -> bool:
            ftp = None
            try:
                ftp = _ftp_connect_login(target, port, user, pwd,
                                          PER_ATTEMPT_TIMEOUT)
                buf: list[bytes] = []
                try:
                    ftp.retrbinary("RETR /etc/passwd", buf.append)
                    return bool(buf)
                except Exception:
                    return False
            except Exception:
                return False
            finally:
                if ftp is not None:
                    try: ftp.quit()
                    except Exception:
                        try: ftp.close()
                        except Exception: pass

        write_ok = await loop.run_in_executor(None, _try_stor_and_cleanup)
        if write_ok:
            finding["privilege_level"] = "admin"
            finding["file_write_capable"] = True
            return finding

        read_ok = await loop.run_in_executor(None, _try_retr_passwd)
        if read_ok:
            finding["privilege_level"] = "user"
            finding["file_write_capable"] = False
            return finding

        finding["privilege_level"] = "guest"
        finding["file_write_capable"] = False
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        next_scanners: list[str] = []
        # Admin first - widest blast radius
        for f in findings:
            if (f.get("confidence") == "CONFIRMED"
                    and f.get("privilege_level") == "admin"):
                next_scanners = [
                    "post_exploit_ftp_dropzone_audit",
                    "post_exploit_ftp_lateral_pivot",
                ]
                break
        if not next_scanners:
            for f in findings:
                if (f.get("confidence") == "CONFIRMED"
                        and f.get("privilege_level") == "user"):
                    next_scanners = ["ftp_directory_traversal_audit"]
                    break
        return next_scanners


# ═══════════════════════════════════════════════════════════════════
#  Endpoint wrapper - adapts MethodologyScanner to existing framework
# ═══════════════════════════════════════════════════════════════════


@router.post("/api/password/ftp_brute")
async def password_ftp_brute(req: FtpBruteRequest, _=Depends(verify_scan_quota)):
    scanner = FtpBrute()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=FTP_BRUTE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)
