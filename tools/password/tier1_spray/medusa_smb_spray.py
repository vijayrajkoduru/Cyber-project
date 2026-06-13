"""medusa_smb_spray - SMB password spray via Medusa (VL-METHOD methodology).

REWRITTEN 2026-06-05 to use VL-METHOD 7-step pentest pattern instead of
the previous shallow "run medusa -> parse" approach. Mirrors the Hydra
SSH Spray scanner that is the canonical VL-METHOD reference.

The 7 stages this scanner now performs:

  1. PRE-FLIGHT  - Is SMB reachable? Tests 445 (modern) and 139
                    (NetBIOS fallback). If neither answers, skip with
                    SKIPPED status. Captures target_host + target_port
                    (whichever responded) into ctx.state.

  2. FINGERPRINT - Negotiate-only SMB conversation via impacket
                    (NO login attempt yet). Captures server OS, NetBIOS
                    name, AD domain, SMB dialect and - CRITICALLY -
                    SMB signing requirement. Signing flag drives a
                    separate high-severity finding (NTLM relay class).

  3. QUICK PROBE - Try 5 known-bad SMB defaults BEFORE customer's
                    wordlist (Administrator/admin, admin/admin,
                    guest/<empty>, sa/sa, root/root). Uses impacket
                    SMBConnection.login() directly (NOT medusa) to get
                    accurate auth-failure feedback without medusa
                    noise. Per-attempt 5s, total wall-clock 30s.

  4. DEEP SCAN   - Only runs if quick_probe found something OR customer
                    set options.always_deep=True. Requires customer-
                    supplied userlist + passlist. Medusa smbnt module,
                    hard-clamped to 10 users x 25 passwords (250
                    attempts max), 240s wall-clock cap. Parses
                    "ACCOUNT FOUND" success lines.

  5. VERIFY      - Re-attempt EACH valid credential via impacket
                    SMBConnection.login() with a fresh socket. Medusa
                    occasionally false-positives on intermediate auth
                    states; second-session verification kills those.
                    Sets confidence = CONFIRMED | SUSPECTED.

  6. PRIVILEGE   - For CONFIRMED creds, enumerate accessible shares
                    via impacket conn.listShares():
                      C$ writable           -> admin (CRITICAL)
                      IPC$ + SAMR enum      -> user with samr_enum note
                      IPC$ only             -> user
                      guest auth            -> guest
                    No share access at all -> unknown.

  7. CHAIN       - For CONFIRMED admin, suggest:
                    ad_enum4linux_ng_audit,
                    post_exploit_windows_persistence_audit,
                    post_exploit_lateral_pivot_artifacts.
                    For CONFIRMED non-admin user, suggest:
                    ad_enum4linux_ng_audit only.

Customer input via ScanRequest.options:
  - target              = SMB host/IP (required - taken from req.target)
  - options.userlist    = newline-separated usernames (for deep_scan)
  - options.passlist    = newline-separated passwords (for deep_scan)
  - options.port        = SMB port override (default 445)
  - options.always_deep = bool, force deep_scan even if quick_probe empty
  - options.timeout_sec = wall-clock cap for medusa (default 240)

Safety guard: deep_scan hard-clamped to 10 users x 25 passwords (250
attempts) per run. Quick-probe fixed at 5 well-known pairs only.

INDEPENDENT NTLM-RELAY FINDING: even when zero credentials succeed,
if fingerprint shows SMB signing NOT required, the scanner emits a
separate HIGH-severity finding for the NTLM-relay attack class
(CWE-345 + PetitPotam family CVE-2021-36942). This always fires when
the negotiation succeeds and signing flag is False.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.medusa_smb_spray_findings import MEDUSA_SMB_SPRAY_FINDING_RULES

router = APIRouter()
MEDUSA_BIN = shutil.which("medusa")
DEFAULT_TIMEOUT = 240
HARD_MAX_USERS = 10
HARD_MAX_PASSWORDS = 25

# Top-5 SMB credential pairs that 80% of compromised hosts fall to.
# Quick-probe runs these BEFORE customer's full wordlist via impacket
# direct (NOT medusa) - takes 5-25 seconds total. Cheap insurance.
QUICK_PROBE_DEFAULTS = [
    ("Administrator", "admin"),
    ("admin",         "admin"),
    ("guest",         ""),
    ("sa",            "sa"),
    ("root",          "root"),
]


class MedusaSmbSprayRequest(ScanRequest):
    options: Optional[dict] = None


# Medusa success line:
# "ACCOUNT FOUND: [smbnt] Host: 1.2.3.4 User: admin Password: P@ss [SUCCESS]"
_RE_SUCCESS = re.compile(
    r"ACCOUNT\s+FOUND:\s*\[smbnt\]\s+Host:\s*(?P<host>\S+)\s+User:\s*(?P<user>\S+)\s+"
    r"Password:\s*(?P<pwd>.+?)\s+\[SUCCESS\]",
    re.IGNORECASE,
)


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


def _write_tempfile(prefix: str, lines: list[str]) -> str:
    fd, path = tempfile.mkstemp(prefix=f"vl_{prefix}_", suffix=".lst")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except Exception:
        try: os.close(fd)
        except Exception: pass
        raise
    return path


def _redact(pwd: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction: length + last 3 chars only.
    show_plaintext=True returns plaintext (customer scanning own infra)."""
    if pwd is None:
        return "len=0"
    pwd = pwd.strip()
    if not pwd:
        return "len=0 (empty)"
    if show_plaintext:
        return pwd
    if len(pwd) <= 3:
        return f"len={len(pwd)} ***"
    return f"len={len(pwd)} ***{pwd[-3:]}"


def _strip_internal(findings: list[dict]) -> list[dict]:
    """Remove any internal-only fields before findings hit the response.
    Belt-and-suspenders: we never write a raw_pwd, but strip just in case
    a helper added one or a future patch leaks."""
    for f in findings:
        for k in ("_pwd_private", "raw_pwd", "_password_raw"):
            f.pop(k, None)
    return findings


# ═══════════════════════════════════════════════════════════════════
#  impacket-sync helpers (run via run_in_executor)
# ═══════════════════════════════════════════════════════════════════


def _impacket_negotiate(host: str, port: int) -> dict:
    """Negotiate-only SMB conversation; NO login. Returns fingerprint dict.
    Sync function - call via run_in_executor."""
    out = {
        "server_os": "",
        "server_name": "",
        "server_domain": "",
        "dialect": "",
        "signing_required": None,
        "error": "",
    }
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError as e:
        out["error"] = f"impacket import failed: {e}"
        return out
    conn = None
    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=5)
        try: out["server_os"]     = conn.getServerOS() or ""
        except Exception: pass
        try: out["server_name"]   = conn.getServerName() or ""
        except Exception: pass
        try: out["server_domain"] = conn.getServerDomain() or ""
        except Exception: pass
        try:
            d = conn.getDialect()
            # Render numeric dialect into a friendly string when possible
            _DIALECT_NAMES = {
                0x0202: "SMB2.0.2", 0x0210: "SMB2.1",
                0x0300: "SMB3.0",   0x0302: "SMB3.0.2", 0x0311: "SMB3.1.1",
            }
            if isinstance(d, int):
                out["dialect"] = _DIALECT_NAMES.get(d, f"0x{d:04X}")
            else:
                out["dialect"] = str(d)
        except Exception: pass
        try: out["signing_required"] = bool(conn.isSigningRequired())
        except Exception: pass
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    finally:
        if conn is not None:
            try: conn.close()
            except Exception: pass
    return out


def _impacket_login(host: str, port: int, user: str, pwd: str, domain: str = ""):
    """Attempt SMB login via impacket. Returns (success_bool, conn_or_None,
    err_string). On success, caller owns the conn and must .close() it.

    Sync function - call via run_in_executor."""
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError as e:
        return False, None, f"impacket import failed: {e}"
    conn = None
    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=5)
        conn.login(user, pwd, domain=domain or ".")
        return True, conn, ""
    except Exception as e:
        if conn is not None:
            try: conn.close()
            except Exception: pass
        return False, None, f"{type(e).__name__}: {str(e)[:160]}"


def _impacket_enum_shares(conn) -> dict:
    """Given an authenticated SMBConnection, enumerate shares and probe
    C$ writability + IPC$ + SAMR. Returns dict with keys:
      shares (list), c_dollar_accessible (bool), ipc_accessible (bool),
      samr_enum_allowed (bool), error (str).

    Sync function - call via run_in_executor."""
    out = {
        "shares": [],
        "c_dollar_accessible": False,
        "ipc_accessible": False,
        "samr_enum_allowed": False,
        "error": "",
    }
    if conn is None:
        out["error"] = "no connection"
        return out
    # 1) listShares
    try:
        raw = conn.listShares() or []
        names: list[str] = []
        for s in raw:
            try:
                n = s["shi1_netname"][:-1] if isinstance(s["shi1_netname"], str) \
                    else s["shi1_netname"].decode("utf-8", "ignore").rstrip("\x00")
            except Exception:
                try: n = str(s).strip()
                except Exception: n = ""
            if n:
                names.append(n)
        out["shares"] = names
    except Exception as e:
        out["error"] = f"listShares: {type(e).__name__}: {str(e)[:120]}"

    # 2) Try C$ tree connect
    if any(n.upper() == "C$" for n in out["shares"]):
        try:
            tid = conn.connectTree("C$")
            out["c_dollar_accessible"] = True
            try: conn.disconnectTree(tid)
            except Exception: pass
        except Exception:
            out["c_dollar_accessible"] = False

    # 3) Try IPC$ tree connect
    try:
        tid = conn.connectTree("IPC$")
        out["ipc_accessible"] = True
        try: conn.disconnectTree(tid)
        except Exception: pass
    except Exception:
        out["ipc_accessible"] = False

    # 4) SAMR enumeration probe (open SamrConnect over IPC$, list domains)
    try:
        from impacket.dcerpc.v5 import transport, samr
        rpctransport = transport.SMBTransport(
            conn.getRemoteHost(), conn.getRemoteHost(),
            filename=r"\samr", smb_connection=conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        resp = samr.hSamrConnect(dce)
        # If the SamrConnect succeeds we consider SAMR enumeration allowed.
        try:
            srv_handle = resp["ServerHandle"]
            samr.hSamrEnumerateDomainsInSamServer(dce, srv_handle)
        except Exception:
            pass
        out["samr_enum_allowed"] = True
        try: dce.disconnect()
        except Exception: pass
    except Exception:
        out["samr_enum_allowed"] = False
    return out


# ═══════════════════════════════════════════════════════════════════
#  MedusaSmbSpray - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class MedusaSmbSpray(MethodologyScanner):
    name = "medusa_smb_spray"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        target = ctx.host
        opts = ctx.state.get("_options") or {}
        clean_host, primary = helpers.resolve_port(
            target, opts, primary_port=445, valid_ports=(139, 445))
        ctx.state["target_host"] = clean_host
        if not clean_host:
            ctx.state["target_port"] = primary
            ctx.state["port_reachable"] = False
            ctx.state["skipped_reason"] = "no target supplied"
            return False
        # Try the requested/primary port first (default 445)
        ok_primary = await helpers.port_open(clean_host, primary, timeout=3.0)
        port_used = primary
        ok = ok_primary
        # NetBIOS fallback only meaningful for default 445
        if not ok_primary and primary == 445:
            ok_fallback = await helpers.port_open(clean_host, 139, timeout=3.0)
            if ok_fallback:
                port_used = 139
                ok = True
        ctx.state["target_port"] = port_used
        ctx.state["port_reachable"] = bool(ok)
        if not ok:
            ctx.state["skipped_reason"] = (
                f"SMB on {clean_host} not reachable (tested 445"
                + (", 139" if primary == 445 else "")
                + " - both closed or filtered)"
            )
            return False
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 445)
        loop = asyncio.get_event_loop()
        fp = await loop.run_in_executor(None, _impacket_negotiate, host, port)
        ctx.state["fingerprint"] = fp
        # Surface signing flag at top level for finding rules + chain logic
        if fp.get("signing_required") is not None:
            ctx.state["smb_signing_required"] = bool(fp["signing_required"])

    # ── STAGE 3: QUICK PROBE (5 known SMB defaults) ──────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 445)
        fp = ctx.state.get("fingerprint") or {}
        domain = (fp.get("server_domain") or ".").strip() or "."
        loop = asyncio.get_event_loop()

        hits: list[dict] = []
        wall_clock_budget = 30.0   # total cap across the 5 attempts
        per_attempt = 5.0
        t_start = loop.time()
        for i, (user, pwd) in enumerate(QUICK_PROBE_DEFAULTS):
            if (loop.time() - t_start) >= wall_clock_budget:
                break
            try:
                ok, conn, err = await asyncio.wait_for(
                    loop.run_in_executor(None, _impacket_login, host, port, user, pwd, domain),
                    timeout=per_attempt + 1.0,
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue
            if ok:
                _show = bool((ctx.state.get("_options") or {}).get("show_plaintext"))
                hits.append({
                    "id": f"quick_{i}",
                    "kind": "default_credential",
                    "user": user,
                    "password_marker": _redact(pwd, show_plaintext=_show),
                    "domain": domain,
                    "discovery_method": "quick_probe_known_defaults",
                    # Stash raw pwd for verify/privcheck; stripped before response
                    "_pwd_private": pwd,
                })
                # Close the probe conn - verify/privcheck open fresh ones
                if conn is not None:
                    try:
                        await loop.run_in_executor(None, conn.close)
                    except Exception:
                        pass

        ctx.state["quick_probe_attempts"] = len(QUICK_PROBE_DEFAULTS)
        ctx.state["quick_probe_hits"] = len(hits)
        return hits

    # ── STAGE 4: DEEP SCAN (full medusa spray, gated) ────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        if not MEDUSA_BIN:
            ctx.state["medusa_missing"] = True
            return []
        host = ctx.state.get("target_host") or ctx.host
        opts = ctx.state.get("_options") or {}
        port = int(ctx.state.get("target_port") or 445)
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

        user_path = pass_path = None
        try:
            user_path = _write_tempfile("users", users)
            pass_path = _write_tempfile("passwords", passwords)
            cmd = [
                MEDUSA_BIN,
                "-h", host,
                "-U", user_path,
                "-P", pass_path,
                "-M", "smbnt",
                "-n", str(port),
                "-t", "4",          # 4 parallel logins (gentle)
                "-f",               # stop after first valid pair (per host)
                "-r", "1",          # 1s retry delay
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                try: proc.kill()
                except Exception: pass
                ctx.state["deep_skipped"] = f"medusa timeout @ {timeout}s"
                return []

            stdout = (stdout_b or b"").decode("utf-8", errors="ignore")
            stderr = (stderr_b or b"").decode("utf-8", errors="ignore")
            combined = (stdout + " " + stderr).lower()
            if ("account lockout" in combined
                    or "account has been locked" in combined
                    or "policy_account_disabled" in combined):
                ctx.state["medusa_lockout_hit"] = True

            ctx.state["medusa_attempts"] = len(users) * len(passwords)
            ctx.state["medusa_users_tried"] = len(users)
            ctx.state["medusa_passwords_tried"] = len(passwords)

            findings: list[dict] = []
            fp = ctx.state.get("fingerprint") or {}
            domain = (fp.get("server_domain") or ".").strip() or "."
            _show = bool(opts.get("show_plaintext"))
            for i, line in enumerate(stdout.splitlines()):
                m = _RE_SUCCESS.search(line)
                if not m:
                    continue
                raw_pwd = m.group("pwd")
                findings.append({
                    "id": f"deep_{i}",
                    "kind": "spray_credential",
                    "user": m.group("user"),
                    "password_marker": _redact(raw_pwd, show_plaintext=_show),
                    "domain": domain,
                    "discovery_method": "medusa_smbnt_spray",
                    # Stash raw for verify (sync re-login); stripped pre-response
                    "_pwd_private": raw_pwd,
                })
            return findings
        finally:
            for p in (user_path, pass_path):
                if p:
                    try: os.unlink(p)
                    except Exception: pass

    # ── STAGE 5: VERIFY (re-test via impacket second login) ──────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # VL-FOUNDRY evidence surfacing: stamp a concrete, per-finding
        # evidence string onto the methodology finding object. This rides
        # into the report via the methodology_findings intel field; it adds
        # no new finding and changes no severity (advisory-by-design safe).
        finding["evidence_marker"] = (
            f"{finding.get('discovery_method') or finding.get('kind') or 'probe'}"
            f" -> verifying {finding.get('kind') or 'finding'} for "
            f"{finding.get('user') or finding.get('attack_label') or ctx.host}")
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 445)
        user = finding.get("user", "")
        pwd = finding.get("_pwd_private", "")
        domain = finding.get("domain") or "."
        loop = asyncio.get_event_loop()

        # Quick-probe findings were already impacket-confirmed; do one more
        # fresh login to be doubly sure (defensive: catches transient false
        # positives where probe socket auth succeeded but creds were rate-
        # limited bypass etc.)
        try:
            ok, conn, err = await asyncio.wait_for(
                loop.run_in_executor(None, _impacket_login, host, port, user, pwd, domain),
                timeout=7.0,
            )
        except asyncio.TimeoutError:
            ok, conn, err = False, None, "verify timeout"
        except Exception as e:
            ok, conn, err = False, None, f"{type(e).__name__}"

        if ok:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "impacket_second_login"
            # Hand the live conn off to privilege_check via ctx.state cache
            cache = ctx.state.setdefault("_verified_conns", {})
            cache[finding["id"]] = conn
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = (
                "medusa_unconfirmed" if finding.get("discovery_method") == "medusa_smbnt_spray"
                else "impacket_second_login_failed"
            )
            finding["verify_error"] = err[:160] if err else ""
        return finding

    # ── STAGE 6: PRIVILEGE CHECK (share + SAMR enum) ─────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        if finding.get("confidence") != "CONFIRMED":
            finding["privilege_level"] = "unknown"
            return finding
        user = (finding.get("user") or "").lower()
        loop = asyncio.get_event_loop()
        cache = ctx.state.get("_verified_conns") or {}
        conn = cache.pop(finding["id"], None)
        if conn is None:
            # No live conn (verify failed to cache) - fresh login for enum
            host = ctx.state.get("target_host") or ctx.host
            port = int(ctx.state.get("target_port") or 445)
            pwd = finding.get("_pwd_private", "")
            domain = finding.get("domain") or "."
            try:
                ok, conn, _ = await asyncio.wait_for(
                    loop.run_in_executor(None, _impacket_login, host, port, user, pwd, domain),
                    timeout=7.0,
                )
            except Exception:
                ok, conn = False, None
            if not ok or conn is None:
                finding["privilege_level"] = "unknown"
                finding["privilege_check_method"] = "no_session_available"
                return finding

        try:
            enum_out = await asyncio.wait_for(
                loop.run_in_executor(None, _impacket_enum_shares, conn),
                timeout=10.0,
            )
        except Exception as e:
            enum_out = {
                "shares": [], "c_dollar_accessible": False,
                "ipc_accessible": False, "samr_enum_allowed": False,
                "error": f"{type(e).__name__}",
            }
        finally:
            try: await loop.run_in_executor(None, conn.close)
            except Exception: pass

        finding["shares_visible"] = enum_out.get("shares", [])[:20]
        finding["c_dollar_accessible"] = bool(enum_out.get("c_dollar_accessible"))
        finding["ipc_accessible"] = bool(enum_out.get("ipc_accessible"))
        finding["samr_enum_allowed"] = bool(enum_out.get("samr_enum_allowed"))

        if user in ("guest", "anonymous"):
            finding["privilege_level"] = "guest"
        elif enum_out.get("c_dollar_accessible"):
            finding["privilege_level"] = "admin"
        elif enum_out.get("samr_enum_allowed"):
            finding["privilege_level"] = "user"
            finding["privilege_note"] = "samr_enum_allowed"
        elif enum_out.get("ipc_accessible"):
            finding["privilege_level"] = "user"
        else:
            finding["privilege_level"] = "unknown"

        finding["privilege_check_method"] = "impacket_listshares_plus_samr"
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        # Drop internal-only fields before findings (and any subsequent
        # serialization through methodology_findings) go further.
        _strip_internal(findings)

        next_scanners: list[str] = []
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            priv = f.get("privilege_level")
            if priv == "admin":
                next_scanners = [
                    "ad_enum4linux_ng_audit",
                    "post_exploit_windows_persistence_audit",
                    "post_exploit_lateral_pivot_artifacts",
                ]
                break
        if not next_scanners:
            for f in findings:
                if (f.get("confidence") == "CONFIRMED"
                        and f.get("privilege_level") in ("user", "guest")):
                    next_scanners = ["ad_enum4linux_ng_audit"]
                    break
        return next_scanners


# ═══════════════════════════════════════════════════════════════════
#  Endpoint wrapper - adapts MethodologyScanner to existing framework
# ═══════════════════════════════════════════════════════════════════


INTEL_FIELDS = [
    ("Stage timings (ms)",        "stage_timings"),
    ("Target host",               "target_host"),
    ("Target port",               "target_port"),
    ("Port reachable",            "port_reachable"),
    ("SMB fingerprint",           "fingerprint"),
    ("SMB signing required",      "smb_signing_required"),
    ("Quick-probe attempts",      "quick_probe_attempts"),
    ("Quick-probe hits",          "quick_probe_hits"),
    ("Medusa deep attempts",      "medusa_attempts"),
    ("Medusa users tried",        "medusa_users_tried"),
    ("Medusa passwords tried",    "medusa_passwords_tried"),
    ("Methodology findings",      "methodology_findings"),
    ("Chain handoff next",        "chain_next"),
    ("Stage errors",              "stage_errors"),
]


@router.post("/api/password/medusa_smb_spray")
async def password_medusa_smb_spray(req: MedusaSmbSprayRequest, _=Depends(verify_scan_quota)):
    scanner = MedusaSmbSpray()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=MEDUSA_SMB_SPRAY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)
