"""mysql_brute - MySQL password spray via VL-METHOD methodology.

7-stage pentest workflow modeled on hydra_ssh_spray (the VL-METHOD
reference scanner). Replaces the previous shallow "run mysql client ->
parse" approach with a real DBA-style audit.

Stages:

  1. PRE-FLIGHT  - Is MySQL/3306 reachable? If not, skip with SKIPPED
                    (no point burning cycles on a closed port).

  2. FINGERPRINT - TCP-connect 3306, read the MySQL greeting packet
                    (4-byte length header + 1-byte sequence + protocol
                    version byte + null-terminated server version string
                    + 4-byte connection id + 2-byte server capabilities).
                    Detects MariaDB vs Oracle MySQL from the version
                    string. Result drives the outdated-version finding.

  3. QUICK PROBE - Try 5 known-bad MySQL defaults BEFORE customer's full
                    wordlist (root/<empty>, root/root, admin/admin,
                    mysql/mysql, test/test). Uses pymysql direct so we
                    can verify the auth result deterministically without
                    subprocess parsing.

  4. DEEP SCAN   - Only runs if quick_probe found something OR customer
                    set options.always_deep=True. Pure-Python pymysql
                    loop with the customer's userlist x passlist,
                    hard-clamped to 10 users x 25 passwords (250 max
                    attempts) and 4s per-attempt timeout to avoid
                    locking out accounts / triggering ban policies.

  5. VERIFY      - Re-confirm EACH valid credential with a separate
                    pymysql connection running SELECT VERSION() +
                    SELECT USER(). Kills any auth-layer false positives
                    from the discovery stage. Sets confidence =
                    CONFIRMED (both queries returned) | SUSPECTED.

  6. PRIVILEGE   - For confirmed accounts, attempt SHOW DATABASES +
                    SELECT * FROM mysql.user LIMIT 1. mysql.user
                    readable -> 'admin' (DBA). SHOW DATABASES works but
                    no mysql.user -> 'user'. Only SHOW GRANTS for self
                    works -> 'guest'.

  7. CHAIN       - For CONFIRMED admin (DBA), suggest follow-ups:
                    post_exploit_mysql_secrets_dump,
                    post_exploit_udf_lateral. For CONFIRMED user,
                    suggest mysql_user_enum_audit. Cross-scanner
                    chaining engine will spawn these with the captured
                    credentials.

Customer input via ScanRequest.options:
  - target              = MySQL host/IP (required - from req.target)
  - options.userlist    = newline-separated usernames (deep_scan)
  - options.passlist    = newline-separated passwords (deep_scan)
  - options.port        = MySQL port override (default 3306)
  - options.always_deep = bool, force deep_scan even if quick_probe empty
  - options.show_plaintext = bool, return actual passwords instead of
                              redacted markers (own-infra scans only)

Safety guard: deep_scan hard-clamped to 10 users x 25 passwords (250
attempts) per run. Quick-probe is fixed at 5 well-known pairs only.
"""
from __future__ import annotations

import asyncio
import socket
import struct
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel  # noqa: F401  (kept for parity with reference scanner)

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.mysql_brute_findings import (
    MYSQL_BRUTE_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()

HARD_MAX_USERS = 10
HARD_MAX_PASSWORDS = 25
PER_ATTEMPT_TIMEOUT = 4  # seconds

# Top-5 MySQL credential pairs most-likely to fall to a quick probe.
# Runs BEFORE customer's full wordlist - 5 attempts at 4s each = 20s max.
QUICK_PROBE_DEFAULTS = [
    ("root", ""),
    ("root", "root"),
    ("admin", "admin"),
    ("mysql", "mysql"),
    ("test", "test"),
]


# Lazy-import pymysql so a missing client lib doesn't crash the whole
# scanner; we surface mysql_lib_missing=True instead and a finding rule
# emits an INFO advising `pip install pymysql`.
try:
    import pymysql  # type: ignore
    _PYMYSQL_OK = True
except ImportError:
    pymysql = None  # type: ignore
    _PYMYSQL_OK = False


class MysqlBruteRequest(ScanRequest):
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
    if not pwd:
        return "len=0"
    pwd = pwd.strip()
    if show_plaintext:
        return pwd
    if len(pwd) <= 3:
        return f"len={len(pwd)} ***"
    return f"len={len(pwd)} ***{pwd[-3:]}"


# ───────────────────────────────────────────────────────────────────
#  MySQL greeting packet parser
# ───────────────────────────────────────────────────────────────────

def _parse_greeting(raw: bytes) -> dict:
    """Parse a raw MySQL greeting packet.

    Wire format (MySQL 10/41 protocol):
      [3 bytes] payload length (little-endian)
      [1 byte]  sequence id
      [1 byte]  protocol version (0x0a)
      [N bytes] server version (null-terminated string)
      [4 bytes] connection id (little-endian)
      [8 bytes] auth-plugin-data-part-1
      [1 byte]  filler (0x00)
      [2 bytes] capability flags (lower)
      ... rest ignored for fingerprint purposes
    """
    out = {
        "server_version": "",
        "protocol_version": None,
        "connection_id": None,
        "capabilities": "",
        "raw_greeting_hex": "",
        "flavor": "",
    }
    if not raw or len(raw) < 5:
        return out
    out["raw_greeting_hex"] = raw[:128].hex()
    try:
        # length header + sequence
        payload_len = raw[0] | (raw[1] << 8) | (raw[2] << 16)
        # raw[3] = sequence id (unused here)
        if len(raw) < 4 + 1:
            return out
        proto = raw[4]
        out["protocol_version"] = int(proto)
        # ERR packet sometimes returned instead of greeting (0xff)
        if proto == 0xff:
            return out
        # Walk null-terminated server version starting at offset 5
        end = raw.find(b"\x00", 5)
        if end < 0:
            return out
        try:
            out["server_version"] = raw[5:end].decode("utf-8", errors="ignore")
        except Exception:
            out["server_version"] = ""
        # Detect MariaDB vs MySQL from version string
        ver_lower = out["server_version"].lower()
        if "mariadb" in ver_lower:
            out["flavor"] = "MariaDB"
        elif out["server_version"]:
            out["flavor"] = "MySQL"
        # connection id = 4 bytes LE at end+1
        cid_off = end + 1
        if len(raw) >= cid_off + 4:
            cid = struct.unpack_from("<I", raw, cid_off)[0]
            out["connection_id"] = int(cid)
        # capability flags lower 2 bytes at cid_off + 4 (auth-plugin-data-part-1)
        # + 8 + 1 (filler) = cid_off + 13
        cap_off = cid_off + 4 + 8 + 1
        if len(raw) >= cap_off + 2:
            caps = struct.unpack_from("<H", raw, cap_off)[0]
            out["capabilities"] = f"0x{caps:04x}"
    except Exception:
        # parser best-effort; keep whatever we managed to collect
        pass
    return out


def _read_greeting_blocking(host: str, port: int, timeout: float = 4.0) -> bytes:
    """Blocking TCP read of the MySQL greeting packet.
    Runs in a thread so the async scanner doesn't stall."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # MySQL greeting arrives unsolicited on connect
            # Read length header first (3 bytes) + seq (1 byte) + payload
            hdr = b""
            while len(hdr) < 4:
                chunk = sock.recv(4 - len(hdr))
                if not chunk:
                    break
                hdr += chunk
            if len(hdr) < 4:
                return hdr
            payload_len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16)
            payload = b""
            target_len = min(payload_len, 512)  # cap to avoid huge reads
            while len(payload) < target_len:
                chunk = sock.recv(target_len - len(payload))
                if not chunk:
                    break
                payload += chunk
            return hdr + payload
    except Exception:
        return b""


# ═══════════════════════════════════════════════════════════════════
#  MysqlBrute - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class MysqlBrute(MethodologyScanner):
    name = "mysql_brute"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        target = ctx.host
        opts = ctx.state.get("_options") or {}
        clean_host, port = helpers.resolve_port(
            target, opts, primary_port=3306, valid_ports=(3307,))
        ctx.state["target_host"] = clean_host
        ctx.state["target_port"] = port
        if not clean_host:
            ctx.state["skipped_reason"] = "no target supplied"
            return False
        if not _PYMYSQL_OK:
            # We still let fingerprint run (raw socket) but flag the lib gap
            # so the deep stages can short-circuit with a clear finding.
            ctx.state["mysql_lib_missing"] = True
        reachable = await helpers.port_open(clean_host, port, timeout=3.0)
        ctx.state["port_reachable"] = reachable
        if not reachable:
            ctx.state["skipped_reason"] = (
                f"MySQL/{port} on {clean_host} not reachable (port closed or filtered)"
            )
            return False
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 3306)
        loop = asyncio.get_event_loop()
        raw = await loop.run_in_executor(
            None, _read_greeting_blocking, target, port, 4.0
        )
        fp = _parse_greeting(raw or b"")
        ctx.state["fingerprint"] = fp

    # ── STAGE 3: QUICK PROBE (5 known defaults) ──────────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        ctx.state["quick_probe_attempts"] = 0
        ctx.state["quick_probe_hits"] = 0
        if not _PYMYSQL_OK:
            return []
        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 3306)
        opts = ctx.state.get("_options") or {}
        show = bool(opts.get("show_plaintext"))

        loop = asyncio.get_event_loop()
        hits: list[dict] = []
        attempts = 0
        for user, pwd in QUICK_PROBE_DEFAULTS:
            attempts += 1
            try:
                def _try():
                    conn = pymysql.connect(
                        host=target,
                        port=port,
                        user=user,
                        password=pwd,
                        connect_timeout=PER_ATTEMPT_TIMEOUT,
                        read_timeout=PER_ATTEMPT_TIMEOUT,
                        write_timeout=PER_ATTEMPT_TIMEOUT,
                    )
                    try:
                        conn.close()
                    except Exception:
                        pass
                    return True
                ok = await loop.run_in_executor(None, _try)
                if ok:
                    hits.append({
                        "id": f"quick_{attempts}",
                        "kind": "default_credential",
                        "user": user,
                        "_pwd_private": pwd,
                        "password_marker": _redact(pwd, show_plaintext=show),
                        "discovery_method": "quick_probe_known_defaults",
                    })
            except Exception:
                # auth fail / network blip - move on
                continue
        ctx.state["quick_probe_attempts"] = attempts
        ctx.state["quick_probe_hits"] = len(hits)
        return hits

    # ── STAGE 4: DEEP SCAN (gated, hard-clamped) ─────────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        if not _PYMYSQL_OK:
            ctx.state["mysql_lib_missing"] = True
            return []
        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 3306)
        opts = ctx.state.get("_options") or {}
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

        show = bool(opts.get("show_plaintext"))
        loop = asyncio.get_event_loop()
        findings: list[dict] = []
        attempts = 0
        seen_users: set[str] = set()  # one hit per user; move on to next user
        for user in users:
            if user in seen_users:
                continue
            for pwd in passwords:
                attempts += 1
                try:
                    def _try(u=user, p=pwd):
                        conn = pymysql.connect(
                            host=target,
                            port=port,
                            user=u,
                            password=p,
                            connect_timeout=PER_ATTEMPT_TIMEOUT,
                            read_timeout=PER_ATTEMPT_TIMEOUT,
                            write_timeout=PER_ATTEMPT_TIMEOUT,
                        )
                        try:
                            conn.close()
                        except Exception:
                            pass
                        return True
                    ok = await loop.run_in_executor(None, _try)
                    if ok:
                        findings.append({
                            "id": f"deep_{attempts}",
                            "kind": "spray_credential",
                            "user": user,
                            "_pwd_private": pwd,
                            "password_marker": _redact(pwd, show_plaintext=show),
                            "discovery_method": "pymysql_deep_spray",
                        })
                        seen_users.add(user)
                        break  # next user
                except Exception:
                    continue
        ctx.state["mysql_deep_attempts"] = attempts
        ctx.state["mysql_users_tried"] = len(users)
        ctx.state["mysql_passwords_tried"] = len(passwords)
        return findings

    # ── STAGE 5: VERIFY (NEW connection + SELECT) ────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        if not _PYMYSQL_OK:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "pymysql_missing_cannot_verify"
            return finding
        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 3306)
        user = finding.get("user", "")
        pwd = finding.get("_pwd_private", "")
        loop = asyncio.get_event_loop()

        def _verify():
            conn = pymysql.connect(
                host=target,
                port=port,
                user=user,
                password=pwd,
                connect_timeout=PER_ATTEMPT_TIMEOUT,
                read_timeout=PER_ATTEMPT_TIMEOUT,
                write_timeout=PER_ATTEMPT_TIMEOUT,
            )
            try:
                cur = conn.cursor()
                cur.execute("SELECT VERSION()")
                ver_row = cur.fetchone()
                cur.execute("SELECT USER()")
                user_row = cur.fetchone()
                cur.close()
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            return (
                (ver_row[0] if ver_row else None),
                (user_row[0] if user_row else None),
            )

        try:
            ver, who = await loop.run_in_executor(None, _verify)
        except Exception:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "pymysql_second_connect_failed"
            return finding

        if ver and who:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "pymysql_second_connect_select"
            finding["verified_version"] = str(ver)[:120]
            finding["verified_who"] = str(who)[:120]
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "pymysql_second_connect_select_empty"
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        finding.setdefault("privilege_level", "unknown")
        if not _PYMYSQL_OK:
            return finding
        if finding.get("confidence") != "CONFIRMED":
            return finding
        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 3306)
        user = finding.get("user", "")
        pwd = finding.get("_pwd_private", "")
        loop = asyncio.get_event_loop()

        def _probe():
            results = {
                "version_ok": False,
                "grants_ok": False,
                "show_db_ok": False,
                "mysql_user_ok": False,
                "grants_preview": "",
            }
            try:
                conn = pymysql.connect(
                    host=target, port=port, user=user, password=pwd,
                    connect_timeout=PER_ATTEMPT_TIMEOUT,
                    read_timeout=PER_ATTEMPT_TIMEOUT,
                    write_timeout=PER_ATTEMPT_TIMEOUT,
                )
            except Exception:
                return results
            try:
                cur = conn.cursor()
                try:
                    cur.execute("SELECT @@version")
                    if cur.fetchone():
                        results["version_ok"] = True
                except Exception:
                    pass
                try:
                    cur.execute("SHOW GRANTS")
                    rows = cur.fetchall() or []
                    if rows:
                        results["grants_ok"] = True
                        results["grants_preview"] = "; ".join(
                            str(r[0])[:200] for r in rows[:4]
                        )[:600]
                except Exception:
                    pass
                try:
                    cur.execute("SHOW DATABASES")
                    rows = cur.fetchall() or []
                    if rows:
                        results["show_db_ok"] = True
                except Exception:
                    pass
                try:
                    cur.execute("SELECT * FROM mysql.user LIMIT 1")
                    if cur.fetchone():
                        results["mysql_user_ok"] = True
                except Exception:
                    pass
                cur.close()
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            return results

        try:
            probe = await loop.run_in_executor(None, _probe)
        except Exception:
            probe = {}

        if probe.get("mysql_user_ok"):
            finding["privilege_level"] = "admin"  # DBA
        elif probe.get("show_db_ok"):
            finding["privilege_level"] = "user"
        elif probe.get("grants_ok") or probe.get("version_ok"):
            finding["privilege_level"] = "guest"
        else:
            finding["privilege_level"] = "unknown"
        if probe.get("grants_preview"):
            finding["grants_preview"] = probe["grants_preview"]
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        next_scanners: list[str] = []
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            priv = f.get("privilege_level")
            if priv == "admin":
                next_scanners = [
                    "post_exploit_mysql_secrets_dump",
                    "post_exploit_udf_lateral",
                ]
                break
        if not next_scanners:
            for f in findings:
                if (f.get("confidence") == "CONFIRMED"
                        and f.get("privilege_level") == "user"):
                    next_scanners = ["mysql_user_enum_audit"]
                    break
        return next_scanners


# ═══════════════════════════════════════════════════════════════════
#  Endpoint wrapper
# ═══════════════════════════════════════════════════════════════════


@router.post("/api/password/mysql_brute")
async def password_mysql_brute(req: MysqlBruteRequest, _=Depends(verify_scan_quota)):
    scanner = MysqlBrute()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=MYSQL_BRUTE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)
