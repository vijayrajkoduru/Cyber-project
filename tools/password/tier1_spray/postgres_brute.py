"""postgres_brute - PostgreSQL password spray (VL-METHOD methodology).

PostgreSQL credential-spray scanner built on the VL-METHOD 7-step pentest
pattern (modeled exactly on hydra_ssh_spray.py).

The 7 stages this scanner performs:

  1. PRE-FLIGHT  - Is PostgreSQL/5432 reachable? If not, skip.
  2. FINGERPRINT - psycopg2.connect with bogus creds; parse FATAL error
                    response which leaks PG server version + db name +
                    auth method (md5 / scram-sha-256 / trust / etc).
  3. QUICK PROBE - 5 well-known defaults via psycopg2.connect:
                    postgres/postgres, postgres/(empty), admin/admin,
                    root/root, test/test. Tries both 'postgres' and
                    'template1' databases.
  4. DEEP SCAN   - Gated on quick_probe hits OR options.always_deep.
                    Hard-clamped 10 users x 25 passwords. Pure-Python
                    psycopg2 loop (no subprocess).
  5. VERIFY      - Re-connect with a NEW psycopg2 connection, run
                    SELECT version() + SELECT current_user, current_database().
                    Both must succeed -> CONFIRMED.
  6. PRIVILEGE   - SHOW is_superuser + query pg_roles for current user.
                    is_superuser=on -> admin; rolcreaterole=t -> user_create;
                    own-role-only visibility -> guest; else user.
  7. CHAIN       - For CONFIRMED admin (superuser): suggest
                    post_exploit_postgres_command_exec +
                    post_exploit_postgres_secrets_dump.
                    For user: postgres_user_enum_audit.

Customer input via ScanRequest.options:
  - target            = PG host/IP (required - from req.target)
  - options.userlist  = newline-separated usernames (deep_scan)
  - options.passlist  = newline-separated passwords (deep_scan)
  - options.port      = PG port override (default 5432)
  - options.always_deep = bool, force deep_scan even if quick_probe empty
  - options.show_plaintext = bool, leak plaintext password into findings
                              (only for customer scanning own infra)

Safety: deep_scan hard-clamped 10 users x 25 passwords (250 attempts).
Quick-probe is fixed at 5 well-known pairs.

psycopg2 is the auth driver. psycopg2-binary works too.
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.postgres_brute_findings import (
    POSTGRES_BRUTE_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()

DEFAULT_PORT = 5432
HARD_MAX_USERS = 10
HARD_MAX_PASSWORDS = 25
CONNECT_TIMEOUT = 4
PROBE_DATABASES = ["postgres", "template1"]

# Top-5 PostgreSQL credential pairs that most exposed PG falls to.
# Quick-probe runs these BEFORE the customer's full wordlist.
QUICK_PROBE_DEFAULTS = [
    ("postgres", "postgres"),
    ("postgres", ""),
    ("admin", "admin"),
    ("root", "root"),
    ("test", "test"),
]


class PostgresBruteRequest(ScanRequest):
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
    actual plaintext password instead of the marker."""
    if not pwd:
        return "len=0"
    pwd = pwd.strip()
    if show_plaintext:
        return pwd
    if len(pwd) <= 3:
        return f"len={len(pwd)} ***"
    return f"len={len(pwd)} ***{pwd[-3:]}"


def _parse_pg_error(err_text: str) -> dict:
    """Parse a psycopg2 OperationalError string to extract PG version /
    auth method / database name. PG's FATAL error response leaks all of
    these on a failed-auth probe."""
    out = {"server_version": "", "auth_method": "", "db_name": "", "error_raw": err_text[:500]}
    s = err_text or ""
    sl = s.lower()
    # Auth method detection from typical PG error messages:
    #   "password authentication failed for user \"x\""  -> md5 / scram-sha-256
    #   "no pg_hba.conf entry"                            -> rejected
    #   "ident authentication failed"                      -> ident
    #   "trust"                                            -> trust (no pwd needed)
    if "scram-sha-256" in sl:
        out["auth_method"] = "scram-sha-256"
    elif re.search(r"\bmd5\b", sl):
        out["auth_method"] = "md5"
    elif "ident" in sl and "authentication" in sl:
        out["auth_method"] = "ident"
    elif "trust" in sl:
        out["auth_method"] = "trust"
    elif "gss" in sl:
        out["auth_method"] = "gss"
    elif "peer authentication" in sl:
        out["auth_method"] = "peer"
    elif "password authentication failed" in sl:
        # Generic password-required, exact hash unknown
        out["auth_method"] = "password"
    # Database name leak: "database \"X\" does not exist" or "for user X"
    m = re.search(r'database "([^"]+)" does not exist', s)
    if m:
        out["db_name"] = m.group(1)
    # Server-side version line (some PG variants include this in FATAL)
    m = re.search(r"PostgreSQL[^\s,]*\s+([0-9][0-9.A-Za-z_+-]*)", s)
    if m:
        out["server_version"] = m.group(1)
    return out


def _pg_select_version(conn) -> tuple[str, str, str]:
    """Run SELECT version() + SELECT current_user, current_database()
    on an open psycopg2 connection. Returns (version, current_user, current_db).
    Raises on failure."""
    cur = conn.cursor()
    try:
        cur.execute("SELECT version()")
        row = cur.fetchone()
        version = (row[0] if row else "") or ""
    finally:
        try:
            cur.close()
        except Exception:
            pass
    cur = conn.cursor()
    try:
        cur.execute("SELECT current_user, current_database()")
        row = cur.fetchone()
        cur_user = (row[0] if row else "") or ""
        cur_db = (row[1] if row else "") or ""
    finally:
        try:
            cur.close()
        except Exception:
            pass
    return version, cur_user, cur_db


# Sync helpers wrapped via run_in_executor so we don't block the loop.

def _try_connect(host: str, port: int, user: str, password: str, dbname: str):
    """Sync psycopg2 connect. Returns conn on success; raises on failure.
    Caller MUST close the returned conn."""
    import psycopg2
    return psycopg2.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        dbname=dbname,
        connect_timeout=CONNECT_TIMEOUT,
    )


async def _async_try_login(host: str, port: int, user: str, password: str,
                            dbname: str) -> tuple[bool, str]:
    """Async wrapper around psycopg2.connect. Returns (ok, error_string).
    On ok=True the connection is closed before return."""
    loop = asyncio.get_event_loop()
    try:
        conn = await loop.run_in_executor(
            None, _try_connect, host, port, user, password, dbname)
        try:
            try:
                conn.close()
            except Exception:
                pass
            return True, ""
        finally:
            pass
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:300]}"


# ═══════════════════════════════════════════════════════════════════
#  PostgresBrute - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class PostgresBrute(MethodologyScanner):
    name = "postgres_brute"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        target = ctx.host
        opts = ctx.state.get("_options") or {}
        port_arg = int(opts.get("port") or DEFAULT_PORT)
        clean_host, parsed_port = helpers.split_host_port(target, default_port=port_arg)
        port = parsed_port if parsed_port else port_arg
        ctx.state["target_host"] = clean_host
        ctx.state["target_port"] = port
        if not clean_host:
            ctx.state["skipped_reason"] = "no target supplied"
            return False
        # Library availability check (psycopg2 absent -> hard-skip everything)
        try:
            import psycopg2  # noqa: F401
        except ImportError:
            ctx.state["psycopg2_lib_missing"] = True
            ctx.state["skipped_reason"] = "psycopg2 not installed; pip install psycopg2-binary"
            ctx.state["port_reachable"] = await helpers.port_open(clean_host, port, timeout=3.0)
            return False
        reachable = await helpers.port_open(clean_host, port, timeout=3.0)
        ctx.state["port_reachable"] = reachable
        if not reachable:
            ctx.state["skipped_reason"] = (
                f"PostgreSQL/{port} on {clean_host} not reachable (port closed or filtered)"
            )
            return False
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or DEFAULT_PORT)
        # Bogus-user probe: PostgreSQL responds with a FATAL message that
        # leaks server version, auth method, and the default db on the box.
        ok, err = await _async_try_login(host, port, "postgres_fp_probe", "x", "postgres")
        if ok:
            # Extremely unusual - "trust" auth on default db. Stash it so
            # rule_trust_auth + verify both fire.
            ctx.state["fingerprint"] = {
                "server_version": "",
                "auth_method": "trust",
                "db_name": "postgres",
                "error_raw": "connection succeeded with bogus creds (trust auth)",
            }
            # Stash a private "open" marker so quick_probe can also see it.
            ctx.state["_pwd_private"] = ctx.state.get("_pwd_private") or {}
            return
        parsed = _parse_pg_error(err)
        ctx.state["fingerprint"] = parsed

    # ── STAGE 3: QUICK PROBE (5 known defaults) ──────────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or DEFAULT_PORT)
        opts = ctx.state.get("_options") or {}
        show = bool(opts.get("show_plaintext"))
        attempts = 0
        findings: list[dict] = []
        # Stash _pwd_private so verify() can re-use real plaintext later.
        pwd_private = ctx.state.get("_pwd_private") or {}
        seen_users: set[str] = set()
        for user, pwd in QUICK_PROBE_DEFAULTS:
            for dbname in PROBE_DATABASES:
                attempts += 1
                ok, _err = await _async_try_login(host, port, user, pwd, dbname)
                if ok:
                    if user in seen_users:
                        continue
                    seen_users.add(user)
                    pwd_private[user] = pwd
                    findings.append({
                        "id": f"quick_{len(findings)}",
                        "kind": "default_credential",
                        "user": user,
                        "database": dbname,
                        "password_marker": (pwd if show else _redact(pwd, show_plaintext=False)),
                        "discovery_method": "quick_probe_known_defaults",
                    })
                    break  # don't keep probing other dbs once we have this user
        ctx.state["_pwd_private"] = pwd_private
        ctx.state["quick_probe_attempts"] = attempts
        ctx.state["quick_probe_hits"] = len(findings)
        return findings

    # ── STAGE 4: DEEP SCAN (pure-python psycopg2 loop, gated) ────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or DEFAULT_PORT)
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
        pwd_private = ctx.state.get("_pwd_private") or {}

        findings: list[dict] = []
        attempts = 0
        # Pure-Python loop - 10 x 25 max = 250 connects worst case.
        for user in users:
            if user in pwd_private:
                continue  # already cracked in quick_probe; skip the user
            for pwd in passwords:
                attempts += 1
                ok, _err = await _async_try_login(host, port, user, pwd, "postgres")
                if ok:
                    pwd_private[user] = pwd
                    findings.append({
                        "id": f"deep_{len(findings)}",
                        "kind": "spray_credential",
                        "user": user,
                        "database": "postgres",
                        "password_marker": (pwd if show else _redact(pwd, show_plaintext=False)),
                        "discovery_method": "psycopg2_spray",
                    })
                    break  # next user once we have a hit
        ctx.state["_pwd_private"] = pwd_private
        ctx.state["pg_deep_attempts"] = attempts
        ctx.state["pg_deep_users_tried"] = len(users)
        ctx.state["pg_deep_passwords_tried"] = len(passwords)
        return findings

    # ── STAGE 5: VERIFY (NEW connection + SELECT version) ────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or DEFAULT_PORT)
        user = finding.get("user", "")
        dbname = finding.get("database") or "postgres"
        pwd_private = ctx.state.get("_pwd_private") or {}
        pwd = pwd_private.get(user, "")
        if not user:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "no_user_recorded"
            return finding
        loop = asyncio.get_event_loop()
        try:
            conn = await loop.run_in_executor(
                None, _try_connect, host, port, user, pwd, dbname)
        except Exception as e:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = f"reconnect_failed:{type(e).__name__}"
            return finding
        try:
            try:
                version, cur_user, cur_db = await loop.run_in_executor(
                    None, _pg_select_version, conn)
                finding["server_version_observed"] = version[:200]
                finding["current_user_observed"] = cur_user
                finding["current_db_observed"] = cur_db
                finding["confidence"] = "CONFIRMED"
                finding["verification_method"] = "psycopg2_second_connect_select"
            except Exception as e:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = f"select_failed:{type(e).__name__}"
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        if finding.get("confidence") != "CONFIRMED":
            finding["privilege_level"] = "unknown"
            return finding
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or DEFAULT_PORT)
        user = finding.get("user", "")
        dbname = finding.get("current_db_observed") or finding.get("database") or "postgres"
        pwd_private = ctx.state.get("_pwd_private") or {}
        pwd = pwd_private.get(user, "")
        loop = asyncio.get_event_loop()
        try:
            conn = await loop.run_in_executor(
                None, _try_connect, host, port, user, pwd, dbname)
        except Exception:
            finding["privilege_level"] = "unknown"
            return finding

        def _probe_privs(_conn):
            is_super = ""
            roles_rows: list[tuple] = []
            visible_role_names: list[str] = []
            try:
                c = _conn.cursor()
                try:
                    c.execute("SHOW is_superuser")
                    r = c.fetchone()
                    is_super = (r[0] if r else "") or ""
                finally:
                    try:
                        c.close()
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                c = _conn.cursor()
                try:
                    c.execute(
                        "SELECT rolname, rolsuper, rolcreaterole "
                        "FROM pg_roles WHERE rolname = current_user")
                    roles_rows = c.fetchall() or []
                finally:
                    try:
                        c.close()
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                c = _conn.cursor()
                try:
                    c.execute("SELECT rolname FROM pg_roles")
                    visible_role_names = [row[0] for row in (c.fetchall() or [])]
                finally:
                    try:
                        c.close()
                    except Exception:
                        pass
            except Exception:
                pass
            return is_super, roles_rows, visible_role_names

        try:
            is_super, roles_rows, visible_role_names = await loop.run_in_executor(
                None, _probe_privs, conn)
        finally:
            try:
                conn.close()
            except Exception:
                pass

        # Decision tree per spec:
        #   is_superuser=on              -> admin (superuser)
        #   rolcreaterole=t              -> user_create
        #   only own role visible        -> guest
        #   else                          -> user
        finding["is_superuser_raw"] = is_super
        if (is_super or "").strip().lower() == "on":
            finding["privilege_level"] = "admin"
            finding["privilege_detail"] = "superuser"
            return finding
        rolcreaterole = False
        rolsuper_row = False
        for row in roles_rows:
            # row order: (rolname, rolsuper, rolcreaterole)
            if len(row) >= 3:
                rolsuper_row = bool(row[1])
                rolcreaterole = bool(row[2])
        if rolsuper_row:
            finding["privilege_level"] = "admin"
            finding["privilege_detail"] = "superuser_via_pg_roles"
            return finding
        if rolcreaterole:
            finding["privilege_level"] = "user_create"
            return finding
        # If we can only see ourselves in pg_roles -> guest-equivalent.
        if visible_role_names and len(set(visible_role_names)) <= 1:
            finding["privilege_level"] = "guest"
            return finding
        finding["privilege_level"] = "user"
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        next_scanners: list[str] = []
        has_admin = False
        has_user = False
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            priv = f.get("privilege_level")
            if priv == "admin":
                has_admin = True
                break
            if priv in ("user", "user_create"):
                has_user = True
        if has_admin:
            next_scanners = [
                "post_exploit_postgres_command_exec",
                "post_exploit_postgres_secrets_dump",
            ]
        elif has_user:
            next_scanners = ["postgres_user_enum_audit"]
        return next_scanners


# ═══════════════════════════════════════════════════════════════════
#  Endpoint wrapper - adapts MethodologyScanner to existing framework
# ═══════════════════════════════════════════════════════════════════


@router.post("/api/password/postgres_brute")
async def password_postgres_brute(req: PostgresBruteRequest, _=Depends(verify_scan_quota)):
    scanner = PostgresBrute()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=POSTGRES_BRUTE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)
