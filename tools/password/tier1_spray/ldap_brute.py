"""ldap_brute - LDAP password spray + anonymous bind audit (VL-METHOD).

Built 2026-06-05 on the VL-METHOD 7-step pentest pattern, modeled on
hydra_ssh_spray.py (the reference scanner) and medusa_smb_spray.py
(reference for INDEPENDENT findings like anonymous-bind/no-StartTLS).

The 7 stages this scanner performs:

  1. PRE-FLIGHT  - Is LDAP/389 reachable? (and 636 if options.use_ldaps).
                    If not, skip with SKIPPED status. Default port 389.

  2. FINGERPRINT - Anonymous connect, read rootDSE via ldap3 ALL info.
                    Captures vendor_name, vendor_version, supported LDAP
                    versions, naming contexts (used for DN guessing),
                    SASL mechanisms, StartTLS support, and whether
                    anonymous bind is allowed at all. Anonymous-bind
                    finding fires INDEPENDENT of credential outcome.

  3. QUICK PROBE - Try 5 known-bad default bind pairs:
                    cn=admin,dc=...    / admin     (OpenLDAP default)
                    Administrator      / Administrator (AD style)
                    admin              / admin     (simple bind)
                    cn=manager,dc=...  / manager   (OpenLDAP legacy)
                    guest              / guest
                    Naming-context aware: if rootDSE returns
                    dc=example,dc=com the DN suffixes are substituted
                    automatically. options.base_dn overrides.

  4. DEEP SCAN   - Only runs if quick_probe found something OR options.
                    always_deep=True. Pure-Python ldap3 loop, hard-
                    clamped at 10 users x 25 passwords.

  5. VERIFY      - Re-bind on a NEW ldap3 Connection and run a search
                    for (objectClass=*) at base_dn with size_limit=1.
                    CONFIRMED if search returns. verification_method =
                    'ldap3_second_bind_search'.

  6. PRIVILEGE   - Search (objectClass=user) requesting memberOf.
                    Member of Domain Admins / Enterprise Admins / Schema
                    Admins -> 'admin'. Basic results -> 'user'. Search
                    blocked / no permission -> 'guest'.

  7. CHAIN       - For CONFIRMED admin (Domain Admins), suggest
                    ad_bloodhound_audit, kerberoast_audit,
                    asreproast_audit, post_exploit_ad_persistence.
                    For user, ldap_user_enum_audit. Empty otherwise.

Customer input via ScanRequest.options:
  - target              = LDAP host/IP (required - taken from req.target)
  - options.userlist    = newline-separated usernames (for deep_scan)
  - options.passlist    = newline-separated passwords (for deep_scan)
  - options.port        = LDAP port override (default 389)
  - options.use_ldaps   = bool, also probe TCP/636
  - options.base_dn     = override base DN for binds/searches
  - options.always_deep = bool, force deep_scan even if quick_probe empty
  - options.show_plaintext = bool, customer scanning own infra

Safety guard: deep_scan hard-clamped to 10 users x 25 passwords per run.
Quick-probe is fixed at 5 well-known pairs only.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.ldap_brute_findings import LDAP_BRUTE_FINDING_RULES, INTEL_FIELDS

router = APIRouter()
HARD_MAX_USERS = 10
HARD_MAX_PASSWORDS = 25
PER_BIND_TIMEOUT = 4.0


class LdapBruteRequest(ScanRequest):
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


def _pick_base_dn(naming_contexts: list[str], override: str = "") -> str:
    """Pick the most likely base DN from rootDSE naming_contexts.
    Prefer 'dc=' contexts over CN= configuration contexts."""
    if override:
        return override
    if not naming_contexts:
        return ""
    # Prefer dc=... contexts (real user trees) over CN=Configuration,...
    for nc in naming_contexts:
        ncl = (nc or "").strip().lower()
        if ncl.startswith("dc=") and "cn=configuration" not in ncl:
            return nc.strip()
    # Fallback: first non-configuration context
    for nc in naming_contexts:
        ncl = (nc or "").strip().lower()
        if "cn=configuration" not in ncl and "cn=schema" not in ncl:
            return nc.strip()
    return naming_contexts[0].strip() if naming_contexts else ""


def _substitute_dn_template(template: str, base_dn: str) -> str:
    """Substitute base_dn into a DN template like 'cn=admin,dc=example,dc=com'.
    If base_dn is provided and looks valid, swap the dc=... part."""
    if not base_dn or "dc=" not in template.lower():
        return template
    # Split template at first dc=
    low = template.lower()
    idx = low.find("dc=")
    if idx <= 0:
        return template
    return template[:idx] + base_dn


# Quick-probe pairs. DN templates are substituted at runtime once we know
# the real naming_contexts (or options.base_dn).
QUICK_PROBE_DEFAULTS: list[tuple[str, str]] = [
    ("cn=admin,dc=example,dc=com", "admin"),       # OpenLDAP factory default
    ("Administrator", "Administrator"),             # Active Directory style
    ("admin", "admin"),                             # simple bind
    ("cn=manager,dc=example,dc=com", "manager"),   # OpenLDAP legacy
    ("guest", "guest"),
]


# Active Directory privileged groups - canonical CN substrings.
AD_PRIVILEGED_GROUPS = (
    "domain admins", "enterprise admins", "schema admins",
)


async def _ldap_bind_attempt(server, user: str, pwd: str,
                              timeout: float = PER_BIND_TIMEOUT) -> tuple[bool, Optional[object]]:
    """Run a single ldap3 bind in a thread executor with timeout.
    Returns (success, connection_or_None). Caller closes the connection."""
    import ldap3
    loop = asyncio.get_event_loop()

    def _bind():
        try:
            conn = ldap3.Connection(
                server, user=user, password=pwd,
                auto_bind=False, read_only=True,
                receive_timeout=timeout,
            )
            ok = conn.bind()
            return (bool(ok), conn)
        except Exception:
            return (False, None)

    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _bind), timeout=timeout + 2.0
        )
    except asyncio.TimeoutError:
        return (False, None)
    except Exception:
        return (False, None)


# ════════════════════════════════════════════════════════════════════
#  LdapBrute - the VL-METHOD scanner class
# ════════════════════════════════════════════════════════════════════


class LdapBrute(MethodologyScanner):
    name = "ldap_brute"

    # ── STAGE 1: PRE-FLIGHT ───────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        target = ctx.host
        opts = ctx.state.get("_options") or {}
        port_arg = int(opts.get("port") or 389)
        use_ldaps = bool(opts.get("use_ldaps"))
        clean_host, parsed_port = helpers.split_host_port(target, default_port=port_arg)
        port = parsed_port if parsed_port else port_arg
        ctx.state["target_host"] = clean_host
        ctx.state["target_port"] = port
        ctx.state["use_ldaps"] = use_ldaps
        if not clean_host:
            ctx.state["skipped_reason"] = "no target supplied"
            ctx.state["port_reachable"] = False
            return False
        # Check ldap3 library availability up-front so finding rules can
        # surface an INFO message instead of looking like "scan worked".
        try:
            import ldap3  # noqa: F401
        except ImportError:
            ctx.state["ldap3_lib_missing"] = True
            ctx.state["skipped_reason"] = (
                "ldap3 Python library not installed - cannot perform "
                "LDAP credential audit. pip install ldap3.")
            ctx.state["port_reachable"] = False
            return False
        reachable_389 = await helpers.port_open(clean_host, port, timeout=3.0)
        reachable_636 = False
        if use_ldaps:
            reachable_636 = await helpers.port_open(clean_host, 636, timeout=3.0)
            ctx.state["target_port_ldaps_reachable"] = reachable_636
        reachable = reachable_389 or reachable_636
        ctx.state["port_reachable"] = reachable
        if not reachable:
            ports = f"{port}" + ("/636" if use_ldaps else "")
            ctx.state["skipped_reason"] = (
                f"LDAP/{ports} on {clean_host} not reachable "
                "(port closed or filtered)")
            return False
        return True

    # ── STAGE 2: FINGERPRINT ──────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        try:
            import ldap3
        except ImportError:
            ctx.state["ldap3_lib_missing"] = True
            return
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 389)
        loop = asyncio.get_event_loop()

        def _read_root_dse():
            fp = {
                "vendor_name": "",
                "vendor_version": "",
                "supported_ldap_versions": [],
                "naming_contexts": [],
                "anonymous_bind_allowed": False,
                "supported_sasl_mechanisms": [],
                "has_starttls": False,
                "error": "",
            }
            try:
                server = ldap3.Server(host, port=port, get_info=ldap3.ALL,
                                       connect_timeout=4)
                conn = ldap3.Connection(server, auto_bind=False, read_only=True,
                                         receive_timeout=4)
                bound = False
                try:
                    bound = bool(conn.bind())
                except Exception as e:
                    fp["error"] = f"anon-bind: {type(e).__name__}"
                fp["anonymous_bind_allowed"] = bool(bound)
                info = getattr(server, "info", None)
                if info is not None:
                    try:
                        fp["vendor_name"] = str(getattr(info, "vendor_name", "") or "")
                    except Exception: pass
                    try:
                        fp["vendor_version"] = str(getattr(info, "vendor_version", "") or "")
                    except Exception: pass
                    try:
                        v = getattr(info, "supported_ldap_versions", None) or []
                        fp["supported_ldap_versions"] = [str(x) for x in v]
                    except Exception: pass
                    try:
                        nc = getattr(info, "naming_contexts", None) or []
                        fp["naming_contexts"] = [str(x) for x in nc]
                    except Exception: pass
                    try:
                        sasl = getattr(info, "supported_sasl_mechanisms", None) or []
                        fp["supported_sasl_mechanisms"] = [str(x) for x in sasl]
                    except Exception: pass
                    try:
                        ext = getattr(info, "supported_extensions", None) or []
                        # StartTLS OID: 1.3.6.1.4.1.1466.20037
                        for e in ext:
                            es = str(e)
                            if "1.3.6.1.4.1.1466.20037" in es or "starttls" in es.lower():
                                fp["has_starttls"] = True
                                break
                    except Exception: pass
                try:
                    conn.unbind()
                except Exception: pass
            except Exception as e:
                fp["error"] = f"server-init: {type(e).__name__}: {str(e)[:120]}"
            return fp

        try:
            fp = await asyncio.wait_for(
                loop.run_in_executor(None, _read_root_dse), timeout=8.0)
        except asyncio.TimeoutError:
            fp = {"error": "rootDSE read timed out at 8s",
                  "anonymous_bind_allowed": False,
                  "naming_contexts": [], "vendor_name": "",
                  "vendor_version": "",
                  "supported_ldap_versions": [],
                  "supported_sasl_mechanisms": [],
                  "has_starttls": False}
        ctx.state["fingerprint"] = fp
        ctx.state["anonymous_bind_allowed"] = bool(fp.get("anonymous_bind_allowed"))
        # Resolve base_dn for downstream stages
        opts = ctx.state.get("_options") or {}
        base_dn = _pick_base_dn(fp.get("naming_contexts") or [],
                                 override=str(opts.get("base_dn") or ""))
        ctx.state["resolved_base_dn"] = base_dn

    # ── STAGE 3: QUICK PROBE ──────────────────────────────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        try:
            import ldap3
        except ImportError:
            ctx.state["ldap3_lib_missing"] = True
            ctx.state["quick_probe_attempts"] = 0
            ctx.state["quick_probe_hits"] = 0
            return []
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 389)
        base_dn = ctx.state.get("resolved_base_dn") or ""
        opts = ctx.state.get("_options") or {}
        show = bool(opts.get("show_plaintext"))

        # Substitute base_dn into DN templates that contain dc=...
        pairs: list[tuple[str, str]] = []
        for user_tmpl, pwd in QUICK_PROBE_DEFAULTS:
            user = _substitute_dn_template(user_tmpl, base_dn)
            pairs.append((user, pwd))

        try:
            server = ldap3.Server(host, port=port, get_info=ldap3.NONE,
                                   connect_timeout=PER_BIND_TIMEOUT)
        except Exception:
            ctx.state["quick_probe_attempts"] = 0
            ctx.state["quick_probe_hits"] = 0
            return []

        findings: list[dict] = []
        attempts = 0
        for i, (user, pwd) in enumerate(pairs):
            attempts += 1
            ok, conn = await _ldap_bind_attempt(server, user, pwd)
            # Make sure we tear down any successful test connection
            if conn is not None:
                try: conn.unbind()
                except Exception: pass
            if not ok:
                continue
            findings.append({
                "id": f"quick_{i}",
                "kind": "default_credential",
                "user": user,
                "_pwd_private": pwd,
                "password_marker": _redact(pwd, show_plaintext=show),
                "discovery_method": "quick_probe_known_defaults",
            })
        ctx.state["quick_probe_attempts"] = attempts
        ctx.state["quick_probe_hits"] = len(findings)
        return findings

    # ── STAGE 4: DEEP SCAN (gated) ────────────────────────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        try:
            import ldap3
        except ImportError:
            ctx.state["ldap3_lib_missing"] = True
            return []
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
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 389)
        base_dn = ctx.state.get("resolved_base_dn") or ""
        show = bool(opts.get("show_plaintext"))

        try:
            server = ldap3.Server(host, port=port, get_info=ldap3.NONE,
                                   connect_timeout=PER_BIND_TIMEOUT)
        except Exception:
            ctx.state["deep_skipped"] = "ldap3 Server init failed"
            return []

        findings: list[dict] = []
        attempts = 0
        for u in users:
            # Build DN candidate: if user has no '=', and base_dn known,
            # try cn=<user>,<base_dn> first then bare <user> (AD style).
            user_variants: list[str] = []
            if "=" in u:
                user_variants.append(u)
            else:
                if base_dn:
                    user_variants.append(f"cn={u},{base_dn}")
                user_variants.append(u)  # AD: sAMAccountName / UPN
            for pwd in passwords:
                attempts += 1
                bound = False
                used_user = u
                for cand in user_variants:
                    ok, conn = await _ldap_bind_attempt(server, cand, pwd)
                    if conn is not None:
                        try: conn.unbind()
                        except Exception: pass
                    if ok:
                        bound = True
                        used_user = cand
                        break
                if not bound:
                    continue
                findings.append({
                    "id": f"deep_{len(findings)}",
                    "kind": "spray_credential",
                    "user": used_user,
                    "_pwd_private": pwd,
                    "password_marker": _redact(pwd, show_plaintext=show),
                    "discovery_method": "ldap3_spray",
                })
                # First-success per user is enough for spray reporting
                break
        ctx.state["ldap_deep_attempts"] = attempts
        ctx.state["ldap_deep_users_tried"] = len(users)
        ctx.state["ldap_deep_passwords_tried"] = len(passwords)
        return findings

    # ── STAGE 5: VERIFY ───────────────────────────────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        try:
            import ldap3
        except ImportError:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "ldap3_missing_cannot_verify"
            return finding
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 389)
        base_dn = ctx.state.get("resolved_base_dn") or ""
        user = finding.get("user", "")
        pwd = finding.get("_pwd_private", "")
        if not user or not pwd:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "no_password_to_replay"
            return finding

        loop = asyncio.get_event_loop()

        def _verify():
            try:
                server = ldap3.Server(host, port=port, get_info=ldap3.NONE,
                                       connect_timeout=PER_BIND_TIMEOUT)
                conn = ldap3.Connection(server, user=user, password=pwd,
                                         auto_bind=False, read_only=True,
                                         receive_timeout=PER_BIND_TIMEOUT)
                if not conn.bind():
                    return (False, "")
                returned = False
                search_evidence = ""
                try:
                    search_base = base_dn or ""
                    if not search_base:
                        try: conn.unbind()
                        except Exception: pass
                        return (True, "bind-only (no base_dn)")
                    ok = conn.search(
                        search_base=search_base,
                        search_filter="(objectClass=*)",
                        search_scope=ldap3.BASE,
                        size_limit=1,
                        attributes=["objectClass"],
                    )
                    if ok and conn.entries:
                        returned = True
                        search_evidence = f"{search_base} returned {len(conn.entries)} entry"
                    elif ok:
                        # Bind worked and search returned no error but no entries
                        returned = True
                        search_evidence = f"{search_base} accepted (0 entries)"
                    else:
                        search_evidence = "search blocked"
                except Exception as e:
                    search_evidence = f"search-error: {type(e).__name__}"
                try: conn.unbind()
                except Exception: pass
                return (returned, search_evidence)
            except Exception as e:
                return (False, f"verify-error: {type(e).__name__}")

        try:
            ok, evidence = await asyncio.wait_for(
                loop.run_in_executor(None, _verify), timeout=PER_BIND_TIMEOUT + 4.0)
        except asyncio.TimeoutError:
            ok, evidence = (False, "verify-timeout")
        except Exception as e:
            ok, evidence = (False, f"verify-exc: {type(e).__name__}")

        if ok:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "ldap3_second_bind_search"
            finding["verification_evidence"] = evidence
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "ldap3_replay_failed"
            finding["verification_evidence"] = evidence
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ──────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        try:
            import ldap3
        except ImportError:
            finding["privilege_level"] = "unknown"
            return finding
        if finding.get("confidence") != "CONFIRMED":
            finding["privilege_level"] = "unknown"
            return finding
        host = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 389)
        base_dn = ctx.state.get("resolved_base_dn") or ""
        user = finding.get("user", "")
        pwd = finding.get("_pwd_private", "")
        loop = asyncio.get_event_loop()

        def _privcheck():
            try:
                server = ldap3.Server(host, port=port, get_info=ldap3.NONE,
                                       connect_timeout=PER_BIND_TIMEOUT)
                conn = ldap3.Connection(server, user=user, password=pwd,
                                         auto_bind=False, read_only=True,
                                         receive_timeout=PER_BIND_TIMEOUT)
                if not conn.bind():
                    return ("unknown", [])
                if not base_dn:
                    try: conn.unbind()
                    except Exception: pass
                    return ("user", [])
                groups: list[str] = []
                try:
                    ok = conn.search(
                        search_base=base_dn,
                        search_filter="(objectClass=user)",
                        search_scope=ldap3.SUBTREE,
                        size_limit=5,
                        attributes=["memberOf"],
                    )
                    if not ok:
                        try: conn.unbind()
                        except Exception: pass
                        return ("guest", [])
                    if not conn.entries:
                        # Search worked, no user objects (or no read perm)
                        try: conn.unbind()
                        except Exception: pass
                        return ("user", [])
                    for entry in conn.entries[:5]:
                        try:
                            mof = getattr(entry, "memberOf", None)
                            if mof is None: continue
                            vals = mof.values if hasattr(mof, "values") else list(mof)
                            for v in vals or []:
                                groups.append(str(v))
                        except Exception: continue
                except Exception:
                    try: conn.unbind()
                    except Exception: pass
                    return ("guest", [])
                try: conn.unbind()
                except Exception: pass
                # Inspect groups
                low_groups = " | ".join(groups).lower()
                for g in AD_PRIVILEGED_GROUPS:
                    if g in low_groups:
                        return ("admin", groups)
                if groups:
                    return ("user", groups)
                return ("user", [])
            except Exception:
                return ("unknown", [])

        try:
            priv, groups = await asyncio.wait_for(
                loop.run_in_executor(None, _privcheck), timeout=PER_BIND_TIMEOUT + 4.0)
        except asyncio.TimeoutError:
            priv, groups = ("unknown", [])
        except Exception:
            priv, groups = ("unknown", [])
        finding["privilege_level"] = priv
        finding["ad_groups"] = groups[:10]
        return finding

    # ── STAGE 7: CHAIN HANDOFF ────────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        next_scanners: list[str] = []
        has_admin = False
        has_user = False
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            priv = f.get("privilege_level")
            groups_low = " | ".join(f.get("ad_groups") or []).lower()
            if priv == "admin" or any(g in groups_low for g in AD_PRIVILEGED_GROUPS):
                has_admin = True
            elif priv == "user":
                has_user = True
        if has_admin:
            next_scanners = [
                "ad_bloodhound_audit",
                "kerberoast_audit",
                "asreproast_audit",
                "post_exploit_ad_persistence",
            ]
        elif has_user:
            next_scanners = ["ldap_user_enum_audit"]
        return next_scanners


# ════════════════════════════════════════════════════════════════════
#  Endpoint wrapper
# ════════════════════════════════════════════════════════════════════


@router.post("/api/password/ldap_brute")
async def password_ldap_brute(req: LdapBruteRequest, _=Depends(verify_scan_quota)):
    scanner = LdapBrute()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=LDAP_BRUTE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)
