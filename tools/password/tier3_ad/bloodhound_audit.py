"""bloodhound_audit - AD graph extraction + shortest-path-to-DA analysis (VL-METHOD).

Phase C Active Directory differentiator. Performs SharpHound-style LDAP
collection via bloodhound-python, then runs in-memory graph traversal
(NO Neo4j required) to surface shortest paths from the supplied
(owned) user to Domain Admin.

MITRE ATT&CK: TA0006 Credential Access / TA0004 Privilege Escalation.

The 7 VL-METHOD stages this scanner performs:

  1. PRE-FLIGHT  - dc_ip + domain + user + (password OR nt_hash) all
                    supplied? LDAP/389 + SMB/445 reachable on the DC?
                    If chain_creds were inherited from an upstream
                    scanner, use them.

  2. FINGERPRINT - ldap3 simple/NTLM bind, read rootDSE for the
                    forest functional level, dnsHostName, naming
                    contexts. Confirms creds work BEFORE running the
                    expensive collection step.

  3. QUICK PROBE - bloodhound-python BloodHound class (or subprocess
                    fallback) runs collection_method=DCOnly by default
                    (LDAP-only, no SMB session enum -> stealthier +
                    faster). Outputs domains/computers/users/groups/
                    gpos/ous JSON to a tempdir. Counts populated.

  4. DEEP SCAN   - In-memory graph traversal of the collected JSON:
                    (a) Domain Admins transitive membership
                    (b) ACL paths (GenericAll/Write, WriteDacl,
                        WriteOwner, ForceChangePassword) -> shadow
                        admins
                    (c) Kerberoastable accounts (HasSPN=true)
                    (d) AS-REP roastable (DontReqPreAuth=true)
                    (e) Unconstrained delegation computers
                    (f) BFS from owned user to any DA via the
                        adjacency graph we built
                    Hard cap 50 paths.

  5. VERIFY      - For each path finding, re-query LDAP for the
                    first edge of the path (e.g. confirm member-of
                    relationship still exists). Reduces stale-data FP.

  6. PRIVILEGE   - Classify by path_type:
                    krbtgt_compromise_path -> Golden-ticket launchpad
                    da_via_kerberoast      -> Offline-crack -> DA
                    da_via_asreproast      -> No-auth crack -> DA
                    da_via_acl_abuse       -> Shadow admin
                    domain_admin_reachable -> Generic graph path to DA

  7. CHAIN       - kerberoast paths -> kerberoast_audit
                    asreproast paths -> asreproast_audit
                    domain_admin reachable WITH creds -> dcsync_audit
                    krbtgt_compromise -> dcsync_audit

Customer input via options:
  - dc_ip             = Domain Controller IP (required)
  - domain            = AD domain name e.g. "lab.local" (required)
  - user              = ANY authenticated AD user (required)
  - password          = plaintext password (required OR nt_hash)
  - nt_hash           = NT hash (LM:NT or just NT)
  - chain_creds       = inherited from upstream
  - collection_method = "Default" | "DCOnly" | "All" (default DCOnly)
  - always_deep       = bool, force deep_scan even if quick_probe empty

Safety: collection_method defaults to DCOnly (no SMB session enum) so
we don't trigger session-collection IDS rules in customer environments.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.bloodhound_audit_findings import (
    BLOODHOUND_AUDIT_FINDING_RULES,
    INTEL_FIELDS,
)

# Probe for bloodhound-python at import; downstream stages branch on this.
try:
    import bloodhound as _bh_pkg  # noqa: F401
    BLOODHOUND_AVAILABLE = True
except ImportError:
    BLOODHOUND_AVAILABLE = False

# ldap3 used for fingerprint + verify (re-validate edges)
try:
    import ldap3 as _ldap3
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False

BLOODHOUND_CLI = shutil.which("bloodhound-python") or shutil.which("bloodhound.py")
HARD_MAX_PATHS = 50
DEFAULT_COLLECTION_TIMEOUT = 180  # seconds


router = APIRouter()


class BloodhoundAuditRequest(ScanRequest):
    options: Optional[dict] = None


# ── ACL right names that grant takeover capability ───────────────────
DANGEROUS_ACE_RIGHTS = {
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "ForceChangePassword",
    "AddMember",
    "AllExtendedRights",
}


def _redact(value: str) -> str:
    """Customer-safe redaction for sensitive strings.
    NT hashes get redacted; usernames are NOT secrets so we leave them
    intact (they're already in the report intel fields)."""
    if not value:
        return ""
    v = str(value).strip()
    # NT hash detection: 32 hex chars OR LM:NT format
    if len(v) == 32 and all(c in "0123456789abcdefABCDEF" for c in v):
        return f"hash:***{v[-4:]}"
    if ":" in v and len(v.split(":")[-1]) == 32:
        return f"hash:LM:***{v[-4:]}"
    return v


def _norm_name(n) -> str:
    """Normalize an AD object name for graph keys."""
    if not n:
        return ""
    return str(n).strip().upper()


def _split_nt_hash(raw: str) -> tuple[str, str]:
    """Split LM:NT or NT-only into (lm, nt). Returns ('', '') on bad input."""
    if not raw:
        return ("", "")
    s = raw.strip()
    if ":" in s:
        lm, _, nt = s.partition(":")
        return (lm.strip(), nt.strip())
    return ("", s)


# ═══════════════════════════════════════════════════════════════════
#  BloodhoundAudit - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class BloodhoundAudit(MethodologyScanner):
    name = "bloodhound_audit"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        opts = ctx.state.get("_options") or {}

        # Inherit creds from upstream chained scanner if user not set
        if not opts.get("user"):
            cc = opts.get("chain_creds") or []
            if cc and isinstance(cc, list) and isinstance(cc[0], dict):
                opts["user"] = cc[0].get("user") or ""
                # chain_creds carry plaintext under 'pwd'
                if not opts.get("password") and not opts.get("nt_hash"):
                    opts["password"] = cc[0].get("pwd") or ""
                ctx.state["inherited_from_chain"] = True

        # Default dc_ip to target if not explicitly supplied
        dc_ip = opts.get("dc_ip") or ctx.host
        opts["dc_ip"] = dc_ip
        domain = opts.get("domain") or ""
        user = opts.get("user") or ""
        password = opts.get("password") or ""
        nt_hash = opts.get("nt_hash") or ""

        ctx.state["dc_ip"] = dc_ip
        ctx.state["domain"] = domain
        ctx.state["bind_user"] = user

        if not dc_ip:
            ctx.state["skipped_reason"] = "requires options.dc_ip (Domain Controller IP)"
            return False
        if not domain:
            ctx.state["skipped_reason"] = "requires options.domain (AD domain name)"
            return False
        if not user:
            ctx.state["skipped_reason"] = "requires options.user (any authenticated domain user)"
            return False
        if not password and not nt_hash:
            ctx.state["skipped_reason"] = "requires options.password OR options.nt_hash"
            return False

        # TCP-test LDAP/389 + SMB/445
        ldap_open = await helpers.port_open(dc_ip, 389, timeout=3.0)
        smb_open = await helpers.port_open(dc_ip, 445, timeout=3.0)
        ctx.state["ldap_reachable"] = ldap_open
        ctx.state["smb_reachable"] = smb_open
        if not ldap_open and not smb_open:
            ctx.state["skipped_reason"] = (
                f"DC {dc_ip} unreachable: LDAP/389 and SMB/445 both closed/filtered"
            )
            return False
        if not ldap_open:
            ctx.state["skipped_reason"] = (
                f"DC {dc_ip} LDAP/389 unreachable - cannot bind for collection"
            )
            return False

        # Stash normalized options back for later stages
        ctx.state["_options"] = opts
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        if not LDAP3_AVAILABLE:
            ctx.state["fingerprint"] = {"error": "ldap3 not installed"}
            return
        opts = ctx.state.get("_options") or {}
        dc_ip = opts.get("dc_ip") or ""
        domain = opts.get("domain") or ""
        user = opts.get("user") or ""
        password = opts.get("password") or ""
        nt_hash = opts.get("nt_hash") or ""

        bind_user = f"{user}@{domain}" if "@" not in user and domain else user

        def _do_bind():
            try:
                server = _ldap3.Server(dc_ip, get_info=_ldap3.DSA, connect_timeout=5)
                if nt_hash:
                    _lm, nt = _split_nt_hash(nt_hash)
                    # NTLM bind via ldap3: user format = DOMAIN\user, pwd = LM:NT
                    ntlm_user = f"{domain}\\{user}" if "\\" not in user else user
                    ntlm_pwd = f"{_lm or 'aad3b435b51404eeaad3b435b51404ee'}:{nt}"
                    conn = _ldap3.Connection(
                        server, user=ntlm_user, password=ntlm_pwd,
                        authentication=_ldap3.NTLM, auto_bind=True,
                        receive_timeout=8,
                    )
                else:
                    conn = _ldap3.Connection(
                        server, user=bind_user, password=password,
                        auto_bind=True, receive_timeout=8,
                    )
                info = server.info
                fp = {
                    "service": "ldap",
                    "dns_host_name": getattr(info, "dns_host_name", "") or "",
                    "domain_functional_level": "",
                    "naming_contexts": [],
                    "supported_ldap_versions": [],
                    "vendor": "",
                }
                # rootDSE attributes
                try:
                    raw = getattr(info, "other", {}) or {}
                    fp["domain_functional_level"] = str((raw.get("domainFunctionality") or [""])[0])
                    fp["naming_contexts"] = list(getattr(info, "naming_contexts", []) or [])[:5]
                    fp["supported_ldap_versions"] = list(getattr(info, "supported_ldap_versions", []) or [])
                    fp["vendor"] = str((raw.get("vendorName") or [""])[0])
                except Exception:
                    pass
                try: conn.unbind()
                except Exception: pass
                return fp, None
            except Exception as e:
                return None, f"{type(e).__name__}: {str(e)[:200]}"

        loop = asyncio.get_event_loop()
        fp, err = await loop.run_in_executor(None, _do_bind)
        if err:
            ctx.state["bind_failed"] = True
            ctx.state["fingerprint"] = {"error": err}
            return
        ctx.state["fingerprint"] = fp

    # ── STAGE 3: QUICK PROBE - run bloodhound-python collection ──
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        if ctx.state.get("bind_failed"):
            return []
        if not BLOODHOUND_AVAILABLE and not BLOODHOUND_CLI:
            ctx.state["bloodhound_missing"] = True
            return []

        opts = ctx.state.get("_options") or {}
        dc_ip = opts.get("dc_ip") or ""
        domain = opts.get("domain") or ""
        user = opts.get("user") or ""
        password = opts.get("password") or ""
        nt_hash = opts.get("nt_hash") or ""
        method = opts.get("collection_method") or "DCOnly"
        if method not in ("Default", "DCOnly", "All"):
            method = "DCOnly"

        tmpdir = tempfile.mkdtemp(prefix="vl_bh_")
        ctx.state["collection_tmpdir"] = tmpdir
        ctx.state["collection_method"] = method

        # Prefer in-process bloodhound-python API; subprocess fallback.
        ok = await self._collect_inprocess(
            tmpdir=tmpdir, dc_ip=dc_ip, domain=domain,
            user=user, password=password, nt_hash=nt_hash, method=method,
        )
        if not ok and BLOODHOUND_CLI:
            ok = await self._collect_subprocess(
                tmpdir=tmpdir, dc_ip=dc_ip, domain=domain,
                user=user, password=password, nt_hash=nt_hash, method=method,
            )

        if not ok:
            ctx.state["collection_failed"] = True
            ctx.state["quick_probe_attempts"] = 1
            ctx.state["quick_probe_hits"] = 0
            return []

        # Parse the JSON outputs
        parsed = self._load_collection_jsons(tmpdir)
        ctx.state["_collection"] = parsed
        ctx.state["bh_user_count"] = len(parsed.get("users", []))
        ctx.state["bh_computer_count"] = len(parsed.get("computers", []))
        ctx.state["bh_group_count"] = len(parsed.get("groups", []))

        # Find Domain Admins group, compute transitive membership for count
        da_members = self._compute_domain_admins(parsed)
        ctx.state["_domain_admins"] = da_members
        ctx.state["bh_domain_admin_count"] = len(da_members)

        ctx.state["quick_probe_attempts"] = 1
        ctx.state["quick_probe_hits"] = len(parsed.get("users", []))

        # Quick probe yields NO findings - graph analysis is deep_scan
        return []

    async def _collect_inprocess(self, tmpdir, dc_ip, domain,
                                  user, password, nt_hash, method) -> bool:
        if not BLOODHOUND_AVAILABLE:
            return False

        def _run():
            try:
                # bloodhound-python public API is finicky across versions;
                # try the documented BloodHound + ADAuthentication path.
                from bloodhound import BloodHound
                from bloodhound.ad.domain import AD, ADDC
                from bloodhound.ad.authentication import ADAuthentication

                lm = ""
                nt = ""
                if nt_hash:
                    lm, nt = _split_nt_hash(nt_hash)

                auth = ADAuthentication(
                    username=user, password=password if not nt_hash else "",
                    domain=domain,
                    lm_hash=lm, nt_hash=nt,
                )
                ad = AD(
                    auth=auth, domain=domain, nameserver=dc_ip,
                    dns_tcp=False, dns_timeout=3.0,
                )
                ad.dns_resolve(domain=domain, kerberos=False)
                bh = BloodHound(ad)
                bh.connect()

                # cwd to tmpdir so JSON files land there
                prev_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    bh.run(
                        collect=[method],
                        num_workers=4,
                        disable_pooling=False,
                        timestamp="",
                        fileNamePrefix="vl",
                        computerfile=None,
                    )
                finally:
                    try: os.chdir(prev_cwd)
                    except Exception: pass
                return True
            except Exception:
                return False

        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _run),
                timeout=DEFAULT_COLLECTION_TIMEOUT,
            )
        except asyncio.TimeoutError:
            return False
        except Exception:
            return False

    async def _collect_subprocess(self, tmpdir, dc_ip, domain,
                                   user, password, nt_hash, method) -> bool:
        if not BLOODHOUND_CLI:
            return False
        cmd = [
            BLOODHOUND_CLI,
            "-u", user, "-d", domain, "-ns", dc_ip,
            "-c", method, "--zip", "false",
        ]
        if nt_hash:
            _lm, nt = _split_nt_hash(nt_hash)
            cmd += ["--hashes", f"{_lm or 'aad3b435b51404eeaad3b435b51404ee'}:{nt}"]
        elif password:
            cmd += ["-p", password]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=tmpdir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(),
                                        timeout=DEFAULT_COLLECTION_TIMEOUT)
            except asyncio.TimeoutError:
                try: proc.kill()
                except Exception: pass
                return False
            return proc.returncode == 0
        except Exception:
            return False

    def _load_collection_jsons(self, tmpdir: str) -> dict:
        """Parse the BloodHound JSON files (computers/users/groups/etc).
        Handles both top-level array form and {data:[...]} envelope."""
        out = {"domains": [], "computers": [], "users": [],
               "groups": [], "gpos": [], "ous": []}
        if not os.path.isdir(tmpdir):
            return out
        for fname in os.listdir(tmpdir):
            low = fname.lower()
            target_key = None
            for k in out.keys():
                if k in low:
                    target_key = k
                    break
            if not target_key:
                continue
            try:
                with open(os.path.join(tmpdir, fname),
                          "r", encoding="utf-8", errors="ignore") as fh:
                    raw = json.load(fh)
            except Exception:
                continue
            # BloodHound JSON envelope: {"data":[...],"meta":{...}} OR plain list
            if isinstance(raw, dict):
                items = raw.get("data") or []
            elif isinstance(raw, list):
                items = raw
            else:
                items = []
            if isinstance(items, list):
                out[target_key].extend(items)
        return out

    def _compute_domain_admins(self, parsed: dict) -> set:
        """Walk Groups to find Domain Admins + compute transitive
        member set (members of members of...). Returns set of member
        principalNames."""
        groups = parsed.get("groups", []) or []
        # Map group SID/name -> group obj
        by_sid = {}
        by_name = {}
        for g in groups:
            props = g.get("Properties") or g.get("properties") or {}
            sid = g.get("ObjectIdentifier") or g.get("objectid") or props.get("objectid") or ""
            name = (props.get("name") or g.get("Name") or "").upper()
            if sid:
                by_sid[sid] = g
            if name:
                by_name[name] = g

        # Find Domain Admins (well-known RID -512)
        da_group = None
        for sid, g in by_sid.items():
            if sid.endswith("-512"):
                da_group = g
                break
        if not da_group:
            for name, g in by_name.items():
                if "DOMAIN ADMINS" in name:
                    da_group = g
                    break
        if not da_group:
            return set()

        # BFS transitive members
        visited = set()
        queue = [da_group]
        while queue:
            g = queue.pop()
            members = (g.get("Members") or g.get("members") or [])
            for m in members:
                pid = m.get("ObjectIdentifier") or m.get("objectid") or ""
                ptype = (m.get("ObjectType") or m.get("type") or "").lower()
                if not pid:
                    continue
                if pid in visited:
                    continue
                visited.add(pid)
                if ptype == "group" and pid in by_sid:
                    queue.append(by_sid[pid])
        return visited

    # ── STAGE 4: DEEP SCAN - in-memory graph analysis ────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        if ctx.state.get("bind_failed"):
            return []
        if ctx.state.get("bloodhound_missing") or ctx.state.get("collection_failed"):
            return []

        parsed = ctx.state.get("_collection") or {}
        da_members = ctx.state.get("_domain_admins") or set()
        opts = ctx.state.get("_options") or {}
        owned_user = (opts.get("user") or "").upper()

        findings: list[dict] = []
        domain = (opts.get("domain") or "").upper()

        # Build adjacency: node -> [(target_node, edge_type)]
        graph = {}

        def _add_edge(src, dst, edge_type):
            if not src or not dst:
                return
            graph.setdefault(src, []).append((dst, edge_type))

        # Index users + computers by SID + by upn for quick lookup
        users = parsed.get("users", []) or []
        computers = parsed.get("computers", []) or []
        groups = parsed.get("groups", []) or []

        sid_to_name = {}
        for u in users:
            props = u.get("Properties") or u.get("properties") or {}
            sid = u.get("ObjectIdentifier") or u.get("objectid") or props.get("objectid") or ""
            name = (props.get("name") or u.get("Name") or "").upper()
            if sid:
                sid_to_name[sid] = name or sid
        for g in groups:
            props = g.get("Properties") or g.get("properties") or {}
            sid = g.get("ObjectIdentifier") or g.get("objectid") or props.get("objectid") or ""
            name = (props.get("name") or g.get("Name") or "").upper()
            if sid:
                sid_to_name[sid] = name or sid
        for c in computers:
            props = c.get("Properties") or c.get("properties") or {}
            sid = c.get("ObjectIdentifier") or c.get("objectid") or props.get("objectid") or ""
            name = (props.get("name") or c.get("Name") or "").upper()
            if sid:
                sid_to_name[sid] = name or sid

        # (a) Domain Admins transitive members - already computed in quick_probe
        # We'll use this set when looking for paths ending in DA.
        da_sids = set(da_members)

        # (b) Build dangerous-ACE edges: principal --(WriteDacl/...)--> DA-object
        # BloodHound JSON puts ACE rights under "Aces" on each object (target side).
        # An ACE entry: {"PrincipalSID":"<sid>","RightName":"GenericAll","IsInherited":bool}
        shadow_admin_edges = []
        for obj in users + groups + computers:
            obj_props = obj.get("Properties") or obj.get("properties") or {}
            obj_sid = obj.get("ObjectIdentifier") or obj.get("objectid") or obj_props.get("objectid") or ""
            if not obj_sid:
                continue
            # Only flag dangerous ACEs against DA-tier objects
            is_da_target = obj_sid in da_sids or obj_sid.endswith("-512")
            aces = obj.get("Aces") or obj.get("aces") or []
            for ace in aces:
                right = (ace.get("RightName") or ace.get("right") or "").strip()
                principal_sid = ace.get("PrincipalSID") or ace.get("principalsid") or ""
                if not principal_sid or not right:
                    continue
                if right in DANGEROUS_ACE_RIGHTS:
                    _add_edge(principal_sid, obj_sid, right)
                    if is_da_target and principal_sid not in da_sids:
                        shadow_admin_edges.append((principal_sid, obj_sid, right))

        # (c) Group MemberOf edges - users/groups -> groups they belong to
        for g in groups:
            g_props = g.get("Properties") or g.get("properties") or {}
            g_sid = g.get("ObjectIdentifier") or g.get("objectid") or g_props.get("objectid") or ""
            members = g.get("Members") or g.get("members") or []
            for m in members:
                m_sid = m.get("ObjectIdentifier") or m.get("objectid") or ""
                if m_sid and g_sid:
                    _add_edge(m_sid, g_sid, "MemberOf")

        # (d) Kerberoastable DAs (HasSPN=true AND in DA)
        kerb_da = []
        asrep_da = []
        for u in users:
            props = u.get("Properties") or u.get("properties") or {}
            u_sid = u.get("ObjectIdentifier") or u.get("objectid") or props.get("objectid") or ""
            name = (props.get("name") or u.get("Name") or "").upper()
            has_spn = bool(props.get("hasspn") or props.get("HasSPN"))
            dont_req_preauth = bool(
                props.get("dontreqpreauth") or props.get("DontRequirePreAuth")
            )
            in_da = u_sid in da_sids
            if has_spn and in_da:
                kerb_da.append({"sid": u_sid, "name": name})
            if dont_req_preauth and in_da:
                asrep_da.append({"sid": u_sid, "name": name})

        # (e) Unconstrained delegation computers
        unconstrained = []
        for c in computers:
            props = c.get("Properties") or c.get("properties") or {}
            c_sid = c.get("ObjectIdentifier") or c.get("objectid") or props.get("objectid") or ""
            name = (props.get("name") or c.get("Name") or "").upper()
            uncon = bool(props.get("unconstraineddelegation")
                         or props.get("UnconstrainedDelegation")
                         or props.get("TrustedForDelegation"))
            if uncon:
                unconstrained.append({"sid": c_sid, "name": name})

        # Emit kerberoastable DA findings
        for k in kerb_da:
            if len(findings) >= HARD_MAX_PATHS:
                break
            findings.append({
                "id": f"krb_{k['sid'][-6:]}",
                "kind": "ad_attack_path",
                "path_type": "kerberoastable_da",
                "source_node": k["name"],
                "target_node": "DOMAIN ADMINS",
                "path_length": 1,
                "edges": ["HasSPN"],
                "discovery_method": "bloodhound_graph_analysis",
                "_target_sid": k["sid"],
            })

        # Emit AS-REP roastable DA findings
        for a in asrep_da:
            if len(findings) >= HARD_MAX_PATHS:
                break
            findings.append({
                "id": f"asrep_{a['sid'][-6:]}",
                "kind": "ad_attack_path",
                "path_type": "asreproastable_da",
                "source_node": a["name"],
                "target_node": "DOMAIN ADMINS",
                "path_length": 1,
                "edges": ["DontRequirePreAuth"],
                "discovery_method": "bloodhound_graph_analysis",
                "_target_sid": a["sid"],
            })

        # Emit shadow-admin (ACL abuse) findings
        for src_sid, tgt_sid, right in shadow_admin_edges:
            if len(findings) >= HARD_MAX_PATHS:
                break
            findings.append({
                "id": f"acl_{src_sid[-6:]}_{right[:6]}",
                "kind": "ad_attack_path",
                "path_type": "shadow_admin_path",
                "source_node": sid_to_name.get(src_sid, src_sid),
                "target_node": sid_to_name.get(tgt_sid, tgt_sid),
                "path_length": 1,
                "edges": [right],
                "discovery_method": "bloodhound_graph_analysis",
                "_source_sid": src_sid,
                "_target_sid": tgt_sid,
            })

        # Emit unconstrained delegation findings
        for u in unconstrained:
            if len(findings) >= HARD_MAX_PATHS:
                break
            findings.append({
                "id": f"unconstrained_{u['sid'][-6:]}",
                "kind": "ad_attack_path",
                "path_type": "krbtgt_compromise_path",
                "source_node": u["name"],
                "target_node": "krbtgt",
                "path_length": 1,
                "edges": ["TrustedForDelegation"],
                "discovery_method": "bloodhound_graph_analysis",
                "_target_sid": u["sid"],
            })

        # (f) BFS from owned_user to any DA member
        # Find the owned user's SID by name lookup
        owned_sid = None
        owned_lookup = owned_user
        if "@" not in owned_lookup and domain:
            owned_lookup = f"{owned_user}@{domain}"
        for sid, name in sid_to_name.items():
            if name == owned_lookup or name.startswith(owned_user + "@"):
                owned_sid = sid
                break

        if owned_sid and da_sids and len(findings) < HARD_MAX_PATHS:
            path = self._bfs_shortest_path(graph, owned_sid, da_sids, max_depth=6)
            if path:
                edge_types = [e for (_, e) in path[1:]]
                node_chain = [sid_to_name.get(s, s) for (s, _) in path]
                findings.append({
                    "id": f"da_path_{owned_sid[-6:]}",
                    "kind": "ad_attack_path",
                    "path_type": "domain_admin_path",
                    "source_node": node_chain[0],
                    "target_node": node_chain[-1],
                    "path_length": len(path) - 1,
                    "edges": edge_types,
                    "node_chain": node_chain,
                    "discovery_method": "bloodhound_graph_analysis",
                    "_source_sid": owned_sid,
                    "_target_sid": path[-1][0],
                })

        ctx.state["ad_attack_paths_count"] = len(findings)
        return findings[:HARD_MAX_PATHS]

    def _bfs_shortest_path(self, graph, start_sid, target_sid_set, max_depth=6):
        """BFS shortest path from start to ANY sid in target set.
        Returns list of (sid, edge_type_from_prev) or None.
        graph: {src_sid: [(dst_sid, edge_type), ...]}"""
        if not start_sid:
            return None
        from collections import deque
        # Each queue entry: (current_sid, path_so_far)
        q = deque()
        q.append((start_sid, [(start_sid, "")]))
        visited = {start_sid}
        while q:
            cur, path = q.popleft()
            if len(path) - 1 > max_depth:
                continue
            if cur in target_sid_set and len(path) > 1:
                return path
            for (dst, edge) in graph.get(cur, []):
                if dst in visited:
                    continue
                visited.add(dst)
                new_path = path + [(dst, edge)]
                if dst in target_sid_set:
                    return new_path
                if len(new_path) - 1 < max_depth:
                    q.append((dst, new_path))
        return None

    # ── STAGE 5: VERIFY (re-query LDAP for edge re-validation) ───
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        if not LDAP3_AVAILABLE or ctx.state.get("bind_failed"):
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "ldap3_unavailable_or_bind_failed"
            return finding

        opts = ctx.state.get("_options") or {}
        dc_ip = opts.get("dc_ip") or ""
        domain = opts.get("domain") or ""
        user = opts.get("user") or ""
        password = opts.get("password") or ""
        nt_hash = opts.get("nt_hash") or ""

        # Identify the edge to re-validate
        edges = finding.get("edges") or []
        first_edge = edges[0] if edges else ""

        def _revalidate():
            try:
                server = _ldap3.Server(dc_ip, get_info=_ldap3.NONE, connect_timeout=5)
                if nt_hash:
                    _lm, nt = _split_nt_hash(nt_hash)
                    ntlm_user = f"{domain}\\{user}" if "\\" not in user else user
                    ntlm_pwd = f"{_lm or 'aad3b435b51404eeaad3b435b51404ee'}:{nt}"
                    conn = _ldap3.Connection(
                        server, user=ntlm_user, password=ntlm_pwd,
                        authentication=_ldap3.NTLM, auto_bind=True,
                        receive_timeout=8,
                    )
                else:
                    bind_user = f"{user}@{domain}" if "@" not in user else user
                    conn = _ldap3.Connection(
                        server, user=bind_user, password=password,
                        auto_bind=True, receive_timeout=8,
                    )
                # Build search base from domain
                base_dn = ",".join(f"DC={part}" for part in domain.split(".") if part)
                source = (finding.get("source_node") or "").split("@")[0]
                if not source or not base_dn:
                    try: conn.unbind()
                    except Exception: pass
                    return False
                # Edge-specific quick LDAP probe
                if first_edge == "HasSPN":
                    flt = f"(&(sAMAccountName={_escape_ldap(source)})(servicePrincipalName=*))"
                elif first_edge == "DontRequirePreAuth":
                    # UAC bit 0x400000 (DONT_REQUIRE_PREAUTH)
                    flt = f"(&(sAMAccountName={_escape_ldap(source)})(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
                elif first_edge == "TrustedForDelegation":
                    cn = source.split(".")[0].rstrip("$")
                    flt = f"(&(sAMAccountName={_escape_ldap(cn)}$)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
                elif first_edge == "MemberOf":
                    flt = f"(sAMAccountName={_escape_ldap(source)})"
                else:
                    # Generic ACL right - just confirm source object still exists
                    flt = f"(sAMAccountName={_escape_ldap(source)})"
                conn.search(base_dn, flt, attributes=["sAMAccountName"])
                hit = bool(conn.entries)
                try: conn.unbind()
                except Exception: pass
                return hit
            except Exception:
                return False

        loop = asyncio.get_event_loop()
        try:
            verified = await asyncio.wait_for(
                loop.run_in_executor(None, _revalidate), timeout=10
            )
        except asyncio.TimeoutError:
            verified = False
        except Exception:
            verified = False

        if verified:
            finding["confidence"] = "CONFIRMED"
        else:
            finding["confidence"] = "SUSPECTED"
        finding["verification_method"] = "ldap_edge_revalidation"
        # Redact any sensitive markers
        for k in list(finding.keys()):
            if "hash" in k.lower() or "pwd" in k.lower() or "password" in k.lower():
                finding[k] = _redact(str(finding[k]))
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        pt = finding.get("path_type") or ""
        if pt == "domain_admin_path":
            finding["privilege_level"] = "domain_admin_reachable"
        elif pt == "krbtgt_compromise_path":
            finding["privilege_level"] = "krbtgt_compromise_path"
        elif pt == "kerberoastable_da":
            finding["privilege_level"] = "da_via_kerberoast"
        elif pt == "asreproastable_da":
            finding["privilege_level"] = "da_via_asreproast"
        elif pt == "shadow_admin_path":
            finding["privilege_level"] = "da_via_acl_abuse"
        else:
            finding["privilege_level"] = "unknown"
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        next_scanners: list[str] = []
        seen: set[str] = set()
        opts = ctx.state.get("_options") or {}
        have_creds = bool(opts.get("password") or opts.get("nt_hash"))

        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            priv = f.get("privilege_level") or ""
            chain_for_this: list[str] = []
            if priv == "da_via_kerberoast":
                chain_for_this = ["kerberoast_audit"]
            elif priv == "da_via_asreproast":
                chain_for_this = ["asreproast_audit"]
            elif priv == "domain_admin_reachable" and have_creds:
                chain_for_this = ["dcsync_audit"]
            elif priv == "krbtgt_compromise_path":
                chain_for_this = ["dcsync_audit"]

            if chain_for_this:
                f["chain_next"] = chain_for_this
                for s in chain_for_this:
                    if s not in seen:
                        seen.add(s)
                        next_scanners.append(s)
        return next_scanners


def _escape_ldap(s: str) -> str:
    """Minimal LDAP filter escape per RFC 4515."""
    if not s:
        return ""
    out = []
    for c in s:
        if c == "\\":
            out.append("\\5c")
        elif c == "*":
            out.append("\\2a")
        elif c == "(":
            out.append("\\28")
        elif c == ")":
            out.append("\\29")
        elif c == "\x00":
            out.append("\\00")
        else:
            out.append(c)
    return "".join(out)


# ═══════════════════════════════════════════════════════════════════
#  Endpoint wrapper
# ═══════════════════════════════════════════════════════════════════


@router.post("/api/password/bloodhound_audit")
async def password_bloodhound_audit(req: BloodhoundAuditRequest,
                                     _=Depends(verify_scan_quota)):
    scanner = BloodhoundAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=BLOODHOUND_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)


# ═══════════════════════════════════════════════════════════════════
#  Chain registry registration
# ═══════════════════════════════════════════════════════════════════


async def _chain_callable(target: str, options: dict, jwt=None) -> dict:
    opts = options or {}
    if not opts.get("user") and (opts.get("chain_creds") or []):
        cred = opts["chain_creds"][0]
        opts["user"] = cred.get("user", "")
        opts["password"] = cred.get("pwd", "")
    if not opts.get("dc_ip"):
        opts["dc_ip"] = target
    req = BloodhoundAuditRequest(target=target, options=opts)
    scanner = BloodhoundAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=BLOODHOUND_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


from tools._methodology import chain_registry
chain_registry.register("bloodhound_audit", _chain_callable)
