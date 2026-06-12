"""offensive_advisory - honest advisory-by-design coverage for AD techniques
that cannot be safely live-probed from an external SaaS scanner.

VulnusLab is VA, not PT. The AD playbook (module_playbooks/19_ad.md) contains
many techniques that require domain credentials, a post-compromise foothold,
on-host execution, LAN adjacency, active exploitation, or destructive actions.
Rather than fabricate findings or scaffold them as fake CRITICALs, this scanner
emits one honest INFO per technique group with an [ADVISORY-BY-DESIGN] marker
and vulnerable:false, so the report transparently shows the full attack surface
catalogue and the corresponding hardening, while the live-probe scanners in this
module do the real detection.

It performs NO network I/O and NEVER emits a graded (CRITICAL/HIGH/MEDIUM/LOW)
severity — every finding is INFO by construction.

Customer input: ScanRequest.target (only used to label the report).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.ad_offensive_advisory_findings import build_rules

router = APIRouter()


# Each entry = one advisory technique GROUP from the playbook that is
# advisory-by-design (cannot be honestly auto-probed from external SaaS).
ADVISORY_CATALOGUE = [
    {"title": "BloodHound / SharpHound graph collection (§1) — needs domain creds",
     "cwe": "CWE-200",
     "reason": "Collecting the AD graph (ACLs, sessions, GPOs) requires an authenticated "
               "LDAP/SMB context.",
     "remediation": "Run BloodHound CE / SharpHound / SOAPHound from inside the domain with a "
                    "low-priv account, then review shortest paths to Tier-0 and prune dangerous "
                    "ACL edges (GenericAll/WriteDACL/WriteOwner)."},

    {"title": "NTLM relay & coercion chains — PetitPotam/PrinterBug/DFSCoerce/Coercer (§8) "
              "— LAN adjacency + active relay",
     "cwe": "CWE-294",
     "reason": "Coercion + ntlmrelayx require a listener on the LAN and active relaying of "
               "victim authentication; this is exploitation, not detection.",
     "remediation": "Enforce SMB signing + LDAP signing/channel binding (the smb_signing_check, "
                    "ldap_signing_check and adcs_web_enrollment probes in THIS module detect those "
                    "relay surfaces), patch MS-EFSRPC/MS-RPRN/MS-DFSNM, and remove WebClient where "
                    "unneeded."},

    {"title": "LLMNR/NBT-NS/mDNS poisoning + IPv6 mitm6 (§2) — broadcast/multicast adjacency",
     "cwe": "CWE-300",
     "reason": "Responder/Inveigh/mitm6 operate by answering broadcast/multicast/IPv6 traffic on "
               "the local segment; no external scanner can reach that layer.",
     "remediation": "Disable LLMNR + NBT-NS via GPO, enable DHCPv6 guard / RA guard, and deploy "
                    "name-resolution monitoring."},

    {"title": "Credential dumping — LSASS/SAM/NTDS/DCSync (§2) — requires admin foothold",
     "cwe": "CWE-522",
     "reason": "Mimikatz/secretsdump/DCSync run AFTER privileged compromise; reading NTDS.dit or "
               "replicating with DRSUAPI needs DA-equivalent rights.",
     "remediation": "Enable Credential Guard / RunAsPPL, restrict DCSync rights (audit "
                    "Replicating Directory Changes), tier admin accounts, and alert on event 4662 "
                    "DRSUAPI from non-DCs."},

    {"title": "Kerberoasting hash retrieval + cracking (§3) — needs a valid account",
     "cwe": "CWE-294",
     "reason": "Requesting service TGS hashes (GetUserSPNs) requires any authenticated domain "
               "user; cracking is offline. THIS module detects AS-REP roastable accounts "
               "(asrep_roast) which is reachable without creds.",
     "remediation": "Use 25+ char (g)MSA / managed service-account passwords, prefer AES, and "
                    "monitor event 4769 for RC4 TGS bursts."},

    {"title": "Lateral movement — PtH / PtT / PsExec / WMIExec / WinRM (§4) — post-compromise",
     "cwe": "CWE-294",
     "reason": "Pass-the-Hash/Ticket and remote-exec tooling all require an already-stolen "
               "credential or ticket.",
     "remediation": "Enforce LAPS for local admin passwords, deny lateral admin logons (Tiering + "
                    "Authentication Policy Silos), and enable SMB signing + Protected Users group."},

    {"title": "Privilege escalation — ACL/Shadow-Credentials/GPO/RBCD/Delegation abuse (§5/§7) "
              "— needs write rights in the domain",
     "cwe": "CWE-269",
     "reason": "GenericAll, msDS-KeyCredentialLink, GPO writes, and RBCD all require an existing "
               "authenticated principal with write access to the target object.",
     "remediation": "Audit and prune dangerous ACLs, restrict who can join machines "
                    "(MachineAccountQuota=0), remove unconstrained delegation from non-DCs, and "
                    "lock down GPO edit rights."},

    {"title": "AD CS ESC1-ESC15 exploitation (§6) — credentialed enumeration + enrollment",
     "cwe": "CWE-295",
     "reason": "Confirming an enrollable vulnerable template and requesting a forged-SAN "
               "certificate requires domain credentials. THIS module's certipy_find (with creds) "
               "and adcs_web_enrollment (ESC8 HTTP surface, no creds) cover the detectable parts.",
     "remediation": "Set template Subject Name to 'Build from AD info', remove low-priv enroll "
                    "ACLs, set EDITF_ATTRIBUTESUBJECTALTNAME2=0, and enforce EPA on web enrollment."},

    {"title": "Persistence — Golden/Silver/Diamond tickets, DSRM, AdminSDHolder, SID history (§9) "
              "— post-DA forging",
     "cwe": "CWE-284",
     "reason": "All ticket-forging and directory-backdoor persistence requires the krbtgt hash or "
               "DA rights already in hand.",
     "remediation": "Rotate krbtgt twice on compromise, monitor AdminSDHolder ACL changes, restrict "
                    "DSRM logon, and alert on golden/diamond-ticket indicators (PAC anomalies)."},

    {"title": "Defense evasion — AMSI/ETW/LSASS-protection bypass (§10) — on-host code execution",
     "cwe": "CWE-693",
     "reason": "These are in-memory patches on a compromised host; there is no external network "
               "surface to probe.",
     "remediation": "Enable RunAsPPL, ASR rules, and tamper-protected EDR; treat any bypass "
                    "attempt as an active intrusion."},

    {"title": "Zerologon (CVE-2020-1472) & noPac (CVE-2021-42278/42287) (§11) — destructive / "
              "active exploitation",
     "cwe": "CWE-330",
     "reason": "A safe Zerologon check still mutates the DC machine-account password (it can "
               "break the DC), and noPac actively renames a machine account — both cross the "
               "VA->PT line and are intentionally NOT auto-run.",
     "remediation": "Ensure DCs have the August-2020+ (Zerologon) and Nov-2021 (noPac) cumulative "
                    "updates and enforce Netlogon secure-channel signing; verify patch level with "
                    "credentialed scanning rather than live exploitation."},
]


async def gather(ctx: ScanContext):
    # No network I/O. Just signal the advisory rules to render.
    ctx.state["ad_advisory_emit"] = True
    ctx.state["ad_advisory_catalogue"] = ADVISORY_CATALOGUE
    ctx.state["ad_advisory_count"] = len(ADVISORY_CATALOGUE)
    # total is for tile counting; advisories are INFO so they are not "vulns".
    ctx.state["offensive_advisory_total"] = 0
    ctx.source("advisory-by-design catalogue")


INTEL_FIELDS = [("Advisory technique groups", "ad_advisory_count")]

_RULES = build_rules(ADVISORY_CATALOGUE)


@router.post("/api/ad/offensive_advisory")
async def ad_offensive_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="offensive_advisory",
        gather_func=gather, finding_rules=_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
