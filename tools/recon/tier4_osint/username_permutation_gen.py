"""Username Permutation Generator — Route: /api/recon/username_permutation_gen
Generates likely employee usernames from target domain + usernames_top.txt
+ username_permutations.txt. Pure intel — feeds sherlock/holehe downstream.
NO active probing — safe for any target.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()
_BASE = Path(__file__).resolve().parent.parent.parent / "_payloads" / "recon"
_USERS = _BASE / "usernames_top.txt"
_RULES = _BASE / "username_permutations.txt"

_FALLBACK_USERS = ["admin","root","test","info","contact","support","hello",
                   "webmaster","postmaster","sales","hr","ceo"]
_FALLBACK_RULES = ["{first}","{first}.{last}","{f}{last}","{first}{last}",
                   "{first}_{last}","{last}.{first}","{f}.{last}"]
_SAMPLE_NAMES = [("john","doe"),("jane","smith"),("alex","kumar"),
                 ("priya","sharma"),("david","chen")]

def _load(p, fb):
    try:
        if p.exists():
            return [l.strip() for l in p.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")]
    except Exception: pass
    return fb

async def gather(ctx: ScanContext):
    domain = ctx.host
    org = (domain or "").split(".")[0]
    common = _load(_USERS, _FALLBACK_USERS)
    rules = _load(_RULES, _FALLBACK_RULES)
    ctx.state["common_count"] = len(common)
    ctx.state["rules_count"] = len(rules)
    ctx.source(f"wordlists ({len(common)} users + {len(rules)} rules)")
    candidates = set()
    # Common usernames + org-derived prefixes
    for u in common: candidates.add(u)
    if org: candidates.add(org)
    # Apply permutation rules with sample names
    for rule in rules:
        for first, last in _SAMPLE_NAMES:
            u = rule.replace("{first}", first).replace("{last}", last) \
                    .replace("{f}", first[0]).replace("{l}", last[0]) \
                    .replace("{org}", org or "")
            if u and "{" not in u: candidates.add(u.lower())
    cands = sorted(candidates)
    ctx.state["candidates"] = cands
    ctx.state["candidates_count"] = len(cands)
    if cands: ctx.source(f"generated ({len(cands)})")

def r_generated(s):
    c = s.get("candidates") or []
    if not c: return None
    return {"name": f"Username candidates generated for OSINT ({len(c)})",
            "severity": "INFO",
            "evidence": f"Sample: {', '.join(c[:10])}",
            "remediation": "Feed candidates into sherlock_username / holehe / hibp_breach_check for confirmation. If your company uses predictable usernames, train staff on phishing surface."}

def r_no_org(s):
    if s.get("candidates"): return None
    return {"name":"No candidates generated","severity":"INFO",
            "evidence":"Wordlists empty or domain invalid"}

FINDING_RULES = [r_generated, r_no_org]
INTEL_FIELDS = [("Common usernames loaded","common_count"),
                ("Permutation rules loaded","rules_count"),
                ("Total candidates","candidates_count")]

@router.post("/api/recon/username_permutation_gen")
async def recon_username_permutation_gen(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="username_permutation_gen",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["candidates","candidates_count"])

def register(app): app.include_router(router)
