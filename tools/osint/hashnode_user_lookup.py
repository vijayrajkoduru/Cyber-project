"""Hashnode user lookup via public GraphQL — playbook §3.

Hashnode (dev-blogging platform) exposes a public GraphQL endpoint.
Query a user's public profile by username — returns name, bio, followers,
publications, social links. No auth required for read.

Real probe. Zero false positives.
"""
import asyncio
import json
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_post, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 10

QUERY = """
query U($u: String!) {
  user(username: $u) {
    name username tagline bio { text } location followersCount followingCount
    socialMediaLinks { website github twitter linkedin }
    publications(first: 5) { edges { node { title url } } }
  }
}
""".strip()


def _do_scan(req: ScanRequest) -> dict:
    user = (req.target or "").strip().lstrip("@").lower()
    if not re.match(r"^[a-z0-9_-]{1,30}$", user):
        return standard_response(
            tool="hashnode_user_lookup", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid Hashnode handle")

    r = safe_post("https://gql.hashnode.com/", req=req, timeout=8,
                   data=json.dumps({"query": QUERY, "variables": {"u": user}}),
                   headers={"User-Agent": "VulnusLab-OSINT/1.0",
                             "Content-Type": "application/json"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="hashnode_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Hashnode GQL status {r.status_code if r else 'no-conn'}")

    try:
        u = r.json().get("data", {}).get("user")
    except Exception:
        return standard_response(
            tool="hashnode_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON response")

    if not u:
        return standard_response(
            tool="hashnode_user_lookup", target=req.target,
            findings=[wrap_finding(
                f"Hashnode user '{user}' not found",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No public footprint.",
                evidence_marker="GraphQL data.user=null (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not found")

    sm = u.get("socialMediaLinks") or {}
    pubs = [e["node"]["title"][:40] for e in u.get("publications", {}).get("edges", [])][:5]

    findings = [wrap_finding(
        f"Hashnode — {u.get('name') or user}",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public dev-blog profile. Cross-platform links + publication "
                    "topics reveal technical focus + employer signals.",
        evidence_marker=(
            f"name={u.get('name','?')} | "
            f"location={u.get('location','—')} | "
            f"github={sm.get('github','—')} | "
            f"twitter={sm.get('twitter','—')} | "
            f"linkedin={sm.get('linkedin','—')} | "
            f"website={sm.get('website','—')} | "
            f"followers={u.get('followersCount',0)} | "
            f"recent_pubs={pubs}"
        ))]

    return standard_response(
        tool="hashnode_user_lookup", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"hashnode: {u.get('username','?')}",
        raw_data=u)


@router.post("/api/osint/hashnode_user_lookup")
async def scan_hashnode_user_lookup(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="hashnode_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
