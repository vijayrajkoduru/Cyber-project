"""Shared org-scoping helpers for the VL-FLOW routers (Phase 2.1 Step 3 + hardening).

Single source of truth so endpoints/recon_flow.py and endpoints/recon_flow_advanced.py
use one membership-verifying implementation and cannot drift apart.
"""


def caller_org(payload):
    """Resolve the caller's CURRENT org from the DB, verifying live membership in
    the org their JWT claims. A demoted / removed / moved user can no longer scope
    to an org they have left (closes the stale-claim isolation gap). Falls back to
    the user's default org, then to the raw claim only if the RBAC layer is
    unavailable (so a DB outage degrades gracefully instead of breaking scans)."""
    if not isinstance(payload, dict):
        return None
    sub = payload.get("sub")
    claimed = payload.get("org_id")
    if not sub:
        return claimed
    try:
        from tools.auth._orgs import get_user_org_role
        if claimed:
            oid, _ = get_user_org_role(sub, claimed)   # member of claimed org?
            if oid:
                return oid
        oid, _ = get_user_org_role(sub)                # else their default org
        return oid
    except Exception:
        return claimed   # RBAC unavailable -> don't hard-fail the request


def org_can_see(rec, oid):
    """A record is visible if it belongs to the caller's org, or it predates org
    tagging (legacy record with no org_id -> grandfathered)."""
    rec_oid = (rec or {}).get("org_id")
    return (not rec_oid) or (oid is not None and rec_oid == oid)
