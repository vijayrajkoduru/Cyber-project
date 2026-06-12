"""ldap_signing_check - LDAP signing / LDAPS availability probe (playbook §2 #23).

Real, credential-less probe of the DC's LDAP surface:
  - is cleartext LDAP (389) reachable?
  - is LDAPS (636, TLS) available?
A DC offering only cleartext LDAP is a concrete relay/downgrade surface.

ZERO-FP: the only graded (LOW) finding fires when we ACTUALLY observe 389 open
+ 636 closed on the live target. Whether the DC *requires* LDAP signing / channel
binding cannot be proven without a valid account (an unsigned authenticated bind),
so that determination is emitted as INFO advisory — never a graded false positive.

VA-not-PT: no creds are sent, no relay is performed. Detection only.
Customer input: ScanRequest.target = DC IP/hostname. No creds needed.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.ad_ldap_signing_check_findings import AD_LDAP_SIGNING_CHECK_FINDING_RULES

router = APIRouter()


def _port_open(host: str, port: int, timeout: float = 6.0) -> bool:
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["ad_ldap_signing_check_total"] = 0
        ctx.source("no-target")
        return
    host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]

    # TCP reachability (facts, no creds).
    p389 = _port_open(host, 389)
    p636 = _port_open(host, 636)

    if not p389 and not p636:
        ctx.state["ad_ldap_signing_check_total"] = 0
        ctx.state["ad_ldap_unreachable"] = True
        ctx.source("389 + 636 closed/unreachable")
        return

    anon_result = "not attempted"
    # A harmless anonymous bind to confirm an LDAP service actually speaks LDAP
    # on 389 (distinguishes a real DC from an unrelated open port).
    if p389:
        try:
            import ldap3
            server = ldap3.Server(host, port=389, get_info=ldap3.NONE, connect_timeout=6)
            conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS,
                                    auto_bind=True, receive_timeout=6)
            anon_result = "anonymous bind accepted"
            try: conn.unbind()
            except Exception: pass
        except ImportError:
            anon_result = "ldap3 missing"
        except Exception as e:
            anon_result = f"anonymous bind rejected ({type(e).__name__})"

    cleartext_only = bool(p389 and not p636)

    ctx.state["ad_ldap_probed"] = True
    ctx.state["ad_ldap_389_open"] = p389
    ctx.state["ad_ldaps_available"] = p636
    ctx.state["ad_ldap_cleartext_only"] = cleartext_only
    ctx.state["ad_ldap_anon_result"] = anon_result
    # total = graded conditions actually detected (cleartext-only downgrade).
    ctx.state["ad_ldap_signing_check_total"] = 1 if cleartext_only else 0
    ctx.source(f"LDAP 389={p389} LDAPS 636={p636}; anon={anon_result}")


INTEL_FIELDS = [("LDAP (389) open", "ad_ldap_389_open"),
                ("LDAPS (636) available", "ad_ldaps_available"),
                ("Cleartext-only", "ad_ldap_cleartext_only"),
                ("Anonymous bind", "ad_ldap_anon_result")]


@router.post("/api/ad/ldap_signing_check")
async def ad_ldap_signing_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="ldap_signing_check",
        gather_func=gather, finding_rules=AD_LDAP_SIGNING_CHECK_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
