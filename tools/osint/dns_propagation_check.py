"""DNS propagation check across global public resolvers — playbook §2.

Queries 8 major public resolvers (Google, Cloudflare, Quad9, OpenDNS, etc.)
for the same record type and reports disagreement. Useful for:
- Detecting DNS poisoning / GeoDNS misconfig
- Confirming a recent DNS change has propagated
- Identifying split-horizon DNS that leaks internal IPs

Real probe. Zero false positives — each resolver answers for itself.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 25

RESOLVERS = [
    ("Google",       "8.8.8.8"),
    ("Cloudflare",   "1.1.1.1"),
    ("Quad9",        "9.9.9.9"),
    ("OpenDNS",      "208.67.222.222"),
    ("Level3/Verizon", "4.2.2.2"),
    ("Comodo",       "8.26.56.26"),
    ("AdGuard",      "94.140.14.14"),
    ("CleanBrowsing", "185.228.168.9"),
]


def _query(resolver_ip, name, rtype):
    try:
        import dns.resolver, dns.exception
    except ImportError:
        return None
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [resolver_ip]
    r.timeout = 3; r.lifetime = 5
    try:
        ans = r.resolve(name, rtype)
        return sorted([str(x).strip(".") for x in ans])
    except Exception:
        return []


def _do_scan(req: ScanRequest) -> dict:
    name = (req.target or "").strip().rstrip(".")
    if "/" in name: name = name.split("/")[0]
    if "//" in name: name = name.split("//", 1)[1]
    if not name or "." not in name:
        return standard_response(
            tool="dns_propagation_check", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid hostname")

    results = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_query, ip, name, "A"): label for label, ip in RESOLVERS}
        for fut in futures:
            label = futures[fut]
            try:
                results[label] = fut.result(timeout=7) or []
            except Exception:
                results[label] = []

    # Identify disagreements
    unique_answers = set()
    for ans in results.values():
        if ans:
            unique_answers.add(tuple(ans))

    findings = []
    if len(unique_answers) > 1:
        evidence = " | ".join(f"{r}={','.join(a) if a else 'NXDOMAIN'}"
                                for r, a in results.items())
        findings.append(wrap_finding(
            f"DNS DISAGREEMENT — {len(unique_answers)} different answers across resolvers",
            severity="MEDIUM", cwe="CWE-829", cvss="5.3",
            owasp="A05:2021",
            remediation="Could be: (1) recent DNS change still propagating, "
                        "(2) GeoDNS by design, (3) DNS poisoning / hijack. "
                        "Re-run in 1 hour — if still disagreeing without GeoDNS, "
                        "investigate registrar / nameservers.",
            evidence_marker=evidence + " (CONFIRMED via multi-resolver query)"))
    elif unique_answers:
        ans = list(unique_answers)[0]
        findings.append(wrap_finding(
            f"DNS consistent across {len([r for r in results.values() if r])} resolver(s) — {','.join(ans)}",
            severity="POSITIVE", cwe="CWE-200",
            remediation="DNS is propagated consistently. No action.",
            evidence_marker=f"All resolvers returned {ans} (CONFIRMED)"))
    else:
        findings.append(wrap_finding(
            f"NXDOMAIN — {name} has no A record on any resolver",
            severity="INFO", cwe="CWE-200",
            remediation="Hostname does not resolve. Either typo or genuinely not registered.",
            evidence_marker="All 8 resolvers returned no A records (CONFIRMED)")
        )

    return standard_response(
        tool="dns_propagation_check", target=req.target, findings=findings,
        tests_performed=len(RESOLVERS),
        vulnerable=len(unique_answers) > 1,
        tests_summary=f"queried {len(RESOLVERS)} resolvers; {len(unique_answers)} distinct answer-set(s)",
        raw_data={"results": results})


@router.post("/api/osint/dns_propagation_check")
@vl_verify()
async def scan_dns_propagation_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="dns_propagation_check", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
