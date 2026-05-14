"""Free Shodan InternetDB Lookup — pure-Python, NO API KEY required.

Pattern: TEMPLATE for OSINT tools that wrap a free public API.
Returns either real findings or an honest skipped_reason — never a
silent skip.
"""
from fastapi import APIRouter, Depends
import dns.resolver as _dns_resolver
import asyncio

from tools._shared import (
    ScanRequest, verify_token, safe_get,
    recon_host, wrap_finding, standard_response,
)

router = APIRouter()


@router.post("/api/osint/internetdb")
async def osint_internetdb(req: ScanRequest, user=Depends(verify_token)):
    host = recon_host(req.target)
    findings = []
    data = {}

    # Resolve to IP (InternetDB takes IPs, not hostnames)
    try:
        loop = asyncio.get_event_loop()
        def _resolve():
            try:
                ans = _dns_resolver.resolve(host, "A")
                return str(ans[0]) if ans else None
            except Exception:
                return None
        ip = await loop.run_in_executor(None, _resolve)
        if not ip:
            return standard_response(
                tool="internetdb", target=req.target, findings=[],
                tests_performed=1,
                tests_summary=f"Could not resolve {host} to an IPv4 address",
                skipped_reason=f"DNS resolution failed for {host}",
            )

        r = safe_get(f"https://internetdb.shodan.io/{ip}",
                     retries=2, timeout=12, req=req)
        if r is None:
            return standard_response(
                tool="internetdb", target=req.target, findings=[],
                tests_performed=1, tests_summary="InternetDB API request failed",
                skipped_reason="internetdb.shodan.io unreachable",
            )
        if r.status_code == 404:
            return standard_response(
                tool="internetdb", target=req.target, findings=[],
                tests_performed=1,
                tests_summary=f"InternetDB has no record for {ip}",
                skipped_reason=f"Shodan has no record for {ip} — IP is not "
                               f"internet-exposed or hasn't been scanned",
                raw_data={"ip": ip},
            )
        if r.status_code != 200:
            return standard_response(
                tool="internetdb", target=req.target, findings=[],
                tests_performed=1, tests_summary="InternetDB returned non-200",
                skipped_reason=f"internetdb HTTP {r.status_code}",
            )

        data = r.json()
        # Each known CVE becomes a finding
        for cve in data.get("vulns", [])[:50]:
            findings.append(wrap_finding(
                f"Shodan/InternetDB reports {cve} affecting {ip} "
                f"(port banner matched a vulnerable CPE)",
                "HIGH", cvss="7.5", cve=cve, cwe="CWE-1395",
                cwe_name="Vulnerable Component (Shodan)", owasp="A06:2021",
                remediation=f"Check NVD: https://nvd.nist.gov/vuln/detail/{cve} — "
                            f"verify the service version then patch or upgrade.",
                evidence_marker=f"InternetDB CVE list for {ip}: {cve}",
            ))
    except Exception as e:
        return standard_response(
            tool="internetdb", target=req.target, findings=[],
            tests_performed=1, tests_summary="InternetDB lookup errored",
            skipped_reason=f"Error: {e}",
        )

    return standard_response(
        tool="internetdb", target=req.target, findings=findings,
        tests_performed=1,
        tests_summary=f"1 InternetDB lookup for {data.get('ip', host)} — "
                      f"free API, no key required",
        raw_data={
            "ip":        data.get("ip"),
            "ports":     data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "vulns":     data.get("vulns", []),
            "tags":      data.get("tags", []),
            "cpes":      data.get("cpes", []),
            "found":     bool(data),
        },
    )


def register(app):
    app.include_router(router)
