"""VulnusLab Scanner Framework — turn the 34 remaining Recon tools into
fill-in-the-blanks exercises.

After building WHOIS Intelligence v2 from scratch (~500 lines), the
reusable pieces lived in four buckets:

  1. Multi-source async data gathering        → gathering.py
  2. Text/regex parsers reused across tools   → parsers.py
  3. Findings rules engine + helpers          → findings.py
  4. Standard orchestrator + response builder → scanner.py

Public API (what tool authors import):

    from tools._framework import (
        ScanContext, run_scanner,
        cli_run, whois_cli, team_cymru_asn,
        http_json_async, dns_resolve, dns_resolve_many,
        grab, grab_all, parse_iso_date, days_between,
        run_rules,
    )

Typical tool file is now ~50 lines:

    async def gather(ctx: ScanContext):
        ctx.state["a"] = await dns_resolve(ctx.host, "A")
        if ctx.state["a"]: ctx.source("dig")
        # ... fire other sources in parallel via asyncio.gather

    INTEL_FIELDS = [("A records", "a"), ("MX servers", "mx"), ...]

    @router.post("/api/recon/dns")
    async def recon_dns(req, _=Depends(verify_scan_quota)):
        return await run_scanner(
            host=recon_host(req.target),
            tool="dns",
            gather_func=gather,
            finding_rules=DNS_FINDING_RULES,
            intel_fields=INTEL_FIELDS,
        )

Everything else (severity-tagged findings, intel table population,
sources_used tracking, backwards-compat flat fields, standard_response
shape) is handled by the framework.
"""
from tools._framework.scanner import ScanContext, run_scanner
from tools._framework.gathering import (
    cli_run, whois_cli, team_cymru_asn,
    http_json, http_json_async,
    dns_resolve, dns_resolve_many,
)
from tools._framework.parsers import (
    grab, grab_all, parse_iso_date, days_between,
)
from tools._framework.findings import run_rules, severity_counts
from tools._framework.orchestrator import run_module_parallel

__all__ = [
    # scanner.py (v1 — single-tool runner)
    "ScanContext", "run_scanner",
    # gathering.py
    "cli_run", "whois_cli", "team_cymru_asn",
    "http_json", "http_json_async",
    "dns_resolve", "dns_resolve_many",
    # parsers.py
    "grab", "grab_all", "parse_iso_date", "days_between",
    # findings.py
    "run_rules", "severity_counts",
    # orchestrator.py (v2 — parallel multi-tool runner)
    "run_module_parallel",
]
