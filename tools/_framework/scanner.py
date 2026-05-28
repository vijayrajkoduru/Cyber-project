"""Main scanner orchestrator + ScanContext.

Tool authors write ONE async gather() function and a list of rules.
The framework handles asyncio plumbing, response shape, intel-table
population, sources_used tracking, and backwards-compat flat fields.

Typical tool file (entire scanner):

    from tools._framework import (ScanContext, run_scanner,
                                   dns_resolve_many)
    from tools._payloads.dns_findings import DNS_FINDING_RULES

    async def gather(ctx: ScanContext):
        rec = await dns_resolve_many(ctx.host,
                                      ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA"])
        ctx.state.update(rec)
        if any(rec.values()): ctx.source("dig")

    INTEL_FIELDS = [("A records", "A"),
                    ("MX servers", "MX"),
                    ("Nameservers", "NS"),
                    ("TXT records", "TXT")]

    @router.post("/api/recon/dns")
    async def recon_dns(req: ScanRequest, _=Depends(verify_scan_quota)):
        return await run_scanner(
            host=recon_host(req.target), tool="dns",
            gather_func=gather, finding_rules=DNS_FINDING_RULES,
            intel_fields=INTEL_FIELDS,
            flat_field_keys=["A","MX","NS","TXT"],
        )

That's the entire DNS Records scanner — ~30 lines instead of ~300.
"""
import asyncio
from dataclasses import dataclass, field
from typing import Callable, Awaitable, Optional

from tools._shared import standard_response
from tools._framework.findings import run_rules


@dataclass
class ScanContext:
    """Mutable state passed through gatherers + rules.

    Fields:
      host          — target hostname (e.g., "vulnuslab.com")
      tool          — scanner name (e.g., "whois", "dns")
      state         — the data dict that gatherers populate + rules read
      sources_used  — ordered list of source identifiers actually used

    Helpers:
      ctx.source("dig")              — register a source as used
      ctx.state["a"] = [...]         — direct state mutation
    """
    host: str
    tool: str
    state: dict = field(default_factory=dict)
    sources_used: list = field(default_factory=list)

    def source(self, name: str):
        """Record that a data source contributed to this scan."""
        if name and name not in self.sources_used:
            self.sources_used.append(name)


async def run_scanner(
    host: str,
    tool: str,
    gather_func: Callable[[ScanContext], Awaitable[None]],
    finding_rules: list,
    intel_fields: list,
    flat_field_keys: Optional[list] = None,
    skip_if_empty: bool = True,
) -> dict:
    # VL-TURBO Session 6: timing telemetry
    import time as _vl_time, logging as _vl_log
    _vl_start = _vl_time.time()
    """Run a recon scanner using the framework pattern.

    Args:
      host:            target hostname
      tool:            tool name for the response (used in tests_summary)
      gather_func:     async (ctx) -> None — populates ctx.state from sources
      finding_rules:   list of rule functions (state -> Optional[finding dict])
      intel_fields:    list of (label, state_key) tuples for Intelligence table
      flat_field_keys: optional state keys to ALSO expose at top level (back-compat)
      skip_if_empty:   if True (default), returns skipped_reason when no sources
                        produced data — prevents empty-PDF-section noise

    Returns: standard_response shape with findings + intel + sources_used.
    """
    ctx = ScanContext(host=host, tool=tool)

    try:
        await gather_func(ctx)
    except Exception as e:
        return standard_response(
            tool=tool, target=host, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"{tool} scan failed during data gathering: {e}",
        )

    # Optional early-return when gather found nothing.
    if skip_if_empty and not ctx.sources_used and not any(ctx.state.values()):
        return standard_response(
            tool=tool, target=host, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"{tool}: no data sources returned usable data for {host}",
        )

    # CTX-SKIPPED-REASON-V1 — gather() can set ctx.state["skipped_reason"] to
    # surface a clean diagnostic (e.g. "target rate-limited the scanner") and
    # have the tile render as SKIPPED (yellow) instead of FAILED (red). Used
    # by gobuster after the GRACEFUL-FAIL-V1 early-bailout.
    _ctx_skip = ctx.state.get("skipped_reason")
    if _ctx_skip:
        return standard_response(
            tool=tool, target=host, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=str(_ctx_skip),
        )

    findings = run_rules(ctx.state, finding_rules)

    # Intel table — only include populated, non-empty fields.
    intel = {}
    for label, key in intel_fields:
        v = ctx.state.get(key)
        if v in (None, "", [], {}):
            continue
        intel[label] = v

    raw_data = {
        "intel":         intel,
        "sources_used":  ctx.sources_used,
    }
    # Backwards-compat flat fields (existing PDF / dashboard readers).
    for k in (flat_field_keys or []):
        if k in ctx.state:
            raw_data[k] = ctx.state[k]

    return standard_response(
        tool=tool,
        target=host,
        findings=findings,
        tests_performed=len(finding_rules),
        tests_summary=(f"{tool} intel: gathered {len(ctx.sources_used)} sources "
                       f"({', '.join(ctx.sources_used) or 'none'}); "
                       f"{len(finding_rules)} rules evaluated; "
                       f"{len(findings)} findings emitted."),
        raw_data=raw_data,
    )
