"""VL-METHOD cross-scanner chaining engine.

When a Stage 7 chain_handoff suggests downstream scanners (e.g. confirmed
root SSH -> privesc_linpeas_remote_audit), this engine consumes those
suggestions, spawns the named scanners with inherited credentials + the
same chain_id, and collects their results so the PDF can render the
chained scans as a connected attack tree.

Design notes:

- ChainRegistry holds the mapping {scanner_name -> async_callable}.
  Downstream scanner modules call register(name, fn) at import time
  (typically inside their endpoint module). Empty registry = chaining is
  a no-op (no scanners spawned), which is the correct state during the
  rollout window where downstream scanners don't exist yet.

- ChainExecutor reads parent_result.raw_data.methodology_findings,
  filters those with non-empty chain_next, dedupes scanner names, and
  invokes each registered downstream scanner. Hard caps:
    max_depth=2          (don't chain a chained scanner more than once)
    max_per_chain=5      (one finding can't fan out to >5 downstream)
    max_total=10         (orchestrator-wide cap to prevent runaway cost)

- Inherited credentials are passed via options.chain_creds = [{user, pwd}].
  Downstream scanners read this to authenticate without re-cracking.
  Plaintext is intentional here - chaining only happens within a single
  scan request (single tenant) and chain_creds never leak to the PDF
  because each downstream scanner re-redacts when generating its own
  findings.

- If a suggested scanner isn't registered, we emit a synthetic INFO
  finding so the PDF still tells the customer "we wanted to run X next
  but it isn't implemented yet" - keeps the chain handoff visible in
  the report instead of silently dropping it.
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional


# ═══════════════════════════════════════════════════════════════════
#  ChainRegistry — global registry of chainable scanners
# ═══════════════════════════════════════════════════════════════════


ChainCallable = Callable[..., Awaitable[dict]]


class ChainRegistry:
    """Process-wide registry of scanners eligible for chain handoff.

    Downstream scanner modules call register() at import time. The
    chaining engine looks up scanner names via get(). Unknown names
    return None and produce a "not yet implemented" INFO finding so the
    chain link is visible in the PDF.
    """

    def __init__(self):
        self._scanners: dict[str, ChainCallable] = {}

    def register(self, name: str, fn: ChainCallable) -> None:
        self._scanners[name] = fn

    def get(self, name: str) -> Optional[ChainCallable]:
        return self._scanners.get(name)

    def known(self) -> list[str]:
        return sorted(self._scanners.keys())


# Global singleton used by the orchestrator
chain_registry = ChainRegistry()


# ═══════════════════════════════════════════════════════════════════
#  ChainExecutor — runs chain_next handoffs after primary scans
# ═══════════════════════════════════════════════════════════════════


class ChainExecutor:
    """Expand chain_next handoffs into actual scanner invocations.

    Usage (inside an orchestrator):

        executor = ChainExecutor(chain_registry)
        chained = await executor.expand_all(
            primary_results=results,
            target=req.target,
            jwt=jwt,
        )
        # chained is a list of result dicts to merge into the response
    """

    def __init__(self, registry: ChainRegistry,
                 max_depth: int = 2,
                 max_per_chain: int = 5,
                 max_total: int = 10):
        self.registry = registry
        self.max_depth = max_depth
        self.max_per_chain = max_per_chain
        self.max_total = max_total

    async def expand_all(self,
                         primary_results: list[dict],
                         target: str,
                         jwt: Optional[str] = None,
                         current_depth: int = 0) -> list[dict]:
        """Walk primary_results, spawn downstream scanners for each
        finding with chain_next. Returns list of new result dicts."""
        # VA-NOT-PT (user directive 2026-06-06): cross-scanner auto-exploitation
        # is permanently DISABLED. VulnusLab finds vulnerabilities; it must never
        # auto-spawn downstream scanners with inherited credentials ("hacking").
        # This is the single chokepoint — returning [] here neutralises chaining
        # for every module and every scanner that calls expand_all. Do NOT
        # re-enable without explicit owner approval.
        return []
        # --- retained for reference only; unreachable while chaining is off ---
        if current_depth >= self.max_depth:
            return []

        chained: list[dict] = []
        seen_scanners: set[str] = set()

        for parent in primary_results:
            for finding in self._findings_with_chain(parent):
                chain_next = finding.get("chain_next") or []
                inherited_creds = self._extract_creds(finding)
                chain_id = finding.get("chain_id") or ""
                parent_tool = parent.get("tool") or "unknown"

                for scanner_name in chain_next[:self.max_per_chain]:
                    if scanner_name in seen_scanners:
                        continue
                    if len(chained) >= self.max_total:
                        break
                    seen_scanners.add(scanner_name)

                    fn = self.registry.get(scanner_name)
                    if fn is None:
                        chained.append(self._not_available_result(
                            scanner_name, target, chain_id, parent_tool))
                        continue

                    try:
                        result = await fn(
                            target=target,
                            options={
                                "chain_id": chain_id,
                                "chain_creds": inherited_creds,
                                "chained_from": parent_tool,
                                "chain_depth": current_depth + 1,
                            },
                            jwt=jwt,
                        )
                        if isinstance(result, dict):
                            result.setdefault("chained_from", parent_tool)
                            result.setdefault("chain_id", chain_id)
                            chained.append(result)
                    except Exception as e:
                        chained.append({
                            "tool": scanner_name,
                            "target": target,
                            "_failed": True,
                            "chained_from": parent_tool,
                            "chain_id": chain_id,
                            "error": f"chain execution failed: "
                                     f"{type(e).__name__}: {str(e)[:200]}",
                        })

        # Recurse: chained results may themselves have chain_next
        if chained and current_depth + 1 < self.max_depth:
            deeper = await self.expand_all(
                chained, target, jwt, current_depth + 1)
            chained.extend(deeper)

        return chained

    # ── helpers ──────────────────────────────────────────────────

    @staticmethod
    def _findings_with_chain(parent: dict) -> list[dict]:
        """Pull methodology_findings that carry chain_next handoffs."""
        rd = parent.get("raw_data") or {}
        out = []
        for f in (rd.get("methodology_findings") or []):
            if f.get("chain_next"):
                out.append(f)
        # Fallback: also accept chain_next stamped at the top-level state
        top_chain = (rd.get("chain_next") or [])
        if top_chain and not out:
            # Synthesize a pseudo-finding so we still process the chain
            out.append({
                "chain_next": top_chain,
                "chain_id": rd.get("chain_id") or "",
                "user": "",
                "_pwd_private": "",
            })
        return out

    @staticmethod
    def _extract_creds(finding: dict) -> list[dict]:
        """Pull (user, pwd) from finding's private slots so the
        downstream scanner can re-authenticate."""
        pwd = (finding.get("_pwd_private")
               or finding.get("_plaintext_internal")
               or "")
        return [{
            "user": finding.get("user") or finding.get("username") or "",
            "pwd": pwd,
        }]

    @staticmethod
    def _not_available_result(scanner_name: str, target: str,
                               chain_id: str, parent_tool: str) -> dict:
        """Emit a result dict for a chain handoff whose target scanner
        isn't registered. PDF renders this as INFO so the chain stays
        visible."""
        return {
            "tool": scanner_name,
            "target": target,
            "_skipped": True,
            "skipped_reason": f"chain handoff scanner '{scanner_name}' not yet implemented",
            "chained_from": parent_tool,
            "chain_id": chain_id,
            "findings": [{
                "name": f"Chain handoff: {scanner_name} not yet implemented",
                "severity": "INFO",
                "evidence": (f"Parent scanner '{parent_tool}' suggested running "
                             f"'{scanner_name}' with inherited credentials, but "
                             f"that scanner is not yet registered with the "
                             f"chaining engine. It will be added in a future "
                             f"VL-METHOD rollout phase."),
                "remediation": (f"Until '{scanner_name}' is implemented, manually "
                                f"run the equivalent test against {target} using "
                                f"the discovered credentials. The chain_id "
                                f"({chain_id or 'unknown'}) ties this gap back to "
                                f"the original finding."),
                "cwe": "CWE-1006",
                "chain_id": chain_id,
                "source_stage": "chain_handoff",
                "confidence": "INFO",
            }],
            "raw_data": {"intel": {}, "sources_used": []},
        }
