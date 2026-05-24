# VL-FOUNDRY Migration Guide

How to retrofit an existing module (forged before VL-FOUNDRY was finalized)
to the current 20-layer framework. The objective is a **score >= 85** from
`scripts/score_module.py` and a **green run** of `scripts/e2e_test.py`.

This guide is for the three already-shipped modules (**recon**, **vuln**,
**webapp**) and any third-party module copied into `tools/`.

---

## Pre-flight

Run the scorer to see where the module stands today:

```bash
python scripts/score_module.py <module> --verbose
```

The output prints per-layer percentages plus a **7-check rollup** showing
which individual DoD check is the module's weakest link. Migrate in
priority order: lowest-percentage check first.

---

## Step 1 — Inventory existing scanners

```bash
ls tools/<module>/**/*.py | grep -v __init__ | grep -v "^_"
```

Cross-check against `endpoints/<module>_orchestrator.py::_all_tools()`:

```python
from endpoints.<module>_orchestrator import _all_tools
{name for name, _ in _all_tools()}
```

Any file on disk NOT in the orchestrator = orphan. Either wire it in or
delete it. Don't ship orphans.

---

## Step 2 — Fix the orchestrator (Layer 4)

If the score's `L4_orchestrator` row is below 100%:

- Open `endpoints/<module>_orchestrator.py`
- Confirm `<MODULE>_TOOLS_BY_TIER` is a dict with tier names as keys
- Add missing scanners to the appropriate tier
- Confirm `_all_tools()` flattens to one (name, callable) tuple per file
- Confirm `/api/<module>/run_all` streams NDJSON (one record per scanner)
- Confirm `/api/<module>/run_all_buffered` exists (non-streaming clients)
- Confirm `/api/<module>/run_all/tiers` returns the discovery payload

Re-run the scorer. Target: 100% on L4.

---

## Step 3 — Add AI curation (Layer 5)

If the score's `L5_curation` row is below 70%:

1. Identify scanners that use hardcoded wordlists / payloads / fingerprints
2. Create `tools/_gen/gen_<module>_assets.py` with the Anthropic SDK
   + a `CONFIGS` list (see `tools/_gen/gen_webapp_assets_v2.py` for shape)
3. Generate wordlists into `tools/_payloads/<module>/`
4. In each scanner, replace the hardcoded list with:

   ```python
   try:
       from tools._payloads.<module> import my_wordlist as _WL
   except ImportError:
       _WL = _FALLBACK_WL   # keep the old hardcoded list as fallback
   ```

5. Add the module's wordlists to the refresh calendar in `VL-FOUNDRY.md`

Re-run the scorer. Target: 90%+ on L5 (some scanners have no list — that's fine).

---

## Step 4 — Lift each scanner to 7/7 DoD (Layer 6)

This is the biggest lift. For each scanner whose `--verbose` output shows
a missing check:

| Missing check | Fix |
|---|---|
| `precheck` | Wrap entry in `precheck_target(target)` (or the module's `safe_get`/`web_url`/`ScanContext`/`run_scanner`) and bail with status=ERROR on failure |
| `uniform_shape` | Return via `standard_response()` / `vuln_response()` / `run_scanner()` instead of a raw dict |
| `positive_emit` | When clean, emit a `status="POSITIVE"` finding so the PDF shows "what we checked"  |
| `severity` | Add severity field to every VULNERABLE finding |
| `remediation` | Add remediation string to every VULNERABLE finding |
| `evidence` | Add evidence_marker (or call `ctx.source(...)`) on every finding |
| `timeout` | Wrap scan body in `asyncio.wait_for(..., timeout=WALL_CLOCK_S)` |

For greenfield scanners use the scaffolder:

```bash
python scripts/forge_scanner.py <module> <scanner_name> --tier=<tier>
```

It generates a file with all 7 checks pre-wired.

For findings that *should* be validated at runtime, drop in:

```python
from tools._framework.finding_schema import validate_finding
validate_finding(f)   # raises FindingError if shape is wrong
```

Target: 90%+ on L6.

---

## Step 5 — Parallelize (Layer 6 sub)

If `L6_parallel` is below 70%:

- Convert blocking I/O scanners to async (`async def run`)
- Use `asyncio.gather` + `asyncio.Semaphore(concurrency)`
- For unavoidable sync libs, wrap with `ThreadPoolExecutor` or
  `asyncio.to_thread`
- Add `asyncio.wait_for` wall-clock cap (same as Step 4's timeout fix)

See the existing VL-TURBO commit log for working examples. Target: 90%+
on parallel.

---

## Step 6 — Frontend integration (Layer 7)

If `L7_frontend` is below 100%:

- Open `src/App.js`
- Find or create `<MODULE>_PHASES` array
- Add one entry per scanner: `{name, tool, endpoint, icon}`
- Confirm count matches orchestrator count
- Confirm `<MODULE>_SECTION_HEADERS` dict has tier headers + colors
- Confirm the module appears in the main navigation

---

## Step 7 — Run the gate

```bash
# All-in-one verification
python scripts/score_module.py <module> --verbose       # >= 85
python scripts/e2e_test.py <module>                     # exit code 0
```

A module **ships** only when BOTH pass.

---

## Step 8 — Update VL-FOUNDRY.md status matrix

Append a row to the **Module status matrix** in `VL-FOUNDRY.md` with the
new score + ship date. This is how downstream contributors know the module
is at-spec.

---

## Common pitfalls during migration

**"Score went DOWN after refactor"** — the pre-commit hook
(`scripts/pre_commit_score.py`) blocks commits that drop a module's score
by >= 2 points. Either fix the regression, or set `SKIP_VL_FOUNDRY=1`
*after* deciding the drop is intentional (e.g. removing a fake scanner).

**"Orchestrator dispatches scanner but it never appears in NDJSON"** —
classic silent crash. Run the scanner directly first:
```bash
python -c "import asyncio; from tools.<module>.<scanner> import run; print(asyncio.run(run('vulnuslab.com')))"
```
Stack traces from this almost always identify the broken import or missing
dependency that `gather(return_exceptions=True)` was swallowing.

**"AST behavioral check fails even though the function IS called"** —
the scorer uses AST `ast.walk` to find calls. If the call is on an alias
(`from tools.vuln._vuln_common import precheck_target as _pre`) you must
either inline the call or accept a slightly lower precheck score; the
behavior is intentional (catches scanners that import without calling).

**"L5 curation stays at 0% despite a wordlist"** — the regex looks for
the literal string `tools._payloads`. Make sure your import uses that
fully-qualified path, not a relative one.

---

## Migration scorecard template

Track per-module migration progress like this:

```
Module: <name>
─────────────────────────────
Pre-migration score:  ??/100
Post-migration score: ??/100
E2E test:             PASS | FAIL
Scanner count:        <orch> / <disk>
7/7 weakest check:    <name> at <pct>%
Hours invested:       ??h
Date:                 YYYY-MM-DD
```

When all rows are filled in and BOTH gates green, append to VL-FOUNDRY.md
status matrix and tag the commit `vl-foundry-<module>-migrated`.
