# VL-CORE Process

**Trigger:** `apply VL-CORE to <module>` or `VL-CORE pass`

**Purpose:** VL-CORE is the **central hub all modules connect to** for
shared infrastructure (orchestrator, scan state, advisory severity policy,
Nuclei wrapper, etc.). Each module's scanners stay isolated from every
other module — they reach into VL-CORE for shared infrastructure but never
into another module's directory.

## Architecture

```
┌─────────────────────────── VL-CORE ───────────────────────────┐
│  orchestrator   scan_state   severity_policy   nuclei_runner  │
│  spa_canary     reserved_domains   findings    framework      │
│  advisory_cap   module_registry    exposure_catalog (future)  │
└────────────┬────────────┬────────────┬────────────┬───────────┘
             │            │            │            │
    ┌────────▼───┐  ┌─────▼───┐  ┌────▼─────┐  ┌───▼─────┐
    │   Recon    │  │  Vuln   │  │  Webapp  │  │  OSINT  │
    │  scanners  │  │ scanners│  │ scanners │  │ scanners│
    │            │  │         │  │          │  │         │
    │ _payloads/ │  │_payloads│  │ _payloads│  │_payloads│
    │ /recon/    │  │ /vuln/  │  │ /webapp/ │  │ /osint/ │
    └────────────┘  └─────────┘  └──────────┘  └─────────┘

Every module connects UP to VL-CORE.
No module connects ACROSS to another module.
```

## What lives in VL-CORE

Single source of truth for shared infrastructure:

| Capability | VL-CORE entry point |
|---|---|
| Multi-tool orchestration | `run_module_parallel`, `run_module_streaming` |
| Per-scanner runtime | `ScanContext`, `run_scanner` |
| Finding shape | `wrap_finding`, `standard_response` |
| Rule engine | `run_rules`, `severity_counts` |
| Advisory severity cap | `cap_if_advisory`, `apply_policy`, `is_advisory` |
| Reserved-domain guard | `is_reserved`, `reserved_reason` |
| SPA canary cache | `detect_spa_catchall_sync`, `is_same_as_canary` |
| Nuclei subprocess wrapper | `run_nuclei`, `nuclei_available` |
| Module registry + isolation | `MODULES`, `module_root`, `assert_isolated_import` |

Backing files live in `tools/_framework/`. VL-CORE re-exports them under
stable names from `tools/_vl_core/__init__.py` so modules import once.

## What lives in each module

Per-module resource pool under `tools/_payloads/<module>/`:

```
tools/
├── <module>/                       # engine scanners (existing)
│   ├── _<module>_common.py         # private helpers
│   ├── tier1_<x>/                  # scanner tiers
│   └── ...
└── _payloads/
    ├── _shared/                    # opt-in cross-module pool
    │   └── _loader.py
    └── <module>/
        ├── __init__.py
        ├── _loader.py              # load_json, load_lines
        ├── ai_*.txt                # AI-curated wordlists
        ├── *.txt                   # generic wordlists
        ├── *.json                  # structured payload lists
        └── *.py                    # payload constants (optional)
```

## Hard rules

1. **Scanners use VL-CORE for shared infrastructure.**
   ```python
   from tools._vl_core import wrap_finding, run_nuclei, is_reserved
   ```

2. **Scanners use their own module's loader for payloads.**
   ```python
   from tools._payloads.webapp._loader import load_json, load_lines
   ```

3. **No cross-module imports.** A webapp scanner pulling from
   `_payloads/vuln/` is a violation. Move the dep to `_payloads/webapp/`
   or `_payloads/_shared/`.

4. **Use `_shared/` only for genuinely cross-module payloads.** Top-1000
   passwords, CVE/EPSS cache, generic breach signal datasets. Default is
   isolated.

## Connection model — one VL-CORE, N isolated modules

| Component | Where it lives | Who can use it |
|---|---|---|
| **Engines** (scanners) | `tools/<module>/` | The module itself only |
| **Payload libraries** | `tools/_payloads/<module>/` | The module's scanners only |
| **AI-curated wordlists** | `tools/_payloads/<module>/ai_*.txt` | The module's scanners only |
| **Generic wordlists** | `tools/_payloads/<module>/*.txt` | The module's scanners only |
| **Shared scan state** | VL-CORE | **All modules connect** |
| **Orchestrator** | VL-CORE | **All modules connect** |
| **Nuclei wrapper** | VL-CORE | **All modules connect** |
| **External binary wrappers** | VL-CORE | **All modules connect** |
| **Truly shared payloads** | `_payloads/_shared/` | All modules (opt-in) |

## The 5-step pass

When triggered (`apply VL-CORE to <module>`):

1. **Audit cross-module imports**
   ```bash
   grep -rn "from tools._payloads.<other>" tools/<module>/
   ```
2. **Classify each cross-module dep:**
   - Module-specific (used only by `<module>`) → move to `_payloads/<module>/`
   - Genuinely cross-module → move to `_payloads/_shared/`
   - Mis-namespaced → move to its correct home
3. **Ensure module loader exists** at `_payloads/<module>/_loader.py`
4. **Update imports:**
   ```bash
   sed -i 's|_payloads.<other>._loader|_payloads.<module>._loader|g'
   ```
5. **Verify:** zero output from step-1 grep + `VL_CORE_STRICT=1 pytest`

## Phase 1 shipped (2026-06-10)

- `tools/_vl_core/__init__.py` — central hub re-exports 21 shared APIs
- `tools/_framework/vl_core.py` — module registry + isolation guard
- Per-module loaders: webapp, recon, osint, _shared (vuln + container_k8s
  already had them)
- Migrated 14 mis-namespaced files from `_payloads/vuln/` to
  `_payloads/webapp/` (they were webapp payloads sitting in vuln's pool)
- Updated 15 webapp scanner imports
- Zero cross-module violations remaining
- VL-CORE central hub importable as `from tools._vl_core import …`

## Phase 2 (incremental)

- Migrate Recon scanners from per-scanner `_PAYLOAD = Path(...)` to the
  canonical `_payloads/recon/_loader.py` (stylistic, low priority)
- Migrate existing scanners from `tools._framework.X` imports to
  `tools._vl_core` re-exports (gradually, for clarity)
- Add `exposure_catalog` to VL-CORE if a future cross-module canonical
  severity table is desired (`exposure_catalog.score("ftp_anonymous")`)

## Why this matters

- **One VL-CORE, N modules.** The product has a single shared brain. Each
  module is a self-contained product line.
- **Modules ship/sell independently.** A customer buying only Recon gets
  Recon's scanners + Recon's payloads + VL-CORE infrastructure. Nothing
  from vuln, webapp, osint.
- **Updating shared infrastructure once propagates everywhere.** Improve
  the advisory severity policy → every module's scanners benefit
  immediately.
- **No accidental drift.** Webapp's XSS payload list change can't
  accidentally shift a vuln scanner's behavior because vuln doesn't even
  import from webapp.
