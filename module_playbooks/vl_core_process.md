# VL-CORE Process

**Trigger:** `apply VL-CORE to <module>` or `VL-CORE pass` (codebase-wide)

**Purpose:** enforce module isolation. Every scanner module owns a
self-contained resource pool (engines + payloads + AI-curated wordlists +
wordlists + loader). Cross-module imports are anti-pattern.

## Canonical structure

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

## Hard rule

> A scanner in module `X` imports **only** from `tools/_payloads/X/` or
> `tools/_payloads/_shared/`. Importing from `tools/_payloads/Y/` (where
> `Y != X`) is a VL-CORE violation.

Enforcement:
- `tools/_framework/vl_core.py` registers module names + computes data roots
- Each module's `_loader.py` calls `assert_isolated_import(module, module)` at import time
- Under `VL_CORE_STRICT=1` (set by VL-AUDIT), any cross-module import raises

## Allowed escape hatch — `_payloads/_shared/`

Use ONLY for genuinely cross-module concepts:
- Top-1000 passwords (every auth scanner)
- CVE/EPSS API cache
- Public breach signal datasets

Putting webapp-specific payloads in `_shared/` so vuln "might want it
later" is the anti-pattern. The default is isolated.

## The 5-step pass

When triggered (`apply VL-CORE to <module>`):

1. **Audit** — grep `tools/<module>/` for `from tools._payloads.<other>` imports
2. **Classify** each cross-module dep:
   - **Module-specific** (e.g. `xss_extra_payloads.json` used only by webapp)
     → move to `_payloads/<module>/`, update import
   - **Genuinely cross-module** (e.g. `top_passwords.txt` used by 4 modules)
     → move to `_payloads/_shared/`, update import
   - **Mis-namespaced** (file in `_payloads/<X>/` but only used by `<Y>`)
     → move to `_payloads/<Y>/`, update imports
3. **Ensure loader exists** — `_payloads/<module>/_loader.py` with `load_json` + `load_lines` API matching `tools/_payloads/vuln/_loader.py`
4. **Update imports** — `sed -i 's|_payloads.<other>._loader|_payloads.<module>._loader|g'`
5. **Verify** — re-run grep from step 1; expect zero output. Run `VL_CORE_STRICT=1 pytest` to confirm.

## Phase 1 (2026-06-10) — initial isolation

- Created `tools/_framework/vl_core.py` with module registry + isolation guard
- Created loaders for: webapp, recon, osint, _shared (vuln + container_k8s already had them)
- Migrated 14 mis-namespaced files from `_payloads/vuln/` to `_payloads/webapp/`:
  `xss_extra_payloads.json`, `sqli_extra_payloads.json`, `lfi_extra_paths.json`,
  `ssrf_extra_targets.json`, `xxe_extra_payloads.json`, `cmd_injection_extra.json`,
  `open_redirect_extra.json`, `ssti_payloads.json`, `nosql_payloads.json`,
  `graphql_payloads.json`, `file_upload_payloads.json`, `cms_fingerprints.json`,
  `wpscan_paths.json`, `exposed_files_paths.json`, `jwt_secrets.txt`
- Updated 15 webapp scanner imports
- Zero cross-module violations remaining

## Phase 2 (TBD) — recon migration

Recon currently uses per-scanner `_PAYLOAD = Path(__file__).parent.parent / "_payloads" / "recon" / "X.txt"` pattern. Migrate to the canonical loader for consistency. Low-priority — no isolation violation, just stylistic.

## Why isolation matters

- **Each module ships, versions, sells independently.** A customer who buys only Recon doesn't get webapp's payload library.
- **Predictable behavior.** Updating webapp's XSS payload list can't accidentally shift a vuln scanner's behavior.
- **Faster onboarding.** A new contributor working on webapp doesn't need to learn the recon payload conventions.
- **Single source of truth per module.** No more duplicated `jwt_secrets.txt` in two modules drifting apart.
