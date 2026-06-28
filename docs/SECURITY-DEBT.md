# Security Debt — tracked exceptions

Everything here is a **known, accepted, scheduled** item. CI gates on
everything *except* these; each must have an owner and a target date.

## Dependency CVEs — accepted with a plan

### Starlette 0.41.x (pulled transitively by FastAPI 0.115.6)
FastAPI `0.115.6` constrains `starlette>=0.40.0,<0.42`, so we cannot move to a
patched Starlette without a coordinated FastAPI major upgrade.

Residual advisories (gated-out via `--ignore-vuln` in `.github/workflows/ci.yml`):

| ID | Needs Starlette | Notes |
|---|---|---|
| PYSEC-2026-161 | 1.0.1 | |
| PYSEC-2026-248 | 1.3.0 | |
| PYSEC-2026-249 | 1.3.1 | |
| CVE-2025-54121 | 0.47.2 | blocking-IO in multipart on threadpool |
| CVE-2025-62727 | 0.49.1 | |
| CVE-2026-48817 | 1.1.0 | |
| CVE-2026-48818 | 1.1.0 | |

**Remediation plan:** upgrade FastAPI to the latest release whose pin allows
Starlette ≥ 1.1, then drop these IDs from the ignore list and re-run
`pip-audit`. Test the full boot smoke + `tests/` afterwards — a Starlette major
bump can change middleware/exception-handler signatures.
**Owner:** _TBD_ · **Target:** _next maintenance window_

### pip / wheel (build tooling, not runtime)
CI upgrades pip+wheel before the audit, so these do not appear in the gated run.
They ship in the base image only; the production image does not execute pip.

## How to clear an item
1. Bump the pin in `requirements.txt` to the fix version.
2. Re-run `pip-audit` (clean), `python -m pytest tests/`, and the boot smoke.
3. Remove the corresponding `--ignore-vuln` flag from CI and the row above.
