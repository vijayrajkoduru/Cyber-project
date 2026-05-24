#!/usr/bin/env python3
"""VL-FOUNDRY — the autonomous module forge.

ONE COMMAND. Module name in. Working module out.

  $ python scripts/vl_foundry.py mobile
    [A] researching mobile pentest domain ...                 done
    [B] scaffolding skeleton (forge_module.py) ...            done
    [C] AI writing 12 scanner gather() bodies ...             done
    [D] AI writing FINDING_RULES per scanner ...              done
    [E] patching endpoints/mobile_orchestrator.py ...         done
    [F] patching src/App.js (PHASES + PDF + tab handler) ...  done
    [G] running scorer + heal loop ...                        91/100 ✅
    [H] writing checklist + tests + commit-ready ...          done

  Module 'mobile' is ready. Review the changes, then:
    git add -A && git commit -m "VL-FOUNDRY forge: mobile" && git push
    ./scripts/deploy.sh mobile      # on VPS

The agent uses RECON as the reference pattern (it scored 99.2/100).
Every generated scanner is structurally identical to a Recon scanner;
only the domain knowledge differs.

ENV REQUIREMENTS:
  ANTHROPIC_API_KEY  — set in shell or .env (real key required)

COST PER FORGE: ~$0.30-$1.50 depending on scanner count + heal iterations.

USAGE:
  python scripts/vl_foundry.py <module_name>
  python scripts/vl_foundry.py <module_name> --tiers 4 --scanners 12
  python scripts/vl_foundry.py <module_name> --dry-run     # plan only
  python scripts/vl_foundry.py <module_name> --resume      # pick up where it left off
"""
from __future__ import annotations
import argparse
import ast
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ─────────────────── CONFIG ───────────────────
MODEL = "claude-sonnet-4-6"
MAX_HEAL_ATTEMPTS = 3
TARGET_SCORE = 85
PLAN_DIR = ROOT / "scripts" / ".vl_foundry_plans"
PLAN_DIR.mkdir(exist_ok=True)


# ─────────────────── ANTHROPIC ───────────────────
def _client():
    try:
        import anthropic
    except ImportError:
        sys.exit("error: anthropic SDK not installed. Run: pip install anthropic")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        # Try loading from .env
        env_path = ROOT / ".env"
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                if line.startswith("ANTHROPIC_API_KEY="):
                    os.environ["ANTHROPIC_API_KEY"] = line.split("=", 1)[1].strip().strip('"\'')
                    break
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("error: ANTHROPIC_API_KEY not set. Add to .env or export it.")
    return anthropic.Anthropic()


def _ask(client, prompt: str, *, max_tokens: int = 8000, system: str = None) -> str:
    """One AI call. Returns plain text. Retries on transient errors."""
    last_err = None
    for attempt in range(3):
        try:
            kwargs = {
                "model": MODEL,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
            if system:
                kwargs["system"] = system
            resp = client.messages.create(**kwargs)
            return resp.content[0].text
        except Exception as e:
            last_err = e
            print(f"    (API attempt {attempt+1}/3 failed: {e}; retrying in 4s)")
            time.sleep(4)
    raise RuntimeError(f"AI call failed after 3 attempts: {last_err}")


def _extract_json(text: str) -> dict | list:
    """Pull the first JSON object/array out of an AI response."""
    # Strip markdown fences if present
    text = re.sub(r"^```(?:json)?\s*\n", "", text.strip())
    text = re.sub(r"\n```\s*$", "", text.strip())
    # Find first { or [
    m = re.search(r"[{\[]", text)
    if not m:
        raise ValueError(f"no JSON in response: {text[:200]}")
    return json.loads(text[m.start():])


def _extract_python(text: str) -> str:
    """Pull pure Python code out of an AI response (strip ``` fences)."""
    text = text.strip()
    text = re.sub(r"^```(?:python)?\s*\n", "", text)
    text = re.sub(r"\n```\s*$", "", text)
    return text.strip()


# ─────────────────── RECON REFERENCE ───────────────────
def _load_recon_examples() -> dict:
    """Read 3 Recon files as in-context examples for the AI.

    Recon scored 99.2/100. Every new module's scanners must follow this exact shape.
    """
    examples = {}
    paths = [
        ("scanner_example", ROOT / "tools" / "recon" / "tier4_web" / "wayback.py"),
        ("findings_example", ROOT / "tools" / "_payloads" / "wayback_findings.py"),
        ("orchestrator_example", ROOT / "endpoints" / "recon_orchestrator.py"),
    ]
    for key, p in paths:
        if not p.exists():
            print(f"  warning: reference file missing: {p}")
            examples[key] = ""
        else:
            examples[key] = p.read_text(encoding="utf-8")
    return examples


# ─────────────────── PROMPTS ───────────────────

SYSTEM_PROMPT = """You are VL-FOUNDRY, the autonomous module forge for VulnusLab — a SaaS security scanner.

Your output is REAL PRODUCTION CODE that will ship to paying customers.

Hard rules:
1. Use Python 3.10+ stdlib + tools._shared.safe_get + tools._framework only.
2. NO external CLI tools (no nmap, no nuclei) — pure-Python only.
3. Every probe must hit a THIRD-PARTY source (search engines, CT logs, public APIs)
   OR be a PASSIVE check. NO direct probing of customer infrastructure.
4. Every finding must have: severity, evidence (something OBSERVED), remediation.
   Severities: POSITIVE, INFO, LOW, MEDIUM, HIGH, CRITICAL.
5. POSITIVE emit when scan is clean (proves the probe ran).
6. ZERO FALSE POSITIVES — only emit findings with concrete evidence.
7. 5-second timeouts on all HTTP. Handle exceptions silently.

CRITICAL — exact run_scanner() signature (DO NOT hallucinate parameter names):
  run_scanner(host=..., tool=..., gather_func=..., finding_rules=...,
              intel_fields=..., flat_field_keys=...)
  Forbidden parameter names: req, scanner_name, gather_fn, scan_fn,
  finding_rule, intel_field, flat_field, rules.

Every scanner file MUST end with:
    def register(app):
        app.include_router(router)

When you produce code, output ONLY the code. No markdown fences. No explanations."""


# Binary-static mode — for modules that analyze uploaded binaries (APK, IPA,
# PE, ELF). Allows subprocess + file paths instead of HTTP-only.
SYSTEM_PROMPT_BINARY_STATIC = """You are VL-FOUNDRY (binary-static mode), the autonomous module forge for VulnusLab.

This module ANALYZES CUSTOMER-UPLOADED BINARIES (APK, IPA, PE, ELF). The customer
uploads the file via POST /api/<module>/upload; the path is stored as ctx.state["apk_path"].

Hard rules:
1. Use Python 3.10+ stdlib + tools._shared + tools._framework + tools._framework.apk_cache.
2. External CLI tools ARE ALLOWED via subprocess (apktool, jadx, aapt, MobSF, checksec,
   nm, strings, unzip, otool). Wrap in subprocess.run(..., timeout=...).
3. Input is a FILE PATH (apk_path / ipa_path / binary_path), not a URL.
4. Use tools._framework.apk_cache.get_unpacked(apk_path) for shared decompile cache —
   scanners stay isolated but redundant decompiles are avoided.
5. Every finding must have: severity, evidence, remediation.
6. POSITIVE emit when scan is clean (proves the analysis ran on the binary).
7. ZERO FALSE POSITIVES — only emit findings with concrete evidence (file path + line).
8. Timeout every subprocess (timeout=60 default; MobSF up to 120s). Handle exceptions silently.
9. Each scanner is ISOLATED — no scanner imports another scanner. Shared infra
   (apk_cache, finding_schema) is via tools._framework only.

CRITICAL — exact run_scanner() signature:
  run_scanner(host=..., tool=..., gather_func=..., finding_rules=...,
              intel_fields=..., flat_field_keys=...)
  For binary-static: pass `host=apk_path` (path is the "target" of analysis).

Every scanner file MUST end with:
    def register(app):
        app.include_router(router)

When you produce code, output ONLY the code. No markdown fences. No explanations."""


PROMPT_LAYER_2 = """Design a VulnusLab module called "{module}".

Research the security industry: what does "{module}" mean as a pentest module?
What are the canonical {n_scanners} probes a senior pentester runs in this domain?

Output a JSON plan with EXACTLY this shape — no other keys:

{{
  "module": "{module}",
  "module_role": "<one sentence: customer question this module answers>",
  "ptes_phase": "<PTES section, e.g. 'Section 4 - Intelligence Gathering'>",
  "why_exists": ["<bullet 1>", "<bullet 2>", "<bullet 3>"],
  "what_it_isnt": ["<bullet 1>", "<bullet 2>", "<bullet 3>"],
  "tiers": [
    {{
      "id": "tier1_<snake_category>",
      "label": "Tier 1 - <Human Label>",
      "scanners": [
        {{
          "name": "<snake_case_name>",
          "role": "<one-line role>",
          "data_source": "<which 3rd-party API/source it hits>",
          "expected_findings": "<what kind of evidence>"
        }}
      ]
    }}
  ]
}}

Requirements:
- {n_tiers} tiers total
- {n_scanners} scanners total (distributed across tiers)
- Every scanner uses a passive / 3rd-party source (no direct probing of customer infra)
- Each scanner is one specific question — not aggregator names

Output ONLY the JSON object. Start with {{ end with }}.
"""


# Binary-static variant — for modules that analyze customer-uploaded binaries
PROMPT_LAYER_2_BINARY_STATIC = """Design a VulnusLab BINARY-STATIC module called "{module}".

This module ANALYZES CUSTOMER-UPLOADED BINARIES (APK / IPA / PE / ELF) — NOT
domains or live targets. The customer uploads the file; each scanner reads
the file and produces findings via static analysis.

Examples of valid §1 (APP BINARY) scanners:
  - apk_decompile_audit (apktool subprocess)
  - android_manifest_audit (parse AndroidManifest.xml)
  - ios_plist_audit (plistlib stdlib)
  - secret_extraction_audit (regex over decompiled tree)
  - native_lib_hardening (checksec subprocess on .so files)
  - bytecode_malware_signatures (Quark-Engine Python lib)
  - mobsf_aggregate_scan (MobSF CLI subprocess)

Output a JSON plan with EXACTLY this shape:

{{
  "module": "{module}",
  "module_role": "<one sentence: what binary class + what risks the module surfaces>",
  "ptes_phase": "PTES Section 7 - Reporting (static analysis)",
  "binary_type": "<APK | IPA | PE | ELF>",
  "why_exists": ["<bullet 1>", "<bullet 2>", "<bullet 3>"],
  "what_it_isnt": ["<bullet 1>", "<bullet 2>", "<bullet 3>"],
  "tiers": [
    {{
      "id": "tier1_<snake_category>",
      "label": "Tier 1 - <Human Label>",
      "scanners": [
        {{
          "name": "<snake_case_name>",
          "role": "<one-line role>",
          "tooling": "<CLI tool or Python lib used — apktool, jadx, plistlib, etc.>",
          "expected_findings": "<concrete finding examples — debuggable=true, hardcoded AWS key, etc.>"
        }}
      ]
    }}
  ]
}}

Requirements:
- {n_tiers} tiers total
- {n_scanners} scanners total (distributed across tiers)
- Every scanner takes a FILE PATH as input (not a URL)
- External CLI tools ARE ALLOWED via subprocess
- Use tools._framework.apk_cache.get_unpacked() for shared decompile cache
- Each scanner is one specific check — not an aggregator

Output ONLY the JSON object. Start with {{ end with }}.
"""


PROMPT_SCANNER = """Generate ONE complete Python file for a VulnusLab scanner.

Path: tools/{module}/{tier_id}/{scanner_name}.py

This is a {module} module scanner. Module role: {module_role}.

Scanner spec:
  name: {scanner_name}
  role: {scanner_role}
  data source: {data_source}
  expected findings: {expected_findings}

Use this EXACT structure (copy reference shape; replace the gather() body and INTEL_FIELDS):

REFERENCE (from Recon module, scored 99.2/100):
```python
{scanner_example}
```

Now generate the new scanner file. Replace:
- Module docstring (1-2 lines for this scanner's role)
- gather() body — REAL working code that calls the data source above using safe_get(url, req=req, timeout=5)
- INTEL_FIELDS — 2-4 (label, state_key) pairs to render in the report
- Route handler path: /api/{module}/{scanner_name}
- Route handler function name: {module}_{scanner_name}
- finding_rules import: from tools._payloads.{scanner_name}_findings import {SCANNER_UPPER}_FINDING_RULES
- recon_host stays — it normalizes the target host

Generate WORKING gather() logic. Don't write `# TODO`. Use real HTTP calls and real parsing.
For 3rd-party data: HTML scrape via safe_get + regex, OR public JSON APIs.

The gather() should populate at least: ctx.state["{scanner_name}_total"] = N

Output ONLY the complete Python file. No markdown fences. No explanation.
"""


PROMPT_SCANNER_BINARY_STATIC = """Generate ONE complete Python file for a VulnusLab BINARY-STATIC scanner.

Path: tools/{module}/{tier_id}/{scanner_name}.py

This is a {module} module scanner. Module role: {module_role}.
Binary type: {binary_type}.

Scanner spec:
  name: {scanner_name}
  role: {scanner_role}
  tooling: {tooling}
  expected findings: {expected_findings}

Required file structure (use this EXACT template — replace only the marked sections):

```python
\"\"\"{scanner_name} — {scanner_role}.\"\"\"
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.apk_cache import get_unpacked   # shared decompile cache
from tools._payloads.{scanner_name}_findings import {SCANNER_UPPER}_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    \"\"\"YOUR CODE: read file from ctx.host (apk_path) and populate ctx.state.\"\"\"
    apk_path = ctx.host  # for binary-static, ctx.host is the uploaded file path
    if not Path(apk_path).is_file():
        ctx.state["{scanner_name}_total"] = 0
        ctx.source("file-not-found")
        return

    # Use the shared cache for any decompile work (avoids 12x redundant unpacks)
    try:
        unpacked_dir = get_unpacked(apk_path)
    except Exception as e:
        ctx.state["{scanner_name}_error"] = str(e)
        return

    # === YOUR SCANNER LOGIC HERE ===
    # Example for {tooling}:
    #   result = subprocess.run(["{tooling}", str(unpacked_dir / "AndroidManifest.xml")],
    #                            capture_output=True, text=True, timeout=60)
    #   parse result.stdout, populate ctx.state with findings
    #
    # Then mark sources used:
    ctx.source("{tooling}")
    ctx.state["{scanner_name}_total"] = 0  # update with real count


INTEL_FIELDS = [
    # ("Display label", "state_key"),
]


@router.post("/api/{module}/{scanner_name}")
async def {module}_{scanner_name}(req: ScanRequest, _=Depends(verify_scan_quota)):
    # req.target is the apk_path uploaded earlier via POST /api/{module}/upload
    apk_path = req.target
    return await run_scanner(
        host=apk_path, tool="{scanner_name}",
        gather_func=gather,
        finding_rules={SCANNER_UPPER}_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
```

Generate WORKING gather() logic. Don't write `# TODO`. Use real subprocess
calls + real parsing. Wrap subprocess.run with timeout. Handle FileNotFoundError
gracefully (binary may have moved). The scanner runs against ONE uploaded file
per scan — don't loop over multiple APKs.

Output ONLY the complete Python file. No markdown fences. No explanation.
"""


PROMPT_FINDINGS = """Generate the findings rules file for a VulnusLab scanner.

Path: tools/_payloads/{scanner_name}_findings.py

Scanner: {scanner_name}
Role: {scanner_role}
Expected findings: {expected_findings}

REFERENCE (from Recon's wayback_findings.py — same pattern you must follow):
```python
{findings_example}
```

Generate the file. It must contain:

1. Module docstring (1 line for the scanner)
2. At least 3 rule_*(s) functions:
   - rule_positive_emit — if state has nothing, return POSITIVE finding with evidence and remediation
   - rule_<descriptive>  — at least 2 more for the actual findings the scanner produces
3. {SCANNER_UPPER}_FINDING_RULES = [list of the rule functions]

Each rule function takes the state dict (named `s`), returns either:
- None (rule doesn't fire) OR
- A dict with keys: name, severity, evidence (REQUIRED — must be observable fact),
  remediation, cwe, owasp, optionally cvss

Severity values: POSITIVE, INFO, LOW, MEDIUM, HIGH, CRITICAL.

ZERO FALSE POSITIVES: a rule fires ONLY when state has concrete evidence the
scanner actually observed something. Don't write speculative rules.

Output ONLY the complete Python file. No markdown fences.
"""


# ─────────────────── PHASES ───────────────────

def phase_a_research(client, module: str, n_tiers: int, n_scanners: int,
                     mode: str = "passive") -> dict:
    print(f"  [A] Researching '{module}' domain (mode={mode}) ...")
    plan_path = PLAN_DIR / f"{module}.json"

    if mode == "binary-static":
        prompt = PROMPT_LAYER_2_BINARY_STATIC.format(
            module=module, n_tiers=n_tiers, n_scanners=n_scanners,
        )
        system = SYSTEM_PROMPT_BINARY_STATIC
    else:
        prompt = PROMPT_LAYER_2.format(
            module=module, n_tiers=n_tiers, n_scanners=n_scanners,
        )
        system = SYSTEM_PROMPT

    raw = _ask(client, prompt, system=system, max_tokens=4000)

    try:
        plan = _extract_json(raw)
    except Exception as e:
        print(f"      ERROR parsing plan JSON: {e}")
        print(f"      AI output (first 500 chars): {raw[:500]}")
        raise

    # Persist (include mode marker so downstream phases know which prompts to use)
    plan["mode"] = mode
    plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    n_actual = sum(len(t.get("scanners", [])) for t in plan.get("tiers", []))
    print(f"      done. {len(plan['tiers'])} tiers, {n_actual} scanners. Plan: {plan_path}")
    return plan


def phase_b_scaffold(plan: dict) -> None:
    module = plan["module"]
    print(f"  [B] Scaffolding skeleton ...")
    if (ROOT / "tools" / module).exists():
        print(f"      tools/{module}/ already exists — skipping forge_module.py")
        return

    tier_ids = [t["id"] for t in plan["tiers"]]
    cmd = [sys.executable, str(ROOT / "scripts" / "forge_module.py"), module,
           "--tiers"] + tier_ids
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"      ERROR scaffold: {result.stderr}")
        raise SystemExit(1)
    print(f"      done.")


def phase_cd_scanners(client, plan: dict, examples: dict) -> list[tuple[str, Path]]:
    """Generate every scanner file + its findings file using AI.

    Returns list of (scanner_name, scanner_path) for downstream phases.
    """
    module = plan["module"]
    module_role = plan.get("module_role", "")
    mode = plan.get("mode", "passive")
    binary_type = plan.get("binary_type", "APK")
    written = []

    total_scanners = sum(len(t["scanners"]) for t in plan["tiers"])
    idx = 0

    for tier in plan["tiers"]:
        tier_id = tier["id"]
        for scanner in tier["scanners"]:
            idx += 1
            name = scanner["name"]
            print(f"  [C/D {idx}/{total_scanners}] AI generating {name} (mode={mode}) ...")

            # Branch by mode — passive uses HTTP example; binary-static uses
            # subprocess template baked into the prompt
            if mode == "binary-static":
                scanner_src = _ask(client, PROMPT_SCANNER_BINARY_STATIC.format(
                    module=module, module_role=module_role,
                    binary_type=binary_type,
                    tier_id=tier_id, scanner_name=name,
                    scanner_role=scanner.get("role", ""),
                    tooling=scanner.get("tooling", "subprocess CLI"),
                    expected_findings=scanner.get("expected_findings", ""),
                    SCANNER_UPPER=name.upper(),
                ), system=SYSTEM_PROMPT_BINARY_STATIC, max_tokens=12000)
            else:
                scanner_src = _ask(client, PROMPT_SCANNER.format(
                    module=module, module_role=module_role,
                    tier_id=tier_id, scanner_name=name,
                    scanner_role=scanner.get("role", ""),
                    data_source=scanner.get("data_source", ""),
                    expected_findings=scanner.get("expected_findings", ""),
                    SCANNER_UPPER=name.upper(),
                    scanner_example=examples["scanner_example"][:4000],
                ), system=SYSTEM_PROMPT, max_tokens=12000)
            scanner_src = _extract_python(scanner_src)

            # Validate Python syntax
            try:
                ast.parse(scanner_src)
            except SyntaxError as e:
                print(f"      WARN scanner syntax error: {e} — saving anyway as .ai_draft")
                draft = ROOT / "tools" / module / tier_id / f"{name}.py.ai_draft"
                draft.parent.mkdir(parents=True, exist_ok=True)
                draft.write_text(scanner_src, encoding="utf-8")
                continue

            scanner_path = ROOT / "tools" / module / tier_id / f"{name}.py"
            scanner_path.parent.mkdir(parents=True, exist_ok=True)
            scanner_path.write_text(scanner_src, encoding="utf-8")

            # The findings file
            findings_src = _ask(client, PROMPT_FINDINGS.format(
                scanner_name=name,
                SCANNER_UPPER=name.upper(),
                scanner_role=scanner.get("role", ""),
                expected_findings=scanner.get("expected_findings", ""),
                findings_example=examples["findings_example"][:3000],
            ), system=SYSTEM_PROMPT, max_tokens=6000)  # findings can have 10+ rules
            findings_src = _extract_python(findings_src)

            try:
                ast.parse(findings_src)
            except SyntaxError as e:
                print(f"      WARN findings syntax error: {e}")
                continue

            findings_path = ROOT / "tools" / "_payloads" / f"{name}_findings.py"
            findings_path.write_text(findings_src, encoding="utf-8")
            written.append((name, scanner_path))
            print(f"      written: {scanner_path.relative_to(ROOT)}")

    return written


def phase_e_orchestrator(plan: dict) -> None:
    """forge_module.py already wrote the orchestrator with one starter per tier.
    Replace it with one containing ALL the AI-generated scanners.
    """
    module = plan["module"]
    print(f"  [E] Updating orchestrator with {sum(len(t['scanners']) for t in plan['tiers'])} scanners ...")
    orch_path = ROOT / "endpoints" / f"{module}_orchestrator.py"
    if not orch_path.exists():
        print(f"      ERROR: orchestrator not found ({orch_path})")
        return

    src = orch_path.read_text(encoding="utf-8")
    # Find the TOOLS_BY_TIER dict — generated by forge_module.py
    new_body_lines = []
    for tier in plan["tiers"]:
        tier_id = tier["id"]
        new_body_lines.append(f'    "{tier_id}": [')
        for scanner in tier["scanners"]:
            n = scanner["name"]
            new_body_lines.append(f'        ("{n}", "/api/{module}/{n}"),')
        new_body_lines.append("    ],")
    new_body = "\n".join(new_body_lines)

    # Pattern: ANY existing TOOLS_BY_TIER content. Match from { after _TOOLS_BY_TIER to matching }
    pattern = re.compile(
        r'(_TOOLS_BY_TIER:\s*dict\[str, list\[tuple\[str, str\]\]\]\s*=\s*\{)\n(.+?)\n(\})',
        re.DOTALL,
    )
    new_src, n = pattern.subn(lambda m: f"{m.group(1)}\n{new_body}\n{m.group(3)}", src)
    if n == 0:
        print(f"      WARN: could not patch orchestrator (pattern not found). Manual edit needed.")
        return
    orch_path.write_text(new_src, encoding="utf-8")
    print(f"      done.")


def phase_f_frontend_snippets(plan: dict) -> Path:
    """Write App.js paste snippets to scripts/_FORGE_OUTPUT_<module>.md.

    NOTE: full App.js auto-patching deferred — too risky to free-edit a 14k-line
    file. The agent writes ready-to-paste snippets with line markers.
    """
    module = plan["module"]
    print(f"  [F] Generating App.js snippets ...")
    cap = module.capitalize()
    MOD = module.upper()

    scanners = [(s["name"], s["role"]) for t in plan["tiers"] for s in t["scanners"]]

    phases_lines = [
        f'  {{name:"{n.replace("_"," ").title()}", tool:"{n}", '
        f'endpoint:"/api/{module}/{n}", icon:"🔹"}},  // {role}'
        for n, role in scanners
    ]
    headers_lines = [
        f'  "{t["id"]}": {{label:"{t["label"]}", color:"#3b82f6"}},'
        for t in plan["tiers"]
    ]

    body = f"""# {cap} module — App.js paste snippets
Generated by vl_foundry.py.

## 1) Paste this near the bottom of src/App.js (alongside OSINT_PHASES etc.):

```javascript
// ═══════════════════════════════════════════════════════════════
//  {MOD} MODULE — VL-FOUNDRY forge
// ═══════════════════════════════════════════════════════════════
const {MOD}_PHASES = [
{chr(10).join(phases_lines)}
];

const {MOD}_SECTION_HEADERS = {{
{chr(10).join(headers_lines)}
}};
```

## 2) Add a tab handler that consumes both:

```javascript
// Inside your main component's tab routing:
function {cap}Tab({{target, token}}) {{
  const [results, setResults] = React.useState({{}});
  const runScan = async () => {{
    const r = await fetch("/api/{module}/run_all", {{
      method: "POST",
      headers: {{"Content-Type":"application/json", Authorization:`Bearer ${{token}}`}},
      body: JSON.stringify({{target, concurrency: 6}})
    }});
    // ... handle NDJSON stream ...
  }};
  return (
    <div>
      {{ {MOD}_PHASES.map(p => <div key={{p.tool}}>{{p.icon}} {{p.name}}</div>) }}
      <button onClick={{runScan}}>Scan</button>
      <button onClick={{() => generate{cap}Report({{target, allResults: results, date: new Date().toLocaleString()}})}}>Download PDF</button>
    </div>
  );
}}
```

## 3) PDF generator

Copy `generateOsintReport` (App.js ~line 10960) and rename to `generate{cap}Report`.
Customize the per-tool sections to match these scanners:
{chr(10).join(f"  - {n}: {role}" for n, role in scanners)}

## 4) After pasting, verify:

```bash
python scripts/score_module.py {module}
```

Layer 22 should now show 3/3 ✅ and score >= 85.
"""

    out_path = ROOT / "scripts" / f"_FORGE_OUTPUT_{module}.md"
    out_path.write_text(body, encoding="utf-8")
    print(f"      written: {out_path.relative_to(ROOT)}")
    return out_path


def phase_g_score_and_heal(client, plan: dict, examples: dict) -> float:
    """Run scorer; if <85, ask AI to fix failing scanners; retry up to 3."""
    module = plan["module"]
    for attempt in range(1, MAX_HEAL_ATTEMPTS + 1):
        print(f"  [G] Scoring (attempt {attempt}/{MAX_HEAL_ATTEMPTS}) ...")
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "score_module.py"), module, "--verbose"],
            capture_output=True, text=True,
        )
        out = result.stdout
        # Parse score
        m = re.search(r"SCORE:\s*(\d+\.?\d*)", out)
        score = float(m.group(1)) if m else 0.0
        print(f"      score: {score}/100")
        if score >= TARGET_SCORE:
            return score

        # Heal — find scanners that failed >= 3 checks
        failing = re.findall(
            r"❌\s+(\w+)\s+\d/7", out
        )
        if not failing:
            print(f"      no per-scanner failures detected — bailing.")
            return score
        print(f"      healing {len(failing)} scanner(s): {', '.join(failing[:5])}")

        for name in failing[:3]:  # cap heal calls per attempt
            scanner_paths = list((ROOT / "tools" / module).rglob(f"{name}.py"))
            if not scanner_paths:
                continue
            sp = scanner_paths[0]
            current = sp.read_text(encoding="utf-8")
            heal_prompt = (
                f"This VulnusLab scanner failed the 7-check Definition of Done.\n\n"
                f"CURRENT FILE ({sp.relative_to(ROOT)}):\n```python\n{current}\n```\n\n"
                f"REFERENCE (correct shape, scored 99.2/100):\n```python\n{examples['scanner_example'][:3500]}\n```\n\n"
                f"Rewrite the scanner to pass all 7 checks. The 7 checks are:\n"
                f"1. precheck — call recon_host() or safe_get() at start\n"
                f"2. uniform_shape — return run_scanner(...)\n"
                f"3. positive_emit — POSITIVE finding when clean\n"
                f"4. severity — every finding has severity\n"
                f"5. remediation — every finding has remediation\n"
                f"6. evidence — every finding has evidence_marker / evidence\n"
                f"7. timeout — explicit timeout= on HTTP calls\n\n"
                f"Output ONLY the corrected Python file. No markdown fences."
            )
            try:
                fixed = _ask(client, heal_prompt, system=SYSTEM_PROMPT, max_tokens=12000)
                fixed = _extract_python(fixed)
                ast.parse(fixed)
                sp.write_text(fixed, encoding="utf-8")
                print(f"        healed: {sp.name}")
            except Exception as e:
                print(f"        heal failed for {sp.name}: {e}")

    return score


# ─────────────────── CLI ───────────────────

def main():
    ap = argparse.ArgumentParser(description="VL-FOUNDRY — autonomous module forge")
    ap.add_argument("module", help="Module name (e.g. mobile, cloud, iot)")
    ap.add_argument("--tiers", type=int, default=4)
    ap.add_argument("--scanners", type=int, default=12)
    ap.add_argument("--dry-run", action="store_true", help="Only generate plan, no code")
    ap.add_argument("--resume", action="store_true", help="Reuse existing plan JSON")
    ap.add_argument("--mode", choices=["passive", "binary-static"], default="passive",
                    help="passive (default — 3rd-party HTTP scanners) or "
                         "binary-static (analyze uploaded APK/IPA/PE/ELF)")
    ap.add_argument("--regenerate-failed", action="store_true",
                    help="Only re-run AI for scanners that ended up as .ai_draft (token-limit failures)")
    args = ap.parse_args()

    if not args.module.replace("_", "").isalnum():
        sys.exit("error: module name must be alphanumeric + underscores")

    print("═" * 65)
    print(f"  VL-FOUNDRY forge — module: {args.module} (mode: {args.mode})")
    print("═" * 65)

    client = _client()
    examples = _load_recon_examples()

    plan_path = PLAN_DIR / f"{args.module}.json"
    if args.resume and plan_path.exists():
        print(f"  [A] Resuming from plan: {plan_path}")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    else:
        plan = phase_a_research(client, args.module, args.tiers, args.scanners, mode=args.mode)

    if args.dry_run:
        print(f"\nDry run — plan saved to {plan_path}. No code generated.")
        return

    # Regenerate-only mode: ONLY rerun the AI for scanners that previously
    # failed (.ai_draft files). Cheap (~$0.30 vs $1.50 full forge) and avoids
    # re-clobbering the working scanners.
    if args.regenerate_failed:
        draft_files = list((ROOT / "tools" / args.module).rglob("*.py.ai_draft"))
        if not draft_files:
            print(f"  No .ai_draft files in tools/{args.module}/ — nothing to regenerate.")
            return
        print(f"  Found {len(draft_files)} failed scanner(s):")
        for d in draft_files:
            print(f"    {d.relative_to(ROOT)}")
        # Subset the plan to only failed scanners
        failed_names = {d.name.replace(".py.ai_draft", "") for d in draft_files}
        reduced_plan = dict(plan)
        reduced_plan["tiers"] = [
            {**t, "scanners": [s for s in t["scanners"] if s["name"] in failed_names]}
            for t in plan["tiers"]
        ]
        reduced_plan["tiers"] = [t for t in reduced_plan["tiers"] if t["scanners"]]
        phase_cd_scanners(client, reduced_plan, examples)
        # Delete the old drafts that now have working .py
        for d in draft_files:
            real = d.with_suffix("")  # foo.py.ai_draft -> foo.py
            if real.exists():
                d.unlink()
                print(f"    removed stale draft: {d.relative_to(ROOT)}")
        # Rerun scoring
        score = phase_g_score_and_heal(client, plan, examples)
        print(f"\n  Final score after regeneration: {score}/100")
        return

    phase_b_scaffold(plan)
    phase_cd_scanners(client, plan, examples)
    phase_e_orchestrator(plan)
    snippets = phase_f_frontend_snippets(plan)
    score = phase_g_score_and_heal(client, plan, examples)

    print("─" * 65)
    print(f"  Final score: {score}/100")
    print(f"  Plan: {plan_path.relative_to(ROOT)}")
    print(f"  App.js snippets: {snippets.relative_to(ROOT)}")
    print(f"\n  Next steps:")
    print(f"    1. Review the generated code in tools/{args.module}/")
    print(f"    2. Paste the App.js snippets from {snippets.relative_to(ROOT)}")
    print(f"    3. Re-run scorer to confirm Layer 22 passes: python scripts/score_module.py {args.module}")
    print(f"    4. Commit + push + ./scripts/deploy.sh {args.module}")
    print("═" * 65)


if __name__ == "__main__":
    main()
