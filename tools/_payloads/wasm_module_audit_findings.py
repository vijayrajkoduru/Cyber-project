"""wasm_module_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("wasm_module_audit_total"):
        return None
    return {"name": "No WebAssembly modules detected in app bundle",
            "severity": "POSITIVE",
            "evidence": "no .wasm files in assets/ or res/raw/",
            "remediation": "Maintain current build practice; WASM expands the RE attack surface.",
            "cwe": "CWE-540", "owasp": "M7:2023"}


def rule_wasm_present(s):
    mods = [m for m in (s.get("wasm_modules") or []) if m.get("valid")]
    if not mods:
        return None
    total_size = sum(m.get("size", 0) for m in mods)
    return {"name": f"{len(mods)} WebAssembly module(s) embedded in app",
            "severity": "INFO",
            "cwe": "CWE-540", "owasp": "M7:2023",
            "evidence": "; ".join(f"{m['rel_path']} ({m.get('size', 0):,} B, v{m.get('version', '?')})" for m in mods[:5]),
            "remediation": f"WASM modules ({total_size:,} bytes total) ship pre-compiled logic that bypasses smali/Java static analysis. Use `wasm-decompile` or `wasm2c` for review."}


def rule_wasm_dwarf_debug(s):
    dwarfed = [m for m in (s.get("wasm_modules") or []) if m.get("has_dwarf")]
    if not dwarfed:
        return None
    return {"name": f"WASM module ships with DWARF debug symbols ({len(dwarfed)} module(s))",
            "severity": "MEDIUM", "cvss": "4.0",
            "cwe": "CWE-489", "owasp": "M10:2023",
            "evidence": "; ".join(m["rel_path"] for m in dwarfed[:5]),
            "remediation": "Strip DWARF debug info from production WASM builds (`wasm-strip module.wasm` or Emscripten `-g0`)."}


def rule_wasm_risky_imports(s):
    risky_modules = []
    risky_calls = {"env.fetch", "env.eval", "env.__cxa_throw", "wasi_snapshot_preview1.path_open"}
    for m in (s.get("wasm_modules") or []):
        hits = [i for i in (m.get("imports") or []) if i in risky_calls]
        if hits:
            risky_modules.append({"path": m["rel_path"], "calls": hits[:5]})
    if not risky_modules:
        return None
    return {"name": f"WASM module imports risky host functions ({len(risky_modules)} module(s))",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-829", "owasp": "M7:2023",
            "evidence": "; ".join(f"{r['path']}: {', '.join(r['calls'])}" for r in risky_modules[:3]),
            "remediation": "WASM imports of fetch / eval / filesystem give the module capabilities beyond pure compute. Review host-WASM boundary."}


WASM_MODULE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_wasm_present,
    rule_wasm_dwarf_debug,
    rule_wasm_risky_imports,
]
