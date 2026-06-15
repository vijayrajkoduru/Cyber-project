"""RED TEAM OPS — internal, isolated adversary-emulation engine.

Authorized, non-destructive red-team emulation. NOT wired into the VulnusLab
app (no API route, no UI, not autoloaded). Standalone CLI only. See README.md.
"""
__version__ = "1.0.0"
__all__ = ["scope", "safety", "attack_catalog", "engine", "report"]
