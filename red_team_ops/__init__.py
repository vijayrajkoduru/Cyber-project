"""RED TEAM OPS — internal, isolated adversary-emulation engine.

Authorized, non-destructive red-team emulation. The engine stays isolated (no
route lives here; not autoloaded). It is driven two ways, both internal-only:
  - standalone CLI: `python -m red_team_ops ...` (see README.md), and
  - the dashboard Red Team console, via the SUPERADMIN-ONLY bridge endpoint
    endpoints/red_team_admin.py (imports this package on demand; never exposed
    to paying customers).
The authorized-scope + non-destructive safety contract (scope.py / safety.py)
is enforced inside the engine regardless of caller and must not be weakened.
"""
__version__ = "1.0.0"
__all__ = ["scope", "safety", "attack_catalog", "engine", "report"]
