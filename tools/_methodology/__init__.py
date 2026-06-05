"""VL-METHOD - methodology-driven pentest pattern for every scanner.

Replaces the shallow "run tool -> parse output -> done" pattern with
a proper 7-step pentest workflow that EVERY scanner implements:

  1. pre_flight     - is the target reachable + in scope?
  2. fingerprint    - what service / version / framework are we testing?
  3. quick_probe    - 5-second triage (known defaults, common payloads)
  4. deep_scan      - full attack only IF quick_probe finds something
  5. verify         - re-test each finding with a DIFFERENT method
                      -> sets confidence = CONFIRMED | SUSPECTED
  6. privilege_check - escalation context (root / sudo / user / guest)
  7. chain_handoff  - what scanners should follow up on this finding?
                      -> feeds the cross-scanner chaining engine

Underscore-prefixed package so the autoloader skips it; scanners import
from here directly: `from tools._methodology import MethodologyScanner`.

Reference scanner: tools/password/tier1_spray/hydra_ssh_spray.py
"""

from tools._methodology.base import MethodologyScanner, helpers
__all__ = ["MethodologyScanner", "helpers"]
