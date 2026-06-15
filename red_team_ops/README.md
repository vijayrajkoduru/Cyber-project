# RED TEAM OPS — internal adversary-emulation engine

**Internal tooling. Not exposed to customers. Not wired into the VulnusLab app.**

This is a self-contained, isolated red-team **adversary-emulation** framework
(MITRE Caldera / Atomic-Red-Team style). It plans and emulates ATT&CK
attack-paths against **authorized, in-scope** targets to test detection and
demonstrate impact, then produces a red-team report.

It is **NOT** wired to any VulnusLab module: nothing under `tools/` or
`endpoints/` imports it, it registers no API route, and it has no UI. It runs
only as a standalone CLI by an operator.

## Hard rules (non-negotiable, enforced in code)
1. **Authorized scope only.** Nothing runs until the operator declares the
   in-scope targets and accepts the Rules of Engagement (`AUTHORIZATION.md`).
   Out-of-scope targets are refused.
2. **Non-destructive.** Data destruction, ransomware, DoS, real exfiltration,
   and out-of-scope persistence are blocked by `safety.py` — always.
3. **Emulation, not weaponization.** Techniques are emulated/planned and
   logged for detection-testing. This framework does not ship working exploits,
   malware, or C2 implants.
4. **Full audit log.** Every step is timestamped and recorded.

These rules are what make this *red team* (authorized adversary emulation) and
not an attack tool. Do not remove them.

## Usage
```
python -m red_team_ops init                 # create an engagement + RoE
python -m red_team_ops scenario list        # list emulation scenarios
python -m red_team_ops run --engagement <id> --scenario full_kill_chain
python -m red_team_ops report --engagement <id>
```

## Layout
- `scope.py`         — engagement + authorized-scope + RoE gate
- `safety.py`        — non-destructive safety contract / forbidden-action guard
- `attack_catalog.py`— MITRE ATT&CK technique emulation library
- `engine.py`        — scenario/chain emulation runner (scope+safety enforced)
- `report.py`        — red-team report (kill chain, ATT&CK heatmap, detection gaps)
- `cli.py` / `__main__.py` — standalone entry point

## Legal
For use only on systems you own or are contractually authorized to test under a
signed Rules of Engagement. Unauthorized use is illegal.
