# Rules of Engagement (RoE) — template

An engagement cannot run until this is filled and acknowledged
(`python -m red_team_ops init` writes a per-engagement copy you confirm).

- **Client / system owner:** ____________________
- **Authorized by (name, role):** ____________________
- **Written authorization reference:** ____________________
- **Engagement window (start → end):** ____________________
- **In-scope targets** (hosts / CIDRs / domains / apps — explicit):
  - ____________________
- **Explicitly OUT of scope:**
  - ____________________
- **Allowed impact level:** emulation-only (default) | atomic-test-on-authorized-hosts
- **Hard limits (always enforced):** no data destruction, no DoS, no ransomware,
  no real exfiltration, no persistence beyond the engagement window.
- **Emergency stop / deconfliction contact:** ____________________

By running this engine you assert you have written authorization to test the
in-scope targets and accept these rules.
