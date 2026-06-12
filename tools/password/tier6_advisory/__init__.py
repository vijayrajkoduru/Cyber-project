"""tier6_advisory - honest advisory-by-design scanners for password-attack
techniques that CANNOT be probed from an external SaaS scanner.

These cover module_playbooks/08_password.md sections whose techniques are
inherently:
  * offline (§2 hash cracking - needs the hash, runs on a GPU rig)
  * input-required local processing (§4 hash ID, §5 wordlist/rule gen)
  * post-compromise / on-host extraction (§7 OS-specific password dump)
  * cloud-rig orchestration (§6 distributed cracking)
  * active-attack / manual / red-team (§8 MFA bypass execution)

Each endpoint returns INFO with an [ADVISORY-BY-DESIGN] marker and
vulnerable:false via tools._pack_common._advisory_by_design_response, so a
customer report shows the technique is intentionally informational (NOT a
forge gap and NEVER a fabricated CRITICAL/HIGH). The DETECTION counterparts
that CAN be probed live in tier1_spray / tier4_discovery / tier5_web.
"""
