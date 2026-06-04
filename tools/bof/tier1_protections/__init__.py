"""tier1_protections - binary mitigation + dangerous-function audit.

Static, mitigation-layer checks that run on every uploaded binary:
  - binary_protection_audit: NX / PIE / RELRO / Canary / Fortify / CET / PAC
  - dangerous_function_detect: strcpy/gets/sprintf/scanf("%s")/system call sites
"""
