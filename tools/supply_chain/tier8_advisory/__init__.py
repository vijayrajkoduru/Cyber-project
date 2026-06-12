"""supply_chain tier8_advisory - honest advisory-by-design techniques (playbook §1/§4/§5/§6/§7).

These playbook techniques CANNOT be probed from an external SaaS scanner by
design: they require build-system credentials, registry org-admin access,
cluster kubeconfig, on-host execution, signing-key custody, or analyst
judgement. Each endpoint returns an INFO finding with an [ADVISORY-BY-DESIGN]
marker (vulnerable:false) via tools._pack_common._advisory_by_design_response,
so the report shows the technique is intentionally informational — NOT a forge
gap and NEVER a fabricated graded finding.
"""
