"""ai_llm tier4_advisory — honest advisory-by-design coverage.

Many playbook techniques in module_playbooks/23_ai_llm.md genuinely CANNOT
be detected from an external SaaS scanner: they require model weights /
training-data access, host or cloud credentials, multi-turn human-driven
red-teaming, white-box gradient access (GCG), or post-compromise foothold.

Per VulnusLab policy (VA not PT; zero false positives), those techniques are
surfaced as INFO findings with an [ADVISORY-BY-DESIGN] marker and
vulnerable:false — never as a fabricated graded severity. This keeps the
report honest: the customer sees the technique is intentionally informational,
not a forge gap, and gets the manual / red-team reference.
"""
