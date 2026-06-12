"""supply_chain tier7_dep_confusion - dependency confusion / typosquat probes (playbook §3).

Real, read-only probes against the PUBLIC npm registry (registry.npmjs.org)
for the dependency-confusion primitive: an internally-scoped package
(@org/name) declared in the target's exposed package.json whose scope or
name is UNCLAIMED on the public registry, letting an attacker publish a
malicious public package the build may resolve instead. Detection only.
"""
