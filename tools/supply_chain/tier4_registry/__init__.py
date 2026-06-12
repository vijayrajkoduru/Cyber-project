"""supply_chain tier4_registry - package-registry & artifact-store exposure probes.

Real, remote, read-only HTTP probes against the customer target for
self-hosted package registries / artifact stores (npm registry, PyPI
warehouse, Docker Registry v2, Maven, Nexus, Artifactory, Verdaccio,
GitLab package registry) that are reachable WITHOUT authentication.

Playbook §6 (Package Registry Security) + §7 (Container Image Supply Chain).
"""
