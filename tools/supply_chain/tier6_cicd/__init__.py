"""supply_chain tier6_cicd - CI/CD pipeline surface exposure probes (playbook §4).

Real, read-only HTTP probes against the customer target for CI/CD surfaces and
build artifacts that should never be web-exposed: an exposed .git directory,
committed CI workflow files, dependency lockfiles, and reachable CI dashboards
(Jenkins, GitLab, Drone, Argo CD, Concourse). Detection only — no exploitation.
"""
