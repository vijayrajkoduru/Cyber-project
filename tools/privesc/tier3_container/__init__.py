"""tier3_container - Container / cloud privilege-escalation surface probes.

REAL, credential-LESS remote checks for externally exposed container and
orchestration control planes (unauthenticated Docker Engine API, open
kubelet / Kubernetes API). A graded severity is emitted ONLY when an endpoint
ACTUALLY answers an unauthenticated request with recognizable data.

On-host / in-cluster §7 techniques (IMDS->IAM, privileged container,
capability escape, runc Leaky Vessels, K8s RBAC, EKS IRSA) are surfaced as
honest advisory-by-design INFO — they require a foothold and cannot be
SaaS-probed.
"""
