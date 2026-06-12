"""supply_chain tier5_oss_health - open-source project health audit (playbook §8).

Real, read-only probes against PUBLIC project-hosting APIs (GitHub public API,
no auth required) to assess OSS supply-chain health signals: commit activity,
maintainer / bus-factor proxy, archived/abandonment status, security policy
presence, and account-takeover (expired domain) risk. Mirrors OpenSSF
Scorecard signal families that are observable without repo credentials.
"""
