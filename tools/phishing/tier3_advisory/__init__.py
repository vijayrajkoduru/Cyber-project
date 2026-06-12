"""tier3_advisory - Honest advisory-by-design INFO for the phishing playbook
techniques that CANNOT be probed from an external SaaS scanner.

VulnusLab is VA (vulnerability assessment / find-the-exposure), not PT
(penetration testing / weaponized execution). A large part of the phishing
playbook (module_playbooks/26_phishing.md) describes attacker TRADECRAFT
that requires:

  - attacker infrastructure the customer must stand up themselves
    (GoPhish / SET / King Phisher senders, EvilGinx2 / Modlishka / Muraena
    reverse proxies, a credential collector, a TLS cert for a spoof domain)
  - actually SENDING a lure to a human (mass / spear email, smishing SMS,
    vishing call, quishing QR) and observing a click / credential entry
  - post-compromise foothold (session-cookie replay, MFA-bypass with a
    captured session, OAuth refresh-token abuse after a victim consents)
  - human OPSEC / creative work (pretext design, persona building, AI
    voice/face deepfakes, manual A/B testing, campaign psychology)

None of these can be measured by inspecting the customer's public surface,
so this tier emits them as INFO-only [ADVISORY-BY-DESIGN] findings (with
vulnerable:false). They are NOT forge gaps and NOT scaffolds - they are the
honest boundary of what a SaaS scanner can assert. The companion live
probes (email-auth posture, MTA-STS, lookalike CT-log, frameability,
open-redirect, OAuth tenant exposure) cover everything that IS externally
observable.
"""
