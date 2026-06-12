"""tier6_advisory - advisory-by-design coverage for non-SaaS-probeable techniques.

The auth_attacks playbook includes many techniques that, BY DESIGN, cannot
be detected from an external SaaS scanner: on-prem Active Directory attacks
(Pass-the-Hash/Ticket/Cert, Kerberoasting, delegation abuse, golden/silver
tickets), post-compromise session theft (Pass-the-Cookie/Token), and
human-targeted phishing tooling (EvilGinx2/Modlishka AiTM, MFA fatigue, SIM
swap). These require LAN adjacency, host/domain credentials, a post-exploit
foothold, or social-engineering execution.

This tier enumerates them HONESTLY as [ADVISORY-BY-DESIGN] INFO findings so
the report shows full playbook coverage without ever fabricating a graded
severity for something the scanner did not (and cannot) detect.
"""
