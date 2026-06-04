"""ai_llm module - AI / LLM security testing (per module_playbooks/23_ai_llm.md).

10 sections, 114 techniques. This package autoloads tier* subdirectories,
each containing real Python probes that exercise OWASP LLM Top 10 (2025)
attack surface against the customer's chatbot / inference endpoint.

Customer input via ScanRequest:
  - target           = LLM endpoint URL (e.g. https://acme.com/api/chat)
  - auth_bearer      = optional bearer token for the customer's endpoint
  - options.headers  = optional dict of extra headers (X-API-Key, etc.)
  - options.prompt_field   = JSON field the endpoint reads the prompt from
  - options.response_field = JSON field the endpoint writes the answer to

Backend dependencies (image-installed):
  - httpx, openai, anthropic, garak, llm_guard

All probes degrade gracefully on ImportError (return INFO with install hint),
mask PII before storing in ctx.state, and respect a default concurrency of 2
because production LLM endpoints rate-limit aggressively.
"""
