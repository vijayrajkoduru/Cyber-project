"""tools._core — framework primitives. Never registered as endpoints.

Layout:
    healing.py    — snapshot + auto-restore on tool load failure
    (future)      — response.py, auth.py, http.py (split from _shared.py)

Rule: tools/<category>/*.py imports FROM _core, never the reverse.
"""
