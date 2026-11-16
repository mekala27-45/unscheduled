"""The triage agent. It drafts; a person approves; nothing is applied, sent or filed by it.

The model proposes and code decides: every typed field comes from the Phase 1 and Phase 2 services,
a language model only writes plan text and picks which retrieved sources to cite, and every call it
makes goes through the router in this package, which ends at a floor that needs no model at all.
"""
