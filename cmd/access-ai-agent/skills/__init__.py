"""access-ai-agent skill package.

Each skill module exposes a ``run(payload: dict) -> dict`` entry point. The
dispatcher in ``main.py`` routes an A2A ``skill_name`` to one of these. Skills
compute a deterministic, rule-based result from the payload and optionally
enrich it with an LLM call (see ``llm.py``); a skill NEVER returns a hardcoded
constant — its output is always a function of the input.
"""
