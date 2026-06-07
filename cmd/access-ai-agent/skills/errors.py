"""Shared skill error types."""
from __future__ import annotations


class SkillError(ValueError):
    """Raised when a skill's payload is malformed.

    The A2A dispatcher catches SkillError and returns HTTP 400; every other
    exception surfaces as HTTP 500 so operators see the traceback in agent logs.
    """
