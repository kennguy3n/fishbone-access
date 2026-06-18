"""Shared numeric-coercion helpers for the deterministic skills.

JSON has a single ``number`` type, so a value a caller means as a count can
arrive as either ``5`` or ``5.0``, and a genuinely continuous quantity (hours
of access, days since last use) can be fractional. Every skill must read these
uniformly, and — just as importantly — must never treat a JSON ``true``/
``false`` as the number 1/0: ``bool`` is a subclass of ``int`` in Python, so a
bare ``isinstance(x, int)`` silently accepts it. These helpers centralise both
rules so the skills stay consistent with one another instead of each
re-deriving the guard (and drifting, as ``duration_hours`` did by rejecting all
floats while ``avg_command_count`` accepted them).
"""

from __future__ import annotations

import math
from typing import Any


def as_number(value: Any) -> float | None:
    """Return ``value`` as a finite ``float``, or ``None`` when it is not a
    usable number.

    Accepts ``int`` and ``float`` (so a count may arrive as ``5`` or ``5.0``
    and a measured quantity may be fractional). Rejects ``bool`` (a subclass of
    ``int``), non-numeric types, and non-finite floats (``NaN``/``±inf``). Use
    this for continuous quantities and for counts whose only use is an ordered
    comparison; keep the original value for any human-readable output so an
    integer still renders without a trailing ``.0``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    f = float(value)
    if not math.isfinite(f):
        return None
    return f


def as_hour(value: Any) -> int | None:
    """Return a whole-hour-of-day value, or ``None`` when ``value`` is not one.

    Hour-of-day is discrete, so ``9`` and the JSON-equivalent ``9.0`` both map
    to ``9`` while a fractional ``9.5`` is rejected. Bools and non-numerics are
    rejected as in :func:`as_number`. The valid range is intentionally not
    enforced here — callers compare the hour against their own business-hours
    set, and an out-of-range value simply reads as off-hours.
    """
    n = as_number(value)
    if n is None or not n.is_integer():
        return None
    return int(n)
