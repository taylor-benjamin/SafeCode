"""Helpers that keep secret values out of reports and logs.

SAFECODE's rule is simple: a secret value is never printed, logged, or
written to a report. These helpers are the last line of defence; the
scanner adapters should also avoid reading secret values in the first place.
"""

from __future__ import annotations

REDACTED = "[REDACTED]"

# Show at most this many leading characters of a secret, and only when the
# secret is long enough that the prefix gives away a negligible fraction of it.
# A prefix such as "AKIA" or "ghp_" helps a developer recognise *which kind*
# of credential leaked without revealing anything usable.
_PREFIX_CHARS = 4
_MIN_LENGTH_FOR_PREFIX = 16


def redact(secret: str) -> str:
    """Return a safe placeholder for a secret value.

    >>> redact("AKIAABCDEFGHIJKLMNOP")
    'AKIA…[REDACTED]'
    >>> redact("hunter2")
    '[REDACTED]'
    """
    if len(secret) >= _MIN_LENGTH_FOR_PREFIX:
        return f"{secret[:_PREFIX_CHARS]}…{REDACTED}"
    return REDACTED


def scrub(text: str, secrets: list[str] | tuple[str, ...]) -> str:
    """Replace every occurrence of each known secret inside text.

    Used on free-form strings (code snippets, scanner messages) that might
    contain a secret we already know about. Longer secrets are replaced
    first so that a secret containing another secret is fully removed.
    """
    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret:
            text = text.replace(secret, redact(secret))
    return text
