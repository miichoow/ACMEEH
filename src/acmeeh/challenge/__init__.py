"""Pluggable ACME challenge validation system.

Exports the abstract base class, the structured error type, and the
registry.
"""

from acmeeh.challenge.base import ChallengeContext, ChallengeError, ChallengeValidator
from acmeeh.challenge.registry import ChallengeRegistry

__all__ = [
    "ChallengeContext",
    "ChallengeError",
    "ChallengeRegistry",
    "ChallengeValidator",
]
