"""Auto-accept challenge validators.

These validators immediately mark challenges as valid without
performing any real verification.  They are used with the
``acme_proxy`` CA backend where ACMEEH acts as an intermediary ---
the downstream client's challenges are auto-accepted because the
actual domain validation happens upstream between ACMEEH and the
real ACME CA.

Enable via ``challenges.auto_accept: true`` in the configuration file.
Standard challenge type names (``http-01``, ``dns-01``, ``tls-alpn-01``)
are used; the registry transparently substitutes auto-accept validators
when the flag is set.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from acmeeh.challenge.base import ChallengeValidator
from acmeeh.core.types import ChallengeType

log = logging.getLogger(__name__)


class AutoAcceptHttpValidator(ChallengeValidator):
    """Auto-accept validator for HTTP-01 challenges."""

    challenge_type: ClassVar[ChallengeType] = ChallengeType.HTTP_01
    supported_identifier_types: ClassVar[frozenset[str]] = frozenset(
        {"dns", "ip"},
    )

    def __init__(self, settings: Any = None) -> None:  # noqa: ANN401
        """Initialize the HTTP-01 auto-accept validator."""
        super().__init__(settings=settings)
        self._auto_validate = True
        self._max_retries = 0

    def validate(  # noqa: ARG002
        self,
        *,
        token: str,
        jwk: dict[str, Any],
        identifier_type: str,
        identifier_value: str,
    ) -> None:
        """Validate an HTTP-01 challenge by auto-accepting it."""
        log.info(
            "Auto-accepting %s challenge for %s:%s",
            self.challenge_type.value,
            identifier_type,
            identifier_value,
        )


class AutoAcceptDnsValidator(ChallengeValidator):
    """Auto-accept validator for DNS-01 challenges."""

    challenge_type: ClassVar[ChallengeType] = ChallengeType.DNS_01
    supported_identifier_types: ClassVar[frozenset[str]] = frozenset(
        {"dns", "ip"},
    )

    def __init__(self, settings: Any = None) -> None:  # noqa: ANN401
        """Initialize the DNS-01 auto-accept validator."""
        super().__init__(settings=settings)
        self._auto_validate = True
        self._max_retries = 0

    def validate(  # noqa: ARG002
        self,
        *,
        token: str,
        jwk: dict[str, Any],
        identifier_type: str,
        identifier_value: str,
    ) -> None:
        """Validate a DNS-01 challenge by auto-accepting it."""
        log.info(
            "Auto-accepting %s challenge for %s:%s",
            self.challenge_type.value,
            identifier_type,
            identifier_value,
        )


class AutoAcceptTlsValidator(ChallengeValidator):
    """Auto-accept validator for TLS-ALPN-01 challenges."""

    challenge_type: ClassVar[ChallengeType] = ChallengeType.TLS_ALPN_01
    supported_identifier_types: ClassVar[frozenset[str]] = frozenset(
        {"dns", "ip"},
    )

    def __init__(self, settings: Any = None) -> None:  # noqa: ANN401
        """Initialize the TLS-ALPN-01 auto-accept validator."""
        super().__init__(settings=settings)
        self._auto_validate = True
        self._max_retries = 0

    def validate(  # noqa: ARG002
        self,
        *,
        token: str,
        jwk: dict[str, Any],
        identifier_type: str,
        identifier_value: str,
    ) -> None:
        """Validate a TLS-ALPN-01 challenge by auto-accepting it."""
        log.info(
            "Auto-accepting %s challenge for %s:%s",
            self.challenge_type.value,
            identifier_type,
            identifier_value,
        )
