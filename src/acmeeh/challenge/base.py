"""Abstract base class for ACME challenge validators.

All challenge validators (built-in and custom) must inherit from
:class:`ChallengeValidator` and implement :meth:`validate`.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from acmeeh.core.types import ChallengeType

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ChallengeContext:
    """Extra request context for validators that need more than a token.

    Most challenge types validate purely from the token, the account JWK and
    the identifier.  DNS-PERSIST-01 (draft-ietf-acme-dns-persist) also has to
    match the published record against the requesting account's URI and know
    whether a wildcard is being requested, so validators that need this set
    :attr:`ChallengeValidator.requires_context` and receive it as the
    ``context`` keyword.

    Parameters
    ----------
    account_uri:
        The requesting account's ACME URL, or ``None`` when the server could
        not construct one.
    is_wildcard:
        Whether the authorization was created for a wildcard identifier.  The
        identifier value passed to :meth:`ChallengeValidator.validate` always
        has the ``*.`` prefix stripped, so this is the only signal.

    """

    account_uri: str | None = None
    is_wildcard: bool = False


class ChallengeError(Exception):
    """Raised by validators on validation failure.

    Parameters
    ----------
    detail:
        Human-readable description of the failure.
    retryable:
        Whether the failure is transient and the challenge may be retried.

    """

    def __init__(self, detail: str, *, retryable: bool = False) -> None:  # noqa: FBT001, FBT002
        self.detail = detail
        self.retryable = retryable
        super().__init__(detail)


class ChallengeValidator(abc.ABC):
    """Base class for all ACME challenge validators.

    Subclasses must set :attr:`challenge_type` and
    :attr:`supported_identifier_types` as class attributes and
    implement :meth:`validate`.

    Parameters
    ----------
    settings:
        Per-type settings (e.g. ``Http01Settings``, ``TlsAlpn01Settings``).

    """

    challenge_type: ClassVar[ChallengeType]
    """The ACME challenge type this validator handles."""

    supported_identifier_types: ClassVar[frozenset[str]] = frozenset({"dns"})
    """Identifier types this validator can validate.

    For example: ``{"dns"}``, ``{"dns", "ip"}``.
    """

    requires_context: ClassVar[bool] = False
    """Whether :meth:`validate` accepts a ``context`` keyword.

    Left ``False`` by default so validators written against the original
    four-argument signature — including third-party ``ext:`` validators —
    keep working unchanged.
    """

    uses_token: ClassVar[bool] = True
    """Whether this challenge type carries a token.

    DNS-PERSIST-01 has no token and no key authorization, so its challenge
    object omits the ``token`` field.
    """

    def __init__(self, settings: Any = None) -> None:  # noqa: ANN401
        self.settings = settings

        # Read auto_validate from per-type settings, fall back to True
        self._auto_validate: bool = getattr(settings, "auto_validate", True)

        # Read max_retries from per-type settings, fall back to 0
        self._max_retries: int = getattr(settings, "max_retries", 0)

    @property
    def auto_validate(self) -> bool:
        """Whether ChallengeService should validate synchronously."""
        return self._auto_validate

    @property
    def max_retries(self) -> int:
        """Maximum retry count before transitioning to terminal invalid."""
        return self._max_retries

    def supports_identifier(self, identifier_type: str) -> bool:
        """Check whether this validator supports the given identifier type."""
        return identifier_type in self.supported_identifier_types

    @abc.abstractmethod
    def validate(
        self,
        *,
        token: str,
        jwk: dict,
        identifier_type: str,
        identifier_value: str,
    ) -> None:
        """Perform the challenge validation.

        Must raise :class:`ChallengeError` on failure.
        Returning without error indicates success.

        Parameters
        ----------
        token:
            The challenge token.
        jwk:
            The account's JWK dictionary.
        identifier_type:
            ``"dns"`` or ``"ip"``.
        identifier_value:
            The domain name or IP address.

        Notes
        -----
        Validators that set :attr:`requires_context` additionally receive a
        ``context`` keyword holding a :class:`ChallengeContext`.

        """

    def cleanup(  # noqa: B027
        self,
        *,
        token: str,
        identifier_type: str,
        identifier_value: str,
    ) -> None:
        """Optional cleanup after validation (success or failure).

        Default implementation is a no-op.
        """
