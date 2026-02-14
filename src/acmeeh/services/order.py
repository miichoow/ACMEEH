"""Order service — ACME order lifecycle (RFC 8555 §7.4).

Handles order creation with identifier validation, authorization
wiring, deduplication, and status queries.
"""

from __future__ import annotations

import encodings.idna  # noqa: F401 — ensure IDNA codec is available
import hashlib
import ipaddress
import json
import logging
import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from acmeeh.app.errors import (
    MALFORMED,
    RATE_LIMITED,
    REJECTED_IDENTIFIER,
    SERVER_INTERNAL,
    UNAUTHORIZED,
    UNSUPPORTED_IDENTIFIER,
    AcmeProblem,
)
from acmeeh.core.types import (
    AuthorizationStatus,
    ChallengeStatus,
    ChallengeType,
    IdentifierType,
    OrderStatus,
)
from acmeeh.db.unit_of_work import UnitOfWork
from acmeeh.logging import security_events
from acmeeh.models.authorization import Authorization
from acmeeh.models.challenge import Challenge
from acmeeh.models.order import Identifier, Order

if TYPE_CHECKING:
    from pypgkit import Database

    from acmeeh.config.settings import (
        ChallengeSettings,
        IdentifierPolicySettings,
        OrderSettings,
        QuotaSettings,
    )
    from acmeeh.hooks.registry import HookRegistry
    from acmeeh.repositories.authorization import AuthorizationRepository
    from acmeeh.repositories.challenge import ChallengeRepository
    from acmeeh.repositories.order import OrderRepository

log = logging.getLogger(__name__)

_MAX_LABEL_LENGTH = 63
_WILDCARD_PREFIX = "*."


def _normalize_idn(value: str) -> str:
    """Normalize an internationalized domain name to A-label (punycode) form.

    If the value is already ASCII, it is returned unchanged (lowercased).
    Non-ASCII labels are encoded via IDNA (RFC 5891).
    """
    try:
        # Fast path: pure ASCII
        value.encode("ascii")
        # RFC 1035 §2.3.4: each label must be 63 octets or less
        for label in value.split("."):
            if label != "*" and len(label) > _MAX_LABEL_LENGTH:
                raise AcmeProblem(
                    REJECTED_IDENTIFIER,
                    f"Domain label '{label}' exceeds "
                    f"{_MAX_LABEL_LENGTH}-byte limit "
                    f"({len(label)} bytes)",
                )
        return value.lower()
    except UnicodeEncodeError:
        pass

    # Encode each label via IDNA
    parts = value.split(".")
    encoded_parts: list[str] = []
    for part in parts:
        if part == "*":
            encoded_parts.append(part)
            continue
        try:
            encoded = part.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError) as err:
            raise AcmeProblem(
                MALFORMED,
                f"Invalid internationalized domain label '{part}' in '{value}'",
            ) from err
        # RFC 1035 §2.3.4: each label must be 63 octets or less
        encoded_len = len(encoded.encode("ascii"))
        if encoded_len > _MAX_LABEL_LENGTH:
            raise AcmeProblem(
                REJECTED_IDENTIFIER,
                f"Domain label '{part}' exceeds "
                f"{_MAX_LABEL_LENGTH}-byte limit after "
                f"punycode encoding ({encoded_len} bytes)",
            )
        encoded_parts.append(encoded)
    return ".".join(encoded_parts).lower()


class OrderService:
    """Manage ACME order lifecycle."""

    def __init__(  # noqa: PLR0913
        self,
        order_repo: OrderRepository,
        authz_repo: AuthorizationRepository,
        challenge_repo: ChallengeRepository,
        order_settings: OrderSettings,
        challenge_settings: ChallengeSettings,
        identifier_policy: IdentifierPolicySettings,
        db: Database,
        hook_registry: HookRegistry | None = None,
        allowlist_repo: Any = None,  # noqa: ANN401
        metrics: Any = None,  # noqa: ANN401
        quota_settings: QuotaSettings | None = None,
        rate_limiter: Any = None,  # noqa: ANN401
    ) -> None:
        """Initialize the order service with its dependencies."""
        self._orders = order_repo
        self._authz = authz_repo
        self._challenges = challenge_repo
        self._order_settings = order_settings
        self._challenge_settings = challenge_settings
        self._policy = identifier_policy
        self._db = db
        self._hooks = hook_registry
        self._allowlist_repo = allowlist_repo
        self._metrics = metrics
        self._quota_settings = quota_settings
        self._rate_limiter = rate_limiter

    def create_order(  # noqa: C901, PLR0912, PLR0915
        self,
        account_id: UUID,
        identifiers: list[dict[str, str]],
        not_before: str | None = None,
        not_after: str | None = None,
        profile: str | None = None,
    ) -> tuple[Order, list[UUID]]:
        """Create a new order with identifier validation and authz wiring.

        Parameters
        ----------
        account_id:
            The owning account's ID.
        identifiers:
            List of ``{"type": "dns"/"ip", "value": "..."}`` dicts.
        not_before, not_after:
            Optional validity window (ISO 8601 strings).
        profile:
            Optional CA profile name.

        Returns
        -------
        tuple
            ``(order, authz_ids)``

        """
        if not identifiers:
            raise AcmeProblem(
                MALFORMED,
                "Order must contain at least one identifier",
            )

        max_ids = self._policy.max_identifiers_per_order
        if len(identifiers) > max_ids:
            raise AcmeProblem(
                MALFORMED,
                f"Too many identifiers ({len(identifiers)}); maximum is {max_ids}",
            )

        # Quota check
        self._check_account_quota(account_id)

        # Parse and validate identifiers
        try:
            parsed = self._parse_identifiers(identifiers)
        except AcmeProblem as exc:
            id_values = [i.get("value", "") for i in identifiers]
            security_events.order_rejected(
                account_id,
                id_values,
                exc.detail,
            )
            raise

        # Per-identifier rate limiting
        if self._rate_limiter is not None:
            for ident in parsed:
                self._rate_limiter.check(
                    ident.value,
                    "new_order_per_identifier",
                )

        # Per-account allowlist enforcement
        if self._policy.enforce_account_allowlist:
            self._enforce_account_allowlist(account_id, parsed)

        # Compute dedup hash
        id_hash = self._compute_hash(parsed)

        # Parse optional timestamps
        nb = _parse_optional_datetime(not_before) if not_before else None
        na = _parse_optional_datetime(not_after) if not_after else None

        expires = datetime.now(UTC) + timedelta(
            seconds=self._order_settings.expiry_seconds,
        )
        authz_expires = datetime.now(UTC) + timedelta(
            seconds=self._order_settings.authorization_expiry_seconds,
        )

        # Enabled challenge types
        enabled_types = [
            ChallengeType(t) for t in self._challenge_settings.enabled if not t.startswith("ext:")
        ]

        # Atomic creation: order + authzs + challenges
        with UnitOfWork(self._db):
            order, authz_ids = self._create_order_atomic(
                account_id=account_id,
                parsed=parsed,
                id_hash=id_hash,
                expires=expires,
                authz_expires=authz_expires,
                nb=nb,
                na=na,
                enabled_types=enabled_types,
            )

        log.info(
            "Created order %s with %d identifiers, %d authzs",
            order.id,
            len(parsed),
            len(authz_ids),
        )

        if self._metrics:
            self._metrics.increment("acmeeh_orders_created_total")

        if self._hooks:
            self._hooks.dispatch(
                "order.creation",
                {
                    "order_id": str(order.id),
                    "account_id": str(account_id),
                    "identifiers": [{"type": i.type.value, "value": i.value} for i in parsed],
                    "authz_ids": [str(a) for a in authz_ids],
                },
            )

        return order, authz_ids

    def _check_account_quota(self, account_id: UUID) -> None:
        """Enforce per-account order-creation quota if configured."""
        if self._quota_settings is None or not self._quota_settings.enabled:
            return
        max_per_day = self._quota_settings.max_orders_per_account_per_day
        if max_per_day <= 0:
            return
        since = datetime.now(UTC) - timedelta(days=1)
        recent_count = self._orders.count_orders_since(
            account_id,
            since,
        )
        if recent_count >= max_per_day:
            raise AcmeProblem(
                RATE_LIMITED,
                f"Account quota exceeded: max {max_per_day} orders per day",
                status=429,
            )

    def _create_order_atomic(  # noqa: PLR0913
        self,
        *,
        account_id: UUID,
        parsed: list[Identifier],
        id_hash: str,
        expires: datetime,
        authz_expires: datetime,
        nb: datetime | None,
        na: datetime | None,
        enabled_types: list[ChallengeType],
    ) -> tuple[Order, list[UUID]]:
        """Create order, authorizations, and challenges atomically.

        Must be called inside a :class:`UnitOfWork` context.
        """
        # Check for existing dedup order
        existing = self._orders.find_pending_for_dedup(
            account_id,
            id_hash,
        )
        if existing is not None:
            authz_ids = self._orders.find_authorization_ids(
                existing.id,
            )
            return existing, authz_ids

        order_id = uuid4()
        order = Order(
            id=order_id,
            account_id=account_id,
            status=OrderStatus.PENDING,
            identifiers=tuple(parsed),
            identifiers_hash=id_hash,
            expires=expires,
            not_before=nb,
            not_after=na,
        )
        self._orders.create(order)

        authz_ids = []
        pending_challenges: list[Challenge] = []
        for ident in parsed:
            is_wildcard = ident.type == IdentifierType.DNS and ident.value.startswith(
                _WILDCARD_PREFIX
            )
            # Base domain for authorization (strip wildcard prefix)
            authz_value = ident.value.removeprefix(_WILDCARD_PREFIX) if is_wildcard else ident.value

            # Try reusing existing valid authorization
            reusable = self._authz.find_reusable(
                account_id,
                ident.type,
                authz_value,
            )
            if reusable is not None:
                self._orders.link_authorization(
                    order_id,
                    reusable.id,
                )
                authz_ids.append(reusable.id)
                continue

            # Create new authorization
            authz_id = uuid4()
            authz = Authorization(
                id=authz_id,
                account_id=account_id,
                identifier_type=ident.type,
                identifier_value=authz_value,
                status=AuthorizationStatus.PENDING,
                expires=authz_expires,
                wildcard=is_wildcard,
            )
            self._authz.create(authz)
            self._orders.link_authorization(order_id, authz_id)
            authz_ids.append(authz_id)

            # Collect challenges for batch insert
            for ctype in enabled_types:
                if not self._challenge_applicable(
                    ctype,
                    ident,
                    is_wildcard,
                ):
                    continue
                token = secrets.token_urlsafe(32)  # noqa: PLR2004
                challenge = Challenge(
                    id=uuid4(),
                    authorization_id=authz_id,
                    type=ctype,
                    token=token,
                    status=ChallengeStatus.PENDING,
                )
                pending_challenges.append(challenge)

        # Batch insert all challenges in one query
        if pending_challenges:
            if hasattr(self._challenges, "create_many"):
                self._challenges.create_many(pending_challenges)
            else:
                for challenge in pending_challenges:
                    self._challenges.create(challenge)

        return order, authz_ids

    def create_renewal_order(
        self,
        account_id: UUID,
        replacing_cert_id: str,
        cert_repo: Any = None,  # noqa: ANN401
    ) -> tuple[Order, list[UUID]]:
        """Create a renewal order replacing an existing certificate.

        Parameters
        ----------
        account_id:
            The owning account's ID.
        replacing_cert_id:
            The ARI certID of the certificate being replaced.
        cert_repo:
            Certificate repository to look up the original certificate.

        Returns
        -------
        tuple
            ``(order, authz_ids)``

        """
        if cert_repo is None:
            raise AcmeProblem(
                SERVER_INTERNAL,
                "Certificate repository not available for renewal",
                status=500,
            )

        # Look up original certificate by serial (certID format)
        cert = cert_repo.find_by_serial(replacing_cert_id)
        if cert is None:
            raise AcmeProblem(
                MALFORMED,
                f"Certificate not found for certID '{replacing_cert_id}'",
                status=404,
            )

        # Verify the certificate belongs to this account
        if cert.account_id != account_id:
            raise AcmeProblem(
                UNAUTHORIZED,
                "Certificate does not belong to this account",
                status=403,
            )

        # Build identifiers from the original cert's SAN values
        identifiers = _build_identifiers_from_sans(cert.san_values)

        if not identifiers:
            raise AcmeProblem(
                MALFORMED,
                "Original certificate has no SAN values to renew",
            )

        # Create order with the same identifiers
        order, authz_ids = self.create_order(
            account_id=account_id,
            identifiers=identifiers,
        )

        # Set the replaces field on the order
        if order.replaces is None:
            order = replace(order, replaces=replacing_cert_id)

        return order, authz_ids

    def get_order(
        self,
        order_id: UUID,
        account_id: UUID,
    ) -> tuple[Order, list[UUID]]:
        """Get an order with ownership check.

        Returns
        -------
        tuple
            ``(order, authz_ids)``

        Raises
        ------
        AcmeProblem
            ``MALFORMED`` if not found, ``UNAUTHORIZED`` if wrong account.

        """
        order = self._orders.find_by_id(order_id)
        if order is None:
            raise AcmeProblem(
                MALFORMED,
                "Order not found",
                status=404,
            )
        if order.account_id != account_id:
            raise AcmeProblem(
                UNAUTHORIZED,
                "Order does not belong to this account",
                status=403,
            )
        authz_ids = self._orders.find_authorization_ids(order_id)
        return order, authz_ids

    def list_orders(self, account_id: UUID) -> list[Order]:
        """List all orders for an account."""
        return self._orders.find_by_account(account_id)

    def list_orders_paginated(
        self,
        account_id: UUID,
        cursor: UUID | None = None,
        limit: int = 50,  # noqa: PLR2004
    ) -> tuple[list[Order], UUID | None]:
        """List orders for an account with cursor-based pagination.

        Return ``(orders, next_cursor)``.
        """
        return self._orders.find_by_account_paginated(
            account_id,
            cursor,
            limit,
        )

    def get_authorization_ids(self, order_id: UUID) -> list[UUID]:
        """Return authorization IDs linked to an order."""
        return self._orders.find_authorization_ids(order_id)

    def _parse_identifiers(  # noqa: C901
        self,
        raw: list[dict[str, str]],
    ) -> list[Identifier]:
        """Parse and validate identifier dicts.

        Collect all per-identifier errors and report them as
        RFC 8555 6.7.1 subproblems when multiple identifiers fail.
        """
        result: list[Identifier] = []
        subproblems: list[dict[str, Any]] = []
        for item in raw:
            id_type = item.get("type", "")
            id_value = item.get("value", "")

            if not id_type or not id_value:
                raise AcmeProblem(
                    MALFORMED,
                    "Each identifier must have 'type' and 'value'",
                )

            # Enforce max identifier value length
            max_len = self._policy.max_identifier_value_length
            if len(id_value) > max_len:
                raise AcmeProblem(
                    REJECTED_IDENTIFIER,
                    f"Identifier value too long ({len(id_value)} chars); maximum is {max_len}",
                )

            try:
                if id_type == "dns":
                    # Normalize IDN to A-label (punycode) + lowercase
                    id_value = _normalize_idn(id_value)
                    self._validate_dns_identifier(id_value)
                    result.append(
                        Identifier(
                            type=IdentifierType.DNS,
                            value=id_value,
                        )
                    )
                elif id_type == "ip":
                    if not self._policy.allow_ip:
                        raise AcmeProblem(
                            UNSUPPORTED_IDENTIFIER,
                            "IP identifiers are not allowed by server policy",
                        )
                    self._validate_ip_identifier(id_value)
                    result.append(
                        Identifier(
                            type=IdentifierType.IP,
                            value=id_value,
                        )
                    )
                else:
                    raise AcmeProblem(
                        UNSUPPORTED_IDENTIFIER,
                        f"Unsupported identifier type '{id_type}'",
                    )
            except AcmeProblem as exc:
                subproblems.append(
                    {
                        "type": exc.error_type,
                        "detail": exc.detail,
                        "identifier": {
                            "type": id_type,
                            "value": id_value,
                        },
                    }
                )

        if subproblems:
            if len(subproblems) == 1:
                # Single failure: raise the original error directly
                sp = subproblems[0]
                raise AcmeProblem(sp["type"], sp["detail"])
            raise AcmeProblem(
                REJECTED_IDENTIFIER,
                f"{len(subproblems)} identifier(s) rejected",
                subproblems=subproblems,
            )

        return result

    def _validate_dns_identifier(self, value: str) -> None:
        """Validate a DNS identifier against policy."""
        is_wildcard = value.startswith(_WILDCARD_PREFIX)
        base_domain = value.removeprefix(_WILDCARD_PREFIX) if is_wildcard else value

        # Reject multi-level wildcards (e.g. *.*.example.com)
        if is_wildcard and "*" in base_domain:
            raise AcmeProblem(
                REJECTED_IDENTIFIER,
                f"Multi-level wildcard '{value}' is not "
                f"permitted; only single-level wildcards "
                f"(*.example.com) are allowed",
            )

        if is_wildcard and not self._policy.allow_wildcards:
            raise AcmeProblem(
                REJECTED_IDENTIFIER,
                "Wildcard identifiers are not allowed by server policy",
            )

        # Check forbidden domains
        for forbidden in self._policy.forbidden_domains:
            if self._domain_matches(base_domain, forbidden):
                raise AcmeProblem(
                    REJECTED_IDENTIFIER,
                    f"Domain '{value}' is forbidden by server policy",
                )

        # Check allowed domains (if configured)
        if self._policy.allowed_domains and not any(
            self._domain_matches(base_domain, allowed) for allowed in self._policy.allowed_domains
        ):
            raise AcmeProblem(
                REJECTED_IDENTIFIER,
                f"Domain '{value}' is not in the allowed domains list",
            )

    def _validate_ip_identifier(self, value: str) -> None:
        """Validate an IP identifier."""
        try:
            ipaddress.ip_address(value)
        except ValueError as err:
            raise AcmeProblem(
                MALFORMED,
                f"Invalid IP address '{value}'",
            ) from err

    @staticmethod
    def _domain_matches(domain: str, pattern: str) -> bool:
        """Check if *domain* matches *pattern*.

        ``*.corp.internal`` matches ``foo.corp.internal`` and
        ``corp.internal`` itself.
        """
        domain = domain.lower().rstrip(".")
        pattern = pattern.lower().rstrip(".")

        if pattern.startswith(_WILDCARD_PREFIX):
            base = pattern.removeprefix(_WILDCARD_PREFIX)
            return domain == base or domain.endswith(
                "." + base,
            )

        return domain == pattern

    @staticmethod
    def _challenge_applicable(
        ctype: ChallengeType,
        identifier: Identifier,
        is_wildcard: bool,  # noqa: FBT001
    ) -> bool:
        """Determine if a challenge type applies to an identifier."""
        if ctype == ChallengeType.HTTP_01:
            # HTTP-01 not valid for wildcards or IP identifiers
            if is_wildcard or identifier.type == IdentifierType.IP:
                return False
        # TLS-ALPN-01 supports both DNS and IP
        # DNS-01 supports DNS only
        return not (ctype == ChallengeType.DNS_01 and identifier.type == IdentifierType.IP)

    @staticmethod
    def _compute_hash(identifiers: list[Identifier]) -> str:
        """Compute a deterministic SHA-256 hash of sorted identifiers."""
        pairs = sorted((i.type.value, i.value.lower()) for i in identifiers)
        canonical = json.dumps(pairs, separators=(",", ":"))
        return hashlib.sha256(
            canonical.encode("utf-8"),
        ).hexdigest()

    def _enforce_account_allowlist(
        self,
        account_id: UUID,
        identifiers: list[Identifier],
    ) -> None:
        """Check each identifier against the account's allowlist."""
        if self._allowlist_repo is None:
            raise AcmeProblem(
                SERVER_INTERNAL,
                "Account allowlist enforcement is enabled "
                "but the allowlist repository is not available "
                "(admin API may be disabled)",
                status=500,
            )

        allowed = self._allowlist_repo.find_allowed_values_for_account(
            account_id,
        )
        if not allowed:
            # No allowlist entries -> nothing is allowed
            if identifiers:
                subproblems = [
                    {
                        "type": REJECTED_IDENTIFIER,
                        "detail": (
                            f"Account is not authorized to request identifier '{ident.value}'"
                        ),
                        "identifier": {
                            "type": ident.type.value,
                            "value": ident.value,
                        },
                    }
                    for ident in identifiers
                ]
                raise AcmeProblem(
                    REJECTED_IDENTIFIER,
                    "Account is not authorized to request the given identifiers",
                    subproblems=subproblems,
                )
            return

        allowed_dns = [v for t, v in allowed if t == "dns"]
        allowed_ips = {v for t, v in allowed if t == "ip"}

        rejected = []
        for ident in identifiers:
            if ident.type == IdentifierType.IP:
                if ident.value not in allowed_ips:
                    rejected.append(ident)
            else:
                # DNS: strip wildcard prefix for matching
                base_domain = ident.value.removeprefix(
                    _WILDCARD_PREFIX,
                )
                if not any(self._domain_matches(base_domain, pattern) for pattern in allowed_dns):
                    rejected.append(ident)

        if rejected:
            subproblems = [
                {
                    "type": REJECTED_IDENTIFIER,
                    "detail": (f"Account is not authorized to request identifier '{ident.value}'"),
                    "identifier": {
                        "type": ident.type.value,
                        "value": ident.value,
                    },
                }
                for ident in rejected
            ]
            raise AcmeProblem(
                REJECTED_IDENTIFIER,
                f"Account is not authorized to request identifier '{rejected[0].value}'",
                subproblems=subproblems,
            )


def _build_identifiers_from_sans(
    san_values: list[str] | None,
) -> list[dict[str, str]]:
    """Build identifier dicts from a certificate's SAN values."""
    if not san_values:
        return []
    identifiers: list[dict[str, str]] = []
    for san in san_values:
        try:
            ipaddress.ip_address(san)
        except ValueError:
            identifiers.append({"type": "dns", "value": san})
        else:
            identifiers.append({"type": "ip", "value": san})
    return identifiers


def _parse_optional_datetime(value: str) -> datetime | None:
    """Parse an ISO 8601 datetime string, returning None on failure."""
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError) as err:
        raise AcmeProblem(
            MALFORMED,
            f"Invalid datetime format: '{value}'",
        ) from err
