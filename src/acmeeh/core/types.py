"""Enumerated types for the ACMEEH persistence layer.

All enums inherit from ``str, Enum`` so their ``.value`` is a plain
string that psycopg serialises as TEXT and JSON round-trips naturally.
:class:`RevocationReason` inherits from :class:`enum.IntEnum` per
RFC 5280 §5.3.1 integer codes.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum

# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------


class AccountStatus(StrEnum):
    VALID = "valid"
    DEACTIVATED = "deactivated"
    REVOKED = "revoked"


# ---------------------------------------------------------------------------
# Order
# ---------------------------------------------------------------------------


class OrderStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


class AuthorizationStatus(StrEnum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"
    REVOKED = "revoked"


# ---------------------------------------------------------------------------
# Challenge
# ---------------------------------------------------------------------------


class ChallengeStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


# ---------------------------------------------------------------------------
# Identifiers
# ---------------------------------------------------------------------------


class IdentifierType(StrEnum):
    DNS = "dns"
    IP = "ip"


# ---------------------------------------------------------------------------
# Challenge types
# ---------------------------------------------------------------------------


class ChallengeType(StrEnum):
    HTTP_01 = "http-01"
    DNS_01 = "dns-01"
    TLS_ALPN_01 = "tls-alpn-01"


# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------


class NotificationType(StrEnum):
    DELIVERY_SUCCEEDED = "delivery_succeeded"
    DELIVERY_FAILED = "delivery_failed"
    REVOCATION_SUCCEEDED = "revocation_succeeded"
    REVOCATION_FAILED = "revocation_failed"
    REGISTRATION_SUCCEEDED = "registration_succeeded"
    REGISTRATION_FAILED = "registration_failed"
    ADMIN_USER_CREATED = "admin_user_created"
    ADMIN_PASSWORD_RESET = "admin_password_reset"
    EXPIRATION_WARNING = "expiration_warning"
    ORDER_REJECTED = "order_rejected"
    CHALLENGE_FAILED = "challenge_failed"
    CSR_VALIDATION_FAILED = "csr_validation_failed"
    ORDER_STALE_RECOVERED = "order_stale_recovered"
    ACCOUNT_DEACTIVATED = "account_deactivated"
    ACCOUNT_REVOKED = "account_revoked"
    KEY_ROLLOVER_SUCCEEDED = "key_rollover_succeeded"
    ORDER_QUOTA_EXCEEDED = "order_quota_exceeded"
    AUTHORIZATION_DEACTIVATED = "authorization_deactivated"


class NotificationStatus(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Revocation reasons — RFC 5280 §5.3.1
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------


class AdminRole(StrEnum):
    ADMIN = "admin"
    AUDITOR = "auditor"


class RevocationReason(IntEnum):
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    # 7 is unused
    REMOVE_FROM_CRL = 8
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10
