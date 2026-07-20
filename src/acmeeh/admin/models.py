"""Admin API domain entities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID

    from acmeeh.core.types import AdminRole

_EPOCH = datetime(1970, 1, 1)


@dataclass(frozen=True)
class AdminUser:
    id: UUID
    username: str
    email: str
    password_hash: str
    role: AdminRole
    enabled: bool
    created_at: datetime = _EPOCH
    updated_at: datetime = _EPOCH
    last_login_at: datetime | None = None
    password_changed_at: datetime = _EPOCH


@dataclass(frozen=True)
class EabCredential:
    id: UUID
    kid: str
    hmac_key: str
    label: str = ""
    account_id: UUID | None = None
    created_by: UUID | None = None
    used: bool = False
    used_at: datetime | None = None
    revoked: bool = False
    created_at: datetime = _EPOCH


@dataclass(frozen=True)
class AllowedIdentifier:
    id: UUID
    identifier_type: str  # "dns" or "ip"
    identifier_value: str
    created_by: UUID | None = None
    created_at: datetime = _EPOCH


@dataclass(frozen=True)
class CsrProfile:
    id: UUID
    name: str
    profile_data: dict[str, Any]
    description: str = ""
    created_by: UUID | None = None
    created_at: datetime = _EPOCH
    updated_at: datetime = _EPOCH


@dataclass(frozen=True)
class AuditLogEntry:
    id: UUID
    action: str
    user_id: UUID | None = None
    target_user_id: UUID | None = None
    details: dict[str, Any] | None = None
    ip_address: str | None = None
    created_at: datetime = _EPOCH
