"""Response serializers for admin API entities."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID

    from acmeeh.admin.models import (
        AdminUser,
        AllowedIdentifier,
        AuditLogEntry,
        CsrProfile,
        EabCredential,
    )
    from acmeeh.models.account import Account, AccountContact


def serialize_admin_user(user: AdminUser) -> dict:
    """Serialize an admin user (excludes password_hash)."""
    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "enabled": user.enabled,
        "created_at": user.created_at.isoformat(),
        "updated_at": user.updated_at.isoformat(),
        "last_login_at": (user.last_login_at.isoformat() if user.last_login_at else None),
    }


def serialize_audit_log(entry: AuditLogEntry) -> dict:
    """Serialize an audit log entry."""
    return {
        "id": str(entry.id),
        "user_id": str(entry.user_id) if entry.user_id else None,
        "action": entry.action,
        "target_user_id": (str(entry.target_user_id) if entry.target_user_id else None),
        "details": entry.details,
        "ip_address": entry.ip_address,
        "created_at": entry.created_at.isoformat(),
    }


def serialize_eab_credential(cred: EabCredential, *, include_hmac: bool = False) -> dict:
    """Serialize an EAB credential.

    The HMAC key is only included when ``include_hmac=True``
    (i.e. at creation time — the only time the admin sees it).
    """
    result = {
        "id": str(cred.id),
        "kid": cred.kid,
        "label": cred.label,
        "created_by": str(cred.created_by) if cred.created_by else None,
        "account_id": str(cred.account_id) if cred.account_id else None,
        "used": cred.used,
        "used_at": cred.used_at.isoformat() if cred.used_at else None,
        "revoked": cred.revoked,
        "created_at": cred.created_at.isoformat(),
    }
    if include_hmac:
        result["hmac_key"] = cred.hmac_key
    return result


def serialize_allowed_identifier(
    identifier: AllowedIdentifier,
    account_ids: list | None = None,
) -> dict:
    """Serialize an allowed identifier."""
    result: dict[str, Any] = {
        "id": str(identifier.id),
        "identifier_type": identifier.identifier_type,
        "identifier_value": identifier.identifier_value,
        "created_by": str(identifier.created_by) if identifier.created_by else None,
        "created_at": identifier.created_at.isoformat(),
    }
    if account_ids is not None:
        result["account_ids"] = [str(a) for a in account_ids]
    return result


def serialize_csr_profile(
    profile: CsrProfile,
    account_ids: list | None = None,
) -> dict:
    """Serialize a CSR profile."""
    result: dict[str, Any] = {
        "id": str(profile.id),
        "name": profile.name,
        "description": profile.description,
        "profile_data": profile.profile_data,
        "created_by": str(profile.created_by) if profile.created_by else None,
        "created_at": profile.created_at.isoformat(),
        "updated_at": profile.updated_at.isoformat(),
    }
    if account_ids is not None:
        result["account_ids"] = [str(a) for a in account_ids]
    return result


def serialize_login_response(user: AdminUser, token: str) -> dict:
    """Serialize a login response with token and user info."""
    return {
        "token": token,
        "user": serialize_admin_user(user),
    }


def serialize_notification(notification) -> dict:
    """Serialize a notification entity."""
    return {
        "id": str(notification.id),
        "notification_type": notification.notification_type.value,
        "recipient": notification.recipient,
        "subject": notification.subject,
        "status": notification.status.value,
        "account_id": str(notification.account_id) if notification.account_id else None,
        "error_detail": notification.error_detail,
        "retry_count": notification.retry_count,
        "created_at": notification.created_at.isoformat(),
        "sent_at": notification.sent_at.isoformat() if notification.sent_at else None,
    }


def serialize_account(
    account: Account,
    *,
    contacts: list[AccountContact] | None = None,
    eab_kid: str | None = None,
    csr_profile_id: UUID | None = None,
    redacted: bool = False,
) -> dict:
    """Serialize an ACME account.

    When ``redacted=True`` (e.g. auditor role), omit the full JWK and
    expose only the thumbprint.
    """
    result: dict[str, Any] = {
        "id": str(account.id),
        "jwk_thumbprint": account.jwk_thumbprint,
        "status": account.status.value,
        "tos_agreed": account.tos_agreed,
        "eab_kid": eab_kid,
        "created_at": account.created_at.isoformat(),
        "updated_at": account.updated_at.isoformat(),
    }
    if not redacted:
        result["jwk"] = account.jwk
    if contacts is not None:
        result["contacts"] = [c.contact_uri for c in contacts]
    if csr_profile_id is not None:
        result["csr_profile_id"] = str(csr_profile_id)
    return result


def serialize_certificate(cert) -> dict:
    """Serialize a certificate entity for admin API."""
    return {
        "id": str(cert.id),
        "account_id": str(cert.account_id),
        "order_id": str(cert.order_id),
        "serial_number": cert.serial_number,
        "fingerprint": cert.fingerprint,
        "not_before": cert.not_before_cert.isoformat(),
        "not_after": cert.not_after_cert.isoformat(),
        "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
        "revocation_reason": cert.revocation_reason.name if cert.revocation_reason else None,
        "san_values": cert.san_values,
        "created_at": cert.created_at.isoformat(),
    }
