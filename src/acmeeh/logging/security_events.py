"""Structured security event logger.

Emits standardized security events for SIEM integration.
All events are logged to the ``acmeeh.security`` logger with
a consistent ``event_id`` field for filtering and alerting.

Sensitive material (JWK key values, PEM bodies, CSR data) is
automatically redacted via :func:`~acmeeh.logging.sanitize.sanitize_for_logs`
before emission.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from acmeeh.logging.sanitize import sanitize_for_logs

if TYPE_CHECKING:
    from uuid import UUID

security_log = logging.getLogger("acmeeh.security")

_NONCE_PREVIEW_LENGTH = 16


def _emit(
    event_id: str,
    message: str,
    *args: Any,  # noqa: ANN401
    account_id: UUID | None = None,
    severity: str = "INFO",
    **extra: Any,  # noqa: ANN401
) -> None:
    """Emit a structured security event.

    All *extra* keyword arguments are sanitized to redact
    cryptographic material before logging.
    """
    sanitized_extra = sanitize_for_logs(extra)
    data: dict[str, object] = {
        "event_id": event_id,
        "severity": severity,
    }
    if account_id is not None:
        data["account_id"] = str(account_id)
    data.update(sanitized_extra)
    level = getattr(logging, severity.upper(), logging.INFO)
    security_log.log(level, message, *args, extra=data)


def account_created(
    account_id: UUID,
    thumbprint: str,
    contacts: list[str],
) -> None:
    """Log creation of a new ACME account."""
    _emit(
        "acmeeh.security.account_created",
        "Account created: %s",
        account_id,
        thumbprint=thumbprint,
        contacts=contacts,
    )


def account_deactivated(account_id: UUID) -> None:
    """Log deactivation of an ACME account."""
    _emit(
        "acmeeh.security.account_deactivated",
        "Account deactivated: %s",
        account_id,
        severity="WARNING",
    )


def account_revoked(account_id: UUID, reason: str = "") -> None:
    """Log server-initiated revocation of an ACME account."""
    _emit(
        "acmeeh.security.account_revoked",
        "Account revoked: %s reason=%s",
        account_id,
        reason,
        reason=reason,
        severity="WARNING",
    )


def key_changed(
    account_id: UUID,
    old_thumbprint: str,
    new_thumbprint: str,
) -> None:
    """Log an account key change event."""
    _emit(
        "acmeeh.security.key_changed",
        "Key changed for account %s",
        account_id,
        old_thumbprint=old_thumbprint,
        new_thumbprint=new_thumbprint,
        severity="WARNING",
    )


def certificate_issued(
    account_id: UUID,
    serial_number: str,
    domains: list[str],
) -> None:
    """Log issuance of a new certificate."""
    _emit(
        "acmeeh.security.certificate_issued",
        "Certificate issued: serial=%s, domains=%s",
        serial_number,
        domains,
        account_id=account_id,
    )


def certificate_revoked(
    account_id: UUID,
    serial_number: str,
    reason: str,
) -> None:
    """Log revocation of a certificate."""
    _emit(
        "acmeeh.security.certificate_revoked",
        "Certificate revoked: serial=%s, reason=%s",
        serial_number,
        reason,
        account_id=account_id,
        severity="WARNING",
    )


def admin_login_failed(username: str, ip_address: str) -> None:
    """Log a failed admin login attempt."""
    _emit(
        "acmeeh.security.admin_login_failed",
        "Admin login failed: user=%s, ip=%s",
        username,
        ip_address,
        severity="WARNING",
    )


def admin_login_succeeded(username: str, ip_address: str) -> None:
    """Log a successful admin login."""
    _emit(
        "acmeeh.security.admin_login_succeeded",
        "Admin login succeeded: user=%s, ip=%s",
        username,
        ip_address,
    )


def admin_login_lockout(key: str) -> None:
    """Log an admin login lockout event."""
    _emit(
        "acmeeh.security.admin_login_lockout",
        "Admin login lockout triggered: %s",
        key,
        severity="WARNING",
    )


def eab_credential_used(account_id: UUID, eab_kid: str) -> None:
    """Log use of an EAB credential during account registration."""
    _emit(
        "acmeeh.security.eab_credential_used",
        "EAB credential used: kid=%s, account=%s",
        eab_kid,
        account_id,
        account_id=account_id,
    )


def challenge_validation_failed(
    challenge_id: UUID,
    identifier: str,
    challenge_type: str,
    reason: str,
    *,
    account_id: UUID | None = None,
) -> None:
    """Log a failed challenge validation attempt."""
    _emit(
        "acmeeh.security.challenge_validation_failed",
        "Challenge validation failed: challenge=%s, identifier=%s, type=%s, reason=%s",
        challenge_id,
        identifier,
        challenge_type,
        reason,
        account_id=account_id,
        challenge_type=challenge_type,
        identifier=identifier,
        severity="WARNING",
    )


def jws_signature_failed(
    thumbprint: str,
    client_ip: str,
    detail: str,
) -> None:
    """Log a JWS signature verification failure."""
    _emit(
        "acmeeh.security.jws_signature_failed",
        "JWS signature verification failed: thumbprint=%s, ip=%s, detail=%s",
        thumbprint,
        client_ip,
        detail,
        thumbprint=thumbprint,
        client_ip=client_ip,
        severity="WARNING",
    )


def rate_limit_exceeded(
    key: str,
    category: str,
    client_ip: str,
) -> None:
    """Log a rate limit exceedance event."""
    _emit(
        "acmeeh.security.rate_limit_exceeded",
        "Rate limit exceeded: key=%s, category=%s, ip=%s",
        key,
        category,
        client_ip,
        category=category,
        client_ip=client_ip,
        severity="WARNING",
    )


def order_rejected(
    account_id: UUID,
    identifiers: list[str],
    reason: str,
) -> None:
    """Log rejection of an ACME order."""
    _emit(
        "acmeeh.security.order_rejected",
        "Order rejected: account=%s, identifiers=%s, reason=%s",
        account_id,
        identifiers,
        reason,
        account_id=account_id,
        identifiers=identifiers,
        severity="WARNING",
    )


def certificate_downloaded(
    account_id: UUID,
    serial_number: str,
) -> None:
    """Log download of a certificate by an account."""
    _emit(
        "acmeeh.security.certificate_downloaded",
        "Certificate downloaded: serial=%s, account=%s",
        serial_number,
        account_id,
        account_id=account_id,
    )


def csr_rejected(account_id: UUID, reason: str) -> None:
    """Log rejection of a CSR."""
    _emit(
        "acmeeh.security.csr_rejected",
        "CSR rejected: account=%s, reason=%s",
        account_id,
        reason,
        account_id=account_id,
        severity="WARNING",
    )


# ── Authentication failures ───────────────────────────────────────────


def nonce_invalid(
    client_ip: str,
    nonce_value: str,
    reason: str,
) -> None:
    """Log an invalid nonce from a client."""
    truncated = (
        nonce_value[:_NONCE_PREVIEW_LENGTH] + "..."
        if len(nonce_value) > _NONCE_PREVIEW_LENGTH
        else nonce_value
    )
    _emit(
        "acmeeh.security.nonce_invalid",
        "Invalid nonce from %s: %s",
        client_ip,
        reason,
        client_ip=client_ip,
        nonce_value=truncated,
        severity="WARNING",
    )


def jws_auth_failed(
    client_ip: str,
    reason: str,
    *,
    thumbprint: str = "",
) -> None:
    """Log a JWS authentication failure."""
    _emit(
        "acmeeh.security.jws_auth_failed",
        "JWS authentication failed from %s: %s",
        client_ip,
        reason,
        client_ip=client_ip,
        thumbprint=thumbprint,
        severity="WARNING",
    )


def key_policy_violation(client_ip: str, detail: str) -> None:
    """Log a key policy violation from a client."""
    _emit(
        "acmeeh.security.key_policy_violation",
        "Key policy violation from %s: %s",
        client_ip,
        detail,
        client_ip=client_ip,
        severity="WARNING",
    )


# ── Authorization lifecycle ───────────────────────────────────────────


def authorization_deactivated(
    account_id: UUID,
    authz_id: UUID,
    identifier: str,
) -> None:
    """Log deactivation of an authorization."""
    _emit(
        "acmeeh.security.authorization_deactivated",
        "Authorization deactivated: authz=%s, identifier=%s",
        authz_id,
        identifier,
        account_id=account_id,
        severity="WARNING",
    )


# ── External CA calls ────────────────────────────────────────────────


def external_ca_call(
    action: str,
    backend: str,
    *,
    serial_number: str = "",
    success: bool = True,  # noqa: FBT001, FBT002
    detail: str = "",
) -> None:
    """Log a call to an external CA backend."""
    _emit(
        "acmeeh.security.external_ca_call",
        "External CA %s via %s: success=%s %s",
        action,
        backend,
        success,
        detail,
        backend=backend,
        serial_number=serial_number,
        success=success,
        severity="INFO" if success else "WARNING",
    )


# ── Maintenance / operational ─────────────────────────────────────────


def maintenance_mode_changed(
    enabled: bool,  # noqa: FBT001
    changed_by: str,
) -> None:
    """Log a change to the maintenance mode setting."""
    _emit(
        "acmeeh.security.maintenance_mode_changed",
        "Maintenance mode %s by %s",
        "ENABLED" if enabled else "DISABLED",
        changed_by,
        enabled=enabled,
        severity="WARNING",
    )


def bulk_revocation(
    admin_user: str,
    count: int,
    *,
    reason: str = "",
    filter_desc: str = "",
) -> None:
    """Log a bulk certificate revocation event."""
    _emit(
        "acmeeh.security.bulk_revocation",
        "Bulk revocation by %s: %d certificates, filter=%s",
        admin_user,
        count,
        filter_desc,
        admin_user=admin_user,
        count=count,
        reason=reason,
        severity="WARNING",
    )
