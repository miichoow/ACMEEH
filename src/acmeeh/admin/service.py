"""Admin user management business logic."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from acmeeh.admin.auth import create_token
from acmeeh.admin.models import (
    AdminUser,
    AllowedIdentifier,
    AuditLogEntry,
    CsrProfile,
    EabCredential,
)
from acmeeh.admin.password import generate_password, hash_password, verify_password
from acmeeh.core.types import AdminRole, NotificationType

if TYPE_CHECKING:
    from acmeeh.admin.repository import (
        AdminUserRepository,
        AllowedIdentifierRepository,
        AuditLogRepository,
        CsrProfileRepository,
        EabCredentialRepository,
    )
    from acmeeh.config.settings import AdminApiSettings
    from acmeeh.repositories.certificate import CertificateRepository
    from acmeeh.repositories.notification import NotificationRepository
    from acmeeh.services.notification import NotificationService

log = logging.getLogger(__name__)


class AdminUserService:
    """Manage admin user CRUD, authentication, and auditing."""

    def __init__(  # noqa: PLR0913
        self,
        user_repo: AdminUserRepository,
        audit_repo: AuditLogRepository,
        settings: AdminApiSettings,
        notification_service: NotificationService | None = None,
        eab_repo: EabCredentialRepository | None = None,
        allowlist_repo: AllowedIdentifierRepository | None = None,
        csr_profile_repo: CsrProfileRepository | None = None,
        notification_repo: NotificationRepository | None = None,
        cert_repo: CertificateRepository | None = None,
    ) -> None:
        """Initialize the admin user service with repositories and settings."""
        self._users = user_repo
        self._audit = audit_repo
        self._settings = settings
        self._notifications = notification_service
        self._eab = eab_repo
        self._allowlist = allowlist_repo
        self._csr_profiles = csr_profile_repo
        self._notification_repo = notification_repo
        self._cert_repo = cert_repo

    def authenticate(
        self,
        username: str,
        password: str,
        ip_address: str | None = None,
    ) -> tuple[AdminUser, str]:
        """Verify credentials and return (user, token).

        Raises ``AcmeProblem`` on failure.
        """
        from acmeeh.admin.auth import ADMIN_UNAUTHORIZED  # noqa: PLC0415
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        user = self._users.find_by_username(username)
        if user is None or not verify_password(password, user.password_hash):
            raise AcmeProblem(
                ADMIN_UNAUTHORIZED,
                "Invalid username or password",
                status=401,
            )

        if not user.enabled:
            raise AcmeProblem(
                ADMIN_UNAUTHORIZED,
                "Account is disabled",
                status=401,
            )

        self._users.update_last_login(user.id)
        token = create_token(
            user,
            self._settings.token_secret,
            self._settings.token_expiry_seconds,
        )

        self._log_action(user.id, "login", ip_address=ip_address)

        return user, token

    def create_user(
        self,
        username: str,
        email: str,
        role: AdminRole = AdminRole.AUDITOR,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> tuple[AdminUser, str]:
        """Create a new admin user with a server-generated password.

        Returns (user, plain_password).
        """
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        existing = self._users.find_by_username(username)
        if existing is not None:
            msg = "urn:acmeeh:admin:error:conflict"
            raise AcmeProblem(
                msg,
                f"Username '{username}' already exists",
                status=409,
            )

        plain_password = generate_password(self._settings.password_length)
        pw_hash = hash_password(plain_password)

        user = AdminUser(
            id=uuid4(),
            username=username,
            email=email,
            password_hash=pw_hash,
            role=role,
            enabled=True,
        )
        self._users.create(user)

        self._log_action(
            actor_id,
            "create_user",
            target_user_id=user.id,
            details={"username": username, "role": role.value},
            ip_address=ip_address,
        )

        self._send_password_email(
            NotificationType.ADMIN_USER_CREATED,
            user,
            plain_password,
        )

        return user, plain_password

    def update_user(
        self,
        user_id: UUID,
        *,
        enabled: bool | None = None,
        role: AdminRole | None = None,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> AdminUser:
        """Update user attributes (enable/disable, role change)."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        user = self._users.find_by_id(user_id)
        if user is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "User not found",
                status=404,
            )

        details: dict[str, Any] = {}
        if enabled is not None and enabled != user.enabled:
            user = self._users.update_enabled(user_id, enabled)
            details["enabled"] = enabled
        if role is not None and role != user.role:
            user = self._users.update_role(user_id, role)
            details["role"] = role.value

        if details:
            self._log_action(
                actor_id,
                "update_user",
                target_user_id=user_id,
                details=details,
                ip_address=ip_address,
            )

        return user

    def delete_user(
        self,
        user_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Delete an admin user."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        user = self._users.find_by_id(user_id)
        if user is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "User not found",
                status=404,
            )

        self._log_action(
            actor_id,
            "delete_user",
            target_user_id=user_id,
            details={"username": user.username},
            ip_address=ip_address,
        )
        self._users.delete(user_id)

    def reset_password(
        self,
        user_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> tuple[AdminUser, str]:
        """Reset a user's password to a new server-generated password.

        Returns (user, plain_password).
        """
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        user = self._users.find_by_id(user_id)
        if user is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "User not found",
                status=404,
            )

        plain_password = generate_password(self._settings.password_length)
        pw_hash = hash_password(plain_password)
        updated_user = self._users.update_password(user_id, pw_hash)
        if updated_user is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Failed to update password",
                status=500,
            )

        self._log_action(
            actor_id,
            "reset_password",
            target_user_id=user_id,
            ip_address=ip_address,
        )

        self._send_password_email(
            NotificationType.ADMIN_PASSWORD_RESET,
            updated_user,
            plain_password,
        )

        return updated_user, plain_password

    def get_user(self, user_id: UUID) -> AdminUser:
        """Get a user by ID."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        user = self._users.find_by_id(user_id)
        if user is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "User not found",
                status=404,
            )
        return user

    def list_users(self) -> list[AdminUser]:
        """List all admin users."""
        return self._users.find_all()

    def bootstrap_admin(self, email: str) -> str | None:
        """Create the initial admin user if no users exist.

        Returns the plain password if a user was created, None otherwise.
        """
        if self._users.count_all() > 0:
            return None

        plain_password = generate_password(self._settings.password_length)
        pw_hash = hash_password(plain_password)

        user = AdminUser(
            id=uuid4(),
            username="admin",
            email=email,
            password_hash=pw_hash,
            role=AdminRole.ADMIN,
            enabled=True,
        )
        self._users.create(user)

        self._log_action(
            None,
            "bootstrap_admin",
            target_user_id=user.id,
            details={"email": email},
        )

        self._send_password_email(
            NotificationType.ADMIN_USER_CREATED,
            user,
            plain_password,
        )

        return plain_password

    def get_audit_log(
        self,
        limit: int = 100,
    ) -> list[AuditLogEntry]:
        """Get recent audit log entries."""
        return self._audit.find_recent(limit)

    def cleanup_audit_log(self, max_age_days: int) -> int:
        """Delete audit log entries older than *max_age_days*.

        Returns the number of deleted entries.
        """
        count = self._audit.delete_older_than(max_age_days)
        if count > 0:
            log.info(
                "Cleaned up %d audit log entries older than %d days",
                count,
                max_age_days,
            )
        return count

    # -- Notification management --

    def list_notifications(
        self,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Any]:
        """List notifications with optional filter and pagination."""
        if self._notification_repo is None:
            return []
        return self._notification_repo.find_all_paginated(
            status,
            limit,
            offset,
        )

    def retry_failed_notifications(self) -> int:
        """Reset failed notifications for retry. Return count."""
        if self._notification_repo is None:
            return 0
        return self._notification_repo.reset_failed_for_retry()

    def purge_notifications(self, days: int) -> int:
        """Purge sent notifications older than days. Return count."""
        if self._notification_repo is None:
            return 0
        return self._notification_repo.purge_old(days)

    # -- Certificate search --

    def search_certificates(
        self,
        filters: dict[str, Any],
        limit: int = 50,
        offset: int = 0,
    ) -> list[Any]:
        """Search certificates with filters."""
        if self._cert_repo is None:
            return []
        return self._cert_repo.search(filters, limit, offset)

    def get_certificate_by_serial(self, serial: str) -> Any:
        """Get a certificate by serial number."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._cert_repo is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Certificate search not available",
                status=503,
            )

        cert = self._cert_repo.find_by_serial(serial)
        if cert is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Certificate not found",
                status=404,
            )
        return cert

    # -- Audit log search --

    def search_audit_log(
        self,
        filters: dict[str, Any],
        limit: int = 1000,
    ) -> list[Any]:
        """Search audit log with filters."""
        return self._audit.search(filters, limit)

    # -- EAB credential management --

    def create_eab(
        self,
        kid: str,
        *,
        label: str = "",
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> EabCredential:
        """Create an EAB credential with admin-supplied kid.

        Generate a server-side HMAC key.
        Return the credential with the plaintext HMAC key
        (base64url-encoded).
        """
        import base64  # noqa: PLC0415
        import secrets  # noqa: PLC0415

        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._eab is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "EAB management is not available",
                status=503,
            )

        if not kid or not kid.strip():
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "EAB 'kid' is required and must not be empty",
                status=400,
            )

        existing = self._eab.find_by_kid(kid)
        if existing is not None:
            msg = "urn:acmeeh:admin:error:conflict"
            raise AcmeProblem(
                msg,
                f"EAB kid '{kid}' already exists",
                status=409,
            )

        # Generate 256-bit HMAC key, base64url-encoded (no padding)
        hmac_raw = secrets.token_bytes(32)
        hmac_key = base64.urlsafe_b64encode(hmac_raw).rstrip(b"=").decode("ascii")

        cred = EabCredential(
            id=uuid4(),
            kid=kid.strip(),
            hmac_key=hmac_key,
            label=label,
            created_by=actor_id,
        )
        self._eab.create(cred)

        self._log_action(
            actor_id,
            "create_eab",
            details={"kid": kid, "label": label},
            ip_address=ip_address,
        )

        return cred

    def list_eab(self) -> list[EabCredential]:
        """List all EAB credentials."""
        if self._eab is None:
            return []
        return self._eab.find_all_ordered()

    def get_eab(self, cred_id: UUID) -> EabCredential:
        """Get a specific EAB credential by ID."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._eab is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "EAB management is not available",
                status=503,
            )
        cred = self._eab.find_by_id(cred_id)
        if cred is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "EAB credential not found",
                status=404,
            )
        return cred

    def revoke_eab(
        self,
        cred_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> EabCredential:
        """Revoke an EAB credential so it can no longer be used."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._eab is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "EAB management is not available",
                status=503,
            )

        cred = self._eab.find_by_id(cred_id)
        if cred is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "EAB credential not found",
                status=404,
            )

        updated = self._eab.revoke(cred_id)
        if updated is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Failed to revoke EAB credential",
                status=500,
            )

        self._log_action(
            actor_id,
            "revoke_eab",
            details={"kid": cred.kid},
            ip_address=ip_address,
        )

        return updated

    # -- EAB ↔ Allowed Identifier linkage --

    def add_eab_identifier(
        self,
        eab_id: UUID,
        identifier_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Associate an allowed identifier with an EAB credential."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._eab is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "EAB management is not available", status=503)

        cred = self._eab.find_by_id(eab_id)
        if cred is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "EAB credential not found", status=404)

        if self._allowlist is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "Allowlist management is not available", status=503)

        ident = self._allowlist.find_by_id(identifier_id)
        if ident is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "Allowed identifier not found", status=404)

        self._eab.add_identifier_association(eab_id, identifier_id)

        self._log_action(
            actor_id,
            "add_eab_identifier",
            details={
                "eab_id": str(eab_id),
                "identifier_id": str(identifier_id),
            },
            ip_address=ip_address,
        )

    def remove_eab_identifier(
        self,
        eab_id: UUID,
        identifier_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Remove an identifier association from an EAB credential."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._eab is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "EAB management is not available", status=503)

        cred = self._eab.find_by_id(eab_id)
        if cred is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "EAB credential not found", status=404)

        self._eab.remove_identifier_association(eab_id, identifier_id)

        self._log_action(
            actor_id,
            "remove_eab_identifier",
            details={
                "eab_id": str(eab_id),
                "identifier_id": str(identifier_id),
            },
            ip_address=ip_address,
        )

    def list_eab_identifiers(self, eab_id: UUID) -> list[AllowedIdentifier]:
        """List all allowed identifiers linked to an EAB credential."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._eab is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "EAB management is not available", status=503)

        cred = self._eab.find_by_id(eab_id)
        if cred is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "EAB credential not found", status=404)

        return self._eab.find_identifiers_for_eab(eab_id)

    # -- EAB ↔ CSR Profile linkage --

    def assign_eab_csr_profile(
        self,
        eab_id: UUID,
        profile_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Assign a CSR profile to an EAB credential."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._eab is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "EAB management is not available", status=503)

        cred = self._eab.find_by_id(eab_id)
        if cred is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "EAB credential not found", status=404)

        if self._csr_profiles is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "CSR profile management is not available", status=503)

        profile = self._csr_profiles.find_by_id(profile_id)
        if profile is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "CSR profile not found", status=404)

        self._eab.assign_csr_profile(eab_id, profile_id, actor_id)

        self._log_action(
            actor_id,
            "assign_eab_csr_profile",
            details={
                "eab_id": str(eab_id),
                "profile_id": str(profile_id),
            },
            ip_address=ip_address,
        )

    def unassign_eab_csr_profile(
        self,
        eab_id: UUID,
        profile_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Remove the CSR profile assignment from an EAB credential."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._eab is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "EAB management is not available", status=503)

        cred = self._eab.find_by_id(eab_id)
        if cred is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "EAB credential not found", status=404)

        if self._csr_profiles is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "CSR profile management is not available", status=503)

        profile = self._csr_profiles.find_by_id(profile_id)
        if profile is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "CSR profile not found", status=404)

        self._eab.unassign_csr_profile(eab_id, profile_id)

        self._log_action(
            actor_id,
            "unassign_eab_csr_profile",
            details={
                "eab_id": str(eab_id),
                "profile_id": str(profile_id),
            },
            ip_address=ip_address,
        )

    def get_eab_csr_profile(self, eab_id: UUID) -> CsrProfile | None:
        """Return the CSR profile assigned to an EAB credential, or None."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._eab is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "EAB management is not available", status=503)

        cred = self._eab.find_by_id(eab_id)
        if cred is None:
            msg = "about:blank"
            raise AcmeProblem(msg, "EAB credential not found", status=404)

        return self._eab.find_csr_profile_for_eab(eab_id)

    # -- Allowed identifier management --

    def list_allowed_identifiers(
        self,
    ) -> list[tuple[AllowedIdentifier, list[UUID]]]:
        """List all allowed identifiers with associated account IDs."""
        if self._allowlist is None:
            return []
        return self._allowlist.find_all_with_accounts()

    def create_allowed_identifier(
        self,
        identifier_type: str,
        identifier_value: str,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> AllowedIdentifier:
        """Create a new allowed identifier."""
        import ipaddress as _ipaddr  # noqa: PLC0415

        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._allowlist is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Allowlist management is not available",
                status=503,
            )

        if identifier_type not in ("dns", "ip"):
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                (f"Invalid identifier type '{identifier_type}'. Must be 'dns' or 'ip'"),
                status=400,
            )

        if not identifier_value or not identifier_value.strip():
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Identifier value is required",
                status=400,
            )

        identifier_value = identifier_value.strip()

        if identifier_type == "ip":
            try:
                addr = _ipaddr.ip_address(identifier_value)
            except ValueError:
                msg = "about:blank"
                raise AcmeProblem(  # noqa: B904
                    msg,
                    f"Invalid IP address '{identifier_value}'",
                    status=400,
                )
            if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
                msg = "about:blank"
                raise AcmeProblem(
                    msg,
                    f"IP address '{identifier_value}' is not allowed (loopback, unspecified, or multicast)",
                    status=400,
                )
        else:
            # Basic domain validation
            identifier_value = identifier_value.lower()
            self._validate_dns_label(identifier_value)

        existing = self._allowlist.find_by_type_value(
            identifier_type,
            identifier_value,
        )
        if existing is not None:
            msg = "urn:acmeeh:admin:error:conflict"
            raise AcmeProblem(
                msg,
                (f"Identifier ({identifier_type}, {identifier_value}) already exists"),
                status=409,
            )

        ident = AllowedIdentifier(
            id=uuid4(),
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            created_by=actor_id,
        )
        self._allowlist.create(ident)

        self._log_action(
            actor_id,
            "create_allowed_identifier",
            details={
                "identifier_type": identifier_type,
                "identifier_value": identifier_value,
            },
            ip_address=ip_address,
        )

        return ident

    def get_allowed_identifier(
        self,
        identifier_id: UUID,
    ) -> tuple[AllowedIdentifier, list[UUID]]:
        """Get an allowed identifier with its associated accounts."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._allowlist is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Allowlist management is not available",
                status=503,
            )

        result = self._allowlist.find_one_with_accounts(identifier_id)
        if result is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Allowed identifier not found",
                status=404,
            )
        return result

    def delete_allowed_identifier(
        self,
        identifier_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Delete an allowed identifier (cascade associations)."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._allowlist is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Allowlist management is not available",
                status=503,
            )

        ident = self._allowlist.find_by_id(identifier_id)
        if ident is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Allowed identifier not found",
                status=404,
            )

        self._log_action(
            actor_id,
            "delete_allowed_identifier",
            details={
                "identifier_type": ident.identifier_type,
                "identifier_value": ident.identifier_value,
            },
            ip_address=ip_address,
        )
        self._allowlist.delete(identifier_id)

    def add_identifier_account(
        self,
        identifier_id: UUID,
        account_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Associate an allowed identifier with an ACME account."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._allowlist is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Allowlist management is not available",
                status=503,
            )

        ident = self._allowlist.find_by_id(identifier_id)
        if ident is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Allowed identifier not found",
                status=404,
            )

        self._allowlist.add_account_association(
            identifier_id,
            account_id,
        )

        self._log_action(
            actor_id,
            "add_identifier_account",
            details={
                "identifier_id": str(identifier_id),
                "account_id": str(account_id),
            },
            ip_address=ip_address,
        )

    def remove_identifier_account(
        self,
        identifier_id: UUID,
        account_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Remove an identifier-account association."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._allowlist is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Allowlist management is not available",
                status=503,
            )

        ident = self._allowlist.find_by_id(identifier_id)
        if ident is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Allowed identifier not found",
                status=404,
            )

        self._allowlist.remove_account_association(
            identifier_id,
            account_id,
        )

        self._log_action(
            actor_id,
            "remove_identifier_account",
            details={
                "identifier_id": str(identifier_id),
                "account_id": str(account_id),
            },
            ip_address=ip_address,
        )

    def list_account_identifiers(
        self,
        account_id: UUID,
    ) -> list[AllowedIdentifier]:
        """List all allowed identifiers for a specific account."""
        if self._allowlist is None:
            return []
        return self._allowlist.find_by_account(account_id)

    # -- CSR profile dry-run validation --

    def validate_csr(
        self,
        profile_id: UUID,
        csr_b64: str,
    ) -> dict[str, Any]:
        """Validate a CSR against a profile without issuing.

        Return ``{"valid": True/False, "violations": [...]}``.
        """
        import base64  # noqa: PLC0415

        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._csr_profiles is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile management is not available",
                status=503,
            )

        profile = self._csr_profiles.find_by_id(profile_id)
        if profile is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile not found",
                status=404,
            )

        # Decode CSR
        try:
            csr_der = base64.b64decode(csr_b64)
        except Exception:  # noqa: BLE001
            msg = "about:blank"
            raise AcmeProblem(  # noqa: B904
                msg,
                "'csr' must be valid base64-encoded DER",
                status=400,
            )

        from cryptography import x509 as _x509  # noqa: PLC0415

        try:
            csr = _x509.load_der_x509_csr(csr_der)
        except Exception as exc:  # noqa: BLE001
            msg = "about:blank"
            raise AcmeProblem(  # noqa: B904
                msg,
                f"Cannot parse CSR: {exc}",
                status=400,
            )

        from acmeeh.services.csr_validator import validate_csr_against_profile  # noqa: PLC0415

        try:
            validate_csr_against_profile(
                csr,
                profile.profile_data,
                certificate_repo=self._cert_repo,
            )
        except AcmeProblem as exc:
            # Extract violations from detail
            detail = exc.detail if hasattr(exc, "detail") else str(exc)
            violations: list[str] = []
            prefix = "CSR profile violations: "
            if detail.startswith(prefix):
                violations = [v.strip() for v in detail[len(prefix) :].split(";")]
            else:
                violations = [detail]
            return {"valid": False, "violations": violations}
        else:
            return {"valid": True, "violations": []}

    # -- CSR profile management --

    def create_csr_profile(  # noqa: PLR0913
        self,
        name: str,
        profile_data: dict[str, Any],
        *,
        description: str = "",
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> CsrProfile:
        """Create a new CSR profile."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._csr_profiles is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile management is not available",
                status=503,
            )

        if not name or not name.strip():
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Profile 'name' is required and must not be empty",
                status=400,
            )

        existing = self._csr_profiles.find_by_name(name.strip())
        if existing is not None:
            msg = "urn:acmeeh:admin:error:conflict"
            raise AcmeProblem(
                msg,
                f"CSR profile '{name}' already exists",
                status=409,
            )

        self._validate_profile_data(profile_data)

        profile = CsrProfile(
            id=uuid4(),
            name=name.strip(),
            description=description,
            profile_data=profile_data,
            created_by=actor_id,
        )
        self._csr_profiles.create(profile)

        self._log_action(
            actor_id,
            "create_csr_profile",
            details={
                "name": name,
                "profile_id": str(profile.id),
            },
            ip_address=ip_address,
        )

        return profile

    def list_csr_profiles(self) -> list[CsrProfile]:
        """List all CSR profiles."""
        if self._csr_profiles is None:
            return []
        return self._csr_profiles.find_all_ordered()

    def get_csr_profile(
        self,
        profile_id: UUID,
    ) -> tuple[CsrProfile, list[UUID]]:
        """Get a CSR profile with its associated account IDs."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._csr_profiles is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile management is not available",
                status=503,
            )

        profile = self._csr_profiles.find_by_id(profile_id)
        if profile is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile not found",
                status=404,
            )

        account_ids = self._csr_profiles.find_accounts_for_profile(
            profile_id,
        )
        return profile, account_ids

    def update_csr_profile(  # noqa: PLR0913
        self,
        profile_id: UUID,
        name: str,
        profile_data: dict[str, Any],
        *,
        description: str = "",
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> CsrProfile:
        """Update a CSR profile (full replacement)."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._csr_profiles is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile management is not available",
                status=503,
            )

        profile = self._csr_profiles.find_by_id(profile_id)
        if profile is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile not found",
                status=404,
            )

        if not name or not name.strip():
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Profile 'name' is required and must not be empty",
                status=400,
            )

        # Check name uniqueness if changed
        if name.strip() != profile.name:
            existing = self._csr_profiles.find_by_name(name.strip())
            if existing is not None:
                msg = "urn:acmeeh:admin:error:conflict"
                raise AcmeProblem(
                    msg,
                    f"CSR profile '{name}' already exists",
                    status=409,
                )

        self._validate_profile_data(profile_data)

        updated = self._csr_profiles.update_profile(
            profile_id,
            name.strip(),
            description,
            profile_data,
        )
        if updated is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Failed to update CSR profile",
                status=500,
            )

        self._log_action(
            actor_id,
            "update_csr_profile",
            details={
                "profile_id": str(profile_id),
                "name": name,
            },
            ip_address=ip_address,
        )

        return updated

    def delete_csr_profile(
        self,
        profile_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Delete a CSR profile (cascade clean associations)."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._csr_profiles is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile management is not available",
                status=503,
            )

        profile = self._csr_profiles.find_by_id(profile_id)
        if profile is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile not found",
                status=404,
            )

        self._log_action(
            actor_id,
            "delete_csr_profile",
            details={
                "name": profile.name,
                "profile_id": str(profile_id),
            },
            ip_address=ip_address,
        )
        self._csr_profiles.delete(profile_id)

    def assign_profile_to_account(  # noqa: PLR0913
        self,
        profile_id: UUID,
        account_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Assign a CSR profile to an ACME account."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._csr_profiles is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile management is not available",
                status=503,
            )

        profile = self._csr_profiles.find_by_id(profile_id)
        if profile is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile not found",
                status=404,
            )

        self._csr_profiles.assign_to_account(
            profile_id,
            account_id,
            actor_id,
        )

        self._log_action(
            actor_id,
            "assign_csr_profile",
            details={
                "profile_id": str(profile_id),
                "account_id": str(account_id),
            },
            ip_address=ip_address,
        )

    def unassign_profile_from_account(  # noqa: PLR0913
        self,
        profile_id: UUID,
        account_id: UUID,
        *,
        actor_id: UUID | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Remove a CSR profile assignment from an account."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if self._csr_profiles is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile management is not available",
                status=503,
            )

        profile = self._csr_profiles.find_by_id(profile_id)
        if profile is None:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "CSR profile not found",
                status=404,
            )

        self._csr_profiles.unassign_from_account(
            profile_id,
            account_id,
        )

        self._log_action(
            actor_id,
            "unassign_csr_profile",
            details={
                "profile_id": str(profile_id),
                "account_id": str(account_id),
            },
            ip_address=ip_address,
        )

    def get_account_csr_profile(
        self,
        account_id: UUID,
    ) -> CsrProfile | None:
        """Return the CSR profile assigned to an account, or None."""
        if self._csr_profiles is None:
            return None
        return self._csr_profiles.find_profile_for_account(account_id)

    @staticmethod
    def _validate_profile_data(  # noqa: C901, PLR0912
        profile_data: dict[str, Any],
    ) -> None:
        """Validate profile_data structure and types."""
        import re as _re  # noqa: PLC0415

        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        if not isinstance(profile_data, dict):
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "'profile_data' must be a JSON object",
                status=400,
            )

        # Validate regex fields are compilable
        for field in (
            "common_name_regex",
            "san_regex",
            "subject_regex",
        ):
            val = profile_data.get(field)
            if val is not None:
                if not isinstance(val, str):
                    msg = "about:blank"
                    raise AcmeProblem(
                        msg,
                        f"'{field}' must be a string",
                        status=400,
                    )
                try:
                    _re.compile(val)
                except _re.error as exc:
                    msg = "about:blank"
                    raise AcmeProblem(  # noqa: B904
                        msg,
                        f"'{field}' is not a valid regex: {exc}",
                        status=400,
                    )

        # Validate authorized_keys is a dict of str -> int
        ak = profile_data.get("authorized_keys")
        if ak is not None:
            if not isinstance(ak, dict):
                msg = "about:blank"
                raise AcmeProblem(
                    msg,
                    "'authorized_keys' must be a JSON object",
                    status=400,
                )
            for k, v in ak.items():
                if not isinstance(v, (int, float)):
                    msg = "about:blank"
                    raise AcmeProblem(
                        msg,
                        f"'authorized_keys[\"{k}\"]' must be a number",
                        status=400,
                    )

        # Validate list fields
        for field in (
            "authorized_signature_algorithms",
            "authorized_key_usages",
            "authorized_extended_key_usages",
            "san_types",
            "depth_base_domains",
        ):
            val = profile_data.get(field)
            if val is not None and not isinstance(val, list):
                msg = "about:blank"
                raise AcmeProblem(
                    msg,
                    f"'{field}' must be a JSON array",
                    status=400,
                )

        # Validate integer fields
        for field in (
            "common_name_minimum",
            "common_name_maximum",
            "san_minimum",
            "san_maximum",
            "renewal_window_days",
            "max_subdomain_depth",
        ):
            val = profile_data.get(field)
            if val is not None and not isinstance(val, int):
                msg = "about:blank"
                raise AcmeProblem(
                    msg,
                    f"'{field}' must be an integer",
                    status=400,
                )

        # Validate boolean fields
        for field in (
            "wildcard_in_common_name",
            "wildcard_in_san",
            "reuse_key",
        ):
            val = profile_data.get(field)
            if val is not None and not isinstance(val, bool):
                msg = "about:blank"
                raise AcmeProblem(
                    msg,
                    f"'{field}' must be a boolean",
                    status=400,
                )

        # Validate max_subdomain_depth >= 0
        msd = profile_data.get("max_subdomain_depth")
        if msd is not None and msd < 0:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "'max_subdomain_depth' must be >= 0",
                status=400,
            )

        # Validate depth_base_domains entries are non-empty strings
        dbd = profile_data.get("depth_base_domains")
        if dbd is not None:
            for i, entry in enumerate(dbd):
                if not isinstance(entry, str) or not entry.strip():
                    msg = "about:blank"
                    raise AcmeProblem(
                        msg,
                        f"'depth_base_domains[{i}]' must be a non-empty string",
                        status=400,
                    )

    # -- internal helpers --

    @staticmethod
    def _validate_dns_label(value: str) -> None:
        """Validate DNS identifier labels (RFC 952 / RFC 1123)."""
        from acmeeh.app.errors import AcmeProblem  # noqa: PLC0415

        # Handle wildcard prefix
        is_wildcard = value.startswith("*.")
        base = value[2:] if is_wildcard else value

        # Reject wildcards not at leftmost position (e.g. foo.*.com)
        if not is_wildcard and "*" in value:
            msg = "about:blank"
            raise AcmeProblem(msg, f"Invalid wildcard in '{value}'", status=400)

        # Reject multi-level wildcards (e.g. *.*.example.com)
        if is_wildcard and "*" in base:
            msg = "about:blank"
            raise AcmeProblem(msg, f"Multi-level wildcard in '{value}' is not allowed", status=400)

        for label in base.split("."):
            if not label:
                continue
            if label.startswith("-") or label.endswith("-"):
                msg = "about:blank"
                raise AcmeProblem(
                    msg,
                    f"DNS label '{label}' must not start or end with a hyphen",
                    status=400,
                )

    def _log_action(
        self,
        user_id: UUID | None,
        action: str,
        *,
        target_user_id: UUID | None = None,
        details: dict[str, Any] | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Record an action in the audit log."""
        entry = AuditLogEntry(
            id=uuid4(),
            user_id=user_id,
            action=action,
            target_user_id=target_user_id,
            details=details,
            ip_address=ip_address,
        )
        self._audit.create(entry)

    def _send_password_email(
        self,
        notification_type: NotificationType,
        user: AdminUser,
        plain_password: str,
    ) -> None:
        """Send a password notification email to the user."""
        if self._notifications is None:
            return
        try:
            self._notifications.notify(
                notification_type,
                account_id=None,
                context={
                    "username": user.username,
                    "email": user.email,
                    "password": plain_password,
                    "role": user.role.value,
                },
                explicit_recipients=[user.email],
            )
        except Exception:  # noqa: BLE001
            log.exception(
                "Failed to send %s notification to %s",
                notification_type.value,
                user.email,
            )
