"""Admin API data access layer."""

from __future__ import annotations

from typing import TYPE_CHECKING

from psycopg.types.json import Jsonb
from pypgkit import BaseRepository, Database

from acmeeh.admin.models import (
    AdminUser,
    AllowedIdentifier,
    AuditLogEntry,
    CsrProfile,
    EabCredential,
)
from acmeeh.core.types import AdminRole

if TYPE_CHECKING:
    from uuid import UUID


class AdminUserRepository(BaseRepository[AdminUser]):
    schema = "admin"
    table_name = "users"
    primary_key = "id"

    def _row_to_entity(self, row: dict) -> AdminUser:
        return AdminUser(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            password_hash=row["password_hash"],
            role=AdminRole(row["role"]),
            enabled=row["enabled"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_login_at=row.get("last_login_at"),
        )

    def _entity_to_row(self, entity: AdminUser) -> dict:
        return {
            "id": entity.id,
            "username": entity.username,
            "email": entity.email,
            "password_hash": entity.password_hash,
            "role": entity.role.value,
            "enabled": entity.enabled,
        }

    def find_by_username(self, username: str) -> AdminUser | None:
        """Find a user by username."""
        return self.find_one_by({"username": username})

    def update_password(self, user_id: UUID, password_hash: str) -> AdminUser | None:
        """Update a user's password hash."""
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE admin.users SET password_hash = %s WHERE id = %s RETURNING *",
            (password_hash, user_id),
            as_dict=True,
        )
        return self._row_to_entity(row) if row else None

    def update_enabled(self, user_id: UUID, enabled: bool) -> AdminUser | None:
        """Enable or disable a user."""
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE admin.users SET enabled = %s WHERE id = %s RETURNING *",
            (enabled, user_id),
            as_dict=True,
        )
        return self._row_to_entity(row) if row else None

    def update_role(self, user_id: UUID, role: AdminRole) -> AdminUser | None:
        """Change a user's role."""
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE admin.users SET role = %s WHERE id = %s RETURNING *",
            (role.value, user_id),
            as_dict=True,
        )
        return self._row_to_entity(row) if row else None

    def update_last_login(self, user_id: UUID) -> None:
        """Touch last_login_at timestamp."""
        db = Database.get_instance()
        db.execute(
            "UPDATE admin.users SET last_login_at = now() WHERE id = %s",
            (user_id,),
        )

    def count_all(self) -> int:
        """Return the total number of admin users."""
        db = Database.get_instance()
        return db.fetch_value("SELECT count(*) FROM admin.users")


class AuditLogRepository(BaseRepository[AuditLogEntry]):
    schema = "admin"
    table_name = "audit_log"
    primary_key = "id"

    def _row_to_entity(self, row: dict) -> AuditLogEntry:
        return AuditLogEntry(
            id=row["id"],
            user_id=row.get("user_id"),
            action=row["action"],
            target_user_id=row.get("target_user_id"),
            details=row.get("details"),
            ip_address=row.get("ip_address"),
            created_at=row["created_at"],
        )

    def _entity_to_row(self, entity: AuditLogEntry) -> dict:
        row: dict = {
            "id": entity.id,
            "action": entity.action,
        }
        if entity.user_id is not None:
            row["user_id"] = entity.user_id
        if entity.target_user_id is not None:
            row["target_user_id"] = entity.target_user_id
        if entity.details is not None:
            row["details"] = Jsonb(entity.details)
        if entity.ip_address is not None:
            row["ip_address"] = entity.ip_address
        return row

    def find_by_user(self, user_id: UUID, limit: int = 100) -> list[AuditLogEntry]:
        """Return recent audit log entries for a specific user."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT * FROM admin.audit_log WHERE user_id = %s ORDER BY created_at DESC LIMIT %s",
            (user_id, limit),
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def find_recent(self, limit: int = 100) -> list[AuditLogEntry]:
        """Return the most recent audit log entries."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT * FROM admin.audit_log ORDER BY created_at DESC LIMIT %s",
            (limit,),
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def delete_older_than(self, days: int) -> int:
        """Delete audit log entries older than *days*.

        Returns the number of deleted entries.
        """
        db = Database.get_instance()
        return db.execute(
            "DELETE FROM admin.audit_log WHERE created_at < now() - make_interval(days => %s)",
            (days,),
        )

    def search(self, filters: dict, limit: int = 1000) -> list[AuditLogEntry]:
        """Search audit log entries with filters."""
        db = Database.get_instance()
        conditions = []
        params = []

        if "action" in filters:
            conditions.append("action = %s")
            params.append(filters["action"])
        if "user_id" in filters:
            conditions.append("user_id = %s")
            params.append(filters["user_id"])
        if "since" in filters:
            conditions.append("created_at >= %s")
            params.append(filters["since"])
        if "until" in filters:
            conditions.append("created_at <= %s")
            params.append(filters["until"])

        where = " AND ".join(conditions) if conditions else "TRUE"
        query = f"SELECT * FROM admin.audit_log WHERE {where} ORDER BY created_at DESC LIMIT %s"
        params.append(limit)

        rows = db.fetch_all(query, tuple(params), as_dict=True)
        return [self._row_to_entity(r) for r in rows]


class EabCredentialRepository(BaseRepository[EabCredential]):
    schema = "admin"
    table_name = "eab_credentials"
    primary_key = "id"

    def _row_to_entity(self, row: dict) -> EabCredential:
        return EabCredential(
            id=row["id"],
            kid=row["kid"],
            hmac_key=row["hmac_key"],
            label=row.get("label", ""),
            account_id=row.get("account_id"),
            created_by=row.get("created_by"),
            used=row.get("used", False),
            used_at=row.get("used_at"),
            revoked=row.get("revoked", False),
            created_at=row["created_at"],
        )

    def _entity_to_row(self, entity: EabCredential) -> dict:
        row: dict = {
            "id": entity.id,
            "kid": entity.kid,
            "hmac_key": entity.hmac_key,
            "label": entity.label,
            "used": entity.used,
            "revoked": entity.revoked,
        }
        if entity.created_by is not None:
            row["created_by"] = entity.created_by
        if entity.account_id is not None:
            row["account_id"] = entity.account_id
        return row

    def find_by_kid(self, kid: str) -> EabCredential | None:
        """Find an EAB credential by its Key ID."""
        return self.find_one_by({"kid": kid})

    def find_all_ordered(self) -> list[EabCredential]:
        """Return all EAB credentials ordered by creation date."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT * FROM admin.eab_credentials ORDER BY created_at DESC",
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def mark_used(self, kid: str, account_id: UUID) -> EabCredential | None:
        """Mark an EAB credential as used and bind it to an account."""
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE admin.eab_credentials "
            "SET used = true, used_at = now(), account_id = %s "
            "WHERE kid = %s AND used = false AND revoked = false "
            "RETURNING *",
            (account_id, kid),
            as_dict=True,
        )
        return self._row_to_entity(row) if row else None

    def revoke(self, cred_id: UUID) -> EabCredential | None:
        """Revoke an EAB credential."""
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE admin.eab_credentials SET revoked = true WHERE id = %s RETURNING *",
            (cred_id,),
            as_dict=True,
        )
        return self._row_to_entity(row) if row else None

    # -- EAB ↔ Allowed Identifier linkage --

    def add_identifier_association(self, eab_id: UUID, identifier_id: UUID) -> None:
        """Link an allowed identifier to an EAB credential."""
        db = Database.get_instance()
        db.execute(
            "INSERT INTO admin.eab_allowed_identifiers "
            "(eab_credential_id, allowed_identifier_id) VALUES (%s, %s) "
            "ON CONFLICT DO NOTHING",
            (eab_id, identifier_id),
        )

    def remove_identifier_association(self, eab_id: UUID, identifier_id: UUID) -> None:
        """Unlink an allowed identifier from an EAB credential."""
        db = Database.get_instance()
        db.execute(
            "DELETE FROM admin.eab_allowed_identifiers "
            "WHERE eab_credential_id = %s AND allowed_identifier_id = %s",
            (eab_id, identifier_id),
        )

    def find_identifiers_for_eab(self, eab_id: UUID) -> list[AllowedIdentifier]:
        """Return all allowed identifiers linked to an EAB credential."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT ai.* "
            "FROM admin.allowed_identifiers ai "
            "JOIN admin.eab_allowed_identifiers eai "
            "  ON eai.allowed_identifier_id = ai.id "
            "WHERE eai.eab_credential_id = %s "
            "ORDER BY ai.created_at DESC",
            (eab_id,),
            as_dict=True,
        )
        return [
            AllowedIdentifier(
                id=r["id"],
                identifier_type=r["identifier_type"],
                identifier_value=r["identifier_value"],
                created_by=r.get("created_by"),
                created_at=r["created_at"],
            )
            for r in rows
        ]

    # -- EAB ↔ CSR Profile linkage --

    def assign_csr_profile(
        self,
        eab_id: UUID,
        profile_id: UUID,
        assigned_by: UUID | None = None,
    ) -> None:
        """Assign a CSR profile to an EAB credential (UPSERT)."""
        db = Database.get_instance()
        db.execute(
            "INSERT INTO admin.eab_csr_profiles "
            "(eab_credential_id, csr_profile_id, assigned_by) "
            "VALUES (%s, %s, %s) "
            "ON CONFLICT (eab_credential_id) DO UPDATE "
            "SET csr_profile_id = EXCLUDED.csr_profile_id, "
            "    assigned_by = EXCLUDED.assigned_by",
            (eab_id, profile_id, assigned_by),
        )

    def unassign_csr_profile(self, eab_id: UUID, profile_id: UUID) -> None:
        """Remove the CSR profile assignment from an EAB credential."""
        db = Database.get_instance()
        db.execute(
            "DELETE FROM admin.eab_csr_profiles "
            "WHERE eab_credential_id = %s AND csr_profile_id = %s",
            (eab_id, profile_id),
        )

    def find_csr_profile_for_eab(self, eab_id: UUID) -> CsrProfile | None:
        """Return the CSR profile assigned to an EAB credential, or None."""
        db = Database.get_instance()
        row = db.fetch_one(
            "SELECT cp.* "
            "FROM admin.csr_profiles cp "
            "JOIN admin.eab_csr_profiles ecp "
            "  ON ecp.csr_profile_id = cp.id "
            "WHERE ecp.eab_credential_id = %s",
            (eab_id,),
            as_dict=True,
        )
        if row is None:
            return None
        return CsrProfile(
            id=row["id"],
            name=row["name"],
            profile_data=row["profile_data"],
            description=row.get("description", ""),
            created_by=row.get("created_by"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # -- Account binding (called by AccountService) --

    def bind_account(self, kid: str, account_id: UUID) -> None:
        """Bind an EAB credential to an account (without marking as used)."""
        db = Database.get_instance()
        db.execute(
            "UPDATE admin.eab_credentials SET account_id = %s WHERE kid = %s AND revoked = false",
            (account_id, kid),
        )

    def copy_to_account_by_kid(self, kid: str, account_id: UUID) -> None:
        """Copy EAB-linked identifiers and CSR profile to the account."""
        db = Database.get_instance()
        # Copy allowed identifiers
        db.execute(
            "INSERT INTO admin.account_allowed_identifiers "
            "(allowed_identifier_id, account_id) "
            "SELECT eai.allowed_identifier_id, %s "
            "FROM admin.eab_allowed_identifiers eai "
            "JOIN admin.eab_credentials ec ON ec.id = eai.eab_credential_id "
            "WHERE ec.kid = %s "
            "ON CONFLICT DO NOTHING",
            (account_id, kid),
        )
        # Copy CSR profile
        db.execute(
            "INSERT INTO admin.account_csr_profiles "
            "(account_id, csr_profile_id, assigned_by) "
            "SELECT %s, ecp.csr_profile_id, ecp.assigned_by "
            "FROM admin.eab_csr_profiles ecp "
            "JOIN admin.eab_credentials ec ON ec.id = ecp.eab_credential_id "
            "WHERE ec.kid = %s "
            "ON CONFLICT (account_id) DO UPDATE "
            "SET csr_profile_id = EXCLUDED.csr_profile_id, "
            "    assigned_by = EXCLUDED.assigned_by",
            (account_id, kid),
        )

    def sync_linkage_to_account(self, account_id: UUID) -> None:
        """Sync EAB-linked identifiers and CSR profile to an account.

        Looks up the EAB credential by account_id, so no kid is needed.
        Safe to call even if no EAB is bound — the SELECTs simply return
        zero rows.
        """
        db = Database.get_instance()
        # Copy allowed identifiers from all EAB credentials bound to this account
        db.execute(
            "INSERT INTO admin.account_allowed_identifiers "
            "(allowed_identifier_id, account_id) "
            "SELECT eai.allowed_identifier_id, %s "
            "FROM admin.eab_allowed_identifiers eai "
            "JOIN admin.eab_credentials ec ON ec.id = eai.eab_credential_id "
            "WHERE ec.account_id = %s "
            "ON CONFLICT DO NOTHING",
            (account_id, account_id),
        )
        # Copy CSR profile (last-bound EAB wins if multiple)
        db.execute(
            "INSERT INTO admin.account_csr_profiles "
            "(account_id, csr_profile_id, assigned_by) "
            "SELECT %s, ecp.csr_profile_id, ecp.assigned_by "
            "FROM admin.eab_csr_profiles ecp "
            "JOIN admin.eab_credentials ec ON ec.id = ecp.eab_credential_id "
            "WHERE ec.account_id = %s "
            "LIMIT 1 "
            "ON CONFLICT (account_id) DO UPDATE "
            "SET csr_profile_id = EXCLUDED.csr_profile_id, "
            "    assigned_by = EXCLUDED.assigned_by",
            (account_id, account_id),
        )


class AllowedIdentifierRepository(BaseRepository[AllowedIdentifier]):
    schema = "admin"
    table_name = "allowed_identifiers"
    primary_key = "id"

    def _row_to_entity(self, row: dict) -> AllowedIdentifier:
        return AllowedIdentifier(
            id=row["id"],
            identifier_type=row["identifier_type"],
            identifier_value=row["identifier_value"],
            created_by=row.get("created_by"),
            created_at=row["created_at"],
        )

    def _entity_to_row(self, entity: AllowedIdentifier) -> dict:
        row: dict = {
            "id": entity.id,
            "identifier_type": entity.identifier_type,
            "identifier_value": entity.identifier_value,
        }
        if entity.created_by is not None:
            row["created_by"] = entity.created_by
        return row

    def find_all_with_accounts(self) -> list[tuple]:
        """Return all identifiers with their associated account IDs."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT ai.*, array_remove(array_agg(aai.account_id), NULL) AS account_ids "
            "FROM admin.allowed_identifiers ai "
            "LEFT JOIN admin.account_allowed_identifiers aai "
            "  ON aai.allowed_identifier_id = ai.id "
            "GROUP BY ai.id "
            "ORDER BY ai.created_at DESC",
            as_dict=True,
        )
        return [(self._row_to_entity(r), list(r.get("account_ids") or [])) for r in rows]

    def find_one_with_accounts(self, identifier_id: UUID) -> tuple | None:
        """Return a single identifier with its associated account IDs."""
        db = Database.get_instance()
        row = db.fetch_one(
            "SELECT ai.*, array_remove(array_agg(aai.account_id), NULL) AS account_ids "
            "FROM admin.allowed_identifiers ai "
            "LEFT JOIN admin.account_allowed_identifiers aai "
            "  ON aai.allowed_identifier_id = ai.id "
            "WHERE ai.id = %s "
            "GROUP BY ai.id",
            (identifier_id,),
            as_dict=True,
        )
        if row is None:
            return None
        return (self._row_to_entity(row), list(row.get("account_ids") or []))

    def find_by_type_value(
        self,
        identifier_type: str,
        identifier_value: str,
    ) -> AllowedIdentifier | None:
        """Find by the unique (type, value) pair."""
        return self.find_one_by(
            {
                "identifier_type": identifier_type,
                "identifier_value": identifier_value,
            }
        )

    def find_by_account(self, account_id: UUID) -> list[AllowedIdentifier]:
        """Return all identifiers associated with an account."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT ai.* "
            "FROM admin.allowed_identifiers ai "
            "JOIN admin.account_allowed_identifiers aai "
            "  ON aai.allowed_identifier_id = ai.id "
            "WHERE aai.account_id = %s "
            "ORDER BY ai.created_at DESC",
            (account_id,),
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def add_account_association(self, identifier_id: UUID, account_id: UUID) -> None:
        """Link an identifier to an account."""
        db = Database.get_instance()
        db.execute(
            "INSERT INTO admin.account_allowed_identifiers "
            "(allowed_identifier_id, account_id) VALUES (%s, %s) "
            "ON CONFLICT DO NOTHING",
            (identifier_id, account_id),
        )

    def remove_account_association(self, identifier_id: UUID, account_id: UUID) -> None:
        """Unlink an identifier from an account."""
        db = Database.get_instance()
        db.execute(
            "DELETE FROM admin.account_allowed_identifiers "
            "WHERE allowed_identifier_id = %s AND account_id = %s",
            (identifier_id, account_id),
        )

    def find_allowed_values_for_account(self, account_id: UUID) -> list[tuple]:
        """Return (type, value) pairs for enforcement queries."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT ai.identifier_type, ai.identifier_value "
            "FROM admin.allowed_identifiers ai "
            "JOIN admin.account_allowed_identifiers aai "
            "  ON aai.allowed_identifier_id = ai.id "
            "WHERE aai.account_id = %s",
            (account_id,),
            as_dict=True,
        )
        return [(r["identifier_type"], r["identifier_value"]) for r in rows]


class CsrProfileRepository(BaseRepository[CsrProfile]):
    schema = "admin"
    table_name = "csr_profiles"
    primary_key = "id"

    def _row_to_entity(self, row: dict) -> CsrProfile:
        return CsrProfile(
            id=row["id"],
            name=row["name"],
            profile_data=row["profile_data"],
            description=row.get("description", ""),
            created_by=row.get("created_by"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _entity_to_row(self, entity: CsrProfile) -> dict:
        row: dict = {
            "id": entity.id,
            "name": entity.name,
            "description": entity.description,
            "profile_data": Jsonb(entity.profile_data),
        }
        if entity.created_by is not None:
            row["created_by"] = entity.created_by
        return row

    def find_by_name(self, name: str) -> CsrProfile | None:
        """Find a profile by its unique name."""
        return self.find_one_by({"name": name})

    def find_all_ordered(self) -> list[CsrProfile]:
        """Return all CSR profiles ordered by creation date."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT * FROM admin.csr_profiles ORDER BY created_at DESC",
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def update_profile(
        self,
        profile_id: UUID,
        name: str,
        description: str,
        profile_data: dict,
    ) -> CsrProfile | None:
        """Full replacement update of a CSR profile."""
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE admin.csr_profiles "
            "SET name = %s, description = %s, profile_data = %s "
            "WHERE id = %s RETURNING *",
            (name, description, Jsonb(profile_data), profile_id),
            as_dict=True,
        )
        return self._row_to_entity(row) if row else None

    def find_profile_for_account(self, account_id: UUID) -> CsrProfile | None:
        """Return the CSR profile assigned to an account, or None.

        Falls back to the profile linked via the account's EAB credential
        when no direct account-level assignment exists.
        """
        db = Database.get_instance()
        row = db.fetch_one(
            "SELECT cp.* "
            "FROM admin.csr_profiles cp "
            "JOIN admin.account_csr_profiles acp "
            "  ON acp.csr_profile_id = cp.id "
            "WHERE acp.account_id = %s",
            (account_id,),
            as_dict=True,
        )
        if row is not None:
            return self._row_to_entity(row)
        # Fallback: profile linked through the EAB credential bound to
        # this account.  Covers the case where the admin assigned a
        # profile to the EAB *after* account registration and the
        # client never triggered a newAccount sync.
        row = db.fetch_one(
            "SELECT cp.* "
            "FROM admin.csr_profiles cp "
            "JOIN admin.eab_csr_profiles ecp "
            "  ON ecp.csr_profile_id = cp.id "
            "JOIN admin.eab_credentials ec "
            "  ON ec.id = ecp.eab_credential_id "
            "WHERE ec.account_id = %s "
            "LIMIT 1",
            (account_id,),
            as_dict=True,
        )
        return self._row_to_entity(row) if row else None

    def assign_to_account(
        self,
        profile_id: UUID,
        account_id: UUID,
        assigned_by: UUID | None = None,
    ) -> None:
        """Assign a profile to an account (UPSERT — replaces existing)."""
        db = Database.get_instance()
        db.execute(
            "INSERT INTO admin.account_csr_profiles "
            "(account_id, csr_profile_id, assigned_by) "
            "VALUES (%s, %s, %s) "
            "ON CONFLICT (account_id) DO UPDATE "
            "SET csr_profile_id = EXCLUDED.csr_profile_id, "
            "    assigned_by = EXCLUDED.assigned_by",
            (account_id, profile_id, assigned_by),
        )

    def unassign_from_account(self, profile_id: UUID, account_id: UUID) -> None:
        """Remove the profile-account association."""
        db = Database.get_instance()
        db.execute(
            "DELETE FROM admin.account_csr_profiles WHERE csr_profile_id = %s AND account_id = %s",
            (profile_id, account_id),
        )

    def find_accounts_for_profile(self, profile_id: UUID) -> list[UUID]:
        """Return account IDs associated with a given profile."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT account_id FROM admin.account_csr_profiles WHERE csr_profile_id = %s",
            (profile_id,),
            as_dict=True,
        )
        return [r["account_id"] for r in rows]
