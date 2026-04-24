"""Account and AccountContact repositories."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from pypgkit import BaseRepository, Database

from acmeeh.core.types import AccountStatus
from acmeeh.models.account import Account, AccountContact

if TYPE_CHECKING:
    from uuid import UUID

log = logging.getLogger(__name__)


class AccountRepository(BaseRepository[Account]):
    table_name = "accounts"
    primary_key = "id"

    def _row_to_entity(self, row: dict) -> Account:
        return Account(
            id=row["id"],
            jwk_thumbprint=row["jwk_thumbprint"],
            jwk=row["jwk"],
            status=AccountStatus(row["status"]),
            tos_agreed=row["tos_agreed"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            eab_credential_id=row.get("eab_credential_id"),
        )

    def _entity_to_row(self, entity: Account) -> dict:
        return {
            "id": entity.id,
            "jwk_thumbprint": entity.jwk_thumbprint,
            "jwk": Jsonb(entity.jwk),
            "status": entity.status.value,
            "tos_agreed": entity.tos_agreed,
            "eab_credential_id": entity.eab_credential_id,
        }

    def find_by_thumbprint(self, thumbprint: str) -> Account | None:
        """Find an account by its JWK thumbprint."""
        return self.find_one_by({"jwk_thumbprint": thumbprint})

    def update_jwk(
        self,
        account_id: UUID,
        new_jwk: dict,
        new_thumbprint: str,
    ) -> Account | None:
        """Atomically update account JWK and thumbprint.

        Only succeeds if the account is in 'valid' status (CAS guard).

        Returns the updated account, or None if the account was not
        in 'valid' status.
        """
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE accounts "
            "SET jwk = %s, jwk_thumbprint = %s "
            "WHERE id = %s AND status = %s "
            "RETURNING *",
            (Jsonb(new_jwk), new_thumbprint, account_id, AccountStatus.VALID.value),
            as_dict=True,
        )
        if row is None:
            log.debug(
                "CAS guard failed: account %s not in valid status for JWK update",
                account_id,
            )
        return self._row_to_entity(row) if row else None

    def search(
        self,
        filters: dict,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Account]:
        """Search accounts with dynamic filters.

        Supported keys: ``status``, ``eab_only`` (bool), ``eab_kid``,
        ``contact`` (substring on contact URI), ``created_before``,
        ``created_after``.
        """
        db = Database.get_instance()
        conditions: list[str] = []
        params: list = []

        if "status" in filters:
            conditions.append("status = %s")
            params.append(filters["status"])

        if filters.get("eab_only") or "eab_kid" in filters:
            # Filter on the immutable ``accounts.eab_credential_id`` column so
            # accounts rebound away from a reusable EAB still match. The
            # mutable ``admin.eab_credentials.account_id`` back-pointer only
            # tracks the most recent registration and would drop older ones.
            if "eab_kid" in filters:
                conditions.append(
                    "eab_credential_id IN (SELECT id FROM admin.eab_credentials WHERE kid = %s)",
                )
                params.append(filters["eab_kid"])
            else:
                conditions.append("eab_credential_id IS NOT NULL")

        if "contact" in filters:
            conditions.append(
                "id IN (SELECT account_id FROM account_contacts WHERE contact_uri ILIKE %s)",
            )
            params.append(f"%{filters['contact']}%")

        if "created_before" in filters:
            conditions.append("created_at < %s")
            params.append(filters["created_before"])
        if "created_after" in filters:
            conditions.append("created_at > %s")
            params.append(filters["created_after"])

        where = " AND ".join(conditions) if conditions else "TRUE"
        query = (
            f"SELECT * FROM accounts WHERE {where} "
            "ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s"
        )
        params.extend([limit, offset])
        rows = db.fetch_all(query, tuple(params), as_dict=True)
        return [self._row_to_entity(r) for r in rows]

    def find_eab_kids_for_accounts(
        self,
        account_ids: list[UUID],
    ) -> dict[UUID, str]:
        """Return a mapping of account_id -> EAB kid for bound accounts.

        Joins via the immutable ``accounts.eab_credential_id`` column so
        every historical registration keeps its kid in admin listings,
        even after a reusable EAB has been rebound to another account
        (which overwrites the mutable ``admin.eab_credentials.account_id``
        back-pointer).
        """
        if not account_ids:
            return {}
        db = Database.get_instance()
        placeholders = ", ".join(["%s"] * len(account_ids))
        rows = db.fetch_all(
            f"SELECT a.id AS account_id, e.kid "  # noqa: S608
            f"FROM accounts a "
            f"JOIN admin.eab_credentials e ON e.id = a.eab_credential_id "
            f"WHERE a.id IN ({placeholders})",
            tuple(account_ids),
            as_dict=True,
        )
        return {r["account_id"]: r["kid"] for r in rows}

    def deactivate(self, account_id: UUID) -> Account | None:
        """Atomically transition an account from valid → deactivated.

        Returns the updated account, or None if the account was not
        in 'valid' status (CAS guard).
        """
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE accounts SET status = %s WHERE id = %s AND status = %s RETURNING *",
            (AccountStatus.DEACTIVATED.value, account_id, AccountStatus.VALID.value),
            as_dict=True,
        )
        if row is None:
            log.debug(
                "CAS guard failed: account %s not in valid status for deactivation",
                account_id,
            )
        return self._row_to_entity(row) if row else None

    def find_valid_by_eab_credential(self, eab_credential_id: UUID) -> list[Account]:
        """Return all ``valid`` accounts registered with the given EAB.

        Uses the immutable ``accounts.eab_credential_id`` column rather
        than the mutable ``admin.eab_credentials.account_id`` pointer,
        so all historical registrations are returned even when the EAB
        has since been re-bound to another account.
        """
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT * FROM accounts "
            "WHERE eab_credential_id = %s AND status = %s "
            "ORDER BY created_at",
            (eab_credential_id, AccountStatus.VALID.value),
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def revoke(self, account_id: UUID) -> Account | None:
        """Atomically transition an account from valid → revoked (RFC 8555 §7.1.2).

        Returns the updated account, or None if the account was not
        in 'valid' status (CAS guard). Revocation is server-initiated
        (for example, cascading from a revoked EAB credential) and
        cannot be undone.
        """
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE accounts SET status = %s WHERE id = %s AND status = %s RETURNING *",
            (AccountStatus.REVOKED.value, account_id, AccountStatus.VALID.value),
            as_dict=True,
        )
        if row is None:
            log.debug(
                "CAS guard failed: account %s not in valid status for revocation",
                account_id,
            )
        return self._row_to_entity(row) if row else None


class AccountContactRepository(BaseRepository[AccountContact]):
    table_name = "account_contacts"
    primary_key = "id"

    def _row_to_entity(self, row: dict) -> AccountContact:
        return AccountContact(
            id=row["id"],
            account_id=row["account_id"],
            contact_uri=row["contact_uri"],
            created_at=row["created_at"],
        )

    def _entity_to_row(self, entity: AccountContact) -> dict:
        return {
            "id": entity.id,
            "account_id": entity.account_id,
            "contact_uri": entity.contact_uri,
        }

    def find_by_account(self, account_id: UUID) -> list[AccountContact]:
        """Return all contacts for a given account."""
        return self.find_by({"account_id": account_id})

    def replace_for_account(
        self,
        account_id: UUID,
        contacts: list[AccountContact],
    ) -> list[AccountContact]:
        """Replace all contacts for an account atomically.

        Deletes existing contacts and inserts the new set within a
        single transaction.
        """
        db = Database.get_instance()
        with db.transaction() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "DELETE FROM account_contacts WHERE account_id = %s",
                (account_id,),
            )
            results = []
            for contact in contacts:
                row = self._entity_to_row(contact)
                columns = list(row.keys())
                placeholders = ", ".join(["%s"] * len(columns))
                col_list = ", ".join(columns)
                cur.execute(
                    f"INSERT INTO account_contacts ({col_list}) "
                    f"VALUES ({placeholders}) RETURNING *",
                    list(row.values()),
                )
                results.append(self._row_to_entity(cur.fetchone()))
        return results

    def delete_by_account(self, account_id: UUID) -> int:
        """Delete all contacts for a given account. Returns count deleted."""
        return self.delete_by({"account_id": account_id})
