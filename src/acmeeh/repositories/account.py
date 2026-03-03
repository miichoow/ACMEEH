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
        )

    def _entity_to_row(self, entity: Account) -> dict:
        return {
            "id": entity.id,
            "jwk_thumbprint": entity.jwk_thumbprint,
            "jwk": Jsonb(entity.jwk),
            "status": entity.status.value,
            "tos_agreed": entity.tos_agreed,
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
