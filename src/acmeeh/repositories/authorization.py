"""Authorization repository."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pypgkit import BaseRepository, Database

from acmeeh.core.types import AuthorizationStatus, IdentifierType
from acmeeh.models.authorization import Authorization

if TYPE_CHECKING:
    from uuid import UUID

log = logging.getLogger(__name__)


class AuthorizationRepository(BaseRepository[Authorization]):
    table_name = "authorizations"
    primary_key = "id"

    def _row_to_entity(self, row: dict) -> Authorization:
        return Authorization(
            id=row["id"],
            account_id=row["account_id"],
            identifier_type=IdentifierType(row["identifier_type"]),
            identifier_value=row["identifier_value"],
            status=AuthorizationStatus(row["status"]),
            expires=row.get("expires"),
            wildcard=row["wildcard"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _entity_to_row(self, entity: Authorization) -> dict:
        return {
            "id": entity.id,
            "account_id": entity.account_id,
            "identifier_type": entity.identifier_type.value,
            "identifier_value": entity.identifier_value,
            "status": entity.status.value,
            "expires": entity.expires,
            "wildcard": entity.wildcard,
        }

    def find_reusable(
        self,
        account_id: UUID,
        identifier_type: IdentifierType,
        identifier_value: str,
    ) -> Authorization | None:
        """Find a valid, non-expired authorization for reuse."""
        db = Database.get_instance()
        row = db.fetch_one(
            "SELECT * FROM authorizations "
            "WHERE account_id = %s "
            "  AND identifier_type = %s "
            "  AND identifier_value = %s "
            "  AND status = %s "
            "  AND (expires IS NULL OR expires > now()) "
            "LIMIT 1",
            (
                account_id,
                identifier_type.value,
                identifier_value,
                AuthorizationStatus.VALID.value,
            ),
            as_dict=True,
        )
        return self._row_to_entity(row) if row else None

    def find_by_order(self, order_id: UUID) -> list[Authorization]:
        """Return authorizations linked to an order via the join table."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT a.* FROM authorizations a "
            "JOIN order_authorizations oa ON oa.authorization_id = a.id "
            "WHERE oa.order_id = %s",
            (order_id,),
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def all_valid_for_order(self, order_id: UUID) -> bool:
        """Check if all authorizations for an order are valid using a single query.

        Returns True if the order has at least one authorization and all
        of them have status 'valid'. More efficient than loading all rows.
        """
        db = Database.get_instance()
        row = db.fetch_one(
            "SELECT "
            "  COUNT(*) AS total, "
            "  COUNT(*) FILTER (WHERE a.status = %s) AS valid_count "
            "FROM authorizations a "
            "JOIN order_authorizations oa ON oa.authorization_id = a.id "
            "WHERE oa.order_id = %s",
            (AuthorizationStatus.VALID.value, order_id),
            as_dict=True,
        )
        if row is None:
            return False
        return row["total"] > 0 and row["total"] == row["valid_count"]

    def transition_status(
        self,
        authz_id: UUID,
        from_status: AuthorizationStatus,
        to_status: AuthorizationStatus,
    ) -> Authorization | None:
        """Atomic compare-and-swap status transition.

        Returns the updated authorization, or None if current status
        did not match *from_status*.
        """
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE authorizations SET status = %s WHERE id = %s AND status = %s RETURNING *",
            (to_status.value, authz_id, from_status.value),
            as_dict=True,
        )
        if row is None:
            log.debug(
                "CAS guard failed: authz %s not in %s for transition to %s",
                authz_id,
                from_status.value,
                to_status.value,
            )
        return self._row_to_entity(row) if row else None

    def deactivate_for_account(self, account_id: UUID) -> int:
        """Deactivate all pending/valid authorizations for an account. Returns count."""
        db = Database.get_instance()
        result = db.execute(
            "UPDATE authorizations SET status = %s WHERE account_id = %s AND status IN (%s, %s)",
            (
                AuthorizationStatus.DEACTIVATED.value,
                account_id,
                AuthorizationStatus.PENDING.value,
                AuthorizationStatus.VALID.value,
            ),
        )
        return result if isinstance(result, int) else 0

    def find_expired_pending(self, cutoff=None) -> list[Authorization]:
        """Find pending authorizations whose expires timestamp has passed."""
        db = Database.get_instance()
        if cutoff is not None:
            rows = db.fetch_all(
                "SELECT * FROM authorizations WHERE status = %s AND expires < %s ORDER BY expires",
                (AuthorizationStatus.PENDING.value, cutoff),
                as_dict=True,
            )
        else:
            rows = db.fetch_all(
                "SELECT * FROM authorizations "
                "WHERE status = %s AND expires < now() "
                "ORDER BY expires",
                (AuthorizationStatus.PENDING.value,),
                as_dict=True,
            )
        return [self._row_to_entity(r) for r in rows]
