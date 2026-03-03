"""Order repository."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from psycopg.types.json import Jsonb
from pypgkit import BaseRepository, Database

from acmeeh.core.types import IdentifierType, OrderStatus
from acmeeh.models.order import Identifier, Order

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

log = logging.getLogger(__name__)


class OrderRepository(BaseRepository[Order]):
    table_name = "orders"
    primary_key = "id"

    def _row_to_entity(self, row: dict) -> Order:
        raw_ids = row["identifiers"]
        identifiers = tuple(
            Identifier(type=IdentifierType(i["type"]), value=i["value"]) for i in raw_ids
        )
        return Order(
            id=row["id"],
            account_id=row["account_id"],
            status=OrderStatus(row["status"]),
            identifiers=identifiers,
            identifiers_hash=row["identifiers_hash"],
            expires=row.get("expires"),
            not_before=row.get("not_before"),
            not_after=row.get("not_after"),
            error=row.get("error"),
            certificate_id=row.get("certificate_id"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _entity_to_row(self, entity: Order) -> dict:
        ids_json = [{"type": i.type.value, "value": i.value} for i in entity.identifiers]
        return {
            "id": entity.id,
            "account_id": entity.account_id,
            "status": entity.status.value,
            "identifiers": Jsonb(ids_json),
            "identifiers_hash": entity.identifiers_hash,
            "expires": entity.expires,
            "not_before": entity.not_before,
            "not_after": entity.not_after,
            "error": Jsonb(entity.error) if entity.error is not None else None,
            "certificate_id": entity.certificate_id,
        }

    def find_by_account(
        self,
        account_id: UUID,
        status: OrderStatus | None = None,
    ) -> list[Order]:
        """Find orders for an account, optionally filtered by status."""
        conditions: dict = {"account_id": account_id}
        if status is not None:
            conditions["status"] = status.value
        return self.find_by(conditions)

    def find_by_account_paginated(
        self,
        account_id: UUID,
        cursor: UUID | None = None,
        limit: int = 50,
    ) -> tuple[list[Order], UUID | None]:
        """Find orders for an account with cursor-based pagination.

        Returns ``(orders, next_cursor)`` where *next_cursor* is the
        last order's ID (to pass as *cursor* for the next page) or
        ``None`` when there are no more results.
        """
        db = Database.get_instance()
        # Fetch limit+1 to detect whether there is a next page
        fetch_limit = limit + 1
        if cursor is not None:
            rows = db.fetch_all(
                "SELECT * FROM orders WHERE account_id = %s AND id > %s ORDER BY id LIMIT %s",
                (account_id, cursor, fetch_limit),
                as_dict=True,
            )
        else:
            rows = db.fetch_all(
                "SELECT * FROM orders WHERE account_id = %s ORDER BY id LIMIT %s",
                (account_id, fetch_limit),
                as_dict=True,
            )

        orders = [self._row_to_entity(r) for r in rows[:limit]]
        next_cursor = orders[-1].id if len(rows) > limit else None
        return orders, next_cursor

    def find_pending_for_dedup(
        self,
        account_id: UUID,
        identifiers_hash: str,
    ) -> Order | None:
        """Find a pending/ready order for deduplication (SELECT FOR UPDATE).

        Returns the matching order locked for update, or None.
        Must be called within a UnitOfWork / transaction.
        """
        db = Database.get_instance()
        row = db.fetch_one(
            "SELECT * FROM orders "
            "WHERE account_id = %s "
            "  AND identifiers_hash = %s "
            "  AND status IN (%s, %s) "
            "FOR UPDATE",
            (
                account_id,
                identifiers_hash,
                OrderStatus.PENDING.value,
                OrderStatus.READY.value,
            ),
            as_dict=True,
        )
        return self._row_to_entity(row) if row else None

    def find_stale_processing(self, stale_threshold_seconds: int = 600, *, conn=None) -> list[Order]:
        """Find orders stuck in PROCESSING longer than the threshold.

        These orders likely belong to an instance that crashed mid-finalization.
        """
        db = conn or Database.get_instance()
        rows = db.fetch_all(
            "SELECT * FROM orders "
            "WHERE status = %s "
            "  AND updated_at < now() - interval '1 second' * %s "
            "ORDER BY updated_at",
            (OrderStatus.PROCESSING.value, stale_threshold_seconds),
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def find_expired_actionable(self, cutoff=None, *, conn=None) -> list[Order]:
        """Find orders whose expires timestamp has passed and are still actionable.

        Parameters
        ----------
        cutoff:
            Optional datetime cutoff.  Defaults to ``now()`` in SQL.

        """
        db = conn or Database.get_instance()
        if cutoff is not None:
            rows = db.fetch_all(
                "SELECT * FROM orders "
                "WHERE expires < %s "
                "  AND status IN (%s, %s, %s) "
                "ORDER BY expires",
                (
                    cutoff,
                    OrderStatus.PENDING.value,
                    OrderStatus.READY.value,
                    OrderStatus.PROCESSING.value,
                ),
                as_dict=True,
            )
        else:
            rows = db.fetch_all(
                "SELECT * FROM orders "
                "WHERE expires < now() "
                "  AND status IN (%s, %s, %s) "
                "ORDER BY expires",
                (
                    OrderStatus.PENDING.value,
                    OrderStatus.READY.value,
                    OrderStatus.PROCESSING.value,
                ),
                as_dict=True,
            )
        return [self._row_to_entity(r) for r in rows]

    def transition_status(
        self,
        order_id: UUID,
        from_status: OrderStatus,
        to_status: OrderStatus,
        error: dict | None = None,
        certificate_id: UUID | None = None,
        conn=None,
    ) -> Order | None:
        """Atomic compare-and-swap status transition.

        Returns the updated order, or None if the current status did
        not match *from_status*.
        """
        db = conn or Database.get_instance()
        set_parts = ["status = %s"]
        params: list = [to_status.value]

        if error is not None:
            set_parts.append("error = %s")
            params.append(Jsonb(error))
        if certificate_id is not None:
            set_parts.append("certificate_id = %s")
            params.append(certificate_id)

        params.extend([order_id, from_status.value])

        row = db.fetch_one(
            f"UPDATE orders SET {', '.join(set_parts)} WHERE id = %s AND status = %s RETURNING *",
            tuple(params),
            as_dict=True,
        )
        if row is None:
            log.debug(
                "CAS guard failed: order %s not in %s for transition to %s",
                order_id,
                from_status.value,
                to_status.value,
            )
        return self._row_to_entity(row) if row else None

    def link_authorization(self, order_id: UUID, authz_id: UUID) -> None:
        """Insert a row into the order_authorizations join table."""
        db = Database.get_instance()
        db.execute(
            "INSERT INTO order_authorizations (order_id, authorization_id) "
            "VALUES (%s, %s) "
            "ON CONFLICT DO NOTHING",
            (order_id, authz_id),
        )

    def find_authorization_ids(self, order_id: UUID) -> list[UUID]:
        """Return authorization IDs linked to an order."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT authorization_id FROM order_authorizations WHERE order_id = %s",
            (order_id,),
            as_dict=True,
        )
        return [r["authorization_id"] for r in rows]

    def find_orders_by_authorization(self, authz_id: UUID) -> list[Order]:
        """Return orders linked to an authorization via the join table."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT o.* FROM orders o "
            "JOIN order_authorizations oa ON oa.order_id = o.id "
            "WHERE oa.authorization_id = %s",
            (authz_id,),
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def count_orders_since(self, account_id: UUID, since: datetime) -> int:
        """Count orders created by an account since a given timestamp.

        Used for per-account quota enforcement.
        """
        db = Database.get_instance()
        result = db.fetch_value(
            "SELECT COUNT(*) FROM orders WHERE account_id = %s AND created_at >= %s",
            (account_id, since),
        )
        return result if isinstance(result, int) else 0
