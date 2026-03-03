"""Notification repository."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pypgkit import BaseRepository, Database

from acmeeh.core.types import NotificationStatus, NotificationType
from acmeeh.models.notification import Notification

if TYPE_CHECKING:
    from uuid import UUID

log = logging.getLogger(__name__)


class NotificationRepository(BaseRepository[Notification]):
    table_name = "notifications"
    primary_key = "id"

    def _row_to_entity(self, row: dict) -> Notification:
        return Notification(
            id=row["id"],
            notification_type=NotificationType(row["notification_type"]),
            recipient=row["recipient"],
            subject=row["subject"],
            body=row["body"],
            status=NotificationStatus(row["status"]),
            account_id=row.get("account_id"),
            error_detail=row.get("error_detail"),
            retry_count=row.get("retry_count", 0),
            created_at=row["created_at"],
            sent_at=row.get("sent_at"),
        )

    def _entity_to_row(self, entity: Notification) -> dict:
        return {
            "id": entity.id,
            "notification_type": entity.notification_type.value,
            "recipient": entity.recipient,
            "subject": entity.subject,
            "body": entity.body,
            "status": entity.status.value,
            "account_id": entity.account_id,
            "error_detail": entity.error_detail,
            "retry_count": entity.retry_count,
        }

    def find_pending_retry(
        self,
        max_retries: int,
        batch_size: int = 50,
        base_delay: int = 60,
        backoff_multiplier: float = 2.0,
        max_delay: int = 3600,
    ) -> list[Notification]:
        """Find failed notifications eligible for retry with exponential backoff.

        Uses ``SELECT ... FOR UPDATE SKIP LOCKED`` so multiple workers
        can process retries concurrently without contention.

        The backoff delay for attempt N is:
        ``min(base_delay * multiplier^retry_count, max_delay)`` seconds
        since the last failure (updated_at).
        """
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT * FROM notifications "
            "WHERE status = %s AND retry_count < %s "
            "AND updated_at + (LEAST(%s * POWER(%s, retry_count), %s) "
            "    * INTERVAL '1 second') <= NOW() "
            "ORDER BY created_at "
            "LIMIT %s "
            "FOR UPDATE SKIP LOCKED",
            (
                NotificationStatus.FAILED.value,
                max_retries,
                base_delay,
                backoff_multiplier,
                max_delay,
                batch_size,
            ),
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def mark_sent(self, notification_id: UUID) -> Notification | None:
        """Mark a notification as successfully sent."""
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE notifications SET status = %s, sent_at = now() WHERE id = %s RETURNING *",
            (NotificationStatus.SENT.value, notification_id),
            as_dict=True,
        )
        return self._row_to_entity(row) if row else None

    def mark_failed(self, notification_id: UUID, error_detail: str) -> Notification | None:
        """Mark a notification as failed, incrementing retry_count."""
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE notifications "
            "SET status = %s, error_detail = %s, "
            "    retry_count = retry_count + 1 "
            "WHERE id = %s "
            "RETURNING *",
            (NotificationStatus.FAILED.value, error_detail, notification_id),
            as_dict=True,
        )
        return self._row_to_entity(row) if row else None

    def reset_for_retry(self, notification_id: UUID) -> Notification | None:
        """Reset a failed notification to pending for retry."""
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE notifications SET status = %s WHERE id = %s AND status = %s RETURNING *",
            (NotificationStatus.PENDING.value, notification_id, NotificationStatus.FAILED.value),
            as_dict=True,
        )
        return self._row_to_entity(row) if row else None

    def find_all_paginated(
        self,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Notification]:
        """Find notifications with optional status filter and pagination."""
        db = Database.get_instance()
        if status:
            rows = db.fetch_all(
                "SELECT * FROM notifications "
                "WHERE status = %s "
                "ORDER BY created_at DESC "
                "LIMIT %s OFFSET %s",
                (status, limit, offset),
                as_dict=True,
            )
        else:
            rows = db.fetch_all(
                "SELECT * FROM notifications ORDER BY created_at DESC LIMIT %s OFFSET %s",
                (limit, offset),
                as_dict=True,
            )
        return [self._row_to_entity(r) for r in rows]

    def purge_old(self, days: int) -> int:
        """Delete sent notifications older than *days*. Returns count deleted."""
        db = Database.get_instance()
        return db.execute(
            "DELETE FROM notifications "
            "WHERE status = %s AND created_at < now() - make_interval(days => %s)",
            (NotificationStatus.SENT.value, days),
        )

    def reset_failed_for_retry(self) -> int:
        """Reset all failed notifications to pending for retry. Returns count."""
        db = Database.get_instance()
        return db.execute(
            "UPDATE notifications SET status = %s WHERE status = %s",
            (NotificationStatus.PENDING.value, NotificationStatus.FAILED.value),
        )
