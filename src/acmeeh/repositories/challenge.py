"""Challenge repository."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from psycopg.types.json import Jsonb
from pypgkit import BaseRepository, Database

from acmeeh.core.types import ChallengeStatus, ChallengeType
from acmeeh.models.challenge import Challenge

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

log = logging.getLogger(__name__)


class ChallengeRepository(BaseRepository[Challenge]):
    table_name = "challenges"
    primary_key = "id"

    def _row_to_entity(self, row: dict) -> Challenge:
        return Challenge(
            id=row["id"],
            authorization_id=row["authorization_id"],
            type=ChallengeType(row["type"]),
            token=row["token"],
            status=ChallengeStatus(row["status"]),
            error=row.get("error"),
            validated_at=row.get("validated_at"),
            retry_count=row["retry_count"],
            next_retry_at=row.get("next_retry_at"),
            locked_by=row.get("locked_by"),
            locked_at=row.get("locked_at"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _entity_to_row(self, entity: Challenge) -> dict:
        return {
            "id": entity.id,
            "authorization_id": entity.authorization_id,
            "type": entity.type.value,
            "token": entity.token,
            "status": entity.status.value,
            "error": Jsonb(entity.error) if entity.error is not None else None,
            "validated_at": entity.validated_at,
            "retry_count": entity.retry_count,
            "next_retry_at": entity.next_retry_at,
            "locked_by": entity.locked_by,
            "locked_at": entity.locked_at,
        }

    def create_many(self, entities: list[Challenge]) -> None:
        """Batch-insert multiple challenges in a single query.

        Uses multi-row INSERT for better performance when creating
        challenges for a new authorization.
        """
        if not entities:
            return

        db = Database.get_instance()
        columns = (
            "id",
            "authorization_id",
            "type",
            "token",
            "status",
            "error",
            "validated_at",
            "retry_count",
            "next_retry_at",
            "locked_by",
            "locked_at",
        )
        col_list = ", ".join(columns)
        placeholders = ", ".join("%s" for _ in columns)
        values_list = ", ".join(f"({placeholders})" for _ in entities)

        params: list = []
        for entity in entities:
            row = self._entity_to_row(entity)
            for col in columns:
                params.append(row.get(col))

        db.execute(
            f"INSERT INTO challenges ({col_list}) VALUES {values_list}",
            tuple(params),
        )

    def find_by_authorization(self, authz_id: UUID) -> list[Challenge]:
        """Return all challenges for a given authorization."""
        return self.find_by({"authorization_id": authz_id})

    def auto_accept_by_authorization(self, authz_id: UUID) -> int:
        """Bulk-transition all pending challenges for an authorization to valid.

        Sets ``validated_at = now()`` and clears any locks.
        Returns the number of challenges updated.
        """
        db = Database.get_instance()
        return db.execute(
            "UPDATE challenges "
            "SET status = %s, validated_at = now(), "
            "    locked_by = NULL, locked_at = NULL "
            "WHERE authorization_id = %s "
            "  AND status = %s",
            (
                ChallengeStatus.VALID.value,
                authz_id,
                ChallengeStatus.PENDING.value,
            ),
        )

    def find_retryable(self, now: datetime, *, conn=None) -> list[Challenge]:
        """Return pending challenges eligible for retry by the background worker.

        Selects challenges that are PENDING with retry_count >= 1 and whose
        backoff window has elapsed (next_retry_at IS NULL or <= now).
        """
        db = conn or Database.get_instance()
        rows = db.fetch_all(
            "SELECT * FROM challenges "
            "WHERE status = %s "
            "  AND retry_count >= 1 "
            "  AND (next_retry_at IS NULL OR next_retry_at <= %s) "
            "ORDER BY updated_at "
            "LIMIT 100",
            (ChallengeStatus.PENDING.value, now),
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def claim_for_processing(
        self,
        challenge_id: UUID,
        worker_id: str,
    ) -> Challenge | None:
        """Atomically claim a pending challenge for processing.

        Sets status to 'processing' and records the worker lock only if
        the challenge is currently 'pending' and not already locked.

        Returns the claimed challenge, or None if the CAS guard failed.
        """
        db = Database.get_instance()
        row = db.fetch_one(
            "UPDATE challenges "
            "SET status = %s, locked_by = %s, locked_at = now() "
            "WHERE id = %s "
            "  AND status = %s "
            "  AND locked_by IS NULL "
            "RETURNING *",
            (
                ChallengeStatus.PROCESSING.value,
                worker_id,
                challenge_id,
                ChallengeStatus.PENDING.value,
            ),
            as_dict=True,
        )
        if row is None:
            log.debug(
                "CAS guard failed: challenge %s not claimable (not pending or already locked)",
                challenge_id,
            )
        return self._row_to_entity(row) if row else None

    def complete_validation(
        self,
        challenge_id: UUID,
        worker_id: str,
        success: bool,
        error: dict | None = None,
    ) -> Challenge | None:
        """Complete validation of a challenge held by *worker_id*.

        Transitions from 'processing' → 'valid' (success) or
        'processing' → 'invalid' (failure).  Only succeeds if
        *locked_by* matches *worker_id*.
        """
        db = Database.get_instance()
        new_status = ChallengeStatus.VALID.value if success else ChallengeStatus.INVALID.value

        if success:
            row = db.fetch_one(
                "UPDATE challenges "
                "SET status = %s, validated_at = now(), "
                "    locked_by = NULL, locked_at = NULL "
                "WHERE id = %s "
                "  AND status = %s "
                "  AND locked_by = %s "
                "RETURNING *",
                (
                    new_status,
                    challenge_id,
                    ChallengeStatus.PROCESSING.value,
                    worker_id,
                ),
                as_dict=True,
            )
        else:
            error_param = Jsonb(error) if error is not None else None
            row = db.fetch_one(
                "UPDATE challenges "
                "SET status = %s, error = %s, "
                "    locked_by = NULL, locked_at = NULL "
                "WHERE id = %s "
                "  AND status = %s "
                "  AND locked_by = %s "
                "RETURNING *",
                (
                    new_status,
                    error_param,
                    challenge_id,
                    ChallengeStatus.PROCESSING.value,
                    worker_id,
                ),
                as_dict=True,
            )
        return self._row_to_entity(row) if row else None

    def release_stale_locks(self, stale_threshold: datetime, *, conn=None) -> int:
        """Release locks on challenges stuck in 'processing' state.

        Resets challenges locked before *stale_threshold* back to
        'pending' so they can be retried.

        Returns the number of released challenges.
        """
        db = conn or Database.get_instance()
        count = db.execute(
            "UPDATE challenges "
            "SET status = %s, retry_count = retry_count + 1, locked_by = NULL, locked_at = NULL "
            "WHERE status = %s "
            "  AND locked_at < %s",
            (
                ChallengeStatus.PENDING.value,
                ChallengeStatus.PROCESSING.value,
                stale_threshold,
            ),
        )
        if count:
            log.info("Released %d stale challenge lock(s)", count)
        return count

    def claim_with_advisory_lock(self, challenge_id: UUID) -> bool:
        """Try to acquire a PostgreSQL advisory lock for a challenge.

        Uses ``pg_try_advisory_xact_lock()`` with a hash of the challenge
        UUID.  The lock is automatically released at the end of the
        current transaction.

        Returns True if the lock was acquired, False if another worker
        already holds it.
        """
        import hashlib

        lock_key = int(hashlib.md5(challenge_id.bytes).hexdigest()[:16], 16) & 0x7FFFFFFFFFFFFFFF
        db = Database.get_instance()
        result = db.fetch_value(
            "SELECT pg_try_advisory_xact_lock(%s)",
            (lock_key,),
        )
        return result is True

    def drain_processing(self) -> int:
        """Move all PROCESSING challenges back to PENDING for graceful shutdown.

        Returns the number of challenges drained.
        """
        db = Database.get_instance()
        result = db.execute(
            "UPDATE challenges "
            "SET status = %s, retry_count = retry_count + 1, locked_by = NULL, locked_at = NULL "
            "WHERE status = %s",
            (ChallengeStatus.PENDING.value, ChallengeStatus.PROCESSING.value),
        )
        return result if isinstance(result, int) else 0

    def retry_challenge(
        self,
        challenge_id: UUID,
        worker_id: str,
        backoff_seconds: int = 0,
    ) -> Challenge | None:
        """Reset a processing challenge back to pending for retry.

        Increments retry_count, sets next_retry_at for exponential
        backoff, and clears the lock.  Only succeeds if the challenge
        is currently held by *worker_id*.

        Parameters
        ----------
        backoff_seconds:
            Seconds to wait before the next retry attempt.  When > 0,
            ``next_retry_at`` is set to ``now() + interval``.

        """
        db = Database.get_instance()
        if backoff_seconds > 0:
            row = db.fetch_one(
                "UPDATE challenges "
                "SET status = %s, "
                "    retry_count = retry_count + 1, "
                "    next_retry_at = now() + make_interval(secs => %s), "
                "    locked_by = NULL, locked_at = NULL "
                "WHERE id = %s "
                "  AND status = %s "
                "  AND locked_by = %s "
                "RETURNING *",
                (
                    ChallengeStatus.PENDING.value,
                    backoff_seconds,
                    challenge_id,
                    ChallengeStatus.PROCESSING.value,
                    worker_id,
                ),
                as_dict=True,
            )
        else:
            row = db.fetch_one(
                "UPDATE challenges "
                "SET status = %s, "
                "    retry_count = retry_count + 1, "
                "    next_retry_at = NULL, "
                "    locked_by = NULL, locked_at = NULL "
                "WHERE id = %s "
                "  AND status = %s "
                "  AND locked_by = %s "
                "RETURNING *",
                (
                    ChallengeStatus.PENDING.value,
                    challenge_id,
                    ChallengeStatus.PROCESSING.value,
                    worker_id,
                ),
                as_dict=True,
            )
        return self._row_to_entity(row) if row else None
