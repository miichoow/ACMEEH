"""Background challenge validation worker.

Polls for stale PROCESSING challenges and re-processes them.
Runs as a daemon thread started during application startup.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acmeeh.repositories.account import AccountRepository
    from acmeeh.repositories.authorization import AuthorizationRepository
    from acmeeh.repositories.challenge import ChallengeRepository
    from acmeeh.services.challenge import ChallengeService

log = logging.getLogger(__name__)


class ChallengeWorker:
    """Daemon thread that processes stale PROCESSING challenges.

    When a database is provided, uses ``pg_try_advisory_lock`` to ensure
    only one instance across the cluster processes stale challenges.

    Parameters
    ----------
    challenge_service:
        The challenge service for processing.
    challenge_repo:
        Challenge repository for finding stale challenges.
    authz_repo:
        Authorization repository for looking up authz -> account.
    account_repo:
        Account repository for looking up account -> JWK.
    poll_seconds:
        How often to poll for stale challenges (default 10).
    stale_seconds:
        Max age in seconds before a PROCESSING challenge is considered stale (default 300).

    """

    # Advisory lock ID for leader election (arbitrary but stable)
    _ADVISORY_LOCK_ID = 712_003  # stable lock ID for challenge worker

    def __init__(
        self,
        challenge_service: ChallengeService,
        challenge_repo: ChallengeRepository,
        authz_repo: AuthorizationRepository,
        account_repo: AccountRepository,
        poll_seconds: int = 10,
        stale_seconds: int = 300,
        metrics=None,
        db=None,
    ) -> None:
        self._service = challenge_service
        self._challenges = challenge_repo
        self._authz = authz_repo
        self._accounts = account_repo
        self._poll_seconds = poll_seconds
        self._stale_seconds = stale_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._metrics = metrics
        self._consecutive_failures = 0
        self._db = db

    def start(self) -> None:
        """Start the background worker thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="challenge-worker",
            daemon=True,
        )
        self._thread.start()
        log.info(
            "Challenge worker started (poll=%ds, stale=%ds)",
            self._poll_seconds,
            self._stale_seconds,
        )

    def stop(self) -> None:
        """Signal the worker to stop and wait for it."""
        self._stop_event.set()
        if self._thread is not None:
            # Short timeout: the thread is a daemon and will die with the
            # process anyway.  A long join blocks the atexit chain and can
            # cause gunicorn to SIGKILL the worker.
            self._thread.join(timeout=5)
            log.info("Challenge worker stopped")

    def _run(self) -> None:
        """Main worker loop."""
        from acmeeh.db.init import advisory_lock, is_pool_healthy, log_pool_stats  # noqa: PLC0415

        while not self._stop_event.is_set():
            # Yield to request-handling threads when pool is stressed.
            if self._db is not None and not is_pool_healthy(self._db):
                log.debug("Challenge worker: pool under pressure — skipping cycle")
                self._stop_event.wait(timeout=self._poll_seconds * 2)
                continue

            work_items = None

            # Collect work while holding the advisory lock.
            # The lock is released when the with-block exits (before
            # slow challenge processing).
            try:
                with advisory_lock(self._db, self._ADVISORY_LOCK_ID) as (acquired, conn):
                    if acquired:
                        work_items = self._collect_work(conn)
            except Exception:  # noqa: BLE001
                self._consecutive_failures += 1
                log.exception(
                    "Challenge worker poll error (consecutive failures: %d)",
                    self._consecutive_failures,
                )
                if self._metrics:
                    self._metrics.increment("acmeeh_challenge_worker_errors_total")
                if self._db is not None:
                    log_pool_stats(self._db, "challenge_worker")
                backoff = min(
                    self._poll_seconds * (2**self._consecutive_failures),
                    300,
                )
                self._stop_event.wait(timeout=backoff)
                continue

            # Process challenges without holding the advisory lock.
            if work_items:
                try:
                    self._process_work(work_items)
                    self._consecutive_failures = 0
                    if self._metrics:
                        self._metrics.increment("acmeeh_challenge_worker_polls_total")
                except Exception:  # noqa: BLE001
                    self._consecutive_failures += 1
                    log.exception(
                        "Challenge worker process error (consecutive failures: %d)",
                        self._consecutive_failures,
                    )
                    if self._metrics:
                        self._metrics.increment("acmeeh_challenge_worker_errors_total")
            else:
                self._consecutive_failures = 0
                if self._metrics:
                    self._metrics.increment("acmeeh_challenge_worker_polls_total")

            self._stop_event.wait(timeout=self._poll_seconds)

    def _collect_work(self, conn=None) -> list:
        """Release stale locks and gather retryable challenges with context.

        Pre-fetches authorization and account data while the advisory-lock
        connection is available, avoiding 2 extra pool checkouts per
        challenge during the processing phase.

        Returns a list of ``(challenge, jwk)`` tuples.
        """
        from datetime import datetime, timedelta

        threshold = datetime.now(UTC) - timedelta(seconds=self._stale_seconds)
        released = self._challenges.release_stale_locks(threshold, conn=conn)
        if released > 0:
            log.info("Released %d stale challenge locks", released)

        now_utc = datetime.now(UTC)
        retryable = self._challenges.find_retryable(now_utc, conn=conn)
        if not retryable or conn is None:
            # Without conn, fall back to per-item lookup in _process_work
            return [(ch, None) for ch in retryable]

        # Batch-fetch authz + account JWKs in a single query
        authz_ids = list({ch.authorization_id for ch in retryable})
        rows = conn.fetch_all(
            "SELECT a.id AS authz_id, acc.jwk "
            "FROM authorizations a "
            "JOIN accounts acc ON acc.id = a.account_id "
            "WHERE a.id = ANY(%s)",
            (authz_ids,),
            as_dict=True,
        )
        jwk_by_authz = {row["authz_id"]: row["jwk"] for row in rows}

        return [
            (ch, jwk_by_authz.get(ch.authorization_id))
            for ch in retryable
        ]

    def _process_work(self, work_items: list) -> None:
        """Process retryable challenges (slow, advisory lock already released)."""
        import uuid as _uuid
        from uuid import uuid4

        from acmeeh.db.init import is_pool_healthy  # noqa: PLC0415

        _request_id = f"bg-worker-{_uuid.uuid4().hex[:12]}"

        for challenge, jwk in work_items:
            if self._stop_event.is_set():
                break
            # Stop processing challenges when pool is stressed — let
            # request-handling threads use the connections instead.
            if self._db is not None and not is_pool_healthy(self._db):
                log.debug(
                    "Challenge worker: pool under pressure — "
                    "deferring remaining %d challenges",
                    len(work_items),
                )
                break

            # Fall back to per-item lookup if JWK wasn't pre-fetched
            if jwk is None:
                authz = self._authz.find_by_id(challenge.authorization_id)
                if authz is None:
                    continue
                account = self._accounts.find_by_id(authz.account_id)
                if account is None:
                    continue
                jwk = account.jwk

            worker_id = f"bg-{uuid4().hex[:8]}"
            log.debug(
                "Processing stale challenge %s",
                challenge.id,
                extra={"request_id": _request_id, "worker_id": worker_id},
            )
            try:
                claimed = self._challenges.claim_for_processing(
                    challenge.id,
                    worker_id,
                )
                if claimed is None:
                    continue

                self._service.process_pending(
                    challenge.id,
                    worker_id,
                    jwk,
                )
            except Exception:
                log.exception(
                    "Failed to process challenge %s",
                    challenge.id,
                )
