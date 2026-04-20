"""Unified cleanup worker -- run periodic maintenance tasks.

Single daemon thread running multiple cleanup tasks on independent
intervals.  Each task tracks its own ``last_run`` timestamp.
Exceptions in one task do not block others.

Usage::

    worker = CleanupWorker(nonce_service=ns, order_repo=orders, ...)
    worker.start()
    ...
    worker.stop()
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from acmeeh.app.rate_limiter import DatabaseRateLimiter
    from acmeeh.config.settings import AcmeehSettings
    from acmeeh.repositories.order import OrderRepository
    from acmeeh.services.nonce import NonceService

log = logging.getLogger(__name__)

_DEFAULT_LOOP_INTERVAL = 60  # seconds between wakeups


class _CleanupTask:
    """Internal: a named task with its own interval and last-run tracking."""

    __slots__ = ("_last_run", "consecutive_failures", "func", "interval_seconds", "name")

    def __init__(
        self,
        name: str,
        interval_seconds: int,
        func: Callable,
    ) -> None:
        """Initialise a cleanup task with its name, interval, and callable."""
        self.name = name
        self.interval_seconds = interval_seconds
        self.func = func
        self._last_run: float = 0.0
        self.consecutive_failures: int = 0

    def is_due(self, now: float) -> bool:
        """Return whether the task is due based on elapsed time."""
        return (now - self._last_run) >= self.interval_seconds

    def run(self, now: float, conn=None) -> None:
        """Execute the task and record the current time as last run."""
        self._last_run = now
        self.func(conn)


class CleanupWorker:
    """Daemon thread that runs multiple cleanup tasks on independent intervals.

    When a database is provided, uses ``pg_try_advisory_lock`` to ensure
    only one instance across the cluster runs cleanup tasks at a time.
    """

    # Advisory lock ID for leader election (arbitrary but stable)
    _ADVISORY_LOCK_ID = 712_001  # stable lock ID for cleanup worker

    def __init__(  # noqa: PLR0913, C901, PLR0912, PLR0915
        self,
        nonce_service: NonceService | None = None,
        order_repo: OrderRepository | None = None,
        settings: AcmeehSettings | None = None,
        db_rate_limiter: DatabaseRateLimiter | None = None,
        db: Any = None,
        metrics: Any = None,
        notifier: Any = None,
    ) -> None:
        """Initialise the cleanup worker and register applicable tasks."""
        self._tasks: list[_CleanupTask] = []
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._metrics = metrics
        self._db = db
        self._notifier = notifier
        self._loop_interval = (
            settings.retention.cleanup_loop_interval_seconds
            if settings is not None
            else _DEFAULT_LOOP_INTERVAL
        )

        # Nonce GC
        if nonce_service is not None and settings is not None:
            self._tasks.append(
                _CleanupTask(
                    name="nonce_gc",
                    interval_seconds=settings.nonce.gc_interval_seconds,
                    func=lambda conn: self._nonce_gc(nonce_service, conn),
                )
            )

        # Order expiry
        if order_repo is not None and settings is not None:
            self._tasks.append(
                _CleanupTask(
                    name="order_expiry",
                    interval_seconds=settings.order.cleanup_interval_seconds,
                    func=lambda conn: self._order_expiry(order_repo, conn),
                )
            )
            # Stale PROCESSING order recovery
            self._tasks.append(
                _CleanupTask(
                    name="stale_processing_recovery",
                    interval_seconds=settings.order.cleanup_interval_seconds,
                    func=lambda conn: self._stale_processing_recovery(
                        order_repo,
                        settings.order.stale_processing_threshold_seconds,
                        conn,
                        notifier=self._notifier,
                    ),
                )
            )

        # Audit retention
        if db is not None and settings is not None and settings.audit_retention.enabled:
            self._tasks.append(
                _CleanupTask(
                    name="audit_retention",
                    interval_seconds=settings.audit_retention.cleanup_interval_seconds,
                    func=lambda conn: self._audit_retention(
                        conn or db,
                        settings.audit_retention.max_age_days,
                    ),
                )
            )

        # Rate limit GC (database backend only)
        if db_rate_limiter is not None:
            gc_interval = 300  # noqa: PLR2004
            if settings is not None:
                gc_interval = settings.security.rate_limits.gc_interval_seconds
            self._tasks.append(
                _CleanupTask(
                    name="rate_limit_gc",
                    interval_seconds=gc_interval,
                    func=lambda conn: self._rate_limit_gc(db_rate_limiter, conn),
                )
            )

        # Data retention tasks
        if db is not None and settings is not None and settings.retention.enabled:
            ret = settings.retention
            self._tasks.append(
                _CleanupTask(
                    name="authz_retention",
                    interval_seconds=ret.cleanup_interval_seconds,
                    func=lambda conn: self._authz_retention(
                        conn or db,
                        ret.expired_authz_max_age_days,
                    ),
                )
            )
            self._tasks.append(
                _CleanupTask(
                    name="challenge_retention",
                    interval_seconds=ret.cleanup_interval_seconds,
                    func=lambda conn: self._challenge_retention(
                        conn or db,
                        ret.invalid_challenge_max_age_days,
                    ),
                )
            )
            self._tasks.append(
                _CleanupTask(
                    name="order_retention",
                    interval_seconds=ret.cleanup_interval_seconds,
                    func=lambda conn: self._order_retention(
                        conn or db,
                        ret.invalid_order_max_age_days,
                    ),
                )
            )
            self._tasks.append(
                _CleanupTask(
                    name="notice_retention",
                    interval_seconds=ret.cleanup_interval_seconds,
                    func=lambda conn: self._notice_retention(
                        conn or db,
                        ret.expiration_notice_max_age_days,
                    ),
                )
            )

    def start(self) -> None:
        """Start the background worker thread."""
        if not self._tasks:
            return
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="cleanup-worker",
            daemon=True,
        )
        self._thread.start()
        task_names = [t.name for t in self._tasks]
        log.info("Cleanup worker started (tasks: %s)", task_names)

    def stop(self) -> None:
        """Signal the worker to stop and wait for it."""
        self._stop_event.set()
        if self._thread is not None:
            # Short timeout: the thread is a daemon and will die with the
            # process anyway.  A long join blocks the atexit chain and can
            # cause gunicorn to SIGKILL the worker.
            self._thread.join(timeout=5)
            log.info("Cleanup worker stopped")

    def _run(self) -> None:  # noqa: C901
        """Run main loop -- wake periodically, check which tasks are due."""
        from acmeeh.db.init import advisory_lock, is_pool_healthy, log_pool_stats  # noqa: PLC0415

        while not self._stop_event.is_set():
            # Yield to request-handling threads when pool is stressed.
            if self._db is not None and not is_pool_healthy(self._db):
                log.debug("Cleanup worker: pool under pressure — skipping cycle")
                self._stop_event.wait(timeout=self._loop_interval * 2)
                continue

            try:
                with advisory_lock(self._db, self._ADVISORY_LOCK_ID) as (acquired, conn):
                    if acquired:
                        now = time.monotonic()
                        for task in self._tasks:
                            if self._stop_event.is_set():
                                break
                            if task.is_due(now):
                                self._execute_task(task, now, conn)
            except Exception:  # noqa: BLE001
                log.debug("Advisory lock cycle failed, skipping this cycle")
                if self._db is not None:
                    log_pool_stats(self._db, "cleanup_worker")
            self._stop_event.wait(timeout=self._loop_interval)

    def _execute_task(self, task: _CleanupTask, now: float, conn=None) -> None:
        """Execute a single cleanup task with error tracking and metrics."""
        try:
            task.run(now, conn)
            task.consecutive_failures = 0
            if self._metrics:
                self._metrics.increment(
                    "acmeeh_cleanup_runs_total",
                    labels={"task": task.name},
                )
        except Exception:  # noqa: BLE001
            task.consecutive_failures += 1
            log.exception(
                "Cleanup task '%s' failed (consecutive: %d)",
                task.name,
                task.consecutive_failures,
            )
            if self._metrics:
                self._metrics.increment(
                    "acmeeh_cleanup_errors_total",
                    labels={"task": task.name},
                )

    # -- Task implementations --------------------------------------------------

    # Max rows to delete per iteration to avoid long-held locks.
    _DELETE_BATCH_SIZE = 1000

    @staticmethod
    def _batched_delete(
        db: Any,
        table: str,
        where_clause: str,
        params: tuple,
        label: str,
    ) -> int:
        """Delete rows in batches to avoid long-held row locks.

        Uses a CTE to select a bounded set of ``ctid``s, then deletes
        only those rows.  Repeats until fewer than ``_DELETE_BATCH_SIZE``
        rows are removed in a single pass.

        Parameters
        ----------
        table:
            Fully-qualified table name (e.g. ``"admin.audit_log"``).
        where_clause:
            SQL ``WHERE`` fragment **without** the ``WHERE`` keyword.
        params:
            Bind parameters for *where_clause*.

        Returns total rows deleted.
        """
        batch_limit = CleanupWorker._DELETE_BATCH_SIZE
        total = 0
        while True:
            affected = db.execute(
                f"WITH batch AS ("
                f"  SELECT ctid FROM {table} WHERE {where_clause} LIMIT %s"
                f") DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM batch)",
                (*params, batch_limit),
            )
            if not isinstance(affected, int):
                break
            total += affected
            if affected < batch_limit:
                break
        if total:
            log.info("%s: deleted %d rows", label, total)
        return total

    @staticmethod
    def _nonce_gc(nonce_service: NonceService, conn=None) -> None:
        """Remove expired nonces via the nonce service."""
        deleted = nonce_service.gc(conn=conn)
        if deleted:
            log.debug("Nonce GC: removed %d expired nonces", deleted)

    @staticmethod
    def _order_expiry(order_repo: OrderRepository, conn=None) -> None:
        """Transition expired actionable orders to invalid status."""
        from acmeeh.core.types import OrderStatus  # noqa: PLC0415

        expired = order_repo.find_expired_actionable(conn=conn)
        count = 0
        for order in expired:
            order_repo.transition_status(
                order.id,
                order.status,
                OrderStatus.INVALID,
                error={
                    "type": "urn:ietf:params:acme:error:serverInternal",
                    "detail": "Order expired",
                },
                conn=conn,
            )
            count += 1
        if count:
            log.info(
                "Order expiry: transitioned %d expired orders to invalid",
                count,
            )

    @staticmethod
    def _stale_processing_recovery(
        order_repo: OrderRepository,
        threshold_seconds: int,
        conn=None,
        notifier=None,
    ) -> None:
        """Recover orders stuck in PROCESSING state past the threshold."""
        from acmeeh.core.types import NotificationType, OrderStatus  # noqa: PLC0415

        stale = order_repo.find_stale_processing(threshold_seconds, conn=conn)
        count = 0
        for order in stale:
            order_repo.transition_status(
                order.id,
                OrderStatus.PROCESSING,
                OrderStatus.INVALID,
                error={
                    "type": "urn:ietf:params:acme:error:serverInternal",
                    "detail": (
                        "Order stuck in processing -- likely due to "
                        "instance crash during finalization"
                    ),
                },
                conn=conn,
            )
            count += 1
            if notifier:
                try:
                    domains = [ident.value for ident in order.identifiers]
                    notifier.notify(
                        NotificationType.ORDER_STALE_RECOVERED,
                        order.account_id,
                        {
                            "order_id": str(order.id),
                            "domains": domains,
                        },
                    )
                except Exception:  # noqa: BLE001
                    log.exception("Failed to send ORDER_STALE_RECOVERED notification")
        if count:
            log.warning(
                "Stale processing recovery: transitioned %d stuck orders to invalid",
                count,
            )

    @staticmethod
    def _audit_retention(db: Any, max_age_days: int) -> None:
        """Delete audit log entries older than the retention period."""
        cutoff = datetime.now(UTC) - timedelta(days=max_age_days)
        CleanupWorker._batched_delete(
            db,
            table="admin.audit_log",
            where_clause="created_at < %s",
            params=(cutoff,),
            label="Audit retention",
        )

    @staticmethod
    def _rate_limit_gc(limiter: DatabaseRateLimiter, conn=None) -> None:
        """Remove expired rate-limit counters."""
        deleted = limiter.gc(conn=conn)
        if deleted:
            log.debug(
                "Rate limit GC: deleted %d expired counters",
                deleted,
            )

    @staticmethod
    def _authz_retention(db: Any, max_age_days: int) -> None:
        """Delete old expired/invalid authorizations past retention."""
        cutoff = datetime.now(UTC) - timedelta(days=max_age_days)
        CleanupWorker._batched_delete(
            db,
            table="authorizations",
            where_clause="status IN ('expired', 'invalid') AND updated_at < %s",
            params=(cutoff,),
            label="Authz retention",
        )

    @staticmethod
    def _challenge_retention(db: Any, max_age_days: int) -> None:
        """Delete old invalid challenges past retention."""
        cutoff = datetime.now(UTC) - timedelta(days=max_age_days)
        CleanupWorker._batched_delete(
            db,
            table="challenges",
            where_clause="status = 'invalid' AND updated_at < %s",
            params=(cutoff,),
            label="Challenge retention",
        )

    @staticmethod
    def _order_retention(db: Any, max_age_days: int) -> None:
        """Delete old invalid orders past retention."""
        cutoff = datetime.now(UTC) - timedelta(days=max_age_days)
        CleanupWorker._batched_delete(
            db,
            table="orders",
            where_clause="status = 'invalid' AND updated_at < %s",
            params=(cutoff,),
            label="Order retention",
        )

    @staticmethod
    def _notice_retention(db: Any, max_age_days: int) -> None:
        """Delete old expiration notices past retention."""
        cutoff = datetime.now(UTC) - timedelta(days=max_age_days)
        CleanupWorker._batched_delete(
            db,
            table="certificate_expiration_notices",
            where_clause="notified_at < %s",
            params=(cutoff,),
            label="Notice retention",
        )
