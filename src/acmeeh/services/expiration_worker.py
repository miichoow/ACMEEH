"""Certificate expiration warning worker.

Daemon thread that periodically checks for certificates nearing expiry
and sends notification warnings.  Deduplicates via a
``certificate_expiration_notices`` table so each (cert, threshold)
pair is only notified once.

Usage::

    worker = ExpirationWorker(cert_repo, notification_service, settings, db)
    worker.start()
    ...
    worker.stop()
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pypgkit import Database

    from acmeeh.config.settings import NotificationSettings
    from acmeeh.repositories.certificate import CertificateRepository
    from acmeeh.services.notification import NotificationService

log = logging.getLogger(__name__)


class ExpirationWorker:
    """Daemon thread that sends certificate expiration warnings.

    When a database is provided, uses ``pg_try_advisory_lock`` to ensure
    only one instance across the cluster sends expiration notifications.
    """

    # Advisory lock ID for leader election (arbitrary but stable)
    _ADVISORY_LOCK_ID = 712_002  # stable lock ID for expiration worker

    def __init__(
        self,
        cert_repo: CertificateRepository,
        notification_service: NotificationService | None,
        settings: NotificationSettings,
        db: Database | None = None,
        metrics=None,
    ) -> None:
        self._certs = cert_repo
        self._notifier = notification_service
        self._settings = settings
        self._db = db
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._metrics = metrics
        self._consecutive_failures = 0

    def start(self) -> None:
        """Start the background worker thread."""
        if not self._settings.enabled or not self._settings.expiration_warning_days:
            log.debug(
                "Expiration worker not started: notifications disabled or no warning thresholds configured"
            )
            return
        if self._notifier is None:
            log.debug("Expiration worker not started: no notification service configured")
            return
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="expiration-worker",
            daemon=True,
        )
        self._thread.start()
        log.info(
            "Expiration worker started (thresholds=%s, interval=%ds)",
            list(self._settings.expiration_warning_days),
            self._settings.expiration_check_interval_seconds,
        )

    def stop(self) -> None:
        """Signal the worker to stop and wait for it."""
        self._stop_event.set()
        if self._thread is not None:
            # Short timeout: the thread is a daemon and will die with the
            # process anyway.  A long join blocks the atexit chain and can
            # cause gunicorn to SIGKILL the worker.
            self._thread.join(timeout=5)
            log.info("Expiration worker stopped")

    def _run(self) -> None:
        """Main worker loop."""
        from acmeeh.db.init import advisory_lock, is_pool_healthy, log_pool_stats  # noqa: PLC0415

        interval = self._settings.expiration_check_interval_seconds
        while not self._stop_event.is_set():
            # Yield to request-handling threads when pool is stressed.
            if self._db is not None and not is_pool_healthy(self._db):
                log.debug("Expiration worker: pool under pressure — skipping cycle")
                self._stop_event.wait(timeout=interval * 2)
                continue

            work = None

            # Collect expiring certs while holding the advisory lock.
            # The lock is released when the with-block exits (before
            # slow notification sending).
            try:
                with advisory_lock(self._db, self._ADVISORY_LOCK_ID) as (acquired, conn):
                    if acquired:
                        work = self._collect_expiring(conn)
            except Exception:  # noqa: BLE001
                self._consecutive_failures += 1
                log.exception(
                    "Expiration worker collect failed (consecutive: %d)",
                    self._consecutive_failures,
                )
                if self._metrics:
                    self._metrics.increment("acmeeh_expiration_worker_errors_total")
                if self._db is not None:
                    log_pool_stats(self._db, "expiration_worker")
                backoff = min(interval * (2**self._consecutive_failures), interval * 8)
                self._stop_event.wait(timeout=backoff)
                continue

            # Send notifications without holding the advisory lock.
            if work:
                try:
                    self._send_notifications(work)
                    self._consecutive_failures = 0
                except Exception:  # noqa: BLE001
                    self._consecutive_failures += 1
                    log.exception(
                        "Expiration worker notify failed (consecutive: %d)",
                        self._consecutive_failures,
                    )
                    if self._metrics:
                        self._metrics.increment("acmeeh_expiration_worker_errors_total")
            else:
                self._consecutive_failures = 0

            self._stop_event.wait(timeout=interval)

    def _collect_expiring(self, conn=None) -> list[tuple[int, list]]:
        """Collect expiring certificates per threshold (fast, under advisory lock)."""
        now = datetime.now(UTC)
        work: list[tuple[int, list]] = []
        for warning_days in self._settings.expiration_warning_days:
            cutoff = now + timedelta(days=warning_days)
            expiring = self._certs.find_expiring(cutoff, conn=conn)
            if expiring:
                work.append((warning_days, expiring))
        return work

    def _send_notifications(self, work: list[tuple[int, list]]) -> None:
        """Send expiration warnings (slow, advisory lock already released).

        Structured in two phases to avoid holding DB connections during
        SMTP network I/O:
        1. Batch-claim all notifications in a single INSERT (1 pool checkout)
        2. Send emails for claimed notifications (slow network I/O)
        """
        from acmeeh.core.types import NotificationType  # noqa: PLC0415

        if self._stop_event.is_set():
            return

        # Phase 1: Batch-claim all notifications in a single DB round-trip.
        # This replaces N separate checkouts with exactly 1, which is
        # critical for avoiding pool exhaustion when many certs expire.
        items: list[tuple[int, Any]] = []  # (warning_days, cert)
        for warning_days, certs in work:
            for cert in certs:
                items.append((warning_days, cert))

        claimed_set = self._batch_claim_notices(items)

        claimed = [(days, cert) for days, cert in items if (cert.id, days) in claimed_set]

        # Phase 2: Send notifications for claimed items (network I/O)
        for warning_days, cert in claimed:
            if self._stop_event.is_set():
                return

            if self._notifier is not None:
                self._notifier.notify(
                    NotificationType.EXPIRATION_WARNING,
                    cert.account_id,
                    {
                        "certificate_id": str(cert.id),
                        "serial_number": cert.serial_number,
                        "not_after": str(cert.not_after_cert),
                        "warning_days": warning_days,
                    },
                )
                log.info(
                    "Sent expiration warning for certificate %s (serial=%s, expires=%s, threshold=%dd)",
                    cert.id,
                    cert.serial_number,
                    cert.not_after_cert,
                    warning_days,
                )

            if self._metrics:
                self._metrics.increment("acmeeh_expiration_warnings_sent_total")

    def _batch_claim_notices(
        self,
        items: list[tuple[int, Any]],
    ) -> set[tuple]:
        """Batch-claim notifications via a single INSERT ON CONFLICT DO NOTHING.

        Returns a set of ``(certificate_id, warning_days)`` tuples that
        were successfully claimed (i.e. this instance won the insert).
        Uses one pool checkout regardless of how many items are claimed.
        """
        if not items:
            return set()
        if self._db is None:
            # No DB — cannot deduplicate, allow all
            return {(cert.id, days) for days, cert in items}

        try:
            values_sql = ", ".join(["(%s, %s)"] * len(items))
            params: list = []
            for warning_days, cert in items:
                params.extend([cert.id, warning_days])

            rows = self._db.fetch_all(
                "INSERT INTO certificate_expiration_notices "
                "(certificate_id, warning_days) VALUES "
                f"{values_sql} "
                "ON CONFLICT DO NOTHING "
                "RETURNING certificate_id, warning_days",
                tuple(params),
                as_dict=True,
            )
            return {(r["certificate_id"], r["warning_days"]) for r in rows}
        except Exception:
            log.exception("Failed to batch-claim expiration notices")
            # On error, skip all to avoid duplicates
            return set()
