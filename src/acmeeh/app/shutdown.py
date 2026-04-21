"""Graceful shutdown coordinator.

Tracks in-flight operations and ensures they complete (up to a timeout)
before the process exits.

Usage::

    from acmeeh.app.shutdown import ShutdownCoordinator

    coordinator = ShutdownCoordinator(graceful_timeout=30)

    with coordinator.track("crl_rebuild"):
        rebuild_crl()

    coordinator.initiate()  # waits for tracked ops to finish
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Generator

log = logging.getLogger(__name__)


class ShutdownCoordinator:
    """Coordinates graceful shutdown by tracking in-flight operations.

    Parameters
    ----------
    graceful_timeout:
        Maximum seconds to wait for in-flight operations during shutdown.

    """

    # How long a cached maintenance-mode read is trusted before
    # re-querying the backing store.  Short enough that other workers
    # notice a toggle quickly; long enough that the DB is not queried
    # on every single ACME request.
    _MAINTENANCE_CACHE_TTL_SECONDS: float = 2.0

    def __init__(
        self,
        graceful_timeout: int = 30,
        *,
        settings_repo: Any = None,
        maintenance_cache_ttl: float | None = None,
    ) -> None:
        self._graceful_timeout = graceful_timeout
        self._shutdown_flag = threading.Event()
        self._reload_flag = threading.Event()
        self._maintenance_flag = threading.Event()
        self._in_flight = 0
        self._lock = threading.Lock()
        self._done = threading.Condition(self._lock)
        self._settings_repo = settings_repo
        self._maintenance_ttl = (
            self._MAINTENANCE_CACHE_TTL_SECONDS
            if maintenance_cache_ttl is None
            else maintenance_cache_ttl
        )
        self._maintenance_cache_lock = threading.Lock()
        self._maintenance_cache_expires_at: float = 0.0

    @property
    def is_shutting_down(self) -> bool:
        """True once :meth:`initiate` has been called."""
        return self._shutdown_flag.is_set()

    @property
    def in_flight_count(self) -> int:
        """Number of currently tracked operations."""
        with self._lock:
            return self._in_flight

    @contextmanager
    def track(self, name: str) -> Generator[None, None, None]:
        """Context manager to track an in-flight operation.

        If shutdown has already been initiated, the operation is still
        allowed to proceed (we don't want to break existing work), but
        a warning is logged.
        """
        if self._shutdown_flag.is_set():
            log.warning("Operation '%s' starting during shutdown", name)

        with self._lock:
            self._in_flight += 1

        try:
            yield
        finally:
            with self._done:
                self._in_flight -= 1
                if self._in_flight == 0:
                    self._done.notify_all()

    def initiate(self) -> None:
        """Begin graceful shutdown.

        Sets the shutdown flag and waits up to ``graceful_timeout``
        seconds for in-flight operations to complete.
        """
        if self._shutdown_flag.is_set():
            return

        self._shutdown_flag.set()
        log.info("Graceful shutdown initiated")

        with self._done:
            deadline = time.monotonic() + self._graceful_timeout
            while self._in_flight > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    log.warning(
                        "Shutdown timeout expired with %d operations in flight",
                        self._in_flight,
                    )
                    break
                self._done.wait(timeout=remaining)

        if self._in_flight == 0:
            log.info("All in-flight operations completed")

    def attach_settings_repo(self, settings_repo: Any) -> None:
        """Wire a :class:`ServerSettingsRepository` for cross-worker state.

        Until this is called the coordinator falls back to a per-process
        in-memory flag (useful for tests and the ``--validate-only`` boot
        path that runs without a database).
        """
        self._settings_repo = settings_repo
        # Force the next read to hit the DB so a freshly-attached repo
        # is consulted immediately.
        with self._maintenance_cache_lock:
            self._maintenance_cache_expires_at = 0.0

    @property
    def maintenance_mode(self) -> bool:
        """True when the server is in maintenance mode.

        In maintenance mode, new order and pre-authorization creation
        is blocked (503), but existing order finalization, challenge
        validation, and certificate downloads continue to work.

        When a settings repository is attached, the state is read from
        the shared store (with a short TTL cache) so every gunicorn
        worker observes the same value.  Otherwise the process-local
        flag is used.
        """
        if self._settings_repo is None:
            return self._maintenance_flag.is_set()

        now = time.monotonic()
        with self._maintenance_cache_lock:
            if now < self._maintenance_cache_expires_at:
                return self._maintenance_flag.is_set()

        try:
            value = self._settings_repo.get("maintenance_mode")
        except Exception:
            log.exception(
                "Failed to read maintenance_mode from settings store; using cached value",
            )
            return self._maintenance_flag.is_set()

        enabled = bool(value)
        with self._maintenance_cache_lock:
            if enabled:
                self._maintenance_flag.set()
            else:
                self._maintenance_flag.clear()
            self._maintenance_cache_expires_at = now + self._maintenance_ttl
        return enabled

    def set_maintenance(self, enabled: bool) -> None:
        """Enable or disable maintenance mode."""
        if self._settings_repo is not None:
            try:
                self._settings_repo.set("maintenance_mode", enabled)
            except Exception:
                log.exception(
                    "Failed to persist maintenance_mode to settings store",
                )
                raise

        if enabled:
            self._maintenance_flag.set()
            log.info("Maintenance mode ENABLED — new orders blocked")
        else:
            self._maintenance_flag.clear()
            log.info("Maintenance mode DISABLED — new orders allowed")

        # Force other workers to re-read on their next check, and keep
        # this worker's cache fresh so we don't flip-flop if the DB
        # write and a concurrent read race.
        with self._maintenance_cache_lock:
            self._maintenance_cache_expires_at = time.monotonic() + self._maintenance_ttl

    @property
    def reload_requested(self) -> bool:
        """True if a SIGHUP was received and reload has not been consumed."""
        return self._reload_flag.is_set()

    def consume_reload(self) -> None:
        """Clear the reload flag after handling it."""
        self._reload_flag.clear()

    def register_signals(self) -> None:
        """Register SIGTERM and SIGINT handlers to initiate shutdown.

        Must be called from the main thread.
        """
        try:
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
        except (ValueError, OSError):
            # Not in main thread or signals not supported (Windows service)
            log.debug("Could not register signal handlers (not main thread)")

    def drain_processing_challenges(self, challenge_repo: Any) -> int:
        """Move PROCESSING challenges back to PENDING for retry on healthy instances.

        Called during graceful shutdown to avoid partial state visible to clients.
        Returns the number of challenges drained.
        """
        if challenge_repo is None:
            return 0
        try:
            count = challenge_repo.drain_processing()
            if count > 0:
                log.info("Drained %d PROCESSING challenges back to PENDING", count)
            return count
        except Exception:
            log.exception("Failed to drain processing challenges during shutdown")
            return 0

    def register_reload_signal(self) -> None:
        """Register SIGHUP handler for config hot-reload.

        Must be called from the main thread. On Windows, SIGHUP is not
        available — this is a no-op.
        """
        if not hasattr(signal, "SIGHUP"):
            log.debug("SIGHUP not available on this platform (Windows?)")
            return
        try:
            signal.signal(signal.SIGHUP, self._reload_handler)
            log.info("SIGHUP handler registered for config hot-reload")
        except (ValueError, OSError):
            log.debug("Could not register SIGHUP handler (not main thread)")

    def _signal_handler(self, signum: int, frame) -> None:
        sig_name = signal.Signals(signum).name
        log.info("Received %s, initiating graceful shutdown", sig_name)
        # Run in a thread to avoid blocking the signal handler
        threading.Thread(
            target=self.initiate,
            name="shutdown-coordinator",
            daemon=True,
        ).start()

    def _reload_handler(self, signum: int, frame) -> None:
        log.info("Received SIGHUP, flagging config reload")
        self._reload_flag.set()
