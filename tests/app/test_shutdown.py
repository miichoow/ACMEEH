"""Unit tests for acmeeh.app.shutdown — Shutdown coordinator."""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock

from acmeeh.app.shutdown import ShutdownCoordinator

# ---------------------------------------------------------------------------
# TestShutdownCoordinator
# ---------------------------------------------------------------------------


class TestShutdownCoordinator:
    def test_is_shutting_down_starts_false(self):
        sc = ShutdownCoordinator()
        assert sc.is_shutting_down is False

    def test_initiate_sets_flag(self):
        sc = ShutdownCoordinator()
        sc.initiate()
        assert sc.is_shutting_down is True

    def test_double_initiate_is_idempotent(self):
        sc = ShutdownCoordinator()
        sc.initiate()
        sc.initiate()  # should not raise
        assert sc.is_shutting_down is True

    def test_track_increments_decrements(self):
        sc = ShutdownCoordinator()
        assert sc.in_flight_count == 0
        with sc.track("test-op"):
            assert sc.in_flight_count == 1
        assert sc.in_flight_count == 0

    def test_shutdown_waits_for_tracked(self):
        sc = ShutdownCoordinator(graceful_timeout=5)
        completed = threading.Event()

        def slow_op():
            with sc.track("slow"):
                time.sleep(0.1)
            completed.set()

        t = threading.Thread(target=slow_op)
        t.start()
        time.sleep(0.02)  # let it start
        sc.initiate()  # should wait for slow_op to finish
        t.join(timeout=5)
        assert completed.is_set()
        assert sc.in_flight_count == 0

    def test_shutdown_timeout_expires_gracefully(self):
        sc = ShutdownCoordinator(graceful_timeout=0)

        # Start a tracked operation that won't finish quickly
        started = threading.Event()
        stop = threading.Event()

        def blocking_op():
            with sc.track("blocker"):
                started.set()
                stop.wait(timeout=5)

        t = threading.Thread(target=blocking_op, daemon=True)
        t.start()
        started.wait(timeout=2)

        # initiate should return quickly due to 0 timeout
        start_time = time.monotonic()
        sc.initiate()
        elapsed = time.monotonic() - start_time
        assert elapsed < 2  # shouldn't block forever

        stop.set()
        t.join(timeout=2)


# ---------------------------------------------------------------------------
# TestMaintenanceMode
# ---------------------------------------------------------------------------


class TestMaintenanceMode:
    def test_starts_disabled(self):
        sc = ShutdownCoordinator()
        assert sc.maintenance_mode is False

    def test_set_maintenance_true(self):
        sc = ShutdownCoordinator()
        sc.set_maintenance(True)
        assert sc.maintenance_mode is True

    def test_set_maintenance_false(self):
        sc = ShutdownCoordinator()
        sc.set_maintenance(True)
        sc.set_maintenance(False)
        assert sc.maintenance_mode is False

    def test_toggle_propagates_across_workers_via_settings_repo(self):
        """Regression: maintenance toggles on one worker must be seen by
        every other worker, since each gunicorn process has its own
        ShutdownCoordinator.  We simulate that by pointing two
        coordinators at one shared settings repository, the way all
        workers in production point at the same Postgres.
        """

        class _FakeRepo:
            def __init__(self):
                self.store: dict = {}

            def get(self, key):
                return self.store.get(key)

            def set(self, key, value):
                self.store[key] = value

        repo = _FakeRepo()
        # TTL=0 so each read refetches — mirrors what happens in prod
        # once the cache window has elapsed, without needing time.sleep.
        worker_a = ShutdownCoordinator(
            settings_repo=repo,
            maintenance_cache_ttl=0,
        )
        worker_b = ShutdownCoordinator(
            settings_repo=repo,
            maintenance_cache_ttl=0,
        )

        assert worker_a.maintenance_mode is False
        assert worker_b.maintenance_mode is False

        worker_a.set_maintenance(True)

        assert worker_a.maintenance_mode is True
        assert worker_b.maintenance_mode is True

        worker_a.set_maintenance(False)

        assert worker_a.maintenance_mode is False
        assert worker_b.maintenance_mode is False

    def test_falls_back_to_in_memory_when_repo_read_fails(self):
        class _BrokenRepo:
            def get(self, key):
                raise RuntimeError("db down")

            def set(self, key, value):
                raise RuntimeError("db down")

        sc = ShutdownCoordinator(
            settings_repo=_BrokenRepo(),
            maintenance_cache_ttl=0,
        )
        # With no prior write, the local flag is clear, so a failed
        # read should surface as "not in maintenance".
        assert sc.maintenance_mode is False


# ---------------------------------------------------------------------------
# TestReload
# ---------------------------------------------------------------------------


class TestReload:
    def test_reload_requested_starts_false(self):
        sc = ShutdownCoordinator()
        assert sc.reload_requested is False

    def test_consume_reload_clears_flag(self):
        sc = ShutdownCoordinator()
        sc._reload_flag.set()
        assert sc.reload_requested is True
        sc.consume_reload()
        assert sc.reload_requested is False


# ---------------------------------------------------------------------------
# TestDrainProcessingChallenges
# ---------------------------------------------------------------------------


class TestDrainProcessingChallenges:
    def test_calls_drain_processing(self):
        sc = ShutdownCoordinator()
        repo = MagicMock()
        repo.drain_processing.return_value = 5
        count = sc.drain_processing_challenges(repo)
        assert count == 5
        repo.drain_processing.assert_called_once()

    def test_handles_none_repo(self):
        sc = ShutdownCoordinator()
        count = sc.drain_processing_challenges(None)
        assert count == 0

    def test_handles_exception(self):
        sc = ShutdownCoordinator()
        repo = MagicMock()
        repo.drain_processing.side_effect = RuntimeError("db error")
        count = sc.drain_processing_challenges(repo)
        assert count == 0
