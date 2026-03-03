"""Tests for exponential backoff behavior in all three background workers.

Tests verify that ChallengeWorker, CleanupWorker, and ExpirationWorker
correctly implement exponential backoff on consecutive failures, reset
counters on success, respect their configured caps, and emit the correct
metrics.

Pattern: No actual threads are started.  We invoke ``_run`` directly after
pre-setting ``_stop_event`` so the loop executes exactly one iteration and
then exits.  Internal methods (``_poll``, ``_check_expirations``, task
callables) are mocked to raise or succeed as needed.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from acmeeh.metrics.collector import MetricsCollector
from acmeeh.services.cleanup_worker import CleanupWorker, _CleanupTask
from acmeeh.services.expiration_worker import ExpirationWorker
from acmeeh.services.workers import ChallengeWorker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_challenge_worker(poll_seconds: int = 10, metrics=None) -> ChallengeWorker:
    """Build a ChallengeWorker with fully mocked dependencies."""
    return ChallengeWorker(
        challenge_service=MagicMock(),
        challenge_repo=MagicMock(),
        authz_repo=MagicMock(),
        account_repo=MagicMock(),
        poll_seconds=poll_seconds,
        metrics=metrics,
    )


def _make_expiration_worker(
    interval_seconds: int = 60,
    metrics=None,
) -> ExpirationWorker:
    """Build an ExpirationWorker with a mock NotificationSettings."""
    settings = MagicMock()
    settings.enabled = True
    settings.expiration_warning_days = [30, 7]
    settings.expiration_check_interval_seconds = interval_seconds
    return ExpirationWorker(
        cert_repo=MagicMock(),
        notification_service=MagicMock(),
        settings=settings,
        db=MagicMock(),
        metrics=metrics,
    )


def _run_one_iteration(worker) -> None:
    """Run the worker loop for exactly one iteration.

    Sets the stop event *before* calling ``_run`` so that after the first
    pass through the while-loop body, ``_stop_event.is_set()`` returns True
    and the loop exits.

    Because ``_stop_event.wait()`` is used for sleeping, we also patch it
    to be a no-op so that backoff waits do not actually block.
    """
    original_wait = worker._stop_event.wait

    call_count = 0

    def _wait_then_stop(timeout=None):
        nonlocal call_count
        call_count += 1
        # After the first wait (which is either the backoff wait or the
        # normal poll-interval wait), signal the loop to exit.
        worker._stop_event.set()

    worker._stop_event.wait = _wait_then_stop
    worker._run()
    # Restore original wait so the object is clean.
    worker._stop_event.wait = original_wait


# ---------------------------------------------------------------------------
# ChallengeWorker backoff tests
# ---------------------------------------------------------------------------


class TestChallengeWorkerBackoff:
    """ChallengeWorker exponential backoff on _poll failures."""

    def test_challenge_worker_backoff_on_failure(self):
        """_consecutive_failures increments and backoff delay increases."""
        worker = _make_challenge_worker(poll_seconds=10)
        worker._collect_work = MagicMock(side_effect=RuntimeError("db down"))

        wait_timeouts: list[float] = []
        original_set = worker._stop_event.set

        def capture_wait(timeout=None):
            wait_timeouts.append(timeout)
            worker._stop_event.set()

        # Run three iterations manually to observe escalating backoff.
        for expected_failures in range(1, 4):
            worker._stop_event.clear()
            worker._stop_event.wait = capture_wait
            worker._run()
            assert worker._consecutive_failures == expected_failures

        # backoff = poll_seconds * 2^failures => 10*2=20, 10*4=40, 10*8=80
        assert wait_timeouts == [20, 40, 80]

    def test_challenge_worker_resets_on_success(self):
        """After failures, a successful _poll resets the counter to 0."""
        worker = _make_challenge_worker(poll_seconds=5)

        # Simulate three prior failures.
        worker._consecutive_failures = 3
        worker._collect_work = MagicMock(return_value=[])  # succeeds

        _run_one_iteration(worker)

        assert worker._consecutive_failures == 0

    def test_challenge_worker_backoff_cap(self):
        """Backoff is capped at 300 seconds regardless of failure count."""
        worker = _make_challenge_worker(poll_seconds=10)
        worker._collect_work = MagicMock(side_effect=RuntimeError("fail"))

        # Pre-set a high failure count so 10 * 2^20 would be huge.
        worker._consecutive_failures = 19

        wait_timeouts: list[float] = []

        def capture_wait(timeout=None):
            wait_timeouts.append(timeout)
            worker._stop_event.set()

        worker._stop_event.wait = capture_wait
        worker._run()

        # 10 * 2^20 = 10_485_760 but capped at 300.
        assert wait_timeouts == [300]
        assert worker._consecutive_failures == 20


class TestChallengeWorkerMetrics:
    """ChallengeWorker emits the correct metrics on success and error."""

    def test_challenge_worker_metrics_on_error(self):
        """acmeeh_challenge_worker_errors_total increments on poll failure."""
        metrics = MetricsCollector()
        worker = _make_challenge_worker(poll_seconds=5, metrics=metrics)
        worker._collect_work = MagicMock(side_effect=RuntimeError("boom"))

        _run_one_iteration(worker)

        assert metrics.get("acmeeh_challenge_worker_errors_total") == 1

    def test_challenge_worker_metrics_on_success(self):
        """acmeeh_challenge_worker_polls_total increments on successful poll."""
        metrics = MetricsCollector()
        worker = _make_challenge_worker(poll_seconds=5, metrics=metrics)
        worker._collect_work = MagicMock(return_value=[])  # succeeds

        _run_one_iteration(worker)

        assert metrics.get("acmeeh_challenge_worker_polls_total") == 1


# ---------------------------------------------------------------------------
# CleanupWorker / _CleanupTask backoff tests
# ---------------------------------------------------------------------------


class TestCleanupTaskBackoff:
    """_CleanupTask tracks consecutive_failures independently."""

    def test_cleanup_task_consecutive_failures(self):
        """consecutive_failures increments when the task callable raises."""
        failing_func = MagicMock(side_effect=RuntimeError("task error"))
        task = _CleanupTask(name="test_task", interval_seconds=60, func=failing_func)

        assert task.consecutive_failures == 0

        # Simulate what CleanupWorker._run does on exception.
        import time as _time

        now = _time.monotonic()
        for i in range(1, 4):
            try:
                task.run(now)
                task.consecutive_failures = 0  # pragma: no cover
            except Exception:
                task.consecutive_failures += 1

            assert task.consecutive_failures == i

    def test_cleanup_task_resets_on_success(self):
        """consecutive_failures resets to 0 after a successful run."""
        call_count = 0

        def sometimes_fail(conn=None):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise RuntimeError("fail")

        task = _CleanupTask(name="flaky", interval_seconds=60, func=sometimes_fail)

        import time as _time

        now = _time.monotonic()

        # Two failures.
        for _ in range(2):
            try:
                task.run(now)
                task.consecutive_failures = 0
            except Exception:
                task.consecutive_failures += 1

        assert task.consecutive_failures == 2

        # Third call succeeds.
        try:
            task.run(now)
            task.consecutive_failures = 0
        except Exception:
            task.consecutive_failures += 1  # pragma: no cover

        assert task.consecutive_failures == 0


class TestCleanupWorkerMetrics:
    """CleanupWorker emits cleanup_runs_total and cleanup_errors_total."""

    def test_cleanup_worker_metrics(self):
        """Verify both success and error metrics are emitted."""
        metrics = MetricsCollector()

        # Build a CleanupWorker with no built-in tasks (we add our own).
        worker = CleanupWorker(metrics=metrics)

        # Add a task that succeeds.
        good_func = MagicMock()
        good_task = _CleanupTask(name="good", interval_seconds=0, func=good_func)
        worker._tasks.append(good_task)

        # Add a task that fails.
        bad_func = MagicMock(side_effect=RuntimeError("kaboom"))
        bad_task = _CleanupTask(name="bad", interval_seconds=0, func=bad_func)
        worker._tasks.append(bad_task)

        # Run one iteration of the loop.
        _run_one_iteration(worker)

        # The good task should record a run.
        assert metrics.get("acmeeh_cleanup_runs_total", labels={"task": "good"}) == 1

        # The bad task should record an error.
        assert metrics.get("acmeeh_cleanup_errors_total", labels={"task": "bad"}) == 1

        # The bad task's failure counter should have incremented.
        assert bad_task.consecutive_failures == 1

        # The good task's failure counter should remain zero.
        assert good_task.consecutive_failures == 0


# ---------------------------------------------------------------------------
# ExpirationWorker backoff tests
# ---------------------------------------------------------------------------


class TestExpirationWorkerBackoff:
    """ExpirationWorker exponential backoff on _check_expirations failure."""

    def test_expiration_worker_backoff(self):
        """Backoff increases exponentially: interval * 2^failures."""
        interval = 60
        worker = _make_expiration_worker(interval_seconds=interval)
        worker._collect_expiring = MagicMock(
            side_effect=RuntimeError("db unreachable"),
        )

        wait_timeouts: list[float] = []

        def capture_wait(timeout=None):
            wait_timeouts.append(timeout)
            worker._stop_event.set()

        # Run three consecutive failing iterations.
        for expected_failures in range(1, 4):
            worker._stop_event.clear()
            worker._stop_event.wait = capture_wait
            worker._run()
            assert worker._consecutive_failures == expected_failures

        # backoff = interval * 2^failures, capped at interval * 8
        # failures=1 => 60*2=120, failures=2 => 60*4=240, failures=3 => 60*8=480 -> cap 480
        assert wait_timeouts == [120, 240, 480]

    def test_expiration_worker_backoff_cap(self):
        """Backoff is capped at interval * 8 even for many failures."""
        interval = 60
        worker = _make_expiration_worker(interval_seconds=interval)
        worker._collect_expiring = MagicMock(
            side_effect=RuntimeError("fail"),
        )

        # Pre-set high failure count so 2^failures would be enormous.
        worker._consecutive_failures = 99

        wait_timeouts: list[float] = []

        def capture_wait(timeout=None):
            wait_timeouts.append(timeout)
            worker._stop_event.set()

        worker._stop_event.wait = capture_wait
        worker._run()

        # Cap is interval * 8 = 480.
        assert wait_timeouts == [interval * 8]
        assert worker._consecutive_failures == 100

    def test_expiration_worker_resets_on_success(self):
        """Successful _check_expirations resets _consecutive_failures to 0."""
        worker = _make_expiration_worker(interval_seconds=30)
        worker._consecutive_failures = 5
        worker._collect_expiring = MagicMock(return_value=[])  # succeeds

        _run_one_iteration(worker)

        assert worker._consecutive_failures == 0

    def test_expiration_worker_metrics_on_error(self):
        """acmeeh_expiration_worker_errors_total increments on failure."""
        metrics = MetricsCollector()
        worker = _make_expiration_worker(interval_seconds=30, metrics=metrics)
        worker._collect_expiring = MagicMock(
            side_effect=RuntimeError("fail"),
        )

        _run_one_iteration(worker)

        assert metrics.get("acmeeh_expiration_worker_errors_total") == 1
