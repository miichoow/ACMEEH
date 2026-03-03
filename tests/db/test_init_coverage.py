"""Tests for db/init.py pool helpers, advisory lock, and fork-reset code."""

from __future__ import annotations

from collections import deque
from unittest.mock import MagicMock, patch

from acmeeh.db.init import (
    _close_inherited_connections,
    _ConnectionWrapper,
    _get_raw_pool,
    _has_pool_internals,
    _reset_pool_after_fork,
    advisory_lock,
    get_pool_health,
    init_database,
    is_pool_healthy,
    log_pool_stats,
    reinit_pool_after_fork,
)

# ======================================================================
# _get_raw_pool
# ======================================================================


class TestGetRawPool:
    def test_none_when_no_pool_attr(self):
        db = object()
        assert _get_raw_pool(db) is None

    def test_returns_pool_with_get_stats_and_open(self):
        db = MagicMock()
        pool = MagicMock(spec=["get_stats", "open"])
        db.pool = pool
        result = _get_raw_pool(db)
        assert result is pool

    def test_digs_into_wrapper(self):
        db = MagicMock()
        wrapper = MagicMock(spec=["_pool"])
        inner_pool = MagicMock()
        wrapper._pool = inner_pool
        db.pool = wrapper
        # wrapper lacks get_stats+open, so we dig
        del wrapper.get_stats
        del wrapper.open
        result = _get_raw_pool(db)
        assert result is inner_pool

    def test_returns_wrapper_as_last_resort(self):
        db = MagicMock()
        wrapper = MagicMock(spec=[])
        db.pool = wrapper
        # Remove get_stats and open to skip the first check
        result = _get_raw_pool(db)
        # Should return wrapper (or something from it)
        assert result is not None

    def test_uses_underscore_pool_attr(self):
        db = MagicMock(spec=["_pool"])
        inner = MagicMock(spec=["get_stats", "open"])
        db._pool = inner
        db.pool = None
        result = _get_raw_pool(db)
        assert result is inner


# ======================================================================
# log_pool_stats
# ======================================================================


class TestLogPoolStats:
    def test_no_pool(self):
        db = object()
        log_pool_stats(db)  # should not raise

    @patch("acmeeh.db.init._get_raw_pool")
    def test_with_pool(self, mock_get):
        pool = MagicMock()
        pool.get_stats.return_value = {
            "pool_size": 10,
            "pool_available": 5,
            "requests_waiting": 0,
        }
        mock_get.return_value = pool
        log_pool_stats(MagicMock(), context="test")

    @patch("acmeeh.db.init._get_raw_pool")
    def test_stats_raises(self, mock_get):
        pool = MagicMock()
        pool.get_stats.side_effect = RuntimeError("broken")
        mock_get.return_value = pool
        log_pool_stats(MagicMock())  # should not raise

    @patch("acmeeh.db.init._get_raw_pool")
    def test_no_context(self, mock_get):
        pool = MagicMock()
        pool.get_stats.return_value = {
            "pool_size": 10,
            "pool_available": 5,
            "requests_waiting": 0,
        }
        mock_get.return_value = pool
        log_pool_stats(MagicMock())  # context=""


# ======================================================================
# get_pool_health
# ======================================================================


class TestGetPoolHealth:
    def test_no_pool(self):
        health, stats = get_pool_health(object())
        assert health == "healthy"
        assert stats == {}

    @patch("acmeeh.db.init._get_raw_pool")
    def test_healthy(self, mock_get):
        pool = MagicMock()
        pool.get_stats.return_value = {
            "pool_available": 10,
            "requests_waiting": 0,
            "pool_size": 20,
            "pool_max": 20,
        }
        mock_get.return_value = pool
        health, stats = get_pool_health(MagicMock())
        assert health == "healthy"
        assert stats["available"] == 10

    @patch("acmeeh.db.init._get_raw_pool")
    def test_pressure(self, mock_get):
        pool = MagicMock()
        pool.get_stats.return_value = {
            "pool_available": 2,
            "requests_waiting": 0,
            "pool_size": 10,
            "pool_max": 10,
        }
        mock_get.return_value = pool
        health, stats = get_pool_health(MagicMock(), pressure_threshold=3)
        assert health == "pressure"

    @patch("acmeeh.db.init._get_raw_pool")
    def test_critical(self, mock_get):
        pool = MagicMock()
        pool.get_stats.return_value = {
            "pool_available": 0,
            "requests_waiting": 5,
            "pool_size": 10,
            "pool_max": 10,
        }
        mock_get.return_value = pool
        health, stats = get_pool_health(MagicMock())
        assert health == "critical"

    @patch("acmeeh.db.init._get_raw_pool")
    def test_exception(self, mock_get):
        pool = MagicMock()
        pool.get_stats.side_effect = RuntimeError("broken")
        mock_get.return_value = pool
        health, stats = get_pool_health(MagicMock())
        assert health == "healthy"
        assert stats == {}

    @patch("acmeeh.db.init._get_raw_pool")
    def test_pool_no_get_stats(self, mock_get):
        pool = MagicMock(spec=[])  # No get_stats
        mock_get.return_value = pool
        health, stats = get_pool_health(MagicMock())
        assert health == "healthy"


# ======================================================================
# is_pool_healthy
# ======================================================================


class TestIsPoolHealthy:
    @patch("acmeeh.db.init.get_pool_health")
    def test_healthy(self, mock_health):
        mock_health.return_value = ("healthy", {})
        assert is_pool_healthy(MagicMock()) is True

    @patch("acmeeh.db.init.get_pool_health")
    def test_pressure(self, mock_health):
        mock_health.return_value = ("pressure", {})
        assert is_pool_healthy(MagicMock()) is False


# ======================================================================
# _ConnectionWrapper
# ======================================================================


class TestConnectionWrapper:
    def test_execute(self):
        conn = MagicMock()
        cur = MagicMock()
        cur.rowcount = 3
        conn.execute.return_value = cur
        w = _ConnectionWrapper(conn)
        assert w.execute("UPDATE x SET y = 1") == 3

    def test_fetch_all_as_dict(self):
        conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [{"id": 1}]
        conn.cursor.return_value = mock_cursor
        w = _ConnectionWrapper(conn)
        result = w.fetch_all("SELECT * FROM x", as_dict=True)
        assert result == [{"id": 1}]

    def test_fetch_all_no_dict(self):
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchall.return_value = [(1, 2)]
        conn.execute.return_value = cur
        w = _ConnectionWrapper(conn)
        result = w.fetch_all("SELECT * FROM x")
        assert result == [(1, 2)]

    def test_fetch_one_as_dict(self):
        conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {"id": 1}
        conn.cursor.return_value = mock_cursor
        w = _ConnectionWrapper(conn)
        result = w.fetch_one("SELECT * FROM x LIMIT 1", as_dict=True)
        assert result == {"id": 1}

    def test_fetch_one_no_dict(self):
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchone.return_value = (1, 2)
        conn.execute.return_value = cur
        w = _ConnectionWrapper(conn)
        result = w.fetch_one("SELECT * FROM x LIMIT 1")
        assert result == (1, 2)

    def test_fetch_value(self):
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchone.return_value = (42,)
        conn.execute.return_value = cur
        w = _ConnectionWrapper(conn)
        assert w.fetch_value("SELECT COUNT(*)") == 42

    def test_fetch_value_none(self):
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchone.return_value = None
        conn.execute.return_value = cur
        w = _ConnectionWrapper(conn)
        assert w.fetch_value("SELECT COUNT(*)") is None


# ======================================================================
# advisory_lock
# ======================================================================


class TestAdvisoryLock:
    def test_no_db(self):
        with advisory_lock(None, 123) as (acquired, conn):
            assert acquired is True
            assert conn is None

    def test_db_without_connection_method(self):
        db = MagicMock(spec=[])
        with advisory_lock(db, 123) as (acquired, conn):
            assert acquired is True
            assert conn is None

    @patch("acmeeh.db.init._get_raw_pool")
    def test_pool_empty_yields_false(self, mock_get):
        pool = MagicMock()
        pool.get_stats.return_value = {"pool_available": 0}
        mock_get.return_value = pool
        db = MagicMock()
        with advisory_lock(db, 123) as (acquired, conn):
            assert acquired is False
            assert conn is None

    @patch("acmeeh.db.init._get_raw_pool")
    def test_pool_stats_exception(self, mock_get):
        pool = MagicMock()
        pool.get_stats.side_effect = RuntimeError("broken")
        mock_get.return_value = pool
        db = MagicMock()
        # Mock the connection context
        mock_conn = MagicMock()
        mock_row = (True,)
        mock_conn.execute.return_value.fetchone.return_value = mock_row
        db.connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        db.connection.return_value.__exit__ = MagicMock(return_value=False)
        with advisory_lock(db, 123) as (acquired, conn):
            assert acquired is True
            assert conn is not None

    @patch("acmeeh.db.init._get_raw_pool")
    def test_lock_acquired(self, mock_get):
        mock_get.return_value = None  # No pool check
        db = MagicMock()
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (True,)
        db.connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        db.connection.return_value.__exit__ = MagicMock(return_value=False)
        with advisory_lock(db, 123) as (acquired, conn):
            assert acquired is True
            assert isinstance(conn, _ConnectionWrapper)

    @patch("acmeeh.db.init._get_raw_pool")
    def test_lock_not_acquired(self, mock_get):
        mock_get.return_value = None
        db = MagicMock()
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (False,)
        db.connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        db.connection.return_value.__exit__ = MagicMock(return_value=False)
        with advisory_lock(db, 123) as (acquired, conn):
            assert acquired is False
            assert conn is None

    @patch("acmeeh.db.init._get_raw_pool")
    def test_lock_released_on_exit(self, mock_get):
        mock_get.return_value = None
        db = MagicMock()
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (True,)
        db.connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        db.connection.return_value.__exit__ = MagicMock(return_value=False)
        with advisory_lock(db, 123):
            pass
        # Check that pg_advisory_unlock was called
        calls = mock_conn.execute.call_args_list
        unlock_calls = [c for c in calls if "pg_advisory_unlock" in str(c)]
        assert len(unlock_calls) >= 1


# ======================================================================
# _has_pool_internals
# ======================================================================


class TestHasPoolInternals:
    def test_has_all(self):
        pool = MagicMock()
        # MagicMock has all attributes by default
        assert _has_pool_internals(pool) is True

    def test_missing_attr(self):
        pool = MagicMock(spec=[])
        assert _has_pool_internals(pool) is False


# ======================================================================
# _close_inherited_connections
# ======================================================================


class TestCloseInheritedConnections:
    def test_no_pool_deque(self):
        pool = MagicMock(spec=[])
        assert _close_inherited_connections(pool) == 0

    def test_close_connections(self):
        conn1 = MagicMock()
        conn2 = MagicMock()
        pool = MagicMock()
        pool._pool = deque([conn1, conn2])
        result = _close_inherited_connections(pool)
        assert result == 2
        conn1.close.assert_called_once()
        conn2.close.assert_called_once()

    def test_close_exception(self):
        conn1 = MagicMock()
        conn1.close.side_effect = RuntimeError("close error")
        pool = MagicMock()
        pool._pool = deque([conn1])
        result = _close_inherited_connections(pool)
        assert result == 1  # Still counted

    def test_empty_deque(self):
        pool = MagicMock()
        pool._pool = deque()
        assert _close_inherited_connections(pool) == 0


# ======================================================================
# _reset_pool_after_fork
# ======================================================================


class TestResetPoolAfterFork:
    def test_full_reset(self):
        pool = MagicMock()
        pool._pool = deque()
        pool._nconns = 5
        pool._growing = True
        pool._nconns_min = 3
        pool._waiting = deque([1, 2])
        pool._workers = ["dead-thread"]
        pool._sched_runner = "dead-sched"
        pool._closed = False
        pool._opened = True
        pool._min_size = 5
        pool._pool_full_event = "something"

        _reset_pool_after_fork(pool)

        assert pool._nconns == 5  # Set to min_size
        assert pool._growing is False
        assert pool._nconns_min == 0
        assert pool._workers == []
        assert pool._sched_runner is None
        assert pool._closed is True
        assert pool._opened is False
        assert pool._pool_full_event is None
        pool.open.assert_called_once_with(wait=False)

    def test_open_fails(self):
        pool = MagicMock()
        pool._pool = deque()
        pool._nconns = 0
        pool._growing = False
        pool._workers = []
        pool._closed = False
        pool._opened = True
        pool._min_size = 3
        pool.open.side_effect = RuntimeError("open failed")

        # Should not raise
        _reset_pool_after_fork(pool)

    def test_missing_optional_attrs(self):
        """Test reset when pool lacks optional attributes like _growing."""
        pool = MagicMock(
            spec=["_pool", "_nconns", "_workers", "_closed", "_opened", "_min_size", "open"]
        )
        pool._pool = deque()
        pool._nconns = 0
        pool._workers = []
        pool._closed = False
        pool._opened = True
        pool._min_size = 5

        _reset_pool_after_fork(pool)
        pool.open.assert_called_once()


# ======================================================================
# reinit_pool_after_fork
# ======================================================================


class TestReinitPoolAfterFork:
    @patch("acmeeh.db.init.Database")
    def test_not_initialized(self, MockDB):
        MockDB.is_initialized.return_value = False
        reinit_pool_after_fork()  # should return early

    @patch("acmeeh.db.init._reset_pool_after_fork")
    @patch("acmeeh.db.init._has_pool_internals")
    @patch("acmeeh.db.init._get_raw_pool")
    @patch("acmeeh.db.init.Database")
    def test_full_reset_path(self, MockDB, mock_get, mock_has, mock_reset):
        MockDB.is_initialized.return_value = True
        db = MockDB.get_instance.return_value
        pool = MagicMock()
        mock_get.return_value = pool
        mock_has.return_value = True

        reinit_pool_after_fork()

        mock_reset.assert_called_once_with(pool)

    @patch("acmeeh.db.init._get_raw_pool")
    @patch("acmeeh.db.init.Database")
    def test_no_pool(self, MockDB, mock_get):
        MockDB.is_initialized.return_value = True
        mock_get.return_value = None
        reinit_pool_after_fork()  # should log warning and return

    @patch("acmeeh.db.init._has_pool_internals")
    @patch("acmeeh.db.init._get_raw_pool")
    @patch("acmeeh.db.init.Database")
    def test_fallback_to_check(self, MockDB, mock_get, mock_has):
        MockDB.is_initialized.return_value = True
        pool = MagicMock()
        mock_get.return_value = pool
        mock_has.return_value = False

        reinit_pool_after_fork()

        pool.check.assert_called_once()

    @patch("acmeeh.db.init._has_pool_internals")
    @patch("acmeeh.db.init._get_raw_pool")
    @patch("acmeeh.db.init.Database")
    def test_fallback_check_raises(self, MockDB, mock_get, mock_has):
        MockDB.is_initialized.return_value = True
        pool = MagicMock()
        pool.check.side_effect = RuntimeError("check failed")
        mock_get.return_value = pool
        mock_has.return_value = False

        reinit_pool_after_fork()  # should not raise

    @patch("acmeeh.db.init._has_pool_internals")
    @patch("acmeeh.db.init._get_raw_pool")
    @patch("acmeeh.db.init.Database")
    def test_fallback_no_check_method(self, MockDB, mock_get, mock_has):
        MockDB.is_initialized.return_value = True
        pool = MagicMock(spec=[])  # No check method
        mock_get.return_value = pool
        mock_has.return_value = False

        reinit_pool_after_fork()  # should not raise


# ======================================================================
# init_database warning paths
# ======================================================================


class TestInitDatabaseWarnings:
    @patch("acmeeh.db.init.Database")
    def test_small_max_connections_warning(self, MockDB):
        MockDB.is_initialized.return_value = False
        MockDB.init.return_value = MagicMock()
        settings = MagicMock()
        settings.host = "localhost"
        settings.port = 5432
        settings.database = "test"
        settings.user = "user"
        settings.password = "pass"
        settings.sslmode = "prefer"
        settings.min_connections = 1
        settings.max_connections = 5  # < 10
        settings.connection_timeout = 5.0
        settings.max_idle_seconds = 300
        settings.auto_setup = False

        with patch("acmeeh.db.init.log") as mock_log:
            init_database(settings)
            warning_calls = [
                c for c in mock_log.warning.call_args_list if "max_connections" in str(c)
            ]
            assert len(warning_calls) >= 1

    @patch("acmeeh.db.init.Database")
    def test_high_timeout_warning(self, MockDB):
        MockDB.is_initialized.return_value = False
        MockDB.init.return_value = MagicMock()
        settings = MagicMock()
        settings.host = "localhost"
        settings.port = 5432
        settings.database = "test"
        settings.user = "user"
        settings.password = "pass"
        settings.sslmode = "prefer"
        settings.min_connections = 5
        settings.max_connections = 20
        settings.connection_timeout = 30.0  # > 15
        settings.max_idle_seconds = 300
        settings.auto_setup = False

        with patch("acmeeh.db.init.log") as mock_log:
            init_database(settings)
            warning_calls = [
                c for c in mock_log.warning.call_args_list if "connection_timeout" in str(c)
            ]
            assert len(warning_calls) >= 1

    @patch("acmeeh.db.init.Database")
    def test_successful_init_logging(self, MockDB):
        MockDB.is_initialized.return_value = False
        MockDB.init.return_value = MagicMock()
        settings = MagicMock()
        settings.host = "localhost"
        settings.port = 5432
        settings.database = "test"
        settings.user = "user"
        settings.password = "pass"
        settings.sslmode = "prefer"
        settings.min_connections = 5
        settings.max_connections = 20
        settings.connection_timeout = 5.0
        settings.max_idle_seconds = 300
        settings.auto_setup = True

        result = init_database(settings)
        assert result is not None
