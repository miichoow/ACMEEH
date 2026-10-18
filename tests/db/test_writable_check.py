"""Unit tests for the pool check that rejects connections attached to a standby.

After a Patroni failover, pooled connections can stay attached to the node that was
demoted.  ``SELECT 1`` succeeds there and ``ReadOnlySqlTransaction`` does not close the
connection, so without this check such connections keep failing writes for minutes.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import psycopg
import pytest

from acmeeh.db.init import (
    ReadOnlyConnectionError,
    _reject_read_only_connection,
    install_writable_check,
)


class _FakeCursor:
    def __init__(self, conn, in_recovery):
        self._conn = conn
        self._in_recovery = in_recovery

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, query):
        self._conn.queries.append((query, self._conn.autocommit))

    def fetchone(self):
        return (self._in_recovery,)


class _FakeConn:
    def __init__(self, *, in_recovery, autocommit):
        self.autocommit = autocommit
        self.closed = False
        self.queries = []
        self._in_recovery = in_recovery

    def cursor(self, **_kwargs):
        return _FakeCursor(self, self._in_recovery)

    def close(self):
        self.closed = True


class TestRejectReadOnlyConnection:
    def test_writable_connection_passes_and_stays_open(self):
        conn = _FakeConn(in_recovery=False, autocommit=True)
        _reject_read_only_connection(conn)
        assert not conn.closed
        assert conn.queries == [("SELECT pg_is_in_recovery()", True)]

    def test_standby_connection_is_closed_and_rejected(self):
        conn = _FakeConn(in_recovery=True, autocommit=True)
        with pytest.raises(ReadOnlyConnectionError):
            _reject_read_only_connection(conn)
        # Closing is what makes psycopg_pool discard and replace it; a connection that
        # is rejected but still open would be handed back to the pool and re-checked.
        assert conn.closed

    def test_is_an_operational_error(self):
        assert issubclass(ReadOnlyConnectionError, psycopg.OperationalError)

    @pytest.mark.parametrize("in_recovery", [False, True])
    def test_autocommit_is_enabled_for_the_query_and_restored(self, in_recovery):
        conn = _FakeConn(in_recovery=in_recovery, autocommit=False)
        try:
            _reject_read_only_connection(conn)
        except ReadOnlyConnectionError:
            pass
        assert conn.queries == [("SELECT pg_is_in_recovery()", True)]
        # not left in autocommit, and not left in a transaction either
        assert conn.autocommit is False


class TestInstallWritableCheck:
    def test_replaces_the_pool_check(self):
        raw_pool = SimpleNamespace(_check=object(), get_stats=lambda: {}, open=lambda: None)
        db = SimpleNamespace(pool=raw_pool)
        assert install_writable_check(db) is True
        assert raw_pool._check is _reject_read_only_connection

    def test_unknown_pool_layout_is_a_warning_not_a_crash(self, caplog):
        raw_pool = SimpleNamespace(get_stats=lambda: {}, open=lambda: None)  # no _check
        db = SimpleNamespace(pool=raw_pool)
        with caplog.at_level("WARNING", logger="acmeeh.db.init"):
            assert install_writable_check(db) is False
        assert any("writable" in r.getMessage() for r in caplog.records)

    def test_no_pool_is_a_warning_not_a_crash(self):
        assert install_writable_check(SimpleNamespace()) is False


class TestInitDatabaseInstallsCheck:
    def _settings(self):
        return SimpleNamespace(
            host="h",
            port=5432,
            database="d",
            user="u",
            password="p",
            sslmode="prefer",
            min_connections=1,
            max_connections=10,
            connection_timeout=5.0,
            auto_setup=False,
            max_idle_seconds=300.0,
            sslrootcert="",
            sslcert="",
            sslkey="",
        )

    @patch("acmeeh.db.init.install_writable_check")
    @patch("acmeeh.db.init._settings_to_config")
    @patch("acmeeh.db.init.Database")
    def test_installed_once_on_first_init(self, mock_db_cls, _cfg, mock_install):
        from acmeeh.db.init import init_database

        mock_db_cls.is_initialized.return_value = False
        db = init_database(self._settings())
        mock_install.assert_called_once_with(db)

    @patch("acmeeh.db.init.install_writable_check")
    @patch("acmeeh.db.init.Database")
    def test_not_reinstalled_when_already_initialised(self, mock_db_cls, mock_install):
        from acmeeh.db.init import init_database

        mock_db_cls.is_initialized.return_value = True
        mock_db_cls.get_instance.return_value = MagicMock()
        init_database(self._settings())
        mock_install.assert_not_called()
