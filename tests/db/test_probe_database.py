"""Unit tests for ``probe_database``: a readiness probe that fails fast.

During a failover ``/readyz`` used to wait for a pool connection up to
``database.connection_timeout`` (8 s on the test cluster), longer than a load balancer's check
timeout.  The balancer logged ``Layer7 timeout`` and dropped every instance at once.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from psycopg_pool import PoolTimeout

from acmeeh.db.init import PROBE_TIMEOUT_SECONDS, probe_database


class _Conn:
    def __init__(self, queries):
        self._queries = queries

    def execute(self, query):
        self._queries.append(query)


class _Ctx:
    def __init__(self, queries):
        self._queries = queries

    def __enter__(self):
        return _Conn(self._queries)

    def __exit__(self, *exc):
        return False


class _FakePool:
    """Looks like a psycopg_pool pool to ``_get_raw_pool``."""

    def __init__(self, exc=None):
        self.exc = exc
        self.timeouts = []
        self.queries = []

    def get_stats(self):
        return {}

    def open(self):
        pass

    def connection(self, timeout=None):
        self.timeouts.append(timeout)
        if self.exc is not None:
            raise self.exc
        return _Ctx(self.queries)


class TestProbeDatabase:
    def test_default_timeout_is_below_a_typical_lb_check_timeout(self):
        assert 0 < PROBE_TIMEOUT_SECONDS < 3

    def test_checks_out_a_connection_with_the_short_timeout(self):
        pool = _FakePool()
        db = SimpleNamespace(pool=pool, fetch_value=MagicMock())
        probe_database(db)
        assert pool.timeouts == [PROBE_TIMEOUT_SECONDS]
        assert pool.queries == ["SELECT 1"]
        db.fetch_value.assert_not_called()  # must not take the blocking path

    def test_explicit_timeout_is_honoured(self):
        pool = _FakePool()
        probe_database(SimpleNamespace(pool=pool), timeout=0.5)
        assert pool.timeouts == [0.5]

    def test_pool_timeout_is_raised_to_the_caller(self):
        pool = _FakePool(exc=PoolTimeout("couldn't get a connection after 2.00 sec"))
        with pytest.raises(PoolTimeout):
            probe_database(SimpleNamespace(pool=pool))

    def test_falls_back_to_fetch_value_without_a_raw_pool(self):
        db = SimpleNamespace(pool=None, _pool=None, fetch_value=MagicMock(return_value=1))
        probe_database(db)
        db.fetch_value.assert_called_once_with("SELECT 1")

    def test_fallback_errors_are_raised(self):
        db = SimpleNamespace(
            pool=None, _pool=None, fetch_value=MagicMock(side_effect=ConnectionError("down"))
        )
        with pytest.raises(ConnectionError):
            probe_database(db)
