"""Comprehensive tests for CRLManager (acmeeh.ca.crl).

Covers: __init__, get_crl, _get_crl_locked, _build_with_shutdown_tracking,
force_rebuild, health_status, _is_stale, _read_db_cache, _write_db_cache,
and _build with various hash algorithms and revocation lists.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from acmeeh.ca.crl import _HASH_MAP, CRLManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(**overrides):
    """Return a mock CrlSettings with sensible defaults."""
    s = MagicMock()
    s.rebuild_interval_seconds = overrides.get("rebuild_interval_seconds", 3600)
    s.next_update_seconds = overrides.get("next_update_seconds", 86400)
    s.hash_algorithm = overrides.get("hash_algorithm", "sha256")
    return s


def _make_revoked_cert(serial="abcdef0123456789", revoked_at=None):
    """Return a mock revoked certificate object."""
    cert = MagicMock()
    cert.serial_number = serial
    cert.revoked_at = revoked_at or datetime.now(UTC)
    return cert


def _patch_builders():
    """Context manager that patches CertificateRevocationListBuilder and
    RevokedCertificateBuilder, returning (MockCRLBuilder_cls, MockRevBuilder_cls,
    mock_crl_bytes).
    """
    return (
        patch("acmeeh.ca.crl.CertificateRevocationListBuilder"),
        patch("acmeeh.ca.crl.RevokedCertificateBuilder"),
    )


def _setup_crl_builder_mock(MockCRLBuilder):
    """Configure the CRL builder mock chain and return (builder_instance, crl_object)."""
    mock_builder = MagicMock()
    MockCRLBuilder.return_value = mock_builder
    mock_builder.issuer_name.return_value = mock_builder
    mock_builder.last_update.return_value = mock_builder
    mock_builder.next_update.return_value = mock_builder
    mock_builder.add_revoked_certificate.return_value = mock_builder

    mock_crl = MagicMock()
    mock_builder.sign.return_value = mock_crl
    mock_crl.public_bytes.return_value = b"\x30\x82\x01\x00"

    return mock_builder, mock_crl


def _setup_rev_builder_mock(MockRevBuilder):
    """Configure the RevokedCertificateBuilder mock chain."""
    mock_rev = MagicMock()
    MockRevBuilder.return_value = mock_rev
    mock_rev.serial_number.return_value = mock_rev
    mock_rev.revocation_date.return_value = mock_rev
    mock_rev.build.return_value = MagicMock(name="revoked_certificate_object")
    return mock_rev


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def crl_settings():
    return _make_settings()


@pytest.fixture
def root_cert():
    cert = MagicMock()
    cert.subject = MagicMock(name="x509_Name")
    return cert


@pytest.fixture
def root_key():
    return MagicMock(name="root_private_key")


@pytest.fixture
def cert_repo():
    repo = MagicMock()
    repo.find_revoked.return_value = []
    repo.count_revoked_since.return_value = 0
    return repo


@pytest.fixture
def mock_db():
    return MagicMock(name="database")


@pytest.fixture
def manager(root_cert, root_key, cert_repo, crl_settings):
    """CRLManager without DB (non-HA mode)."""
    return CRLManager(root_cert, root_key, cert_repo, crl_settings)


@pytest.fixture
def ha_manager(root_cert, root_key, cert_repo, crl_settings, mock_db):
    """CRLManager with DB (HA mode)."""
    return CRLManager(
        root_cert,
        root_key,
        cert_repo,
        crl_settings,
        db=mock_db,
    )


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestInit:
    """CRLManager constructor sets internal state correctly."""

    def test_initial_state(self, root_cert, root_key, cert_repo, crl_settings):
        mgr = CRLManager(root_cert, root_key, cert_repo, crl_settings)
        assert mgr._root_cert is root_cert
        assert mgr._root_key is root_key
        assert mgr._cert_repo is cert_repo
        assert mgr._settings is crl_settings
        assert mgr._cached_crl is None
        assert mgr._cached_at == 0.0
        assert mgr._last_rebuild_error is None
        assert mgr._last_revoked_count == 0
        assert mgr._last_revocation_check == 0.0
        assert mgr._shutdown is None
        assert mgr._db is None

    def test_init_with_shutdown_and_db(
        self,
        root_cert,
        root_key,
        cert_repo,
        crl_settings,
        mock_db,
    ):
        shutdown = MagicMock()
        mgr = CRLManager(
            root_cert,
            root_key,
            cert_repo,
            crl_settings,
            shutdown_coordinator=shutdown,
            db=mock_db,
        )
        assert mgr._shutdown is shutdown
        assert mgr._db is mock_db


# ---------------------------------------------------------------------------
# get_crl()
# ---------------------------------------------------------------------------


class TestGetCrl:
    """get_crl() caching, double-check, stale fallback, and raise."""

    def test_returns_cached_crl_when_fresh(self, manager):
        """Scenario 1: cached CRL returned without rebuild."""
        manager._cached_crl = b"cached-crl-data"
        manager._cached_at = time.monotonic()

        result = manager.get_crl()
        assert result == b"cached-crl-data"
        # _build should not have been called (cert_repo untouched)
        manager._cert_repo.find_revoked.assert_not_called()

    def test_rebuilds_when_cache_expired(self, manager):
        """Scenario 2: expired cache triggers rebuild."""
        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2 as MockRev:
            _setup_crl_builder_mock(MockCRL)
            _setup_rev_builder_mock(MockRev)

            # Cache is old
            manager._cached_crl = b"old"
            manager._cached_at = time.monotonic() - 9999

            result = manager.get_crl()
            assert isinstance(result, bytes)
            # cert_repo.count_revoked_since should be called for incremental check
            manager._cert_repo.count_revoked_since.assert_called()

    def test_double_check_optimization(self, manager):
        """Scenario 3: another thread already rebuilt while waiting for lock.

        The first (unlocked) check sees a stale cache.  By the time the lock
        is acquired, the cache has been refreshed by another thread, so the
        second (locked) check returns immediately without rebuilding.
        """
        manager._cached_crl = b"rebuilt-by-other-thread"
        # First check sees stale cache
        manager._cached_at = time.monotonic() - 9999

        # Replace the lock with a mock so we can intercept __enter__
        real_lock = manager._lock
        mock_lock = MagicMock(wraps=real_lock)

        original_enter = real_lock.__enter__

        def enter_and_refresh(*args, **kwargs):
            result = original_enter(*args, **kwargs)
            # Simulate another thread having rebuilt the cache while we waited
            manager._cached_at = time.monotonic()
            return result

        mock_lock.__enter__ = enter_and_refresh
        mock_lock.__exit__ = real_lock.__exit__
        manager._lock = mock_lock

        result = manager.get_crl()
        assert result == b"rebuilt-by-other-thread"
        # _build should NOT have been called
        manager._cert_repo.find_revoked.assert_not_called()

    def test_returns_stale_crl_when_rebuild_fails(self, manager):
        """Scenario 4: stale CRL served when rebuild raises."""
        manager._cached_crl = b"stale-crl"
        manager._cached_at = 0.0  # force stale

        manager._cert_repo.count_revoked_since.side_effect = RuntimeError("boom")

        result = manager.get_crl()
        assert result == b"stale-crl"

    def test_raises_when_rebuild_fails_and_no_cache(self, manager):
        """Scenario 5: no stale CRL -> exception propagated."""
        assert manager._cached_crl is None

        # Patch the builders so the real cryptography code does not run
        # before find_revoked gets a chance to raise.
        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _setup_crl_builder_mock(MockCRL)
            manager._cert_repo.find_revoked.side_effect = RuntimeError("db down")

            with pytest.raises(RuntimeError, match="db down"):
                manager.get_crl()


# ---------------------------------------------------------------------------
# _get_crl_locked()
# ---------------------------------------------------------------------------


class TestGetCrlLocked:
    """_get_crl_locked() HA DB cache, incremental check, full rebuild."""

    def test_reads_fresh_db_cache_in_ha_mode(self, ha_manager, mock_db):
        """Scenario 6: DB cache hit that is fresh."""
        mock_db.fetch_one.return_value = {
            "crl_der": b"\x30\x00",
            "built_at": datetime.now(UTC) - timedelta(seconds=10),
            "revoked_count": 5,
        }

        result = ha_manager._get_crl_locked()
        assert result == b"\x30\x00"
        assert ha_manager._cached_crl == b"\x30\x00"
        assert ha_manager._last_rebuild_error is None
        assert ha_manager._last_revoked_count == 5
        mock_db.fetch_one.assert_called_once()

    def test_skips_stale_db_cache(self, ha_manager, mock_db):
        """Scenario 7: DB cache row exists but is stale -> falls through to build."""
        mock_db.fetch_one.return_value = {
            "crl_der": b"\x30\x00",
            "built_at": datetime.now(UTC) - timedelta(seconds=99999),
            "revoked_count": 1,
        }

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _setup_crl_builder_mock(MockCRL)

            result = ha_manager._get_crl_locked()
            assert isinstance(result, bytes)
            # Should have attempted a build (find_revoked called)
            ha_manager._cert_repo.find_revoked.assert_called_once()

    def test_incremental_no_new_revocations_extends_cache(self, manager, cert_repo):
        """Scenario 8: no new revocations -> cache extended, no rebuild."""
        manager._cached_crl = b"existing-crl"
        manager._cached_at = time.monotonic() - 5000
        manager._last_revocation_check = time.monotonic() - 100
        cert_repo.count_revoked_since.return_value = 0

        result = manager._get_crl_locked()
        assert result == b"existing-crl"
        # find_revoked should NOT be called (no rebuild)
        cert_repo.find_revoked.assert_not_called()
        # cached_at should be refreshed
        assert manager._cached_at > time.monotonic() - 2

    def test_incremental_new_revocations_triggers_rebuild(self, manager, cert_repo):
        """Scenario 9: new revocations detected -> full rebuild."""
        manager._cached_crl = b"old-crl"
        manager._cached_at = time.monotonic() - 5000
        manager._last_revocation_check = time.monotonic() - 100
        cert_repo.count_revoked_since.return_value = 3

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            mock_builder, mock_crl = _setup_crl_builder_mock(MockCRL)

            result = manager._get_crl_locked()
            assert result == mock_crl.public_bytes.return_value
            cert_repo.find_revoked.assert_called_once()

    def test_writes_to_db_after_rebuild_in_ha_mode(self, ha_manager, mock_db):
        """Scenario 10: after a full rebuild in HA mode, _write_db_cache called."""
        # DB cache returns None (no row or stale)
        mock_db.fetch_one.return_value = None

        # _write_db_cache now uses db.connection() context manager
        # so the advisory lock + upsert run on a single connection
        mock_conn = MagicMock()
        lock_row = MagicMock()
        lock_row.__getitem__ = lambda self, i: True  # row[0] -> True (lock acquired)
        lock_row.__bool__ = lambda self: True
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = lock_row
        mock_conn.execute.return_value = mock_cursor
        mock_db.connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_db.connection.return_value.__exit__ = MagicMock(return_value=False)

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            mock_builder, mock_crl = _setup_crl_builder_mock(MockCRL)

            ha_manager._get_crl_locked()

            # Connection used for the lock + upsert
            mock_db.connection.assert_called_once()
            assert mock_conn.execute.call_count >= 2  # lock + upsert (+ unlock)

    def test_first_build_when_no_cache_and_no_db(self, manager, cert_repo):
        """No cache, no DB -> full build."""
        assert manager._cached_crl is None

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _setup_crl_builder_mock(MockCRL)

            result = manager._get_crl_locked()
            assert result is not None
            cert_repo.find_revoked.assert_called_once()
            assert manager._last_rebuild_error is None

    def test_incremental_check_uses_datetime_min_when_no_prior_check(
        self,
        manager,
        cert_repo,
    ):
        """When _last_revocation_check is 0, datetime.min used as threshold."""
        manager._cached_crl = b"existing"
        manager._cached_at = time.monotonic() - 5000
        manager._last_revocation_check = 0.0
        cert_repo.count_revoked_since.return_value = 0

        manager._get_crl_locked()

        # Verify the datetime passed is very old
        call_args = cert_repo.count_revoked_since.call_args[0][0]
        assert call_args.year == 1  # datetime.min


# ---------------------------------------------------------------------------
# _build_with_shutdown_tracking()
# ---------------------------------------------------------------------------


class TestBuildWithShutdownTracking:
    def test_with_coordinator(self, manager):
        """Scenario 11: shutdown coordinator track() is entered and exited."""
        shutdown = MagicMock()
        ctx = MagicMock()
        shutdown.track.return_value = ctx
        manager._shutdown = shutdown

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _setup_crl_builder_mock(MockCRL)

            manager._build_with_shutdown_tracking()

            shutdown.track.assert_called_once_with("crl_rebuild")
            ctx.__enter__.assert_called_once()
            ctx.__exit__.assert_called_once_with(None, None, None)

    def test_without_coordinator(self, manager):
        """Scenario 12: no shutdown coordinator -> build runs normally."""
        assert manager._shutdown is None

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _setup_crl_builder_mock(MockCRL)

            result = manager._build_with_shutdown_tracking()
            assert result == b"\x30\x82\x01\x00"

    def test_coordinator_exit_called_even_on_build_error(self, manager):
        """Shutdown context exited even when _build raises."""
        shutdown = MagicMock()
        ctx = MagicMock()
        shutdown.track.return_value = ctx
        manager._shutdown = shutdown

        # Patch the builders so the real cryptography code does not run
        # before find_revoked raises.
        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _setup_crl_builder_mock(MockCRL)
            manager._cert_repo.find_revoked.side_effect = RuntimeError("build fail")

            with pytest.raises(RuntimeError, match="build fail"):
                manager._build_with_shutdown_tracking()

        ctx.__exit__.assert_called_once_with(None, None, None)


# ---------------------------------------------------------------------------
# force_rebuild()
# ---------------------------------------------------------------------------


class TestForceRebuild:
    def test_basic_force_rebuild(self, manager):
        """Scenario 13: force_rebuild returns bytes, updates cache."""
        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _setup_crl_builder_mock(MockCRL)

            result = manager.force_rebuild()
            assert result == b"\x30\x82\x01\x00"
            assert manager._cached_crl == b"\x30\x82\x01\x00"
            assert manager._cached_at > 0
            assert manager._last_rebuild_error is None

    def test_force_rebuild_with_db_write(self, ha_manager, mock_db):
        """Scenario 14: force_rebuild writes to DB in HA mode."""
        # _write_db_cache now uses db.connection() context manager
        mock_conn = MagicMock()
        lock_row = MagicMock()
        lock_row.__getitem__ = lambda self, i: True
        lock_row.__bool__ = lambda self: True
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = lock_row
        mock_conn.execute.return_value = mock_cursor
        mock_db.connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_db.connection.return_value.__exit__ = MagicMock(return_value=False)

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _setup_crl_builder_mock(MockCRL)

            ha_manager.force_rebuild()

            # Connection used for the lock + upsert
            mock_db.connection.assert_called_once()
            assert mock_conn.execute.call_count >= 2

    def test_force_rebuild_clears_previous_error(self, manager):
        """force_rebuild resets _last_rebuild_error."""
        manager._last_rebuild_error = "previous error"

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _setup_crl_builder_mock(MockCRL)

            manager.force_rebuild()
            assert manager._last_rebuild_error is None


# ---------------------------------------------------------------------------
# health_status()
# ---------------------------------------------------------------------------


class TestHealthStatus:
    def test_health_status_with_cache(self, manager):
        """Scenario 15: cache present -> last_rebuild is not None."""
        manager._cached_crl = b"data"
        manager._cached_at = time.monotonic() - 10
        manager._last_revoked_count = 3

        status = manager.health_status()
        assert status["last_rebuild"] is not None
        assert status["last_rebuild"] >= 10
        assert status["revoked_count"] == 3
        assert status["stale"] is False  # 10s < 2*3600

    def test_health_status_without_cache(self, manager):
        """Scenario 16: no cache -> last_rebuild is None, stale after grace period."""
        # Push creation time past the startup grace period
        manager._created_at = time.monotonic() - 9999
        status = manager.health_status()
        assert status["last_rebuild"] is None
        assert status["stale"] is True
        assert status["error"] is None
        assert status["revoked_count"] == 0

    def test_health_status_when_stale(self, manager):
        """Scenario 17: cache too old -> stale is True."""
        manager._cached_crl = b"data"
        # Set cached_at way in the past (older than 2x rebuild interval)
        manager._cached_at = time.monotonic() - 99999

        status = manager.health_status()
        assert status["stale"] is True

    def test_health_status_reports_error(self, manager):
        """Error field is propagated."""
        manager._last_rebuild_error = "something broke"
        status = manager.health_status()
        assert status["error"] == "something broke"


# ---------------------------------------------------------------------------
# _is_stale()
# ---------------------------------------------------------------------------


class TestIsStale:
    def test_no_cache_is_stale_after_grace_period(self, manager):
        """Scenario 18: no cached CRL -> stale after startup grace period."""
        assert manager._cached_crl is None
        # Within grace period: not stale yet
        assert manager._is_stale() is False
        # After grace period: stale
        manager._created_at = time.monotonic() - 9999
        assert manager._is_stale() is True

    def test_fresh_cache_is_not_stale(self, manager):
        """Scenario 19: recently cached -> not stale."""
        manager._cached_crl = b"data"
        manager._cached_at = time.monotonic()
        assert manager._is_stale() is False

    def test_old_cache_is_stale(self, manager):
        """Scenario 20: cache older than 2x rebuild_interval_seconds -> stale."""
        manager._cached_crl = b"data"
        # rebuild_interval = 3600, so stale after 7200
        manager._cached_at = time.monotonic() - 8000
        assert manager._is_stale() is True

    def test_boundary_not_stale(self, manager):
        """Cache age exactly at 2x interval is not stale (> check, not >=)."""
        manager._cached_crl = b"data"
        interval = manager._settings.rebuild_interval_seconds  # 3600
        # Right at the boundary: age == 2*interval -> not stale (uses >)
        manager._cached_at = time.monotonic() - (2 * interval)
        # Due to time passing between setting and checking, this may or may
        # not be exactly at boundary.  Use a value safely under.
        manager._cached_at = time.monotonic() - (2 * interval - 1)
        assert manager._is_stale() is False


# ---------------------------------------------------------------------------
# _read_db_cache()
# ---------------------------------------------------------------------------


class TestReadDbCache:
    def test_fresh_row_returned(self, ha_manager, mock_db):
        """Scenario 21: DB row exists and is fresh -> bytes returned."""
        built_at = datetime.now(UTC) - timedelta(seconds=60)
        mock_db.fetch_one.return_value = {
            "crl_der": b"\x30\x00",
            "built_at": built_at,
            "revoked_count": 7,
        }

        result = ha_manager._read_db_cache()
        assert result == b"\x30\x00"
        assert ha_manager._last_revoked_count == 7

    def test_stale_row_returns_none(self, ha_manager, mock_db):
        """Scenario 22: DB row exists but is older than rebuild_interval -> None."""
        built_at = datetime.now(UTC) - timedelta(seconds=99999)
        mock_db.fetch_one.return_value = {
            "crl_der": b"\x30\x00",
            "built_at": built_at,
            "revoked_count": 2,
        }

        result = ha_manager._read_db_cache()
        assert result is None

    def test_no_row_returns_none(self, ha_manager, mock_db):
        """Scenario 23: no row in DB -> None."""
        mock_db.fetch_one.return_value = None

        result = ha_manager._read_db_cache()
        assert result is None

    def test_exception_returns_none(self, ha_manager, mock_db):
        """Scenario 24: DB exception -> None (graceful degradation)."""
        mock_db.fetch_one.side_effect = RuntimeError("connection lost")

        result = ha_manager._read_db_cache()
        assert result is None

    def test_memoryview_crl_der_converted_to_bytes(self, ha_manager, mock_db):
        """PostgreSQL may return memoryview; bytes() call handles it."""
        built_at = datetime.now(UTC) - timedelta(seconds=10)
        raw = memoryview(b"\x30\x82")
        mock_db.fetch_one.return_value = {
            "crl_der": raw,
            "built_at": built_at,
            "revoked_count": 0,
        }

        result = ha_manager._read_db_cache()
        assert result == b"\x30\x82"
        assert isinstance(result, bytes)


# ---------------------------------------------------------------------------
# _write_db_cache()
# ---------------------------------------------------------------------------


class TestWriteDbCache:
    """_write_db_cache now uses db.connection() to pin all operations
    (advisory lock, upsert, unlock) to a single connection, preventing
    session-level advisory lock leaks across pool connections.
    """

    @staticmethod
    def _setup_conn_mock(mock_db, lock_acquired=True):
        """Wire up mock_db.connection() as a context manager returning a mock conn."""
        mock_conn = MagicMock()
        # conn.execute(...).fetchone() returns a row where row[0] = lock_acquired
        lock_row = MagicMock()
        lock_row.__getitem__ = lambda self, i: lock_acquired
        lock_row.__bool__ = lambda self: bool(lock_acquired)
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = lock_row
        mock_conn.execute.return_value = mock_cursor
        mock_db.connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_db.connection.return_value.__exit__ = MagicMock(return_value=False)
        return mock_conn

    def test_got_lock_and_writes(self, ha_manager, mock_db):
        """Scenario 25: advisory lock acquired -> upsert executed, lock released."""
        mock_conn = self._setup_conn_mock(mock_db, lock_acquired=True)
        ha_manager._last_revoked_count = 5

        ha_manager._write_db_cache(b"\x30\x00")

        # All operations go through a single connection
        mock_db.connection.assert_called_once()
        # At least 3 calls: lock, upsert, unlock
        assert mock_conn.execute.call_count >= 3
        # First call is advisory lock
        first_sql = mock_conn.execute.call_args_list[0][0][0]
        assert "pg_try_advisory_lock" in first_sql
        # Last call is advisory unlock
        last_sql = mock_conn.execute.call_args_list[-1][0][0]
        assert "pg_advisory_unlock" in last_sql

    def test_no_lock_returns_without_writing(self, ha_manager, mock_db):
        """Scenario 26: another instance holds lock -> skip write."""
        mock_conn = self._setup_conn_mock(mock_db, lock_acquired=False)

        ha_manager._write_db_cache(b"\x30\x00")

        mock_db.connection.assert_called_once()
        # Only the lock attempt call, no upsert or unlock
        assert mock_conn.execute.call_count == 1

    def test_exception_handled_gracefully(self, ha_manager, mock_db):
        """Scenario 27: DB exception during connection -> swallowed."""
        mock_db.connection.side_effect = RuntimeError("connection error")

        # Should not raise
        ha_manager._write_db_cache(b"\x30\x00")

    def test_lock_released_even_on_execute_error(self, ha_manager, mock_db):
        """Advisory lock is released even when the INSERT fails."""
        mock_conn = self._setup_conn_mock(mock_db, lock_acquired=True)

        call_count = [0]
        # Build a fetchone result for the lock check
        lock_row = MagicMock()
        lock_row.__getitem__ = lambda self, i: True
        lock_row.__bool__ = lambda self: True
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = lock_row

        def execute_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call: advisory lock check — return cursor
                return mock_cursor
            if call_count[0] == 2:
                # Second call: upsert — fails
                raise RuntimeError("insert failed")
            # Third call: unlock — succeeds
            return mock_cursor

        mock_conn.execute.side_effect = execute_side_effect

        # Should not raise — outer try/except catches it
        ha_manager._write_db_cache(b"\x30\x00")

        # The unlock call should still have been attempted (in the finally)
        assert call_count[0] >= 3


# ---------------------------------------------------------------------------
# _build()
# ---------------------------------------------------------------------------


class TestBuild:
    def test_empty_revoked_list(self, manager, cert_repo):
        """Scenario 28: no revoked certs -> CRL built without add_revoked_certificate."""
        cert_repo.find_revoked.return_value = []

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2 as MockRev:
            mock_builder, mock_crl = _setup_crl_builder_mock(MockCRL)

            result = manager._build()

            assert result == b"\x30\x82\x01\x00"
            mock_builder.add_revoked_certificate.assert_not_called()
            mock_builder.sign.assert_called_once()
            assert manager._last_revoked_count == 0

    def test_with_revoked_certs(self, manager, cert_repo):
        """Scenario 29: revoked certs added to CRL builder."""
        now = datetime.now(UTC)
        cert1 = _make_revoked_cert("1a2b3c", now - timedelta(hours=1))
        cert2 = _make_revoked_cert("4d5e6f", now)
        cert_repo.find_revoked.return_value = [cert1, cert2]

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2 as MockRev:
            mock_builder, mock_crl = _setup_crl_builder_mock(MockCRL)
            mock_rev = _setup_rev_builder_mock(MockRev)

            result = manager._build()

            assert result == b"\x30\x82\x01\x00"
            assert manager._last_revoked_count == 2
            assert MockRev.call_count == 2
            assert mock_builder.add_revoked_certificate.call_count == 2

            # Verify serial numbers were parsed from hex
            serial_calls = mock_rev.serial_number.call_args_list
            assert serial_calls[0][0][0] == int("1a2b3c", 16)
            assert serial_calls[1][0][0] == int("4d5e6f", 16)

            # Verify revocation dates
            date_calls = mock_rev.revocation_date.call_args_list
            assert date_calls[0][0][0] == cert1.revoked_at
            assert date_calls[1][0][0] == cert2.revoked_at

    def test_revoked_cert_with_none_revoked_at_uses_now(self, manager, cert_repo):
        """When revoked_at is None, the current time is used."""
        cert = _make_revoked_cert("abc123")
        cert.revoked_at = None
        cert_repo.find_revoked.return_value = [cert]

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2 as MockRev:
            mock_builder, _ = _setup_crl_builder_mock(MockCRL)
            mock_rev = _setup_rev_builder_mock(MockRev)

            manager._build()

            date_call = mock_rev.revocation_date.call_args[0][0]
            # Should be a recent datetime (the `now` from inside _build)
            assert isinstance(date_call, datetime)
            assert date_call.tzinfo is not None

    def test_sha384_hash_algorithm(self, root_cert, root_key, cert_repo):
        """Scenario 30a: sha384 hash algorithm used."""
        settings = _make_settings(hash_algorithm="sha384")
        mgr = CRLManager(root_cert, root_key, cert_repo, settings)

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            mock_builder, _ = _setup_crl_builder_mock(MockCRL)

            mgr._build()

            sign_call = mock_builder.sign.call_args
            hash_arg = sign_call[0][1]
            assert isinstance(hash_arg, type(_HASH_MAP["sha384"]))

    def test_sha512_hash_algorithm(self, root_cert, root_key, cert_repo):
        """Scenario 30b: sha512 hash algorithm used."""
        settings = _make_settings(hash_algorithm="sha512")
        mgr = CRLManager(root_cert, root_key, cert_repo, settings)

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            mock_builder, _ = _setup_crl_builder_mock(MockCRL)

            mgr._build()

            sign_call = mock_builder.sign.call_args
            hash_arg = sign_call[0][1]
            assert isinstance(hash_arg, type(_HASH_MAP["sha512"]))

    def test_unknown_hash_falls_back_to_sha256(self, root_cert, root_key, cert_repo):
        """Scenario 31: unknown hash algorithm -> SHA256 fallback."""
        settings = _make_settings(hash_algorithm="sha1024_bogus")
        mgr = CRLManager(root_cert, root_key, cert_repo, settings)

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            mock_builder, _ = _setup_crl_builder_mock(MockCRL)

            mgr._build()

            sign_call = mock_builder.sign.call_args
            hash_arg = sign_call[0][1]
            from cryptography.hazmat.primitives.hashes import SHA256

            assert isinstance(hash_arg, SHA256)

    def test_sha256_hash_algorithm_explicit(self, manager):
        """Explicit sha256 setting uses SHA256."""
        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            mock_builder, _ = _setup_crl_builder_mock(MockCRL)

            manager._build()

            sign_call = mock_builder.sign.call_args
            hash_arg = sign_call[0][1]
            from cryptography.hazmat.primitives.hashes import SHA256

            assert isinstance(hash_arg, SHA256)

    def test_build_sets_issuer_from_root_cert(self, manager, root_cert):
        """Builder.issuer_name called with root_cert.subject."""
        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            mock_builder, _ = _setup_crl_builder_mock(MockCRL)

            manager._build()

            mock_builder.issuer_name.assert_called_once_with(root_cert.subject)

    def test_build_sets_next_update(self, manager):
        """next_update is now + next_update_seconds."""
        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            mock_builder, _ = _setup_crl_builder_mock(MockCRL)

            before = datetime.now(UTC)
            manager._build()
            after = datetime.now(UTC)

            # Extract the next_update argument
            next_update_arg = mock_builder.next_update.call_args[0][0]
            expected_delta = timedelta(
                seconds=manager._settings.next_update_seconds,
            )
            assert next_update_arg >= before + expected_delta - timedelta(seconds=1)
            assert next_update_arg <= after + expected_delta + timedelta(seconds=1)

    def test_build_signs_with_root_key(self, manager, root_key):
        """Builder.sign called with root_key."""
        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            mock_builder, _ = _setup_crl_builder_mock(MockCRL)

            manager._build()

            sign_call = mock_builder.sign.call_args
            assert sign_call[0][0] is root_key

    def test_build_returns_der_bytes(self, manager):
        """Return value is from crl.public_bytes(DER)."""
        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _, mock_crl = _setup_crl_builder_mock(MockCRL)

            result = manager._build()

            from cryptography.hazmat.primitives.serialization import Encoding

            mock_crl.public_bytes.assert_called_once_with(Encoding.DER)
            assert result == mock_crl.public_bytes.return_value


# ---------------------------------------------------------------------------
# Integration-style: get_crl -> _get_crl_locked -> _build chain
# ---------------------------------------------------------------------------


class TestGetCrlIntegration:
    """End-to-end flow through get_crl with mocked cryptography."""

    def test_first_call_builds_and_caches(self, manager, cert_repo):
        """Very first get_crl() triggers a full build."""
        cert_repo.find_revoked.return_value = []

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _setup_crl_builder_mock(MockCRL)

            result = manager.get_crl()
            assert result == b"\x30\x82\x01\x00"
            assert manager._cached_crl == b"\x30\x82\x01\x00"

    def test_second_call_returns_cached(self, manager, cert_repo):
        """Second call within interval returns cached without rebuild."""
        cert_repo.find_revoked.return_value = []

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _setup_crl_builder_mock(MockCRL)

            first = manager.get_crl()
            cert_repo.find_revoked.reset_mock()

            second = manager.get_crl()
            assert second == first
            cert_repo.find_revoked.assert_not_called()

    def test_ha_mode_full_cycle(self, ha_manager, mock_db, cert_repo):
        """HA mode: DB miss -> build -> DB write -> cache."""
        mock_db.fetch_one.return_value = None  # no DB cache
        cert_repo.find_revoked.return_value = []

        # Wire up connection() context manager for _write_db_cache
        mock_conn = MagicMock()
        lock_row = MagicMock()
        lock_row.__getitem__ = lambda self, i: True
        lock_row.__bool__ = lambda self: True
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = lock_row
        mock_conn.execute.return_value = mock_cursor
        mock_db.connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_db.connection.return_value.__exit__ = MagicMock(return_value=False)

        p1, p2 = _patch_builders()
        with p1 as MockCRL, p2:
            _setup_crl_builder_mock(MockCRL)

            result = ha_manager.get_crl()
            assert result == b"\x30\x82\x01\x00"

            # DB was queried for cache
            mock_db.fetch_one.assert_called_once()
            # DB write went through connection() context manager
            mock_db.connection.assert_called_once()
