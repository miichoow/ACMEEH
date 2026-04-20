"""Tests for data retention cleanup tasks in CleanupWorker."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from acmeeh.config.settings import build_settings
from acmeeh.services.cleanup_worker import CleanupWorker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_config_data(**retention_overrides) -> dict:
    """Return minimal config dict with retention settings."""
    retention = {
        "enabled": True,
        "cleanup_interval_seconds": 3600,
        **retention_overrides,
    }
    return {
        "server": {"external_url": "https://acme.example.com"},
        "database": {"database": "test", "user": "test"},
        "ca": {
            "internal": {
                "root_cert_path": "/tmp/r.pem",
                "root_key_path": "/tmp/r.key",
            }
        },
        "retention": retention,
    }


def _build_test_settings(**retention_overrides):
    """Build an AcmeehSettings instance with the given retention overrides."""
    data = _minimal_config_data(**retention_overrides)
    return build_settings(data)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.execute.return_value = 5
    return db


@pytest.fixture
def settings_enabled():
    return _build_test_settings(enabled=True)


@pytest.fixture
def settings_disabled():
    return _build_test_settings(enabled=False)


# ---------------------------------------------------------------------------
# Static method tests — individual retention tasks
# ---------------------------------------------------------------------------


class TestAuthzRetention:
    """_authz_retention deletes old expired/invalid authorizations."""

    def test_authz_retention_deletes_old(self, mock_db):
        before = datetime.now(UTC)
        CleanupWorker._authz_retention(mock_db, max_age_days=30)
        after = datetime.now(UTC)

        mock_db.execute.assert_called_once()
        sql, params = mock_db.execute.call_args[0]

        assert "DELETE FROM authorizations" in sql
        assert "expired" in sql
        assert "invalid" in sql
        assert "updated_at" in sql

        cutoff = params[0]
        expected_min = before - timedelta(days=30)
        expected_max = after - timedelta(days=30)
        assert expected_min <= cutoff <= expected_max


class TestChallengeRetention:
    """_challenge_retention deletes old invalid challenges."""

    def test_challenge_retention_deletes_old(self, mock_db):
        before = datetime.now(UTC)
        CleanupWorker._challenge_retention(mock_db, max_age_days=15)
        after = datetime.now(UTC)

        mock_db.execute.assert_called_once()
        sql, params = mock_db.execute.call_args[0]

        assert "DELETE FROM challenges" in sql
        assert "invalid" in sql
        assert "updated_at" in sql

        cutoff = params[0]
        expected_min = before - timedelta(days=15)
        expected_max = after - timedelta(days=15)
        assert expected_min <= cutoff <= expected_max


class TestOrderRetention:
    """_order_retention deletes old invalid orders."""

    def test_order_retention_deletes_old(self, mock_db):
        before = datetime.now(UTC)
        CleanupWorker._order_retention(mock_db, max_age_days=60)
        after = datetime.now(UTC)

        mock_db.execute.assert_called_once()
        sql, params = mock_db.execute.call_args[0]

        assert "DELETE FROM orders" in sql
        assert "invalid" in sql
        assert "updated_at" in sql

        cutoff = params[0]
        expected_min = before - timedelta(days=60)
        expected_max = after - timedelta(days=60)
        assert expected_min <= cutoff <= expected_max


class TestNoticeRetention:
    """_notice_retention deletes old expiration notices."""

    def test_notice_retention_deletes_old(self, mock_db):
        before = datetime.now(UTC)
        CleanupWorker._notice_retention(mock_db, max_age_days=90)
        after = datetime.now(UTC)

        mock_db.execute.assert_called_once()
        sql, params = mock_db.execute.call_args[0]

        assert "DELETE FROM certificate_expiration_notices" in sql
        assert "notified_at" in sql

        cutoff = params[0]
        expected_min = before - timedelta(days=90)
        expected_max = after - timedelta(days=90)
        assert expected_min <= cutoff <= expected_max


# ---------------------------------------------------------------------------
# Task registration tests
# ---------------------------------------------------------------------------


class TestRetentionTaskRegistration:
    """CleanupWorker registers/skips retention tasks based on settings."""

    def test_retention_tasks_registered(self, mock_db, settings_enabled):
        worker = CleanupWorker(db=mock_db, settings=settings_enabled)

        task_names = [t.name for t in worker._tasks]
        assert "authz_retention" in task_names
        assert "challenge_retention" in task_names
        assert "order_retention" in task_names
        assert "notice_retention" in task_names

    def test_retention_tasks_not_registered_when_disabled(self, mock_db, settings_disabled):
        worker = CleanupWorker(db=mock_db, settings=settings_disabled)

        task_names = [t.name for t in worker._tasks]
        assert "authz_retention" not in task_names
        assert "challenge_retention" not in task_names
        assert "order_retention" not in task_names
        assert "notice_retention" not in task_names

    def test_retention_uses_configured_interval(self, mock_db):
        settings = _build_test_settings(
            enabled=True,
            cleanup_interval_seconds=7200,
        )
        worker = CleanupWorker(db=mock_db, settings=settings)

        retention_tasks = [
            t
            for t in worker._tasks
            if t.name
            in (
                "authz_retention",
                "challenge_retention",
                "order_retention",
                "notice_retention",
            )
        ]
        assert len(retention_tasks) == 4
        for task in retention_tasks:
            assert task.interval_seconds == 7200
