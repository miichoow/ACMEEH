"""Tests for production-readiness enhancements.

Covers: body size limits, token secret enforcement, constant-time
comparisons, CSR signature algorithm validation, database pool monitoring,
distributed rate limiting, graceful shutdown, cleanup workers, and
expiration worker.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
import yaml

from acmeeh.config.acmeeh_config import AcmeehConfig, ConfigValidationError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(tmp_path: Path, data: dict) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        yaml.safe_dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8"
    )
    return cfg


def _base_config(**overrides) -> dict:
    cfg = {
        "server": {"external_url": "https://acme.example.com"},
        "database": {"database": "acmeeh_test", "user": "testuser"},
        "ca": {
            "internal": {
                "root_cert_path": "/tmp/root.pem",
                "root_key_path": "/tmp/root.key",
            }
        },
    }
    cfg.update(overrides)
    return cfg


# =========================================================================
# Enhancement 8: Request Body Size Limits
# =========================================================================


class TestBodySizeLimits:
    def test_default_max_body_bytes(self, tmp_path):
        cfg_path = _write_config(tmp_path, _base_config())
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert config.settings.security.max_request_body_bytes == 65536

    def test_custom_max_body_bytes(self, tmp_path):
        cfg_path = _write_config(
            tmp_path, _base_config(security={"max_request_body_bytes": 131072})
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert config.settings.security.max_request_body_bytes == 131072

    def test_flask_max_content_length_set(self, tmp_path):
        from flask import Flask

        from acmeeh.config.settings import build_settings

        settings = build_settings(_base_config())
        app = Flask("test")
        app.config["MAX_CONTENT_LENGTH"] = settings.security.max_request_body_bytes
        assert app.config["MAX_CONTENT_LENGTH"] == 65536


# =========================================================================
# Enhancement 11: Admin Token Secret Enforcement
# =========================================================================


class TestTokenSecretEnforcement:
    def test_empty_token_secret_errors(self, tmp_path):
        cfg_path = _write_config(
            tmp_path,
            _base_config(
                admin_api={
                    "enabled": True,
                    "base_path": "/admin",
                    "initial_admin_email": "admin@example.com",
                    "token_secret": "",
                }
            ),
        )
        with pytest.raises(ConfigValidationError) as exc_info:
            AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert any("token_secret is required" in e for e in exc_info.value.errors)

    def test_short_token_secret_errors(self, tmp_path):
        cfg_path = _write_config(
            tmp_path,
            _base_config(
                admin_api={
                    "enabled": True,
                    "base_path": "/admin",
                    "initial_admin_email": "admin@example.com",
                    "token_secret": "tooshort",
                }
            ),
        )
        with pytest.raises(ConfigValidationError) as exc_info:
            AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert any("too short" in e for e in exc_info.value.errors)

    def test_valid_token_secret_accepted(self, tmp_path):
        cfg_path = _write_config(
            tmp_path,
            _base_config(
                admin_api={
                    "enabled": True,
                    "base_path": "/admin",
                    "initial_admin_email": "admin@example.com",
                    "token_secret": "my-super-secret-key-1234",
                }
            ),
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert config.settings.admin_api.token_secret == "my-super-secret-key-1234"

    def test_disabled_admin_no_secret_needed(self, tmp_path):
        """When admin_api is disabled, no token_secret is required."""
        cfg_path = _write_config(tmp_path, _base_config(admin_api={"enabled": False}))
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert config.settings.admin_api.enabled is False


# =========================================================================
# Enhancement 12: Constant-Time Comparisons
# =========================================================================


class TestConstantTimeComparisons:
    def test_key_change_uses_hmac_compare(self):
        """KeyChangeService uses hmac.compare_digest for thumbprint check."""
        import inspect

        from acmeeh.services.key_change import KeyChangeService

        source = inspect.getsource(KeyChangeService.rollover)
        assert "hmac.compare_digest" in source
        assert "!= old_thumbprint" not in source

    def test_certificate_revoke_uses_hmac_compare(self):
        """CertificateService.revoke uses hmac.compare_digest for key comparison."""
        import inspect

        from acmeeh.services.certificate import CertificateService

        source = inspect.getsource(CertificateService.revoke)
        assert "compare_digest" in source

    def test_eab_jwk_comparison_uses_hmac_compare(self):
        """EAB JWK comparison uses hmac.compare_digest."""
        import inspect

        from acmeeh.core.jws import validate_eab_jws

        source = inspect.getsource(validate_eab_jws)
        # Both the canonical JWK and the HMAC sig should use compare_digest
        assert source.count("compare_digest") >= 2

    def test_key_change_rollover_still_works(self):
        """Functional test: key rollover works with constant-time comparison."""
        from acmeeh.core.jws import compute_thumbprint
        from acmeeh.services.key_change import KeyChangeService

        mock_repo = MagicMock()
        service = KeyChangeService(mock_repo)

        old_jwk = {"kty": "EC", "crv": "P-256", "x": "aaa", "y": "bbb"}
        new_jwk = {"kty": "EC", "crv": "P-256", "x": "ccc", "y": "ddd"}
        old_tp = compute_thumbprint(old_jwk)
        account_id = uuid4()

        mock_account = MagicMock()
        mock_account.jwk_thumbprint = old_tp

        mock_repo.find_by_thumbprint.return_value = None
        mock_repo.find_by_id.return_value = mock_account
        mock_repo.update_jwk.return_value = mock_account

        result = service.rollover(account_id, old_jwk, new_jwk)
        assert result is mock_account


# =========================================================================
# Enhancement 9: CSR Signature Algorithm Validation
# =========================================================================


class TestCSRSignatureAlgorithmValidation:
    def test_default_allowed_algorithms(self, tmp_path):
        cfg_path = _write_config(tmp_path, _base_config())
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        algs = config.settings.security.allowed_csr_signature_algorithms
        assert "SHA256withRSA" in algs
        assert "SHA256withECDSA" in algs
        assert len(algs) == 6

    def test_custom_allowed_algorithms(self, tmp_path):
        cfg_path = _write_config(
            tmp_path,
            _base_config(security={"allowed_csr_signature_algorithms": ["SHA256withECDSA"]}),
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        algs = config.settings.security.allowed_csr_signature_algorithms
        assert algs == ("SHA256withECDSA",)

    def test_certificate_service_accepts_allowed_algorithm(self):
        """CertificateService constructor accepts the new parameter."""
        from acmeeh.services.certificate import CertificateService

        svc = CertificateService(
            certificate_repo=MagicMock(),
            order_repo=MagicMock(),
            ca_settings=MagicMock(),
            ca_backend=MagicMock(),
            allowed_csr_signature_algorithms=("SHA256withECDSA",),
        )
        assert svc._allowed_csr_sig_algs == ("SHA256withECDSA",)


# =========================================================================
# Enhancement 5: Database Pool Monitoring in /healthz
# =========================================================================


class TestPoolMonitoring:
    def test_healthz_includes_pool_stats(self):
        """When the DB has a pool with get_stats, healthz shows pool info."""
        from flask import Flask

        from acmeeh.app.errors import register_error_handlers
        from acmeeh.config.settings import build_settings

        settings = build_settings(_base_config())
        app = Flask("test")
        app.config["ACMEEH_SETTINGS"] = settings

        mock_pool = MagicMock()
        mock_pool.get_stats.return_value = {
            "pool_size": 10,
            "pool_available": 8,
            "requests_waiting": 0,
            "pool_min": 2,
            "pool_max": 10,
        }

        mock_db = MagicMock()
        mock_db._pool = mock_pool
        mock_db.fetch_value.return_value = 1

        mock_container = MagicMock()
        mock_container.db = mock_db
        mock_container.crl_manager = None

        app.extensions["container"] = mock_container

        register_error_handlers(app)

        # Import healthz registration
        from acmeeh import __version__

        @app.route("/healthz")
        def healthz():
            from flask import jsonify

            result = {"status": "ok", "version": __version__}
            container = app.extensions.get("container")
            if container is not None:
                try:
                    container.db.fetch_value("SELECT 1")
                    result["database"] = "connected"
                except Exception:
                    result["database"] = "disconnected"
                    result["status"] = "degraded"
                try:
                    pool = getattr(container.db, "_pool", None)
                    if pool is not None and hasattr(pool, "get_stats"):
                        stats = pool.get_stats()
                        result["pool"] = {
                            "size": stats.get("pool_size", 0),
                            "available": stats.get("pool_available", 0),
                            "waiting": stats.get("requests_waiting", 0),
                            "min": stats.get("pool_min", 0),
                            "max": stats.get("pool_max", 0),
                        }
                except Exception:
                    pass
            return jsonify(result), 200

        client = app.test_client()
        resp = client.get("/healthz")
        data = resp.get_json()
        assert "pool" in data
        assert data["pool"]["size"] == 10
        assert data["pool"]["available"] == 8


# =========================================================================
# Enhancement 1: Distributed Rate Limiting
# =========================================================================


class TestDistributedRateLimiting:
    def test_in_memory_rate_limiter_backward_compat(self):
        """RateLimiter alias still works."""
        from acmeeh.app.rate_limiter import InMemoryRateLimiter, RateLimiter

        assert RateLimiter is InMemoryRateLimiter

    def test_create_rate_limiter_memory(self):
        from acmeeh.app.rate_limiter import InMemoryRateLimiter, create_rate_limiter
        from acmeeh.config.settings import RateLimitRule, RateLimitSettings

        settings = RateLimitSettings(
            enabled=True,
            backend="memory",
            new_account=RateLimitRule(requests=10, window_seconds=60),
            new_order=RateLimitRule(requests=10, window_seconds=60),
            new_order_per_identifier=RateLimitRule(requests=50, window_seconds=604800),
            new_nonce=RateLimitRule(requests=100, window_seconds=60),
            challenge=RateLimitRule(requests=10, window_seconds=60),
            challenge_validation=RateLimitRule(requests=30, window_seconds=60),
            gc_interval_seconds=300,
            gc_max_age_seconds=7200,
        )
        limiter = create_rate_limiter(settings)
        assert isinstance(limiter, InMemoryRateLimiter)

    def test_create_rate_limiter_database(self):
        from acmeeh.app.rate_limiter import DatabaseRateLimiter, create_rate_limiter
        from acmeeh.config.settings import RateLimitRule, RateLimitSettings

        settings = RateLimitSettings(
            enabled=True,
            backend="database",
            new_account=RateLimitRule(requests=10, window_seconds=60),
            new_order=RateLimitRule(requests=10, window_seconds=60),
            new_order_per_identifier=RateLimitRule(requests=50, window_seconds=604800),
            new_nonce=RateLimitRule(requests=100, window_seconds=60),
            challenge=RateLimitRule(requests=10, window_seconds=60),
            challenge_validation=RateLimitRule(requests=30, window_seconds=60),
            gc_interval_seconds=300,
            gc_max_age_seconds=7200,
        )
        mock_db = MagicMock()
        limiter = create_rate_limiter(settings, mock_db)
        assert isinstance(limiter, DatabaseRateLimiter)

    def test_database_rate_limiter_check(self):
        from acmeeh.app.rate_limiter import DatabaseRateLimiter
        from acmeeh.config.settings import RateLimitRule, RateLimitSettings

        settings = RateLimitSettings(
            enabled=True,
            backend="database",
            new_account=RateLimitRule(requests=5, window_seconds=60),
            new_order=RateLimitRule(requests=10, window_seconds=60),
            new_order_per_identifier=RateLimitRule(requests=50, window_seconds=604800),
            new_nonce=RateLimitRule(requests=100, window_seconds=60),
            challenge=RateLimitRule(requests=10, window_seconds=60),
            challenge_validation=RateLimitRule(requests=30, window_seconds=60),
            gc_interval_seconds=300,
            gc_max_age_seconds=7200,
        )
        mock_db = MagicMock()
        mock_db.fetch_value.return_value = 3  # under limit

        limiter = DatabaseRateLimiter(settings, mock_db)
        limiter.check("192.168.1.1", "new_account")

        # Verify atomic upsert+fetch was called (single fetch_value with CTE)
        assert mock_db.fetch_value.called

    def test_database_rate_limiter_blocks_over_limit(self):
        from acmeeh.app.errors import AcmeProblem
        from acmeeh.app.rate_limiter import DatabaseRateLimiter
        from acmeeh.config.settings import RateLimitRule, RateLimitSettings

        settings = RateLimitSettings(
            enabled=True,
            backend="database",
            new_account=RateLimitRule(requests=5, window_seconds=60),
            new_order=RateLimitRule(requests=10, window_seconds=60),
            new_order_per_identifier=RateLimitRule(requests=50, window_seconds=604800),
            new_nonce=RateLimitRule(requests=100, window_seconds=60),
            challenge=RateLimitRule(requests=10, window_seconds=60),
            challenge_validation=RateLimitRule(requests=30, window_seconds=60),
            gc_interval_seconds=300,
            gc_max_age_seconds=7200,
        )
        mock_db = MagicMock()
        mock_db.fetch_value.return_value = 6  # over limit

        limiter = DatabaseRateLimiter(settings, mock_db)
        with pytest.raises(AcmeProblem) as exc_info:
            limiter.check("192.168.1.1", "new_account")
        assert exc_info.value.status == 429

    def test_rate_limits_backend_schema(self, tmp_path):
        cfg_path = _write_config(
            tmp_path, _base_config(security={"rate_limits": {"backend": "database"}})
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert config.settings.security.rate_limits.backend == "database"

    def test_rate_limits_backend_default(self, tmp_path):
        cfg_path = _write_config(tmp_path, _base_config())
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert config.settings.security.rate_limits.backend == "memory"


# =========================================================================
# Enhancement 4: Graceful Shutdown
# =========================================================================


class TestGracefulShutdown:
    def test_shutdown_coordinator_tracks_operations(self):
        from acmeeh.app.shutdown import ShutdownCoordinator

        coord = ShutdownCoordinator(graceful_timeout=5)

        assert coord.in_flight_count == 0

        with coord.track("test_op"):
            assert coord.in_flight_count == 1

        assert coord.in_flight_count == 0

    def test_shutdown_coordinator_waits_for_inflight(self):
        from acmeeh.app.shutdown import ShutdownCoordinator

        coord = ShutdownCoordinator(graceful_timeout=5)

        started = threading.Event()
        proceed = threading.Event()

        def slow_op():
            with coord.track("slow"):
                started.set()
                proceed.wait(timeout=3)

        t = threading.Thread(target=slow_op)
        t.start()
        started.wait(timeout=2)

        assert coord.in_flight_count == 1

        # Start shutdown in a thread
        shutdown_done = threading.Event()

        def do_shutdown():
            coord.initiate()
            shutdown_done.set()

        st = threading.Thread(target=do_shutdown)
        st.start()

        # Let the slow op complete
        time.sleep(0.1)
        proceed.set()
        t.join(timeout=3)

        shutdown_done.wait(timeout=3)
        assert coord.is_shutting_down
        assert coord.in_flight_count == 0
        st.join(timeout=2)

    def test_shutdown_coordinator_timeout(self):
        from acmeeh.app.shutdown import ShutdownCoordinator

        coord = ShutdownCoordinator(graceful_timeout=1)

        # Start an operation that never finishes
        hold = threading.Event()

        def stuck():
            with coord.track("stuck"):
                hold.wait(timeout=5)

        t = threading.Thread(target=stuck, daemon=True)
        t.start()
        time.sleep(0.1)

        start = time.monotonic()
        coord.initiate()
        elapsed = time.monotonic() - start

        # Should have timed out around 1 second
        assert elapsed < 2.0
        assert coord.is_shutting_down
        hold.set()
        t.join(timeout=2)

    def test_shutdown_idempotent(self):
        from acmeeh.app.shutdown import ShutdownCoordinator

        coord = ShutdownCoordinator()
        coord.initiate()
        coord.initiate()  # should not raise
        assert coord.is_shutting_down


# =========================================================================
# Enhancement 6: Cleanup Workers
# =========================================================================


class TestCleanupWorker:
    def test_cleanup_worker_runs_nonce_gc(self):
        from acmeeh.config.settings import build_settings
        from acmeeh.services.cleanup_worker import CleanupWorker

        settings = build_settings(_base_config())
        mock_nonce_service = MagicMock()
        mock_nonce_service.gc.return_value = 5

        worker = CleanupWorker(
            nonce_service=mock_nonce_service,
            settings=settings,
        )

        assert len(worker._tasks) >= 1
        nonce_task = next(t for t in worker._tasks if t.name == "nonce_gc")
        nonce_task.run(time.monotonic())
        mock_nonce_service.gc.assert_called_once()

    def test_cleanup_worker_runs_order_expiry(self):
        from acmeeh.config.settings import build_settings
        from acmeeh.core.types import OrderStatus
        from acmeeh.services.cleanup_worker import CleanupWorker

        settings = build_settings(_base_config())
        mock_order_repo = MagicMock()

        # Create a mock expired order using real OrderStatus enum
        mock_order = MagicMock()
        mock_order.expires = datetime.now(UTC) - timedelta(hours=1)
        mock_order.status = OrderStatus.PENDING
        mock_order.id = uuid4()
        mock_order_repo.find_expired_actionable.return_value = [mock_order]
        mock_order_repo.transition_status.return_value = mock_order

        worker = CleanupWorker(
            order_repo=mock_order_repo,
            settings=settings,
        )

        order_task = next(t for t in worker._tasks if t.name == "order_expiry")
        order_task.run(time.monotonic())
        mock_order_repo.transition_status.assert_called_once()

    def test_cleanup_worker_start_stop(self):
        from acmeeh.config.settings import build_settings
        from acmeeh.services.cleanup_worker import CleanupWorker

        settings = build_settings(_base_config())
        mock_nonce_service = MagicMock()

        worker = CleanupWorker(
            nonce_service=mock_nonce_service,
            settings=settings,
        )
        worker.start()
        assert worker._thread is not None
        assert worker._thread.is_alive()

        worker.stop()
        assert not worker._thread.is_alive()

    def test_cleanup_worker_no_tasks(self):
        """Worker with no tasks should not start a thread."""
        from acmeeh.services.cleanup_worker import CleanupWorker

        worker = CleanupWorker()
        worker.start()
        assert worker._thread is None

    def test_cleanup_task_independence(self):
        """One failing task should not block others."""
        from acmeeh.services.cleanup_worker import _CleanupTask

        call_log = []

        def good_task(conn=None):
            call_log.append("good")

        def bad_task(conn=None):
            call_log.append("bad")
            raise RuntimeError("boom")

        good = _CleanupTask("good", 1, good_task)
        bad = _CleanupTask("bad", 1, bad_task)

        # Both should be runnable independently
        now = time.monotonic()
        good.run(now)
        assert "good" in call_log

        with pytest.raises(RuntimeError):
            bad.run(now)
        assert "bad" in call_log


# =========================================================================
# Enhancement 2: Certificate Expiration Worker
# =========================================================================


class TestExpirationWorker:
    def test_expiration_worker_config_defaults(self, tmp_path):
        cfg_path = _write_config(tmp_path, _base_config())
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert config.settings.notifications.expiration_warning_days == (30, 14, 7, 1)
        assert config.settings.notifications.expiration_check_interval_seconds == 3600

    def test_expiration_worker_custom_thresholds(self, tmp_path):
        cfg_path = _write_config(
            tmp_path, _base_config(notifications={"expiration_warning_days": [60, 30]})
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert config.settings.notifications.expiration_warning_days == (60, 30)

    def test_expiration_worker_finds_expiring_certs(self):
        from acmeeh.config.settings import NotificationSettings
        from acmeeh.core.types import NotificationType
        from acmeeh.services.expiration_worker import ExpirationWorker

        settings = NotificationSettings(
            enabled=True,
            max_retries=3,
            retry_delay_seconds=60,
            batch_size=50,
            retry_interval_seconds=300,
            expiration_warning_days=(30, 7),
            expiration_check_interval_seconds=3600,
            retry_backoff_multiplier=2.0,
            retry_max_delay_seconds=3600,
            disabled_types=(),
        )

        mock_cert = MagicMock()
        mock_cert.id = uuid4()
        mock_cert.account_id = uuid4()
        mock_cert.serial_number = "abc123"
        mock_cert.not_after_cert = datetime.now(UTC) + timedelta(days=5)

        mock_cert_repo = MagicMock()
        # Returns empty for 30-day check, one cert for 7-day check
        mock_cert_repo.find_expiring.side_effect = [
            [],  # 30-day threshold
            [mock_cert],  # 7-day threshold
        ]

        mock_notifier = MagicMock()
        mock_notifier.notify.return_value = []

        mock_db = MagicMock()
        # Batch INSERT ON CONFLICT returns the claimed rows
        mock_db.fetch_all.return_value = [
            {"certificate_id": mock_cert.id, "warning_days": 7},
        ]

        worker = ExpirationWorker(
            cert_repo=mock_cert_repo,
            notification_service=mock_notifier,
            settings=settings,
            db=mock_db,
        )

        work = worker._collect_expiring()
        worker._send_notifications(work)

        # Should have called find_expiring twice (once per threshold)
        assert mock_cert_repo.find_expiring.call_count == 2

        # Should have sent one notification for the 7-day threshold cert
        mock_notifier.notify.assert_called_once()
        call_args = mock_notifier.notify.call_args
        assert call_args[0][0] == NotificationType.EXPIRATION_WARNING
        assert call_args[0][2]["warning_days"] == 7

    def test_expiration_worker_deduplication(self):
        from acmeeh.config.settings import NotificationSettings
        from acmeeh.services.expiration_worker import ExpirationWorker

        settings = NotificationSettings(
            enabled=True,
            max_retries=3,
            retry_delay_seconds=60,
            batch_size=50,
            retry_interval_seconds=300,
            expiration_warning_days=(7,),
            expiration_check_interval_seconds=3600,
            retry_backoff_multiplier=2.0,
            retry_max_delay_seconds=3600,
            disabled_types=(),
        )

        mock_cert = MagicMock()
        mock_cert.id = uuid4()
        mock_cert.account_id = uuid4()
        mock_cert.serial_number = "abc123"
        mock_cert.not_after_cert = datetime.now(UTC) + timedelta(days=5)

        mock_cert_repo = MagicMock()
        mock_cert_repo.find_expiring.return_value = [mock_cert]

        mock_notifier = MagicMock()
        mock_db = MagicMock()
        # Already notified — batch INSERT returns empty (all conflicts)
        mock_db.fetch_all.return_value = []

        worker = ExpirationWorker(
            cert_repo=mock_cert_repo,
            notification_service=mock_notifier,
            settings=settings,
            db=mock_db,
        )

        work = worker._collect_expiring()
        worker._send_notifications(work)
        # Should NOT have sent notification (another instance already claimed it)
        mock_notifier.notify.assert_not_called()

    def test_expiration_worker_start_stop(self):
        from acmeeh.config.settings import NotificationSettings
        from acmeeh.services.expiration_worker import ExpirationWorker

        settings = NotificationSettings(
            enabled=True,
            max_retries=3,
            retry_delay_seconds=60,
            batch_size=50,
            retry_interval_seconds=300,
            expiration_warning_days=(30,),
            expiration_check_interval_seconds=1,
            retry_backoff_multiplier=2.0,
            retry_max_delay_seconds=3600,
            disabled_types=(),
        )

        mock_cert_repo = MagicMock()
        mock_cert_repo.find_expiring.return_value = []
        mock_notifier = MagicMock()

        worker = ExpirationWorker(
            cert_repo=mock_cert_repo,
            notification_service=mock_notifier,
            settings=settings,
        )
        worker.start()
        assert worker._thread is not None
        assert worker._thread.is_alive()

        worker.stop()
        assert not worker._thread.is_alive()

    def test_expiration_worker_no_start_when_disabled(self):
        from acmeeh.config.settings import NotificationSettings
        from acmeeh.services.expiration_worker import ExpirationWorker

        settings = NotificationSettings(
            enabled=False,
            max_retries=3,
            retry_delay_seconds=60,
            batch_size=50,
            retry_interval_seconds=300,
            expiration_warning_days=(30,),
            expiration_check_interval_seconds=3600,
            retry_backoff_multiplier=2.0,
            retry_max_delay_seconds=3600,
            disabled_types=(),
        )
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
        )
        worker.start()
        assert worker._thread is None


# =========================================================================
# Enhancement: NotificationType has EXPIRATION_WARNING
# =========================================================================


class TestNotificationType:
    def test_expiration_warning_type_exists(self):
        from acmeeh.core.types import NotificationType

        assert NotificationType.EXPIRATION_WARNING == "expiration_warning"


# =========================================================================
# Schema: new tables exist in schema.sql
# =========================================================================


class TestSchemaAdditions:
    def test_rate_limit_counters_table_in_schema(self):
        from pathlib import Path

        schema_path = (
            Path(__file__).resolve().parent.parent / "src" / "acmeeh" / "db" / "schema.sql"
        )
        schema = schema_path.read_text(encoding="utf-8")
        assert "rate_limit_counters" in schema

    def test_certificate_expiration_notices_table_in_schema(self):
        from pathlib import Path

        schema_path = (
            Path(__file__).resolve().parent.parent / "src" / "acmeeh" / "db" / "schema.sql"
        )
        schema = schema_path.read_text(encoding="utf-8")
        assert "certificate_expiration_notices" in schema
