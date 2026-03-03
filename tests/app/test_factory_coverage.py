"""Tests for untested branches in the app factory (create_app).

Covers:
- create_app with database=None (no container path)
- create_app with config=None (deferred get_config fallback)
- Rate limiter registration when enabled
- Proxy middleware registration when enabled
- Metrics endpoint registration when enabled
- Admin API registration and bootstrap password output
- Config hot-reload before_request handler (all branches)
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_settings(**overrides):
    """Build a MagicMock settings tree with sensible defaults.

    Every optional subsystem is disabled by default so that tests can
    selectively enable only the branch they care about.

    Values that participate in comparisons with real types (e.g. int, str)
    are set to concrete values to avoid MagicMock comparison errors in
    the request hooks registered by ``register_request_hooks``.
    """
    s = MagicMock()

    # -- Defaults that make create_app() run cleanly ----------------------
    s.security.rate_limits.enabled = False
    s.security.max_request_body_bytes = 1_048_576
    # after_request hook does: ext_url.startswith("https://") and hsts > 0
    s.security.hsts_max_age_seconds = 0
    s.proxy.enabled = False
    s.server.graceful_timeout = 5
    s.server.external_url = "http://localhost"
    s.metrics.enabled = False

    s.admin_api.enabled = False

    # Apply caller overrides
    for dotted_key, value in overrides.items():
        parts = dotted_key.split(".")
        obj = s
        for part in parts[:-1]:
            obj = getattr(obj, part)
        setattr(obj, parts[-1], value)

    return s


def _make_mock_config(settings=None):
    """Return a mock config whose .settings is *settings*."""
    cfg = MagicMock()
    cfg.settings = settings or _make_mock_settings()
    return cfg


def _create_app_simple(config=None, database=None, **settings_kw):
    """Shortcut: create an app with mocked-out Container and blueprints.

    Returns (app, config, settings).
    """
    from acmeeh.app.factory import create_app

    settings = _make_mock_settings(**settings_kw)
    if config is None:
        config = _make_mock_config(settings)
    else:
        config.settings = settings

    with patch("acmeeh.app.factory.atexit"):
        if database is not None:
            mock_container = MagicMock()
            mock_container.challenge_worker = None
            with (
                patch("acmeeh.app.context.Container", return_value=mock_container),
                patch("acmeeh.api.register_blueprints"),
            ):
                app = create_app(config=config, database=database)
        else:
            app = create_app(config=config, database=database)

    return app, config, settings


# ===================================================================
# 1. create_app with database=None
# ===================================================================


class TestCreateAppNoDatabase:
    """When database is None, no Container is wired up."""

    def test_no_container_in_extensions(self):
        app, _, _ = _create_app_simple(database=None)
        assert "container" not in app.extensions

    def test_shutdown_coordinator_still_registered(self):
        app, _, _ = _create_app_simple(database=None)
        assert "shutdown_coordinator" in app.extensions

    def test_livez_returns_200(self):
        app, _, _ = _create_app_simple(database=None)
        with app.test_client() as client:
            resp = client.get("/livez")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["alive"] is True

    def test_readyz_returns_503_without_container(self):
        app, _, _ = _create_app_simple(database=None)
        with app.test_client() as client:
            resp = client.get("/readyz")
            assert resp.status_code == 503
            data = resp.get_json()
            assert data["ready"] is False
            assert "Container not initialized" in data["reason"]


# ===================================================================
# 2. create_app with config=None (falls back to get_config)
# ===================================================================


class TestCreateAppNoConfig:
    """When config=None the factory imports and calls get_config()."""

    def test_falls_back_to_get_config(self):
        from acmeeh.app.factory import create_app

        mock_settings = _make_mock_settings()
        mock_config = MagicMock()
        mock_config.settings = mock_settings

        with (
            patch("acmeeh.config.get_config", return_value=mock_config) as patched,
            patch("acmeeh.app.factory.atexit"),
        ):
            app = create_app(config=None, database=None)

        patched.assert_called_once()
        assert app.config["ACMEEH_CONFIG"] is mock_config


# ===================================================================
# 3. Rate limiter branch
# ===================================================================


class TestRateLimiterBranch:
    def test_rate_limiter_created_when_enabled(self):
        from acmeeh.app.factory import create_app

        settings = _make_mock_settings()
        settings.security.rate_limits.enabled = True
        config = _make_mock_config(settings)

        sentinel = MagicMock()
        with (
            patch(
                "acmeeh.app.rate_limiter.create_rate_limiter", return_value=sentinel
            ) as create_rl,
            patch("acmeeh.app.factory.atexit"),
        ):
            app = create_app(config=config, database=None)

        create_rl.assert_called_once_with(settings.security.rate_limits, None)
        assert app.extensions["rate_limiter"] is sentinel

    def test_no_rate_limiter_when_disabled(self):
        app, _, _ = _create_app_simple(database=None)
        assert "rate_limiter" not in app.extensions


# ===================================================================
# 4. Proxy middleware branch
# ===================================================================


class TestProxyMiddlewareBranch:
    def test_proxy_middleware_applied_when_enabled(self):
        from acmeeh.app.factory import create_app

        settings = _make_mock_settings()
        settings.proxy.enabled = True
        settings.proxy.trusted_proxies = ["10.0.0.1"]
        settings.proxy.forwarded_for_header = "X-Forwarded-For"
        settings.proxy.forwarded_proto_header = "X-Forwarded-Proto"
        config = _make_mock_config(settings)

        sentinel_middleware = MagicMock()
        with (
            patch(
                "acmeeh.app.middleware.TrustedProxyMiddleware", return_value=sentinel_middleware
            ) as mw_cls,
            patch("acmeeh.app.factory.atexit"),
        ):
            app = create_app(config=config, database=None)

        mw_cls.assert_called_once()
        # ServerHeaderMiddleware wraps the outermost layer; proxy middleware
        # is underneath it.
        from acmeeh.app.middleware import ServerHeaderMiddleware

        assert isinstance(app.wsgi_app, ServerHeaderMiddleware)
        assert app.wsgi_app.app is sentinel_middleware


# ===================================================================
# 5. Metrics endpoint branch
# ===================================================================


class TestMetricsBranch:
    def test_metrics_blueprint_registered_when_enabled(self):
        from acmeeh.app.factory import create_app

        settings = _make_mock_settings()
        settings.metrics.enabled = True
        settings.metrics.path = "/metrics"
        config = _make_mock_config(settings)

        mock_container = MagicMock()
        mock_container.challenge_worker = None
        mock_db = MagicMock()

        with (
            patch("acmeeh.app.context.Container", return_value=mock_container),
            patch("acmeeh.api.register_blueprints"),
            patch("acmeeh.app.factory.atexit"),
        ):
            app = create_app(config=config, database=mock_db)

        # The metrics blueprint should be among the registered blueprints
        bp_names = list(app.blueprints.keys())
        assert "metrics" in bp_names or any("metric" in n for n in bp_names), (
            f"Expected a metrics blueprint; registered: {bp_names}"
        )

    def test_metrics_not_registered_when_disabled(self):
        mock_container = MagicMock()
        mock_container.challenge_worker = None
        mock_db = MagicMock()

        settings = _make_mock_settings()
        settings.metrics.enabled = False
        config = _make_mock_config(settings)

        with (
            patch("acmeeh.app.context.Container", return_value=mock_container),
            patch("acmeeh.api.register_blueprints"),
            patch("acmeeh.app.factory.atexit"),
        ):
            from acmeeh.app.factory import create_app

            app = create_app(config=config, database=mock_db)

        bp_names = list(app.blueprints.keys())
        assert "metrics" not in bp_names


# ===================================================================
# 7. Admin API registration & bootstrap
# ===================================================================


class TestAdminBootstrap:
    def _create_admin_app(self, *, bootstrap_return):
        """Helper: create an app with admin_api enabled."""
        from acmeeh.app.factory import create_app

        settings = _make_mock_settings()
        settings.admin_api.enabled = True
        settings.admin_api.base_path = "/admin/"
        settings.admin_api.initial_admin_email = "admin@example.com"
        settings.metrics.enabled = False

        config = _make_mock_config(settings)

        mock_container = MagicMock()
        mock_container.challenge_worker = None
        mock_container.admin_service = MagicMock()
        mock_container.admin_service.bootstrap_admin.return_value = bootstrap_return
        mock_db = MagicMock()

        with (
            patch("acmeeh.app.context.Container", return_value=mock_container),
            patch("acmeeh.api.register_blueprints"),
            patch("acmeeh.app.factory.atexit"),
        ):
            app = create_app(config=config, database=mock_db)

        return app, mock_container

    def test_admin_blueprint_registered(self):
        app, _ = self._create_admin_app(bootstrap_return=None)
        bp_names = list(app.blueprints.keys())
        assert "admin" in bp_names or any("admin" in n for n in bp_names), (
            f"Expected admin blueprint; registered: {bp_names}"
        )

    def test_bootstrap_returns_none_no_stderr(self):
        """When no initial admin is created, nothing is written to stderr."""
        mock_err = MagicMock()
        with patch("acmeeh.app.factory.sys") as mock_sys:
            mock_sys.stderr = mock_err
            _, container = self._create_admin_app(bootstrap_return=None)
        container.admin_service.bootstrap_admin.assert_called_once()
        mock_err.write.assert_not_called()

    def test_bootstrap_returns_password_writes_stderr(self):
        """When bootstrap_admin returns a password, it is printed to stderr."""
        mock_err = MagicMock()
        with patch("acmeeh.app.factory.sys") as mock_sys:
            mock_sys.stderr = mock_err
            _, container = self._create_admin_app(bootstrap_return="S3cretP@ss!")
        mock_err.write.assert_called_once()
        written = mock_err.write.call_args[0][0]
        assert "S3cretP@ss!" in written
        assert "INITIAL ADMIN USER CREATED" in written
        mock_err.flush.assert_called_once()

    def test_admin_not_registered_when_disabled(self):
        from acmeeh.app.factory import create_app

        settings = _make_mock_settings()
        settings.admin_api.enabled = False
        settings.metrics.enabled = False

        config = _make_mock_config(settings)

        mock_container = MagicMock()
        mock_container.challenge_worker = None
        mock_db = MagicMock()

        with (
            patch("acmeeh.app.context.Container", return_value=mock_container),
            patch("acmeeh.api.register_blueprints"),
            patch("acmeeh.app.factory.atexit"),
        ):
            app = create_app(config=config, database=mock_db)

        bp_names = list(app.blueprints.keys())
        assert "admin" not in bp_names

    def test_admin_not_registered_when_service_none(self):
        from acmeeh.app.factory import create_app

        settings = _make_mock_settings()
        settings.admin_api.enabled = True
        settings.admin_api.base_path = "/admin/"
        settings.metrics.enabled = False

        config = _make_mock_config(settings)

        mock_container = MagicMock()
        mock_container.challenge_worker = None
        mock_container.admin_service = None  # no admin service
        mock_db = MagicMock()

        with (
            patch("acmeeh.app.context.Container", return_value=mock_container),
            patch("acmeeh.api.register_blueprints"),
            patch("acmeeh.app.factory.atexit"),
        ):
            app = create_app(config=config, database=mock_db)

        bp_names = list(app.blueprints.keys())
        assert "admin" not in bp_names


# ===================================================================
# 8. Config hot-reload before_request handler
# ===================================================================


@pytest.fixture()
def reload_app():
    """Create an app suitable for testing the config hot-reload handler.

    Returns (app, mock_config, current_settings).
    The ShutdownCoordinator is real so we can manipulate its flags.
    """
    current_settings = _make_mock_settings()
    mock_config = _make_mock_config(current_settings)

    with patch("acmeeh.app.factory.atexit"):
        from acmeeh.app.factory import create_app

        app = create_app(config=mock_config, database=None)

    return app, mock_config, current_settings


class TestConfigHotReload:
    """Cover the _check_config_reload before_request handler."""

    def test_no_reload_when_flag_not_set(self, reload_app):
        """Normal request when reload_requested is False -- early return."""
        app, mock_config, _ = reload_app
        sc = app.extensions["shutdown_coordinator"]
        assert not sc.reload_requested  # default

        with app.test_client() as client:
            resp = client.get("/livez")

        assert resp.status_code == 200
        mock_config.reload_settings.assert_not_called()

    def test_reload_logging_level_changed(self, reload_app):
        """Changing logging.level triggers reload and updates root logger."""
        app, mock_config, current_settings = reload_app
        sc = app.extensions["shutdown_coordinator"]

        # Prepare new_settings with a different logging level
        new_settings = MagicMock()
        new_settings.logging.level = "DEBUG"
        current_settings.logging.level = "INFO"
        # Keep other sections identical (use same mock objects)
        new_settings.security.rate_limits = current_settings.security.rate_limits
        new_settings.notifications = current_settings.notifications
        new_settings.metrics.enabled = current_settings.metrics.enabled
        mock_config.reload_settings.return_value = new_settings

        # Trigger reload
        sc._reload_flag.set()

        with app.test_client() as client:
            client.get("/livez")

        mock_config.reload_settings.assert_called_once()
        # After reload, the settings should have been swapped
        assert app.config["ACMEEH_SETTINGS"] is new_settings
        # Flag should be consumed
        assert not sc.reload_requested

    def test_reload_rate_limits_changed(self, reload_app):
        app, mock_config, current_settings = reload_app
        sc = app.extensions["shutdown_coordinator"]

        new_settings = MagicMock()
        new_settings.logging.level = current_settings.logging.level
        # rate_limits differ by using a distinct MagicMock
        new_settings.security.rate_limits = MagicMock()
        current_settings.security.rate_limits = MagicMock()
        new_settings.notifications = current_settings.notifications
        new_settings.metrics.enabled = current_settings.metrics.enabled
        mock_config.reload_settings.return_value = new_settings

        sc._reload_flag.set()

        with app.test_client() as client:
            client.get("/livez")

        assert app.config["ACMEEH_SETTINGS"] is new_settings
        assert not sc.reload_requested

    def test_reload_notifications_changed(self, reload_app):
        app, mock_config, current_settings = reload_app
        sc = app.extensions["shutdown_coordinator"]

        new_settings = MagicMock()
        new_settings.logging.level = current_settings.logging.level
        new_settings.security.rate_limits = current_settings.security.rate_limits
        # notifications differ
        new_settings.notifications = MagicMock()
        current_settings.notifications = MagicMock()
        new_settings.metrics.enabled = current_settings.metrics.enabled
        mock_config.reload_settings.return_value = new_settings

        sc._reload_flag.set()

        with app.test_client() as client:
            client.get("/livez")

        assert app.config["ACMEEH_SETTINGS"] is new_settings
        assert not sc.reload_requested

    def test_reload_metrics_enabled_changed(self, reload_app):
        app, mock_config, current_settings = reload_app
        sc = app.extensions["shutdown_coordinator"]

        new_settings = MagicMock()
        new_settings.logging.level = current_settings.logging.level
        new_settings.security.rate_limits = current_settings.security.rate_limits
        new_settings.notifications = current_settings.notifications
        # metrics.enabled differs
        new_settings.metrics.enabled = True
        current_settings.metrics.enabled = False
        mock_config.reload_settings.return_value = new_settings

        sc._reload_flag.set()

        with app.test_client() as client:
            client.get("/livez")

        assert app.config["ACMEEH_SETTINGS"] is new_settings
        assert not sc.reload_requested

    def test_reload_all_sections_changed(self, reload_app):
        """All four reloadable sections change at once."""
        app, mock_config, current_settings = reload_app
        sc = app.extensions["shutdown_coordinator"]

        new_settings = MagicMock()
        new_settings.logging.level = "DEBUG"
        current_settings.logging.level = "WARNING"
        new_settings.security.rate_limits = MagicMock()
        current_settings.security.rate_limits = MagicMock()
        new_settings.notifications = MagicMock()
        current_settings.notifications = MagicMock()
        new_settings.metrics.enabled = True
        current_settings.metrics.enabled = False
        mock_config.reload_settings.return_value = new_settings

        sc._reload_flag.set()

        with app.test_client() as client:
            client.get("/livez")

        assert app.config["ACMEEH_SETTINGS"] is new_settings

    def test_reload_no_changes_detected(self, reload_app):
        """When reloaded settings are identical, settings are NOT swapped."""
        app, mock_config, current_settings = reload_app
        sc = app.extensions["shutdown_coordinator"]

        # Return a new_settings that equals current in every reloadable field
        new_settings = MagicMock()
        new_settings.logging.level = current_settings.logging.level
        new_settings.security.rate_limits = current_settings.security.rate_limits
        new_settings.notifications = current_settings.notifications
        new_settings.metrics.enabled = current_settings.metrics.enabled
        mock_config.reload_settings.return_value = new_settings

        sc._reload_flag.set()

        with app.test_client() as client:
            client.get("/livez")

        # Settings should NOT have been swapped
        assert app.config["ACMEEH_SETTINGS"] is current_settings
        assert not sc.reload_requested

    def test_reload_exception_in_reload_settings(self, reload_app):
        """When reload_settings() raises, the error is logged and swallowed."""
        app, mock_config, _ = reload_app
        sc = app.extensions["shutdown_coordinator"]

        mock_config.reload_settings.side_effect = RuntimeError("YAML parse error")

        sc._reload_flag.set()

        with app.test_client() as client:
            resp = client.get("/livez")

        # The request should still succeed (error caught)
        assert resp.status_code == 200
        # Flag should be consumed even on error (finally block)
        assert not sc.reload_requested

    def test_reload_config_is_none(self, reload_app):
        """When ACMEEH_CONFIG is None, reload returns early after consuming."""
        app, mock_config, _ = reload_app
        sc = app.extensions["shutdown_coordinator"]

        # Remove the config from the app
        app.config["ACMEEH_CONFIG"] = None

        sc._reload_flag.set()

        with app.test_client() as client:
            resp = client.get("/livez")

        assert resp.status_code == 200
        mock_config.reload_settings.assert_not_called()
        assert not sc.reload_requested

    def test_reload_shutdown_coordinator_missing(self, reload_app):
        """When shutdown_coordinator extension is missing, early return."""
        app, mock_config, _ = reload_app

        # Remove the coordinator entirely
        del app.extensions["shutdown_coordinator"]

        with app.test_client() as client:
            resp = client.get("/livez")

        assert resp.status_code == 200
        mock_config.reload_settings.assert_not_called()

    def test_reload_flag_consumed_after_successful_reload(self, reload_app):
        """Verify the finally block always runs consume_reload."""
        app, mock_config, current_settings = reload_app
        sc = app.extensions["shutdown_coordinator"]

        new_settings = MagicMock()
        new_settings.logging.level = "DEBUG"
        current_settings.logging.level = "INFO"
        new_settings.security.rate_limits = current_settings.security.rate_limits
        new_settings.notifications = current_settings.notifications
        new_settings.metrics.enabled = current_settings.metrics.enabled
        mock_config.reload_settings.return_value = new_settings

        sc._reload_flag.set()
        assert sc.reload_requested

        with app.test_client() as client:
            client.get("/livez")

        assert not sc.reload_requested

    def test_reload_sets_root_logger_level(self, reload_app):
        """Verify that the root logger level is actually updated."""
        app, mock_config, current_settings = reload_app
        sc = app.extensions["shutdown_coordinator"]

        new_settings = MagicMock()
        new_settings.logging.level = "DEBUG"
        current_settings.logging.level = "INFO"
        new_settings.security.rate_limits = current_settings.security.rate_limits
        new_settings.notifications = current_settings.notifications
        new_settings.metrics.enabled = current_settings.metrics.enabled
        mock_config.reload_settings.return_value = new_settings

        sc._reload_flag.set()

        original_level = logging.getLogger().level

        with app.test_client() as client:
            client.get("/livez")

        try:
            # The root logger should now be set to DEBUG
            assert logging.getLogger().level == logging.DEBUG
        finally:
            # Restore original level to avoid polluting other tests
            logging.getLogger().setLevel(original_level)

    def test_subsequent_requests_do_not_trigger_reload(self, reload_app):
        """After the flag is consumed, the next request does NOT reload."""
        app, mock_config, current_settings = reload_app
        sc = app.extensions["shutdown_coordinator"]

        # First: trigger a reload
        new_settings = MagicMock()
        new_settings.logging.level = current_settings.logging.level
        new_settings.security.rate_limits = current_settings.security.rate_limits
        new_settings.notifications = current_settings.notifications
        new_settings.metrics.enabled = current_settings.metrics.enabled
        mock_config.reload_settings.return_value = new_settings
        sc._reload_flag.set()

        with app.test_client() as client:
            client.get("/livez")  # consumes flag
            mock_config.reload_settings.reset_mock()
            client.get("/livez")  # second request -- no reload expected

        mock_config.reload_settings.assert_not_called()
