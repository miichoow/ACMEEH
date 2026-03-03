"""Unit tests for ACMEEH API route modules: CRL, metrics, and renewal info.

Tests each blueprint in isolation using a minimal Flask app with the
container set directly on ``app.extensions["container"]``, which is
exactly where ``get_container()`` looks it up.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from flask import Flask

from acmeeh.app.errors import register_error_handlers

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app(container=None, settings=None) -> Flask:
    """Create a bare Flask app with optional container & settings."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    register_error_handlers(app)
    if container is not None:
        app.extensions["container"] = container
    if settings is not None:
        app.config["ACMEEH_SETTINGS"] = settings
    return app


# =========================================================================
# CRL endpoint
# =========================================================================


class TestCRLEndpoint:
    """Tests for GET /crl — acmeeh.api.crl.crl_bp."""

    def _register(self, app: Flask) -> None:
        from acmeeh.api.crl import crl_bp

        app.register_blueprint(crl_bp, url_prefix="/crl")

    def test_get_crl_returns_der_bytes(self):
        crl_data = b"\x30\x82\x01\x00"
        container = MagicMock()
        container.crl_manager.get_crl.return_value = crl_data
        container.settings.crl.rebuild_interval_seconds = 3600

        app = _make_app(container=container)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/crl")
        assert resp.status_code == 200
        assert resp.data == crl_data
        assert resp.headers["Content-Type"] == "application/pkix-crl"
        assert "max-age=3600" in resp.headers["Cache-Control"]

    def test_get_crl_custom_max_age(self):
        container = MagicMock()
        container.crl_manager.get_crl.return_value = b"\x30"
        container.settings.crl.rebuild_interval_seconds = 7200

        app = _make_app(container=container)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/crl")
        assert "max-age=7200" in resp.headers["Cache-Control"]

    def test_get_crl_not_available(self):
        container = MagicMock()
        container.crl_manager = None

        app = _make_app(container=container)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/crl")
        assert resp.status_code == 404


# =========================================================================
# Metrics endpoint
# =========================================================================


class TestMetricsEndpoint:
    """Tests for GET /metrics — acmeeh.api.metrics.metrics_bp."""

    def _register(self, app: Flask) -> None:
        from acmeeh.api.metrics import metrics_bp

        app.register_blueprint(metrics_bp, url_prefix="/metrics")

    def test_get_metrics_success(self):
        container = MagicMock()
        container.metrics_collector.export.return_value = "# HELP test\ntest_total 1\n"

        settings = MagicMock()
        settings.metrics.auth_required = False

        app = _make_app(container=container, settings=settings)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/metrics")
        assert resp.status_code == 200
        assert b"test_total 1" in resp.data

    def test_get_metrics_no_collector(self):
        container = MagicMock()
        container.metrics_collector = None

        settings = MagicMock()
        settings.metrics.auth_required = False

        app = _make_app(container=container, settings=settings)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/metrics")
        assert resp.status_code == 200
        assert b"No metrics" in resp.data

    def test_no_auth_when_settings_is_none(self):
        container = MagicMock()
        container.metrics_collector.export.return_value = "ok"

        app = _make_app(container=container, settings=None)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_no_auth_when_auth_required_false(self):
        container = MagicMock()
        container.metrics_collector.export.return_value = "ok"

        settings = MagicMock()
        settings.metrics.auth_required = False

        app = _make_app(container=container, settings=settings)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_no_auth_when_admin_api_disabled(self):
        container = MagicMock()
        container.metrics_collector.export.return_value = "ok"

        settings = MagicMock()
        settings.metrics.auth_required = True
        settings.admin_api.enabled = False

        app = _make_app(container=container, settings=settings)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_auth_required_no_header_returns_401(self):
        container = MagicMock()

        settings = MagicMock()
        settings.metrics.auth_required = True
        settings.admin_api.enabled = True

        app = _make_app(container=container, settings=settings)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/metrics")
        assert resp.status_code == 401

    def test_auth_required_revoked_token(self):
        container = MagicMock()

        settings = MagicMock()
        settings.metrics.auth_required = True
        settings.admin_api.enabled = True

        app = _make_app(container=container, settings=settings)
        self._register(app)

        with patch("acmeeh.admin.auth.get_token_blacklist") as mock_bl:
            mock_bl.return_value.is_revoked.return_value = True
            with app.test_client() as client:
                resp = client.get(
                    "/metrics",
                    headers={"Authorization": "Bearer revoked-token"},
                )
        assert resp.status_code == 401

    def test_auth_required_invalid_token(self):
        container = MagicMock()

        settings = MagicMock()
        settings.metrics.auth_required = True
        settings.admin_api.enabled = True

        app = _make_app(container=container, settings=settings)
        self._register(app)

        with (
            patch("acmeeh.admin.auth.get_token_blacklist") as mock_bl,
            patch("acmeeh.admin.auth.decode_token", return_value=None),
        ):
            mock_bl.return_value.is_revoked.return_value = False
            with app.test_client() as client:
                resp = client.get(
                    "/metrics",
                    headers={"Authorization": "Bearer bad-token"},
                )
        assert resp.status_code == 401

    def test_auth_required_valid_token(self):
        container = MagicMock()
        container.metrics_collector.export.return_value = "ok"

        settings = MagicMock()
        settings.metrics.auth_required = True
        settings.admin_api.enabled = True
        settings.admin_api.token_secret = "secret"
        settings.admin_api.token_expiry_seconds = 3600

        app = _make_app(container=container, settings=settings)
        self._register(app)

        with (
            patch("acmeeh.admin.auth.get_token_blacklist") as mock_bl,
            patch("acmeeh.admin.auth.decode_token", return_value={"sub": "admin"}),
        ):
            mock_bl.return_value.is_revoked.return_value = False
            with app.test_client() as client:
                resp = client.get(
                    "/metrics",
                    headers={"Authorization": "Bearer valid-token"},
                )
        assert resp.status_code == 200


# =========================================================================
# Renewal Info (ARI) endpoint
# =========================================================================


class TestRenewalInfoEndpoint:
    """Tests for GET /renewalInfo/<certID> — acmeeh.api.renewal_info."""

    def _register(self, app: Flask) -> None:
        from acmeeh.api.renewal_info import renewal_info_bp

        app.register_blueprint(renewal_info_bp, url_prefix="/renewalInfo")

    def test_get_renewal_info_success(self):
        container = MagicMock()
        container.renewal_info_service.get_renewal_info.return_value = {
            "suggestedWindow": {
                "start": "2025-01-01T00:00:00Z",
                "end": "2025-01-15T00:00:00Z",
            },
            "retryAfter": 7200,
        }

        app = _make_app(container=container)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/renewalInfo/abc123")
        assert resp.status_code == 200
        assert resp.headers["Retry-After"] == "7200"
        data = resp.get_json()
        assert "suggestedWindow" in data

    def test_get_renewal_info_default_retry_after(self):
        container = MagicMock()
        container.renewal_info_service.get_renewal_info.return_value = {
            "suggestedWindow": {"start": "t0", "end": "t1"},
        }

        app = _make_app(container=container)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/renewalInfo/abc123")
        assert resp.status_code == 200
        assert resp.headers["Retry-After"] == "3600"

    def test_get_renewal_info_not_enabled_no_attr(self):
        container = MagicMock(spec=[])

        app = _make_app(container=container)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/renewalInfo/abc123")
        assert resp.status_code == 503

    def test_get_renewal_info_not_enabled_none(self):
        container = MagicMock()
        container.renewal_info_service = None

        app = _make_app(container=container)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/renewalInfo/abc123")
        assert resp.status_code == 503

    def test_get_renewal_info_cert_not_found(self):
        container = MagicMock()
        container.renewal_info_service.get_renewal_info.return_value = None

        app = _make_app(container=container)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/renewalInfo/nonexistent")
        assert resp.status_code == 404

    def test_get_renewal_info_response_is_json(self):
        container = MagicMock()
        container.renewal_info_service.get_renewal_info.return_value = {
            "suggestedWindow": {"start": "t0", "end": "t1"},
            "retryAfter": 1800,
        }

        app = _make_app(container=container)
        self._register(app)

        with app.test_client() as client:
            resp = client.get("/renewalInfo/cert123")
        assert resp.status_code == 200
        assert "application/json" in resp.headers["Content-Type"]
