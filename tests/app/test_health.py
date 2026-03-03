"""Tests for /healthz and /readyz infrastructure endpoints."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from flask import Flask

from acmeeh.app.factory import _register_health


def _make_app(container=None, shutdown_coordinator=None):
    """Create a minimal Flask app with health routes registered."""
    app = Flask("test_health")
    if container is not None:
        app.extensions["container"] = container
    if shutdown_coordinator is not None:
        app.extensions["shutdown_coordinator"] = shutdown_coordinator
    with patch("acmeeh.__version__", "0.0.0-test"):
        _register_health(app)
    return app


def _make_container(**overrides):
    """Build a mock Container with sensible defaults.

    Keyword overrides are set as attributes on the mock.
    """
    container = MagicMock()

    # DB succeeds by default; no pool (avoids MagicMock serialisation issues)
    container.db.fetch_value.return_value = 1
    container.db.pool = None
    container.db._pool = None

    # No CRL manager by default
    container.crl_manager = None

    # CA backend passes startup_check by default
    container.ca_backend.startup_check.return_value = None

    # Settings defaults for health checks
    container.settings.smtp.enabled = False
    container.settings.dns.resolvers = ()
    container.settings.challenges.dns01.resolvers = ()

    # Workers: default to alive threads
    for worker_attr in ("challenge_worker", "cleanup_worker", "expiration_worker"):
        worker = MagicMock()
        thread = MagicMock()
        thread.is_alive.return_value = True
        worker._thread = thread
        setattr(container, worker_attr, worker)

    for key, value in overrides.items():
        setattr(container, key, value)

    return container


# ---------------------------------------------------------------------------
# /healthz tests
# ---------------------------------------------------------------------------


class TestHealthzNoContainer:
    """GET /healthz when no container is wired (no database)."""

    def test_healthz_no_container(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/healthz")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        # Version no longer exposed (info disclosure hardening)
        assert "version" not in data
        # No database key when container is absent
        assert "database" not in data


class TestHealthzDatabase:
    """Database connectivity checks on /healthz."""

    def test_healthz_db_connected(self):
        container = _make_container()
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/healthz")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["status"] == "ok"
        assert data["checks"]["database"] == "ok"

    def test_healthz_db_disconnected(self):
        container = _make_container()
        container.db.fetch_value.side_effect = Exception("connection refused")
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/healthz")
        data = resp.get_json()

        assert resp.status_code == 503
        assert data["status"] == "degraded"
        assert data["checks"]["database"] == "error"


class TestHealthzWorkers:
    """Worker liveness checks on /healthz."""

    def test_healthz_workers_alive(self):
        container = _make_container()
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/healthz")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["status"] == "ok"
        # Workers now report aggregate status only (no per-worker names)
        assert data["checks"]["workers"] == "ok"

    def test_healthz_worker_dead(self):
        container = _make_container()
        # Kill the cleanup worker thread
        container.cleanup_worker._thread.is_alive.return_value = False
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/healthz")
        data = resp.get_json()

        assert resp.status_code == 503
        assert data["status"] == "degraded"
        assert data["checks"]["workers"] == "degraded"


class TestHealthzCABackend:
    """CA backend checks on /healthz."""

    def test_healthz_ca_backend_ok(self):
        container = _make_container()
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/healthz")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["checks"]["ca_backend"] == "ok"

    def test_healthz_ca_backend_error(self):
        container = _make_container()
        container.ca_backend.startup_check.side_effect = RuntimeError("HSM unreachable")
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/healthz")
        data = resp.get_json()

        assert resp.status_code == 503
        assert data["status"] == "degraded"
        assert data["checks"]["ca_backend"] == "error"


class TestHealthzShutdownCoordinator:
    """Shutdown coordinator status in /healthz response."""

    def test_healthz_shutting_down_degrades(self):
        container = _make_container()
        shutdown_coord = MagicMock()
        shutdown_coord.is_shutting_down = True
        app = _make_app(container=container, shutdown_coordinator=shutdown_coord)
        client = app.test_client()

        resp = client.get("/healthz")
        data = resp.get_json()

        # Shutdown state reflected via degraded status, not exposed directly
        assert data["status"] == "degraded"

    def test_healthz_not_shutting_down(self):
        container = _make_container()
        shutdown_coord = MagicMock()
        shutdown_coord.is_shutting_down = False
        app = _make_app(container=container, shutdown_coordinator=shutdown_coord)
        client = app.test_client()

        resp = client.get("/healthz")
        data = resp.get_json()

        # Not shutting down — no degradation from this alone
        assert "shutting_down" not in data


class TestHealthzCRL:
    """CRL staleness checks on /healthz."""

    def test_healthz_crl_stale_degrades(self):
        crl_manager = MagicMock()
        crl_manager.health_status.return_value = {"stale": True, "age_seconds": 7200}
        container = _make_container(crl_manager=crl_manager)
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/healthz")
        data = resp.get_json()

        assert resp.status_code == 503
        assert data["status"] == "degraded"
        assert data["checks"]["crl"] == "stale"

    def test_healthz_crl_fresh(self):
        crl_manager = MagicMock()
        crl_manager.health_status.return_value = {"stale": False, "age_seconds": 60}
        container = _make_container(crl_manager=crl_manager)
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/healthz")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["checks"]["crl"] == "ok"


class TestHealthzPool:
    """Connection pool stats in /healthz response."""

    def test_healthz_pool_healthy_no_stats_exposed(self):
        """Pool stats are no longer exposed in healthz (info disclosure hardening)."""
        container = _make_container()
        pool = MagicMock()
        pool.get_stats.return_value = {
            "pool_size": 10,
            "pool_available": 5,
            "requests_waiting": 0,
            "pool_min": 2,
            "pool_max": 20,
        }
        container.db._pool = pool
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/healthz")
        data = resp.get_json()

        # Pool internals must not be exposed
        assert "pool" not in data
        assert resp.status_code == 200

    def test_healthz_pool_exhausted_degrades(self):
        container = _make_container()
        pool = MagicMock()
        pool.get_stats.return_value = {
            "pool_size": 10,
            "pool_available": 0,
            "requests_waiting": 3,
            "pool_min": 2,
            "pool_max": 10,
        }
        container.db._pool = pool
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/healthz")
        data = resp.get_json()

        assert resp.status_code == 503
        assert data["status"] == "degraded"
        # Pool internals must not be exposed
        assert "pool" not in data


# ---------------------------------------------------------------------------
# /readyz tests
# ---------------------------------------------------------------------------


class TestReadyzSuccess:
    """GET /readyz when all systems are operational."""

    def test_readyz_success(self):
        container = _make_container()
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/readyz")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["ready"] is True


class TestReadyzNoContainer:
    """GET /readyz when the container is not initialized."""

    def test_readyz_no_container(self):
        app = _make_app()
        client = app.test_client()

        resp = client.get("/readyz")
        data = resp.get_json()

        assert resp.status_code == 503
        assert data["ready"] is False
        assert "Container not initialized" in data["reason"]


class TestReadyzDBDown:
    """GET /readyz when the database is unreachable."""

    def test_readyz_db_down(self):
        container = _make_container()
        container.db.fetch_value.side_effect = ConnectionError("pg down")
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/readyz")
        data = resp.get_json()

        assert resp.status_code == 503
        assert data["ready"] is False
        assert "Database not connected" in data["reason"]


class TestReadyzCANotReady:
    """GET /readyz when the CA backend fails its startup check."""

    def test_readyz_ca_not_ready(self):
        container = _make_container()
        container.ca_backend.startup_check.side_effect = RuntimeError("CA offline")
        app = _make_app(container=container)
        client = app.test_client()

        resp = client.get("/readyz")
        data = resp.get_json()

        assert resp.status_code == 503
        assert data["ready"] is False
        assert "CA backend not ready" in data["reason"]
