"""Gunicorn hooks exposed by ``acmeeh.server.wsgi``.

Used with ``gunicorn.conf.py`` (``from acmeeh.server.wsgi import post_fork,
worker_exit``) for standalone gunicorn deployments, where they are the only
place the pool is re-initialised after fork and closed on worker exit.
"""

from __future__ import annotations

import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture()
def wsgi():
    """Import ``acmeeh.server.wsgi`` with its bootstrap (config, DB, app) mocked."""
    sys.modules.pop("acmeeh.server.wsgi", None)
    app = MagicMock(name="app")
    with (
        patch.dict("os.environ", {"ACMEEH_CONFIG": "config.yaml"}),
        patch("acmeeh.config.AcmeehConfig"),
        patch("acmeeh.logging.configure_logging"),
        patch("acmeeh.db.init_database"),
        patch("acmeeh.app.create_app", return_value=app),
    ):
        module = importlib.import_module("acmeeh.server.wsgi")
    yield module
    sys.modules.pop("acmeeh.server.wsgi", None)


def test_bootstrap_exposes_the_app(wsgi):
    assert wsgi.app is not None


def test_post_fork_reinitialises_pool_then_starts_workers(wsgi):
    calls = MagicMock()
    with (
        patch("acmeeh.db.reinit_pool_after_fork", calls.reinit),
        patch("acmeeh.app.factory.start_workers", calls.start_workers),
    ):
        wsgi.post_fork(MagicMock(), MagicMock())

    assert [c[0] for c in calls.mock_calls] == ["reinit", "start_workers"]
    calls.start_workers.assert_called_once_with(wsgi.app)


def test_worker_exit_stops_workers_before_closing_pool(wsgi):
    """Closing the pool first would leave workers mid-query on a closed pool."""
    calls = MagicMock()
    with (
        patch("acmeeh.app.factory.stop_workers", calls.stop_workers),
        patch("acmeeh.db.close_pool", calls.close_pool),
    ):
        wsgi.worker_exit(MagicMock(), MagicMock())

    assert [c[0] for c in calls.mock_calls] == ["stop_workers", "close_pool"]
    calls.stop_workers.assert_called_once_with(wsgi.app)
