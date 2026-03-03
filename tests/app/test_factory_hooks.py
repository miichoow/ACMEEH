"""Tests for hooks lifecycle in the Flask app factory."""

from __future__ import annotations

import inspect
from unittest.mock import MagicMock, patch

from acmeeh.config.acmeeh_config import _SCHEMA_PATH, AcmeehConfig


class TestFactorySourceCode:
    """Verify structural properties of the factory module source."""

    def _get_source(self) -> str:
        from acmeeh.app import factory

        return inspect.getsource(factory)

    def test_imports_atexit(self):
        src = self._get_source()
        assert "import atexit" in src

    def test_uses_atexit_register(self):
        src = self._get_source()
        assert "atexit.register" in src

    def test_has_teardown_appcontext_for_pool_health(self):
        src = self._get_source()
        assert "teardown_appcontext" in src
        assert "_monitor_pool_health" in src


class TestFactoryAtexitRegistration:
    def test_atexit_register_called_with_database(self, tmp_config_file):
        AcmeehConfig(config_file=tmp_config_file, schema_file=_SCHEMA_PATH)

        mock_db = MagicMock()
        mock_registry = MagicMock()
        mock_container = MagicMock()
        mock_container.hook_registry = mock_registry
        # Disable challenge worker so it doesn't add extra atexit calls
        mock_container.challenge_worker = None

        with (
            patch("acmeeh.app.factory.atexit.register") as mock_atexit,
            patch("acmeeh.app.context.Container", return_value=mock_container),
            patch("acmeeh.api.register_blueprints"),
        ):
            from acmeeh.app.factory import create_app, start_workers

            app = create_app(database=mock_db)
            start_workers(app)

        # atexit registers: shutdown_coordinator, hook_registry (from create_app)
        # + cleanup_worker, expiration_worker (from start_workers)
        registered_callables = [call.args[0] for call in mock_atexit.call_args_list]
        assert mock_registry.shutdown in registered_callables
        assert mock_container.cleanup_worker.stop in registered_callables
        assert mock_container.expiration_worker.stop in registered_callables

    def test_shutdown_coordinator_atexit_without_database(self, tmp_config_file):
        """Shutdown coordinator is always registered, even without a database."""
        AcmeehConfig(config_file=tmp_config_file, schema_file=_SCHEMA_PATH)

        with patch("acmeeh.app.factory.atexit.register") as mock_atexit:
            from acmeeh.app.factory import create_app

            create_app(database=None)

        # Only the shutdown coordinator should be registered (no container)
        assert mock_atexit.call_count == 1
