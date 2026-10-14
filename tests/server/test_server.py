"""Tests for the ACMEEH server module.

Covers:
- ``acmeeh.server.gunicorn_app``: run_gunicorn() and the inner _App class
- ``acmeeh.server.wsgi``: WSGI entry-point module-level bootstrapping

All gunicorn and heavy external dependencies are mocked so that these
tests run on every platform (including Windows where gunicorn is not
available).
"""

from __future__ import annotations

import importlib
import sys
import types
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FakeServerSettings:
    """Lightweight stand-in for acmeeh.config.settings.ServerSettings."""

    external_url: str = "https://acme.example.com"
    bind: str = "0.0.0.0"
    port: int = 8443
    workers: int = 4
    worker_class: str = "sync"
    timeout: int = 30
    graceful_timeout: int = 30
    keepalive: int = 2
    max_requests: int = 0
    max_requests_jitter: int = 0


def _make_settings(**overrides) -> _FakeServerSettings:
    """Build a ``_FakeServerSettings`` with optional field overrides."""
    return _FakeServerSettings(**overrides)


# ===========================================================================
# gunicorn_app.run_gunicorn
# ===========================================================================


class TestRunGunicornImportError:
    """When gunicorn is not installed run_gunicorn raises RuntimeError."""

    def test_raises_runtime_error_when_gunicorn_missing(self):
        """RuntimeError contains install instructions."""
        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings()

        with patch.dict(
            sys.modules, {"gunicorn": None, "gunicorn.app": None, "gunicorn.app.base": None}
        ):
            # Force fresh import resolution so the inner import fails
            with pytest.raises(RuntimeError, match="gunicorn is not installed"):
                run_gunicorn(app, settings)

    def test_error_message_mentions_pip(self):
        """The error tells users how to install gunicorn."""
        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings()

        with patch.dict(
            sys.modules, {"gunicorn": None, "gunicorn.app": None, "gunicorn.app.base": None}
        ):
            with pytest.raises(RuntimeError, match="pip install gunicorn"):
                run_gunicorn(app, settings)

    def test_error_message_mentions_windows(self):
        """The error message mentions that gunicorn only runs on Unix."""
        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings()

        with patch.dict(
            sys.modules, {"gunicorn": None, "gunicorn.app": None, "gunicorn.app.base": None}
        ):
            with pytest.raises(RuntimeError, match="Unix"):
                run_gunicorn(app, settings)

    def test_error_message_mentions_dev_flag(self):
        """The error message suggests using --dev on Windows."""
        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings()

        with patch.dict(
            sys.modules, {"gunicorn": None, "gunicorn.app": None, "gunicorn.app.base": None}
        ):
            with pytest.raises(RuntimeError, match="--dev"):
                run_gunicorn(app, settings)


class TestRunGunicornSuccess:
    """When gunicorn is importable, _App is constructed and .run() is called."""

    def _make_fake_base_application(self):
        """Build a fake ``gunicorn.app.base.BaseApplication`` class.

        The fake records cfg.set calls and captures the .run() invocation
        so we can assert against them.
        """

        class FakeCfg:
            def __init__(self):
                self.settings = {}

            def set(self, key, value):
                self.settings[key] = value

        class FakeBaseApplication:
            """Stand-in for gunicorn.app.base.BaseApplication."""

            def __init__(self):
                self.cfg = FakeCfg()
                # Gunicorn's BaseApplication.__init__ calls load_config()
                self.load_config()

            def load_config(self):
                pass  # overridden by subclass

            def run(self):
                self._run_called = True

        return FakeBaseApplication

    def _install_fake_gunicorn(self, FakeBaseApplication):
        """Install fake gunicorn modules into sys.modules and return
        a cleanup function.

        Returns the module dict for use with patch.dict.
        """
        mod_gunicorn = types.ModuleType("gunicorn")
        mod_app = types.ModuleType("gunicorn.app")
        mod_base = types.ModuleType("gunicorn.app.base")
        mod_base.BaseApplication = FakeBaseApplication
        mod_gunicorn.app = mod_app
        mod_app.base = mod_base

        return {
            "gunicorn": mod_gunicorn,
            "gunicorn.app": mod_app,
            "gunicorn.app.base": mod_base,
        }

    def test_run_is_called(self):
        """_App.run() is invoked when run_gunicorn succeeds."""
        FakeBase = self._make_fake_base_application()
        run_called = []
        original_run = FakeBase.run

        def tracking_run(self):
            run_called.append(True)

        FakeBase.run = tracking_run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings()

        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, settings)

        assert len(run_called) == 1

    def test_bind_address_is_set(self):
        """cfg.set("bind", ...) is called with bind:port."""
        FakeBase = self._make_fake_base_application()
        captured_cfg = {}

        original_run = FakeBase.run

        def capturing_run(self):
            captured_cfg.update(self.cfg.settings)

        FakeBase.run = capturing_run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings(bind="127.0.0.1", port=9999)

        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, settings)

        assert captured_cfg["bind"] == "127.0.0.1:9999"

    def test_worker_exit_hook_stops_workers_then_closes_pool(self):
        """worker_exit stops background workers before closing the DB pool."""
        FakeBase = self._make_fake_base_application()
        captured_cfg = {}

        def capturing_run(self):
            captured_cfg.update(self.cfg.settings)

        FakeBase.run = capturing_run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, _make_settings())

        calls = MagicMock()
        with (
            patch("acmeeh.app.factory.stop_workers", calls.stop_workers),
            patch("acmeeh.db.close_pool", calls.close_pool),
        ):
            captured_cfg["worker_exit"](MagicMock(), MagicMock())

        assert [c[0] for c in calls.mock_calls] == ["stop_workers", "close_pool"]
        calls.stop_workers.assert_called_once_with(app)

    def _gunicorn_hooks(self, app):
        """Run ``run_gunicorn`` against the fake gunicorn; return the cfg it set."""
        FakeBase = self._make_fake_base_application()
        captured_cfg = {}

        def capturing_run(self):
            captured_cfg.update(self.cfg.settings)

        FakeBase.run = capturing_run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, _make_settings())
        return captured_cfg

    def _run_post_fork(self):
        """Fire the ``post_fork`` hook; return (app, calls, registered atexit callable)."""
        app = MagicMock()
        hooks = self._gunicorn_hooks(app)

        calls = MagicMock()
        with (
            patch("acmeeh.db.reinit_pool_after_fork", calls.reinit),
            patch("atexit.register", calls.register),
            patch("acmeeh.app.factory.start_workers", calls.start_workers),
        ):
            hooks["post_fork"](MagicMock(), MagicMock())
        return app, calls, calls.register.call_args.args[0]

    def test_post_fork_hook_reinits_pool_before_starting_workers(self):
        """The inherited pool must be replaced before any worker touches the DB."""
        app, calls, _ = self._run_post_fork()

        assert [c[0] for c in calls.mock_calls] == ["reinit", "register", "start_workers"]
        calls.start_workers.assert_called_once_with(app)

    def test_post_fork_hook_registers_pool_del_suppressor(self):
        _, calls, suppress = self._run_post_fork()

        calls.register.assert_called_once()
        assert suppress.__name__ == "_suppress_pool_del"

    @staticmethod
    def _pypgkit_mocks(*, initialized=True, raw_pool=None, is_initialized_error=None):
        """Run the atexit suppressor with pypgkit and the raw pool mocked."""
        database = MagicMock()
        if is_initialized_error is not None:
            database.is_initialized.side_effect = is_initialized_error
        else:
            database.is_initialized.return_value = initialized
        get_raw_pool = MagicMock(return_value=raw_pool)
        return database, get_raw_pool

    def test_suppress_pool_del_marks_pool_closed(self):
        """Marking the pool closed stops ``__del__`` from tearing it down at exit."""
        _, _, suppress = self._run_post_fork()
        raw_pool = types.SimpleNamespace(_closed=False)
        database, get_raw_pool = self._pypgkit_mocks(raw_pool=raw_pool)

        with (
            patch("pypgkit.Database", database),
            patch("acmeeh.db.init._get_raw_pool", get_raw_pool),
        ):
            suppress()

        assert raw_pool._closed is True
        get_raw_pool.assert_called_once_with(database.get_instance.return_value)

    def test_suppress_pool_del_noop_when_database_not_initialized(self):
        _, _, suppress = self._run_post_fork()
        raw_pool = types.SimpleNamespace(_closed=False)
        database, get_raw_pool = self._pypgkit_mocks(initialized=False, raw_pool=raw_pool)

        with (
            patch("pypgkit.Database", database),
            patch("acmeeh.db.init._get_raw_pool", get_raw_pool),
        ):
            suppress()

        get_raw_pool.assert_not_called()
        assert raw_pool._closed is False

    def test_suppress_pool_del_noop_without_raw_pool(self):
        _, _, suppress = self._run_post_fork()
        database, get_raw_pool = self._pypgkit_mocks(raw_pool=None)

        with (
            patch("pypgkit.Database", database),
            patch("acmeeh.db.init._get_raw_pool", get_raw_pool),
        ):
            suppress()  # must not raise

        get_raw_pool.assert_called_once()

    def test_suppress_pool_del_ignores_pool_without_closed_flag(self):
        """A pool class lacking ``_closed`` must not get a stray attribute."""
        _, _, suppress = self._run_post_fork()
        raw_pool = types.SimpleNamespace()
        database, get_raw_pool = self._pypgkit_mocks(raw_pool=raw_pool)

        with (
            patch("pypgkit.Database", database),
            patch("acmeeh.db.init._get_raw_pool", get_raw_pool),
        ):
            suppress()

        assert not hasattr(raw_pool, "_closed")

    def test_suppress_pool_del_never_raises_at_interpreter_exit(self):
        """An atexit handler must not turn worker exit into a traceback."""
        _, _, suppress = self._run_post_fork()
        database, get_raw_pool = self._pypgkit_mocks(is_initialized_error=RuntimeError("boom"))

        with (
            patch("pypgkit.Database", database),
            patch("acmeeh.db.init._get_raw_pool", get_raw_pool),
        ):
            suppress()  # must not raise

        get_raw_pool.assert_not_called()

    def test_worker_settings_propagated(self):
        """Workers, worker_class, and timeout are forwarded to gunicorn cfg."""
        FakeBase = self._make_fake_base_application()
        captured_cfg = {}

        def capturing_run(self):
            captured_cfg.update(self.cfg.settings)

        FakeBase.run = capturing_run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings(workers=8, worker_class="gthread", timeout=60)

        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, settings)

        assert captured_cfg["workers"] == 8
        assert captured_cfg["worker_class"] == "gthread"
        assert captured_cfg["timeout"] == 60

    def test_graceful_timeout_and_keepalive(self):
        """graceful_timeout and keepalive are forwarded."""
        FakeBase = self._make_fake_base_application()
        captured_cfg = {}

        def capturing_run(self):
            captured_cfg.update(self.cfg.settings)

        FakeBase.run = capturing_run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings(graceful_timeout=45, keepalive=5)

        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, settings)

        assert captured_cfg["graceful_timeout"] == 45
        assert captured_cfg["keepalive"] == 5

    def test_max_requests_set_when_nonzero(self):
        """max_requests is set only when it is truthy (non-zero)."""
        FakeBase = self._make_fake_base_application()
        captured_cfg = {}

        def capturing_run(self):
            captured_cfg.update(self.cfg.settings)

        FakeBase.run = capturing_run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings(max_requests=1000)

        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, settings)

        assert captured_cfg["max_requests"] == 1000

    def test_max_requests_not_set_when_zero(self):
        """max_requests is NOT set when it is 0 (falsy)."""
        FakeBase = self._make_fake_base_application()
        captured_cfg = {}

        def capturing_run(self):
            captured_cfg.update(self.cfg.settings)

        FakeBase.run = capturing_run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings(max_requests=0)

        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, settings)

        assert "max_requests" not in captured_cfg

    def test_max_requests_jitter_set_when_nonzero(self):
        """max_requests_jitter is set only when truthy."""
        FakeBase = self._make_fake_base_application()
        captured_cfg = {}

        def capturing_run(self):
            captured_cfg.update(self.cfg.settings)

        FakeBase.run = capturing_run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings(max_requests_jitter=50)

        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, settings)

        assert captured_cfg["max_requests_jitter"] == 50

    def test_max_requests_jitter_not_set_when_zero(self):
        """max_requests_jitter is NOT set when 0."""
        FakeBase = self._make_fake_base_application()
        captured_cfg = {}

        def capturing_run(self):
            captured_cfg.update(self.cfg.settings)

        FakeBase.run = capturing_run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings(max_requests_jitter=0)

        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, settings)

        assert "max_requests_jitter" not in captured_cfg

    def test_accesslog_set_to_none(self):
        """Gunicorn's access log is silenced (set to None)."""
        FakeBase = self._make_fake_base_application()
        captured_cfg = {}

        def capturing_run(self):
            captured_cfg.update(self.cfg.settings)

        FakeBase.run = capturing_run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings()

        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, settings)

        assert captured_cfg["accesslog"] is None

    def test_load_returns_flask_app(self):
        """The _App.load() method returns the Flask application."""
        FakeBase = self._make_fake_base_application()
        loaded_app = []

        class TrackingBase(FakeBase):
            def run(self):
                loaded_app.append(self.load())

        fake_modules = self._install_fake_gunicorn(TrackingBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings()

        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, settings)

        assert len(loaded_app) == 1
        assert loaded_app[0] is app

    def test_log_info_called(self):
        """An info log message is emitted before starting gunicorn."""
        FakeBase = self._make_fake_base_application()
        FakeBase.run = lambda self: None  # no-op run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings(bind="10.0.0.1", port=443, workers=2, worker_class="gthread")

        with (
            patch.dict(sys.modules, fake_modules),
            patch("acmeeh.server.gunicorn_app.log") as mock_log,
        ):
            run_gunicorn(app, settings)

        mock_log.info.assert_called_once()
        args = mock_log.info.call_args[0]
        # The format string uses %s placeholders; check positional args
        assert "10.0.0.1" in args
        assert 443 in args
        assert 2 in args
        assert "gthread" in args

    def test_both_max_requests_fields_set(self):
        """Both max_requests and max_requests_jitter forwarded when nonzero."""
        FakeBase = self._make_fake_base_application()
        captured_cfg = {}

        def capturing_run(self):
            captured_cfg.update(self.cfg.settings)

        FakeBase.run = capturing_run
        fake_modules = self._install_fake_gunicorn(FakeBase)

        from acmeeh.server.gunicorn_app import run_gunicorn

        app = MagicMock()
        settings = _make_settings(max_requests=500, max_requests_jitter=100)

        with patch.dict(sys.modules, fake_modules):
            run_gunicorn(app, settings)

        assert captured_cfg["max_requests"] == 500
        assert captured_cfg["max_requests_jitter"] == 100


# ===========================================================================
# wsgi module
# ===========================================================================


class TestWsgiMissingEnvVar:
    """When ACMEEH_CONFIG is not set, the wsgi module calls sys.exit(1)."""

    def test_exits_when_acmeeh_config_not_set(self):
        """Importing wsgi without ACMEEH_CONFIG set exits with code 1."""
        # Remove the module if it was previously imported so we can re-import
        sys.modules.pop("acmeeh.server.wsgi", None)

        with patch.dict("os.environ", {}, clear=True), pytest.raises(SystemExit) as exc_info:
            importlib.import_module("acmeeh.server.wsgi")

        assert exc_info.value.code == 1

        # Cleanup
        sys.modules.pop("acmeeh.server.wsgi", None)

    def test_exits_when_acmeeh_config_explicitly_absent(self):
        """Even with other env vars present, missing ACMEEH_CONFIG exits."""
        sys.modules.pop("acmeeh.server.wsgi", None)

        env = {"OTHER_VAR": "value"}
        # Ensure ACMEEH_CONFIG is not in the environment
        with patch.dict("os.environ", env, clear=True), pytest.raises(SystemExit) as exc_info:
            importlib.import_module("acmeeh.server.wsgi")

        assert exc_info.value.code == 1

        sys.modules.pop("acmeeh.server.wsgi", None)


class TestWsgiBootstrap:
    """When ACMEEH_CONFIG is set, the wsgi module bootstraps the app."""

    def test_creates_config_from_env_path(self, tmp_path):
        """AcmeehConfig is instantiated with the path from ACMEEH_CONFIG."""
        sys.modules.pop("acmeeh.server.wsgi", None)

        config_path = str(tmp_path / "config.yaml")
        mock_config = MagicMock()
        mock_config.settings.logging = MagicMock()
        mock_config.settings.database = MagicMock()
        mock_db = MagicMock()
        mock_app = MagicMock()

        env = {"ACMEEH_CONFIG": config_path}

        with (
            patch.dict("os.environ", env, clear=True),
            patch("acmeeh.config.AcmeehConfig", return_value=mock_config) as mock_cfg_cls,
            patch("acmeeh.logging.configure_logging") as mock_logging,
            patch("acmeeh.db.init_database", return_value=mock_db) as mock_init_db,
            patch("acmeeh.app.create_app", return_value=mock_app) as mock_create,
        ):
            mod = importlib.import_module("acmeeh.server.wsgi")

        mock_cfg_cls.assert_called_once_with(config_file=config_path, schema_file="bundled")

        sys.modules.pop("acmeeh.server.wsgi", None)

    def test_configures_logging(self, tmp_path):
        """configure_logging is called with the logging settings."""
        sys.modules.pop("acmeeh.server.wsgi", None)

        config_path = str(tmp_path / "config.yaml")
        mock_config = MagicMock()
        mock_logging_settings = MagicMock()
        mock_config.settings.logging = mock_logging_settings
        mock_config.settings.database = MagicMock()
        mock_db = MagicMock()
        mock_app = MagicMock()

        env = {"ACMEEH_CONFIG": config_path}

        with (
            patch.dict("os.environ", env, clear=True),
            patch("acmeeh.config.AcmeehConfig", return_value=mock_config),
            patch("acmeeh.logging.configure_logging") as mock_log_fn,
            patch("acmeeh.db.init_database", return_value=mock_db),
            patch("acmeeh.app.create_app", return_value=mock_app),
        ):
            importlib.import_module("acmeeh.server.wsgi")

        mock_log_fn.assert_called_once_with(mock_logging_settings)

        sys.modules.pop("acmeeh.server.wsgi", None)

    def test_initializes_database(self, tmp_path):
        """init_database is called with the database settings."""
        sys.modules.pop("acmeeh.server.wsgi", None)

        config_path = str(tmp_path / "config.yaml")
        mock_config = MagicMock()
        mock_db_settings = MagicMock()
        mock_config.settings.logging = MagicMock()
        mock_config.settings.database = mock_db_settings
        mock_db = MagicMock()
        mock_app = MagicMock()

        env = {"ACMEEH_CONFIG": config_path}

        with (
            patch.dict("os.environ", env, clear=True),
            patch("acmeeh.config.AcmeehConfig", return_value=mock_config),
            patch("acmeeh.logging.configure_logging"),
            patch("acmeeh.db.init_database", return_value=mock_db) as mock_init_db,
            patch("acmeeh.app.create_app", return_value=mock_app),
        ):
            importlib.import_module("acmeeh.server.wsgi")

        mock_init_db.assert_called_once_with(mock_db_settings)

        sys.modules.pop("acmeeh.server.wsgi", None)

    def test_creates_flask_app(self, tmp_path):
        """create_app is called with config and database."""
        sys.modules.pop("acmeeh.server.wsgi", None)

        config_path = str(tmp_path / "config.yaml")
        mock_config = MagicMock()
        mock_config.settings.logging = MagicMock()
        mock_config.settings.database = MagicMock()
        mock_db = MagicMock()
        mock_app = MagicMock()

        env = {"ACMEEH_CONFIG": config_path}

        with (
            patch.dict("os.environ", env, clear=True),
            patch("acmeeh.config.AcmeehConfig", return_value=mock_config),
            patch("acmeeh.logging.configure_logging"),
            patch("acmeeh.db.init_database", return_value=mock_db) as mock_init_db,
            patch("acmeeh.app.create_app", return_value=mock_app) as mock_create,
        ):
            importlib.import_module("acmeeh.server.wsgi")

        mock_create.assert_called_once_with(config=mock_config, database=mock_db)

        sys.modules.pop("acmeeh.server.wsgi", None)

    def test_module_exposes_app_attribute(self, tmp_path):
        """The wsgi module exposes an ``app`` attribute (the Flask app)."""
        sys.modules.pop("acmeeh.server.wsgi", None)

        config_path = str(tmp_path / "config.yaml")
        mock_config = MagicMock()
        mock_config.settings.logging = MagicMock()
        mock_config.settings.database = MagicMock()
        mock_db = MagicMock()
        mock_app = MagicMock(name="the_flask_app")

        env = {"ACMEEH_CONFIG": config_path}

        with (
            patch.dict("os.environ", env, clear=True),
            patch("acmeeh.config.AcmeehConfig", return_value=mock_config),
            patch("acmeeh.logging.configure_logging"),
            patch("acmeeh.db.init_database", return_value=mock_db),
            patch("acmeeh.app.create_app", return_value=mock_app),
        ):
            mod = importlib.import_module("acmeeh.server.wsgi")

        assert mod.app is mock_app

        sys.modules.pop("acmeeh.server.wsgi", None)

    def test_bootstrap_order(self, tmp_path):
        """Bootstrapping happens in the correct order:
        config -> logging -> database -> create_app.
        """
        sys.modules.pop("acmeeh.server.wsgi", None)

        config_path = str(tmp_path / "config.yaml")
        call_order = []

        mock_config = MagicMock()
        mock_config.settings.logging = MagicMock()
        mock_config.settings.database = MagicMock()
        mock_db = MagicMock()
        mock_app = MagicMock()

        def track_config(*args, **kwargs):
            call_order.append("config")
            return mock_config

        def track_logging(*args, **kwargs):
            call_order.append("logging")

        def track_db(*args, **kwargs):
            call_order.append("database")
            return mock_db

        def track_create(*args, **kwargs):
            call_order.append("create_app")
            return mock_app

        env = {"ACMEEH_CONFIG": config_path}

        with (
            patch.dict("os.environ", env, clear=True),
            patch("acmeeh.config.AcmeehConfig", side_effect=track_config),
            patch("acmeeh.logging.configure_logging", side_effect=track_logging),
            patch("acmeeh.db.init_database", side_effect=track_db),
            patch("acmeeh.app.create_app", side_effect=track_create),
        ):
            importlib.import_module("acmeeh.server.wsgi")

        assert call_order == ["config", "logging", "database", "create_app"]

        sys.modules.pop("acmeeh.server.wsgi", None)

    def test_schema_file_is_bundled(self, tmp_path):
        """AcmeehConfig is called with schema_file='bundled'."""
        sys.modules.pop("acmeeh.server.wsgi", None)

        config_path = str(tmp_path / "config.yaml")
        mock_config = MagicMock()
        mock_config.settings.logging = MagicMock()
        mock_config.settings.database = MagicMock()

        env = {"ACMEEH_CONFIG": config_path}

        with (
            patch.dict("os.environ", env, clear=True),
            patch("acmeeh.config.AcmeehConfig", return_value=mock_config) as mock_cls,
            patch("acmeeh.logging.configure_logging"),
            patch("acmeeh.db.init_database", return_value=MagicMock()),
            patch("acmeeh.app.create_app", return_value=MagicMock()),
        ):
            importlib.import_module("acmeeh.server.wsgi")

        _, kwargs = mock_cls.call_args
        assert kwargs["schema_file"] == "bundled"

        sys.modules.pop("acmeeh.server.wsgi", None)
