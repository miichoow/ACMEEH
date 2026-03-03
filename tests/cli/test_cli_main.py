"""Tests for the ACMEEH CLI entry point (acmeeh.cli.main).

Covers parser construction, config validation, subcommand dispatch, and
the _run_serve helper.  All external dependencies are mocked.

Key fix: ``main()`` uses deferred imports (``from acmeeh.config import
AcmeehConfig`` inside the function body), so patches target the *source*
module (e.g. ``acmeeh.config.AcmeehConfig``), NOT ``acmeeh.cli.main``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import yaml

from acmeeh.cli.main import _build_parser, main

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def parser():
    """Return a freshly built ArgumentParser."""
    return _build_parser()


@pytest.fixture
def tmp_config(tmp_path):
    """Write a minimal config YAML to a temp file and return its path."""
    config_data = {
        "server": {"external_url": "https://acme.test"},
        "database": {"database": "test", "user": "test"},
        "ca": {
            "internal": {
                "root_cert_path": "/tmp/test.crt",
                "root_key_path": "/tmp/test.key",
            },
        },
    }
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        yaml.safe_dump(config_data, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
    return str(cfg_path)


def _mock_config():
    """Create a MagicMock that impersonates an AcmeehConfig object."""
    cfg = MagicMock()
    cfg.settings.logging = MagicMock()
    cfg.settings.server.external_url = "https://acme.test"
    cfg.settings.server.bind = "0.0.0.0"
    cfg.settings.server.port = 8443
    cfg.settings.server.workers = 4
    cfg.settings.database.user = "test"
    cfg.settings.database.host = "localhost"
    cfg.settings.database.port = 5432
    cfg.settings.database.database = "test"
    cfg.settings.database.auto_setup = True
    cfg.settings.ca.backend = "internal"
    cfg.settings.challenges.enabled = ["http-01"]
    cfg.settings.logging.level = "info"
    cfg.settings.tos.require_agreement = False
    cfg.settings.admin_api.enabled = False
    cfg.settings.crl.enabled = False
    cfg.settings.ari.enabled = False
    return cfg


# ===========================================================================
# Parser construction
# ===========================================================================


class TestBuildParser:
    """_build_parser returns a parser with all expected subcommands."""

    def test_parser_created(self, parser):
        """Parser object is returned."""
        assert parser is not None

    def test_config_required(self, parser):
        """--config / -c is required."""
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_serve_subcommand(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "serve"])
        assert args.command == "serve"

    def test_db_subcommand(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "db", "status"])
        assert args.command == "db"
        assert args.db_command == "status"

    def test_ca_subcommand(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "ca", "test-sign"])
        assert args.command == "ca"
        assert args.ca_command == "test-sign"

    def test_crl_subcommand(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "crl", "rebuild"])
        assert args.command == "crl"
        assert args.crl_command == "rebuild"

    def test_admin_subcommand(self, parser, tmp_config):
        args = parser.parse_args(
            [
                "-c",
                tmp_config,
                "admin",
                "create-user",
                "--username",
                "u",
                "--email",
                "e@e.com",
            ]
        )
        assert args.command == "admin"
        assert args.admin_command == "create-user"

    def test_inspect_subcommand(self, parser, tmp_config):
        args = parser.parse_args(
            [
                "-c",
                tmp_config,
                "inspect",
                "order",
                "some-uuid",
            ]
        )
        assert args.command == "inspect"
        assert args.inspect_command == "order"
        assert args.resource_id == "some-uuid"

    def test_validate_only_flag(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "--validate-only"])
        assert args.validate_only is True

    def test_debug_flag(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "--debug"])
        assert args.debug is True

    def test_dev_flag(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "--dev"])
        assert args.dev is True

    def test_no_subcommand(self, parser, tmp_config):
        """No subcommand means command is None (default serve)."""
        args = parser.parse_args(["-c", tmp_config])
        assert args.command is None


# ===========================================================================
# main() entry point
# ===========================================================================


class TestMain:
    """Tests for the main() function."""

    def test_nonexistent_config_file_exits_1(self):
        """A non-existent config file should cause sys.exit(1)."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", "/no/such/path/config.yaml"])
        assert exc_info.value.code == 1

    def test_validate_only_exits_0(self, tmp_config):
        """--validate-only should print summary and exit 0."""
        mock_cfg = _mock_config()

        with (
            patch("acmeeh.config.AcmeehConfig", return_value=mock_cfg),
            patch("acmeeh.logging.configure_logging"),
            patch("acmeeh.cli.main._print_settings_summary"),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--config", tmp_config, "--validate-only"])

        assert exc_info.value.code == 0

    def test_config_validation_error_exits_1(self, tmp_config):
        """ConfigValidationError during config load exits 1."""
        from acmeeh.config import ConfigValidationError

        with (
            patch(
                "acmeeh.config.AcmeehConfig",
                side_effect=ConfigValidationError("bad schema"),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--config", tmp_config])

        assert exc_info.value.code == 1

    def test_config_generic_error_exits_1(self, tmp_config):
        """Generic exception during config load exits 1."""
        with (
            patch(
                "acmeeh.config.AcmeehConfig",
                side_effect=RuntimeError("oops"),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--config", tmp_config])

        assert exc_info.value.code == 1

    def test_dispatches_to_db(self, tmp_config):
        """command='db' dispatches to run_db."""
        mock_cfg = _mock_config()

        with (
            patch("acmeeh.config.AcmeehConfig", return_value=mock_cfg),
            patch("acmeeh.logging.configure_logging"),
            patch("acmeeh.cli.commands.db.run_db") as mock_run_db,
        ):
            main(["--config", tmp_config, "db", "status"])

        mock_run_db.assert_called_once()
        call_args = mock_run_db.call_args[0]
        assert call_args[0] is mock_cfg  # config
        assert call_args[1].db_command == "status"  # args

    def test_dispatches_to_ca(self, tmp_config):
        """command='ca' dispatches to run_ca."""
        mock_cfg = _mock_config()

        with (
            patch("acmeeh.config.AcmeehConfig", return_value=mock_cfg),
            patch("acmeeh.logging.configure_logging"),
            patch("acmeeh.cli.commands.ca.run_ca") as mock_run_ca,
        ):
            main(["--config", tmp_config, "ca", "test-sign"])

        mock_run_ca.assert_called_once()

    def test_dispatches_to_crl(self, tmp_config):
        """command='crl' dispatches to run_crl."""
        mock_cfg = _mock_config()

        with (
            patch("acmeeh.config.AcmeehConfig", return_value=mock_cfg),
            patch("acmeeh.logging.configure_logging"),
            patch("acmeeh.cli.commands.crl.run_crl") as mock_run_crl,
        ):
            main(["--config", tmp_config, "crl", "rebuild"])

        mock_run_crl.assert_called_once()

    def test_dispatches_to_admin(self, tmp_config):
        """command='admin' dispatches to run_admin."""
        mock_cfg = _mock_config()

        with (
            patch("acmeeh.config.AcmeehConfig", return_value=mock_cfg),
            patch("acmeeh.logging.configure_logging"),
            patch("acmeeh.cli.commands.admin.run_admin") as mock_run_admin,
        ):
            main(
                [
                    "--config",
                    tmp_config,
                    "admin",
                    "create-user",
                    "--username",
                    "u",
                    "--email",
                    "e@e.com",
                ]
            )

        mock_run_admin.assert_called_once()

    def test_dispatches_to_inspect(self, tmp_config):
        """command='inspect' dispatches to run_inspect."""
        mock_cfg = _mock_config()

        with (
            patch("acmeeh.config.AcmeehConfig", return_value=mock_cfg),
            patch("acmeeh.logging.configure_logging"),
            patch("acmeeh.cli.commands.inspect.run_inspect") as mock_run_inspect,
        ):
            main(
                [
                    "--config",
                    tmp_config,
                    "inspect",
                    "order",
                    "some-uuid",
                ]
            )

        mock_run_inspect.assert_called_once()

    def test_no_subcommand_defaults_to_serve(self, tmp_config):
        """No subcommand triggers _run_serve (default serve behaviour)."""
        mock_cfg = _mock_config()

        with (
            patch("acmeeh.config.AcmeehConfig", return_value=mock_cfg),
            patch("acmeeh.logging.configure_logging"),
            patch("acmeeh.cli.main._print_settings_summary"),
            patch("acmeeh.cli.main._run_serve") as mock_serve,
        ):
            main(["--config", tmp_config])

        mock_serve.assert_called_once()


# ===========================================================================
# _run_serve
# ===========================================================================


class TestRunServe:
    """Tests for the _run_serve helper in main.py."""

    def test_dev_mode_calls_app_run(self):
        """In dev mode Flask app.run() is invoked."""
        from acmeeh.cli.main import _run_serve

        mock_cfg = _mock_config()
        mock_cfg.settings.server.bind = "127.0.0.1"
        mock_cfg.settings.server.port = 8443

        args = MagicMock()
        args.dev = True
        args.debug = False

        mock_app = MagicMock()

        with (
            patch("acmeeh.db.init_database") as mock_init_db,
            patch("acmeeh.app.create_app", return_value=mock_app),
            patch("pathlib.Path.is_file", return_value=False),
        ):
            mock_init_db.return_value = MagicMock()
            _run_serve(mock_cfg, args)

        mock_app.run.assert_called_once()
        call_kwargs = mock_app.run.call_args[1]
        assert call_kwargs["debug"] is True
        assert call_kwargs["host"] == "127.0.0.1"
        assert call_kwargs["port"] == 8443

    def test_production_mode_calls_gunicorn(self):
        """Without --dev, run_gunicorn is invoked."""
        from acmeeh.cli.main import _run_serve

        mock_cfg = _mock_config()
        args = MagicMock()
        args.dev = False
        args.debug = False

        mock_app = MagicMock()

        with (
            patch("acmeeh.db.init_database") as mock_init_db,
            patch("acmeeh.app.create_app", return_value=mock_app),
            patch("acmeeh.server.gunicorn_app.run_gunicorn") as mock_gunicorn,
        ):
            mock_init_db.return_value = MagicMock()
            _run_serve(mock_cfg, args)

        mock_gunicorn.assert_called_once_with(mock_app, mock_cfg.settings.server)

    def test_db_init_failure_exits_1(self):
        """Database init failure in _run_serve exits 1."""
        from acmeeh.cli.main import _run_serve

        mock_cfg = _mock_config()
        args = MagicMock()
        args.dev = False
        args.debug = False

        with (
            patch("acmeeh.db.init_database", side_effect=Exception("boom")),
            pytest.raises(SystemExit) as exc_info,
        ):
            _run_serve(mock_cfg, args)

        assert exc_info.value.code == 1

    def test_gunicorn_runtime_error_exits_1(self):
        """RuntimeError from gunicorn exits 1."""
        from acmeeh.cli.main import _run_serve

        mock_cfg = _mock_config()
        args = MagicMock()
        args.dev = False
        args.debug = False

        mock_app = MagicMock()

        with (
            patch("acmeeh.db.init_database", return_value=MagicMock()),
            patch("acmeeh.app.create_app", return_value=mock_app),
            patch(
                "acmeeh.server.gunicorn_app.run_gunicorn", side_effect=RuntimeError("bind failed")
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            _run_serve(mock_cfg, args)

        assert exc_info.value.code == 1

    def test_dev_mode_with_tls_files(self):
        """Dev mode with TLS cert/key present sets ssl_context."""
        from acmeeh.cli.main import _run_serve

        mock_cfg = _mock_config()
        mock_cfg.settings.server.bind = "0.0.0.0"
        mock_cfg.settings.server.port = 8443
        args = MagicMock()
        args.dev = True
        args.debug = False

        mock_app = MagicMock()

        with (
            patch("acmeeh.db.init_database", return_value=MagicMock()),
            patch("acmeeh.app.create_app", return_value=mock_app),
            patch("pathlib.Path.is_file", return_value=True),
        ):
            _run_serve(mock_cfg, args)

        call_kwargs = mock_app.run.call_args[1]
        assert call_kwargs["ssl_context"] is not None
