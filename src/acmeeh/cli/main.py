"""ACMEEH command-line entry point.

Usage::

    acmeeh -c /etc/acmeeh/config.yaml
    acmeeh -c config.yaml --dev
    acmeeh -c config.yaml --validate-only
    acmeeh -c config.yaml serve --dev
    acmeeh -c config.yaml db status
    acmeeh -c config.yaml ca test-sign
    acmeeh -c config.yaml crl rebuild
    acmeeh -c config.yaml admin create-user --username admin --email admin@example.com
    python -m acmeeh -c config.yaml
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

log = logging.getLogger(__name__)


def _get_version() -> str:
    from acmeeh import __version__

    return __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acmeeh",
        description="ACMEEH — Enterprise ACME Server for Internal PKI",
    )
    parser.add_argument(
        "-c",
        "--config",
        required=True,
        metavar="PATH",
        help="Path to the configuration file (YAML or JSON).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug output (full tracebacks, verbose logging).",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        default=False,
        help="Validate the configuration file and exit.",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        default=False,
        help="Use Flask's development server instead of gunicorn.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {_get_version()}",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command")

    # serve
    serve_parser = subparsers.add_parser("serve", help="Start the ACMEEH server")
    serve_parser.add_argument("--dev", action="store_true", default=False, dest="dev")

    # db
    db_parser = subparsers.add_parser("db", help="Database management")
    db_sub = db_parser.add_subparsers(dest="db_command")
    db_sub.add_parser("status", help="Check database connectivity")
    db_sub.add_parser("migrate", help="Run database migration")

    # ca
    ca_parser = subparsers.add_parser("ca", help="CA backend management")
    ca_sub = ca_parser.add_subparsers(dest="ca_command")
    ca_sub.add_parser("test-sign", help="Test CA signing with ephemeral CSR")

    # crl
    crl_parser = subparsers.add_parser("crl", help="CRL management")
    crl_sub = crl_parser.add_subparsers(dest="crl_command")
    crl_sub.add_parser("rebuild", help="Force CRL rebuild")

    # admin
    admin_parser = subparsers.add_parser("admin", help="Admin user management")
    admin_sub = admin_parser.add_subparsers(dest="admin_command")
    create_user = admin_sub.add_parser("create-user", help="Create admin user")
    create_user.add_argument("--username", required=True, help="Username")
    create_user.add_argument("--email", required=True, help="Email address")
    create_user.add_argument("--role", default="auditor", help="Role (admin/auditor)")

    # inspect
    inspect_parser = subparsers.add_parser("inspect", help="Inspect ACME resources")
    inspect_sub = inspect_parser.add_subparsers(dest="inspect_command")
    for name, help_text in [
        ("order", "Inspect an order by UUID"),
        ("certificate", "Inspect a certificate by UUID or serial"),
        ("account", "Inspect an account by UUID"),
    ]:
        p = inspect_sub.add_parser(name, help=help_text)
        p.add_argument("resource_id", help=f"The {name} ID to inspect")

    return parser


def _print_error(message: str) -> None:
    """Print a user-facing error to stderr."""
    print(f"Error: {message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> None:
    """CLI entry point.  Parses arguments, loads config, starts server."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # -- resolve config path ---
    config_path = Path(args.config)
    if not config_path.is_file():
        _print_error(f"configuration file not found: {config_path}")
        sys.exit(1)

    # -- bootstrap logging early (basic stderr until config is loaded) ---
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    # -- load & validate config ---
    try:
        from acmeeh.config import AcmeehConfig, ConfigValidationError

        config = AcmeehConfig(
            config_file=str(config_path),
            schema_file="bundled",
        )
    except ConfigValidationError as exc:
        _print_error(str(exc))
        sys.exit(1)
    except Exception as exc:
        if args.debug:
            raise
        _print_error(f"failed to load configuration: {exc}")
        sys.exit(1)

    # -- replace bootstrap logging with structured logging ---
    from acmeeh.logging import configure_logging

    configure_logging(config.settings.logging)

    if args.validate_only:
        _print_settings_summary(config)
        sys.exit(0)

    # -- dispatch subcommand ---
    command = args.command

    if command == "db":
        from acmeeh.cli.commands.db import run_db

        run_db(config, args)
    elif command == "ca":
        from acmeeh.cli.commands.ca import run_ca

        run_ca(config, args)
    elif command == "crl":
        from acmeeh.cli.commands.crl import run_crl

        run_crl(config, args)
    elif command == "admin":
        from acmeeh.cli.commands.admin import run_admin

        run_admin(config, args)
    elif command == "inspect":
        from acmeeh.cli.commands.inspect import run_inspect

        run_inspect(config, args)
    else:
        # Default: serve (backward compatible — no subcommand = serve)
        _print_settings_summary(config)
        _run_serve(config, args)


def _run_serve(config, args) -> None:
    """Start the server (extracted for backward compat)."""
    try:
        from acmeeh.db import init_database

        db = init_database(config.settings.database)
    except Exception as exc:
        if args.debug:
            raise
        _print_error(f"database initialisation failed: {exc}")
        sys.exit(1)

    from acmeeh.app import create_app

    app = create_app(config=config, database=db)

    if args.dev:
        log.info("Starting development server (not for production)")
        ssl_ctx = None
        tls_cert = Path("dev/tls/server.pem")
        tls_key = Path("dev/tls/server-key.pem")
        if tls_cert.is_file() and tls_key.is_file():
            ssl_ctx = (str(tls_cert), str(tls_key))
            log.info("TLS enabled: %s", tls_cert)
        app.run(
            host=config.settings.server.bind,
            port=config.settings.server.port,
            debug=True,
            use_reloader=True,
            ssl_context=ssl_ctx,
        )
    else:
        try:
            from acmeeh.server.gunicorn_app import run_gunicorn

            run_gunicorn(app, config.settings.server)
        except RuntimeError as exc:
            _print_error(str(exc))
            sys.exit(1)


def _print_settings_summary(config) -> None:
    """Print a short summary of the loaded configuration."""
    s = config.settings
    print(f"ACMEEH v{_get_version()}")
    print(f"  Server:   {s.server.bind}:{s.server.port}")
    print(f"  CA:       {s.ca.backend}")
    print(f"  Database: {s.database.host}:{s.database.port}/{s.database.database}")
