"""Serve subcommand — start the ACMEEH server."""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)


def run_serve(config, args) -> None:
    """Start the ACMEEH server."""
    from acmeeh.app import create_app
    from acmeeh.app.factory import start_workers
    from acmeeh.db import init_database

    db = init_database(config.settings.database)
    app = create_app(config=config, database=db)

    if args.dev:
        log.info("Starting development server (not for production)")
        # No fork — safe to start workers here directly
        start_workers(app)
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
        from acmeeh.server.gunicorn_app import run_gunicorn

        run_gunicorn(app, config.settings.server)
