"""WSGI entry point for external servers (gunicorn, uWSGI, etc.).

The config file path is read from the ``ACMEEH_CONFIG`` environment
variable.

Example (with the CLI — recommended)::

    python -m acmeeh -c /etc/acmeeh/config.yaml serve

Example (standalone gunicorn)::

    export ACMEEH_CONFIG=/etc/acmeeh/config.yaml
    gunicorn "acmeeh.server.wsgi:app" -c gunicorn.conf.py

Where ``gunicorn.conf.py`` must include::

    from acmeeh.server.wsgi import post_fork  # noqa: F401

This ensures background worker threads are started **after** gunicorn
forks child processes (threads do not survive ``fork()``).
"""

from __future__ import annotations

import os
import sys

_config_path = os.environ.get("ACMEEH_CONFIG")
if _config_path is None:
    sys.exit(1)

# Bootstrap the singleton before anything else imports it.
from acmeeh.config import AcmeehConfig  # noqa: E402

_config = AcmeehConfig(config_file=_config_path, schema_file="bundled")

from acmeeh.logging import configure_logging  # noqa: E402

configure_logging(_config.settings.logging)

from acmeeh.db import init_database  # noqa: E402

_db = init_database(_config.settings.database)

from acmeeh.app import create_app  # noqa: E402

app = create_app(config=_config, database=_db)


def post_fork(server, worker):  # noqa: ANN001, ARG001
    """Gunicorn ``post_fork`` hook — reinit pool and start workers."""
    from acmeeh.db import reinit_pool_after_fork  # noqa: PLC0415

    reinit_pool_after_fork()

    from acmeeh.app.factory import start_workers  # noqa: PLC0415

    start_workers(app)
