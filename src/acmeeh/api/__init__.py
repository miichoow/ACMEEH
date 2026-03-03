"""ACME API layer — Flask blueprint registration.

Call :func:`register_blueprints` during application startup to wire
all ACME route blueprints into the Flask app.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from acmeeh.api.decorators import add_acme_headers

if TYPE_CHECKING:
    from flask import Flask

log = logging.getLogger(__name__)


def register_blueprints(app: Flask) -> None:
    """Register all ACME API blueprints on the Flask application.

    Reads ``api.base_path`` and ``acme.paths`` from the app's settings
    to determine URL prefixes.
    """
    settings = app.config["ACMEEH_SETTINGS"]
    base = settings.api.base_path.rstrip("/")
    paths = settings.acme.paths

    # Import blueprints
    from acmeeh.api.account import account_bp  # noqa: PLC0415
    from acmeeh.api.authorization import authorization_bp  # noqa: PLC0415
    from acmeeh.api.certificate import certificate_bp  # noqa: PLC0415
    from acmeeh.api.challenge_routes import challenge_bp  # noqa: PLC0415
    from acmeeh.api.directory import directory_bp  # noqa: PLC0415
    from acmeeh.api.key_change import key_change_bp  # noqa: PLC0415
    from acmeeh.api.new_authz import new_authz_bp  # noqa: PLC0415
    from acmeeh.api.nonce import nonce_bp  # noqa: PLC0415
    from acmeeh.api.order import order_bp  # noqa: PLC0415

    # Register blueprints with appropriate URL prefixes
    # Directory — mounted at the directory path
    app.register_blueprint(directory_bp, url_prefix=base + paths.directory)

    # Nonce — mounted at the new-nonce path
    app.register_blueprint(nonce_bp, url_prefix=base + paths.new_nonce)

    # Account — mounted at base (routes define their own paths)
    app.register_blueprint(account_bp, url_prefix=base)

    # Order — mounted at base (routes define their own paths)
    app.register_blueprint(order_bp, url_prefix=base)

    # Authorization — mounted at base
    app.register_blueprint(authorization_bp, url_prefix=base)

    # Challenge — mounted at base
    app.register_blueprint(challenge_bp, url_prefix=base)

    # Certificate — mounted at base
    app.register_blueprint(certificate_bp, url_prefix=base)

    # Key change — mounted at base
    app.register_blueprint(key_change_bp, url_prefix=base)

    # Pre-authorization
    app.register_blueprint(new_authz_bp, url_prefix=base + paths.new_authz)

    # CRL (optional)
    if settings.crl.enabled:
        from acmeeh.api.crl import crl_bp  # noqa: PLC0415

        app.register_blueprint(
            crl_bp,
            url_prefix=base + settings.crl.path,
        )

    # ARI (optional)
    if settings.ari.enabled:
        from acmeeh.api.renewal_info import renewal_info_bp  # noqa: PLC0415

        app.register_blueprint(
            renewal_info_bp,
            url_prefix=base + settings.ari.path,
        )

    # Register after-request hook for ACME headers on all routes
    app.after_request(add_acme_headers)

    log.info(
        "Registered ACME blueprints under base_path=%r (%d URL rules)",
        base,
        len(list(app.url_map.iter_rules())),
    )
