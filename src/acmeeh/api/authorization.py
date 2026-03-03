"""ACME authorization endpoint (RFC 8555 §7.5).

``POST /authz/{id}`` — get authorization status (POST-as-GET) or
deactivate.
"""

from __future__ import annotations

import logging

from flask import Blueprint, g, jsonify

from acmeeh.api.decorators import require_jws
from acmeeh.api.serializers import serialize_authorization
from acmeeh.app.context import get_container

log = logging.getLogger(__name__)

authorization_bp = Blueprint("authorization", __name__)


@authorization_bp.route(
    "/authz/<uuid:authz_id>",
    methods=["POST"],
    endpoint="authorization",
)
@require_jws(use_kid=True)
def get_authorization(authz_id):
    """POST /authz/{id} — get or deactivate authorization."""
    container = get_container()
    payload = g.payload

    # Deactivation request
    if payload and payload.get("status") == "deactivated":
        log.info("Authorization deactivation requested: %s", authz_id)
        authz = container.authorization_service.deactivate(
            authz_id,
            g.account.id,
        )
        challenges = container.challenges.find_by_authorization(authz_id)
        body = serialize_authorization(authz, challenges, container.urls)
        return jsonify(body), 200

    # POST-as-GET: return current state
    authz, challenges = container.authorization_service.get_authorization(
        authz_id,
        g.account.id,
    )
    body = serialize_authorization(authz, challenges, container.urls)
    response = jsonify(body)
    response.status_code = 200

    # RFC 8555 §7.5: include Retry-After when authz is still pending
    from acmeeh.core.types import AuthorizationStatus

    if authz.status == AuthorizationStatus.PENDING:
        from flask import current_app

        settings = current_app.config.get("ACMEEH_SETTINGS")
        retry_after = settings.challenges.retry_after_seconds if settings else 3
        response.headers["Retry-After"] = str(retry_after)

    return response
