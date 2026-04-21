"""ACME pre-authorization endpoint (RFC 8555 §7.4.1).

``POST /new-authz`` — create a standalone pre-authorization for an
identifier before placing an order.
"""

from __future__ import annotations

import logging

from flask import Blueprint, g, jsonify

from acmeeh.api.decorators import require_jws
from acmeeh.api.serializers import serialize_authorization
from acmeeh.app.context import get_container
from acmeeh.app.errors import MALFORMED, UNSUPPORTED_IDENTIFIER, AcmeProblem

log = logging.getLogger(__name__)

new_authz_bp = Blueprint("new_authz", __name__)


@new_authz_bp.route("", methods=["POST"], endpoint="new_authz")
@require_jws(use_kid=True, block_on_maintenance=True)
def new_authz():
    """POST /new-authz — create a pre-authorization."""
    container = get_container()
    payload = g.payload or {}

    identifier = payload.get("identifier")
    if not identifier:
        raise AcmeProblem(MALFORMED, "Missing 'identifier' in request body")

    id_type = identifier.get("type", "")
    id_value = identifier.get("value", "")
    if not id_type or not id_value:
        raise AcmeProblem(MALFORMED, "Identifier must have 'type' and 'value'")

    if id_type not in ("dns", "ip"):
        raise AcmeProblem(
            UNSUPPORTED_IDENTIFIER,
            f"Unsupported identifier type '{id_type}'",
        )

    authz, challenges = container.authorization_service.create_pre_authorization(
        account_id=g.account.id,
        identifier_type=id_type,
        identifier_value=id_value.lower() if id_type == "dns" else id_value,
    )

    log.info(
        "Pre-authorization created: %s for %s:%s",
        authz.id,
        id_type,
        id_value,
    )
    body = serialize_authorization(authz, challenges, container.urls)
    response = jsonify(body)
    response.status_code = 201
    response.headers["Location"] = container.urls.authorization_url(authz.id)
    return response
