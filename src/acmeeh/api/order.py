"""ACME order endpoints (RFC 8555 §7.4).

- ``POST /new-order`` — create a new order (kid auth)
- ``POST /order/{id}`` — get order status (kid auth, POST-as-GET)
- ``POST /order/{id}/finalize`` — finalize with CSR (kid auth)
"""

from __future__ import annotations

import logging

from flask import Blueprint, current_app, g, jsonify

from acmeeh.api.decorators import require_jws
from acmeeh.api.serializers import serialize_order
from acmeeh.app.context import get_container
from acmeeh.app.errors import MALFORMED, AcmeProblem
from acmeeh.core.jws import _b64url_decode

log = logging.getLogger(__name__)

order_bp = Blueprint("order", __name__)


@order_bp.route("/new-order", methods=["POST"], endpoint="new_order")
@require_jws(use_kid=True, block_on_maintenance=True)
def new_order():
    """POST /new-order — create a new order."""
    container = get_container()
    payload = g.payload or {}

    # ARI renewal: if 'replaces' is present, create a renewal order
    replaces = payload.get("replaces")
    if replaces is not None:
        order, authz_ids = container.order_service.create_renewal_order(
            account_id=g.account.id,
            replacing_cert_id=replaces,
            cert_repo=container.certificates,
        )
    else:
        identifiers = payload.get("identifiers")
        if not identifiers:
            raise AcmeProblem(MALFORMED, "Missing 'identifiers' in request body")

        order, authz_ids = container.order_service.create_order(
            account_id=g.account.id,
            identifiers=identifiers,
            not_before=payload.get("notBefore"),
            not_after=payload.get("notAfter"),
            profile=payload.get("profile"),
        )

    log.info("Order %s created for account %s", order.id, g.account.id)
    body = serialize_order(order, authz_ids, container.urls)
    response = jsonify(body)
    response.status_code = 201
    response.headers["Location"] = container.urls.order_url(order.id)
    return response


@order_bp.route("/order/<uuid:order_id>", methods=["POST"], endpoint="order")
@require_jws(use_kid=True)
def get_order(order_id):
    """POST /order/{id} — get order status (POST-as-GET)."""
    container = get_container()

    order, authz_ids = container.order_service.get_order(
        order_id,
        g.account.id,
    )

    body = serialize_order(order, authz_ids, container.urls)
    response = jsonify(body)
    response.headers["Location"] = container.urls.order_url(order.id)

    # RFC 8555 §7.4: if order is still processing, signal the client to retry
    from acmeeh.core.types import OrderStatus

    if order.status == OrderStatus.PROCESSING:
        settings = current_app.config.get("ACMEEH_SETTINGS")
        retry_after = settings.order.retry_after_seconds if settings else 3
        response.headers["Retry-After"] = str(retry_after)

    return response


@order_bp.route(
    "/order/<uuid:order_id>/finalize",
    methods=["POST"],
    endpoint="finalize",
)
@require_jws(use_kid=True)
def finalize_order(order_id):
    """POST /order/{id}/finalize — finalize order with CSR."""
    container = get_container()
    payload = g.payload or {}

    csr_b64 = payload.get("csr")
    if not csr_b64:
        raise AcmeProblem(MALFORMED, "Missing 'csr' in request body")

    try:
        csr_der = _b64url_decode(csr_b64)
    except Exception:
        log.warning("Malformed base64url CSR in finalize request for order %s", order_id)
        raise AcmeProblem(MALFORMED, "Invalid base64url-encoded CSR")

    log.info("Finalize requested for order %s by account %s", order_id, g.account.id)
    order = container.certificate_service.finalize_order(
        order_id,
        csr_der,
        g.account.id,
    )

    authz_ids = container.order_service.get_authorization_ids(order_id)
    body = serialize_order(order, authz_ids, container.urls)
    response = jsonify(body)
    response.headers["Location"] = container.urls.order_url(order.id)

    # RFC 8555 §7.4: if order is still processing, signal the client to retry
    from acmeeh.core.types import OrderStatus

    if order.status == OrderStatus.PROCESSING:
        settings = current_app.config.get("ACMEEH_SETTINGS")
        retry_after = settings.order.retry_after_seconds if settings else 3
        response.headers["Retry-After"] = str(retry_after)

    return response
