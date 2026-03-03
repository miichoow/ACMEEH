"""ACME account endpoints (RFC 8555 §7.3).

- ``POST /new-account`` — create or find account (JWK auth)
- ``POST /acct/{id}`` — update or deactivate account (kid auth)
- ``POST /acct/{id}/orders`` — list account orders (kid auth)
"""

from __future__ import annotations

import logging
from uuid import UUID

from flask import Blueprint, g, jsonify, request

from acmeeh.api.decorators import require_jws
from acmeeh.api.serializers import serialize_account
from acmeeh.app.context import get_container
from acmeeh.app.errors import MALFORMED, AcmeProblem

log = logging.getLogger(__name__)

account_bp = Blueprint("account", __name__)


@account_bp.route("/new-account", methods=["POST"], endpoint="new_account")
@require_jws(use_kid=False)
def new_account():
    """POST /new-account — create or find an account."""
    container = get_container()
    payload = g.payload or {}

    # onlyReturnExisting
    if payload.get("onlyReturnExisting"):
        account = container.account_service.find_by_jwk(g.jwk_dict)
        contacts = container.account_contacts.find_by_account(account.id)
        body = serialize_account(account, contacts, container.urls)
        response = jsonify(body)
        response.status_code = 200
        response.headers["Location"] = container.urls.account_url(account.id)
        return response

    # Create or find
    account, contacts, created = container.account_service.create_or_find(
        jwk=g.jwk_dict,
        contact=payload.get("contact"),
        tos_agreed=payload.get("termsOfServiceAgreed", False),
        eab_payload=payload.get("externalAccountBinding"),
    )

    body = serialize_account(account, contacts, container.urls)
    status = 201 if created else 200
    if created:
        log.info("New account created: %s", account.id)
    response = jsonify(body)
    response.status_code = status
    response.headers["Location"] = container.urls.account_url(account.id)
    return response


@account_bp.route("/acct/<uuid:account_id>", methods=["POST"], endpoint="account")
@require_jws(use_kid=True)
def update_account(account_id):
    """POST /acct/{id} — update or deactivate account."""
    container = get_container()
    payload = g.payload

    # Verify the kid matches the URL account ID
    if g.account and g.account.id != account_id:
        raise AcmeProblem(
            MALFORMED,
            "Account ID in URL does not match authenticated account",
            status=403,
        )

    # POST-as-GET: return current account
    if payload is None:
        contacts = container.account_contacts.find_by_account(account_id)
        body = serialize_account(g.account, contacts, container.urls)
        response = jsonify(body)
        response.headers["Location"] = container.urls.account_url(account_id)
        return response

    # Deactivation
    if payload.get("status") == "deactivated":
        log.info("Account deactivation requested: %s", account_id)
        account = container.account_service.deactivate(account_id)
        contacts = container.account_contacts.find_by_account(account_id)
        body = serialize_account(account, contacts, container.urls)
        response = jsonify(body)
        response.headers["Location"] = container.urls.account_url(account_id)
        return response

    # Contact update
    if "contact" in payload:
        contacts = container.account_service.update_contacts(
            account_id,
            payload["contact"],
        )
        body = serialize_account(g.account, contacts, container.urls)
        response = jsonify(body)
        response.headers["Location"] = container.urls.account_url(account_id)
        return response

    # No recognized fields
    contacts = container.account_contacts.find_by_account(account_id)
    body = serialize_account(g.account, contacts, container.urls)
    response = jsonify(body)
    response.headers["Location"] = container.urls.account_url(account_id)
    return response


@account_bp.route(
    "/acct/<uuid:account_id>/orders",
    methods=["POST"],
    endpoint="account_orders",
)
@require_jws(use_kid=True)
def list_orders(account_id):
    """POST /acct/{id}/orders — list account orders (POST-as-GET)."""
    container = get_container()

    if g.account and g.account.id != account_id:
        raise AcmeProblem(
            MALFORMED,
            "Account ID in URL does not match authenticated account",
            status=403,
        )

    # Cursor-based pagination
    cursor_param = request.args.get("cursor")
    cursor = None
    if cursor_param:
        try:
            cursor = UUID(cursor_param)
        except ValueError:
            raise AcmeProblem(MALFORMED, "Invalid cursor parameter")

    page_size = container.settings.acme.orders_page_size
    orders, next_cursor = container.order_service.list_orders_paginated(
        account_id,
        cursor=cursor,
        limit=page_size,
    )
    body = {
        "orders": [container.urls.order_url(o.id) for o in orders],
    }
    response = jsonify(body)
    if next_cursor is not None:
        next_url = container.urls.orders_url(account_id) + f"?cursor={next_cursor}"
        response.headers["Link"] = f'<{next_url}>;rel="next"'
    return response, 200
