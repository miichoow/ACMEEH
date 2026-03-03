"""ACME challenge endpoint (RFC 8555 §7.5.1).

``POST /chall/{id}`` — trigger challenge validation.
The client sends ``{}`` as the payload to signal readiness.
"""

from __future__ import annotations

import logging

from flask import Blueprint, current_app, g, jsonify

from acmeeh.api.decorators import require_jws
from acmeeh.api.serializers import serialize_challenge
from acmeeh.app.context import get_container

log = logging.getLogger(__name__)

challenge_bp = Blueprint("challenge", __name__)


@challenge_bp.route(
    "/chall/<uuid:challenge_id>",
    methods=["POST"],
    endpoint="challenge",
)
@require_jws(use_kid=True)
def trigger_challenge(challenge_id):
    """POST /chall/{id} — trigger challenge validation.

    Per RFC 8555 §7.5.1, the client POSTs ``{}`` to indicate it is
    ready for the server to validate.  POST-as-GET (empty payload)
    returns the current challenge state.
    """
    container = get_container()
    payload = g.payload

    if payload is None:
        # POST-as-GET: return current state
        challenge = container.challenges.find_by_id(challenge_id)
        if challenge is None:
            from acmeeh.app.errors import MALFORMED, AcmeProblem

            raise AcmeProblem(MALFORMED, "Challenge not found", status=404)
        body = serialize_challenge(challenge, container.urls)
        response = jsonify(body)
        response.status_code = 200
        # RFC 8555 §7.5.1: Link rel="up" to parent authorization
        response.headers["Link"] = (
            f'<{container.urls.authorization_url(challenge.authorization_id)}>;rel="up"'
        )
        return response

    # Trigger validation (payload should be {})
    log.info("Challenge validation triggered: %s by account %s", challenge_id, g.account.id)
    challenge = container.challenge_service.initiate_validation(
        challenge_id,
        g.account.id,
        g.jwk_dict,
    )

    body = serialize_challenge(challenge, container.urls)
    response = jsonify(body)
    response.status_code = 200
    response.headers["Link"] = (
        f'<{container.urls.authorization_url(challenge.authorization_id)}>;rel="up"'
    )

    # RFC 8555 §7.5.1: include Retry-After when challenge is still processing
    from acmeeh.core.types import ChallengeStatus

    if challenge.status == ChallengeStatus.PROCESSING:
        settings = current_app.config.get("ACMEEH_SETTINGS")
        retry_after = settings.challenges.retry_after_seconds if settings else 3
        response.headers["Retry-After"] = str(retry_after)

    return response
