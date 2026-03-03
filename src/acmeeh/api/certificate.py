"""ACME certificate endpoints (RFC 8555 §7.4.2 / §7.6).

- ``POST /cert/{id}`` — download certificate (kid auth, POST-as-GET)
- ``POST /revoke-cert`` — revoke a certificate (kid or jwk auth)
"""

from __future__ import annotations

import logging

from flask import Blueprint, g, make_response

from acmeeh.api.decorators import require_jws
from acmeeh.app.context import get_container
from acmeeh.app.errors import MALFORMED, AcmeProblem
from acmeeh.core.jws import _b64url_decode

log = logging.getLogger(__name__)

certificate_bp = Blueprint("certificate", __name__)


@certificate_bp.route(
    "/cert/<uuid:cert_id>",
    methods=["POST"],
    endpoint="certificate",
)
@require_jws(use_kid=True)
def download_certificate(cert_id):
    """POST /cert/{id} — download certificate (POST-as-GET)."""
    container = get_container()

    pem_chain = container.certificate_service.download(cert_id, g.account.id)

    response = make_response(pem_chain, 200)
    response.headers["Content-Type"] = "application/pem-certificate-chain"
    return response


@certificate_bp.route("/revoke-cert", methods=["POST"], endpoint="revoke_cert")
@require_jws(use_kid=False, allow_kid_or_jwk=True)
def revoke_certificate():
    """POST /revoke-cert — revoke a certificate."""
    container = get_container()
    payload = g.payload or {}

    cert_b64 = payload.get("certificate")
    if not cert_b64:
        raise AcmeProblem(MALFORMED, "Missing 'certificate' in request body")

    try:
        cert_der = _b64url_decode(cert_b64)
    except Exception:
        log.warning("Malformed base64url certificate in revocation request")
        raise AcmeProblem(MALFORMED, "Invalid base64url-encoded certificate")

    reason = payload.get("reason")

    # Determine auth mode
    account_id = g.account.id if g.account else None
    jwk = g.jwk_dict if g.account is None else None

    log.info("Certificate revocation requested (auth=%s)", "kid" if account_id else "jwk")
    container.certificate_service.revoke(
        cert_der=cert_der,
        reason=reason,
        account_id=account_id,
        jwk=jwk,
    )

    return "", 200
