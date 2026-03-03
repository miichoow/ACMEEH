"""RFC 7807 Problem Details and RFC 8555 ACME error types.

Provides :class:`AcmeProblem` — an exception that renders itself as
an ``application/problem+json`` response — plus all standard ACME
error-type URNs and a Flask error-handler registration function.

Usage::

    raise AcmeProblem(MALFORMED, "Request body is not valid JSON", 400)
"""

from __future__ import annotations

import logging
from typing import Any

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RFC 8555 §6.7 — ACME error-type URNs
# ---------------------------------------------------------------------------
_P = "urn:ietf:params:acme:error:"

ACCOUNT_DOES_NOT_EXIST = _P + "accountDoesNotExist"
ALREADY_REVOKED = _P + "alreadyRevoked"
BAD_CSR = _P + "badCSR"
BAD_NONCE = _P + "badNonce"
BAD_PUBLIC_KEY = _P + "badPublicKey"
BAD_REVOCATION_REASON = _P + "badRevocationReason"
BAD_SIGNATURE_ALGORITHM = _P + "badSignatureAlgorithm"
CAA = _P + "caa"
COMPOUND = _P + "compound"
CONNECTION = _P + "connection"
DNS = _P + "dns"
EXTERNAL_ACCOUNT_REQUIRED = _P + "externalAccountRequired"
INCORRECT_RESPONSE = _P + "incorrectResponse"
INVALID_CONTACT = _P + "invalidContact"
MALFORMED = _P + "malformed"
ORDER_NOT_READY = _P + "orderNotReady"
RATE_LIMITED = _P + "rateLimited"
REJECTED_IDENTIFIER = _P + "rejectedIdentifier"
SERVER_INTERNAL = _P + "serverInternal"
TLS = _P + "tls"
UNAUTHORIZED = _P + "unauthorized"
UNSUPPORTED_CONTACT = _P + "unsupportedContact"
UNSUPPORTED_IDENTIFIER = _P + "unsupportedIdentifier"
USER_ACTION_REQUIRED = _P + "userActionRequired"

# Content type for RFC 7807 responses
PROBLEM_CONTENT_TYPE = "application/problem+json"


# ---------------------------------------------------------------------------
# Problem exception
# ---------------------------------------------------------------------------


class AcmeProblem(Exception):
    """An RFC 7807 *problem details* object that doubles as an exception.

    Raise anywhere in request handling to produce a standards-compliant
    error response.  The registered Flask error handler catches it and
    calls :meth:`to_response`.

    Parameters
    ----------
    error_type:
        A URN string (one of the constants above) or ``"about:blank"``
        for generic HTTP errors.
    detail:
        Human-readable explanation of the problem.
    status:
        HTTP status code (default 400).
    title:
        Short summary; omitted when *error_type* is self-explanatory.
    subproblems:
        Optional list of sub-problem dicts (RFC 8555 §6.7.1).
    headers:
        Extra HTTP headers to include on the response
        (e.g. ``Retry-After``).

    """

    def __init__(
        self,
        error_type: str,
        detail: str,
        status: int = 400,
        *,
        title: str | None = None,
        subproblems: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.error_type = error_type
        self.detail = detail
        self.status = status
        self.title = title
        self.subproblems = subproblems
        self.extra_headers = headers or {}
        super().__init__(detail)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the RFC 7807 JSON structure."""
        body: dict[str, Any] = {
            "type": self.error_type,
            "detail": self.detail,
            "status": self.status,
        }
        if self.title is not None:
            body["title"] = self.title
        if self.subproblems:
            body["subproblems"] = self.subproblems
        return body

    def to_response(self):
        """Build a Flask :class:`~flask.Response`."""
        resp = jsonify(self.to_dict())
        resp.status_code = self.status
        resp.headers["Content-Type"] = PROBLEM_CONTENT_TYPE
        resp.headers["Cache-Control"] = "no-store"
        for key, value in self.extra_headers.items():
            resp.headers[key] = value
        return resp


# ---------------------------------------------------------------------------
# Flask error handler registration
# ---------------------------------------------------------------------------


def _is_pool_timeout(exc: Exception) -> bool:
    """Check whether *exc* (or anything in its ``__cause__`` chain) is a pool timeout.

    Uses class-name matching so we don't need a hard import of
    ``psycopg_pool`` or ``pypgkit.exceptions`` — those may not be
    installed in every environment.
    """
    current: BaseException | None = exc
    while current is not None:
        cls_name = type(current).__name__
        if cls_name in ("PoolTimeout", "DatabaseConnectionError"):
            return True
        if "couldn't get a connection" in str(current):
            return True
        current = current.__cause__
    return False


def register_error_handlers(app: Flask) -> None:
    """Attach handlers that produce RFC 7807 responses for all errors."""

    @app.errorhandler(AcmeProblem)
    def _handle_acme_problem(exc: AcmeProblem):
        return exc.to_response()

    @app.errorhandler(HTTPException)
    def _handle_http_exception(exc: HTTPException):
        problem = AcmeProblem(
            "about:blank",
            exc.description or "An error occurred",
            exc.code or 500,
            title=exc.name,
        )
        return problem.to_response()

    @app.errorhandler(Exception)
    def _handle_unhandled(exc: Exception):
        # Pool timeout → 503 (not 500) so clients retry instead of
        # treating it as a permanent failure.  Logged as WARNING
        # (not ERROR) since it's an expected condition under load.
        if _is_pool_timeout(exc):
            log.warning("Pool timeout during request: %s", exc)
            problem = AcmeProblem(
                SERVER_INTERNAL,
                "Server is temporarily overloaded. Please retry.",
                503,
                headers={"Retry-After": "5"},
            )
            return problem.to_response()

        # HTTPException subclasses are already caught above; this
        # handler covers everything else (genuine 500s).
        log.exception("Unhandled exception during request")
        problem = AcmeProblem(
            SERVER_INTERNAL,
            "An unexpected internal error occurred",
            500,
        )
        return problem.to_response()
