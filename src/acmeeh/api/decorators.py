"""Request pipeline decorators for ACME API routes.

Provides:
- ``add_acme_headers``: after-request hook adding Replay-Nonce, Link, Cache-Control
- ``require_jws``: decorator that parses, validates, and verifies JWS requests

These enforce RFC 8555 §6.2 requirements for all ACME POST endpoints.
"""

from __future__ import annotations

import functools
import logging
from uuid import UUID

from flask import g, request

from acmeeh.app.context import get_container
from acmeeh.app.errors import (
    ACCOUNT_DOES_NOT_EXIST,
    BAD_NONCE,
    MALFORMED,
    UNAUTHORIZED,
    AcmeProblem,
)
from acmeeh.core.jws import (
    jwk_to_public_key,
    parse_jws,
    validate_key_policy,
    validate_protected_header,
    verify_signature,
)
from acmeeh.core.types import AccountStatus

log = logging.getLogger(__name__)


# Endpoints that must never waste a DB connection on nonce generation.
# Health probes, directory (static GET), and admin routes are not ACME
# protocol exchanges and don't need Replay-Nonce.
_NONCE_SKIP_ENDPOINTS = frozenset(
    {
        "livez",
        "healthz",
        "readyz",
    }
)

_NONCE_SKIP_PREFIXES = (
    "admin_api.",
    "metrics.",
)


def add_acme_headers(response):
    """After-request hook: add standard ACME headers to every response.

    - ``Replay-Nonce``: a fresh nonce for the next request
    - ``Link``: directory URL with rel="index"
    - ``Cache-Control: no-store``

    Skips health probes, admin API, and error responses to avoid
    wasting pool connections on non-ACME traffic.
    """
    endpoint = request.endpoint or ""

    # Fast path: skip non-ACME endpoints entirely
    if endpoint in _NONCE_SKIP_ENDPOINTS or endpoint.startswith(_NONCE_SKIP_PREFIXES):
        return response

    container = get_container()

    # Skip nonce generation for error responses (4xx/5xx).  Clients
    # that receive an error will request a fresh nonce explicitly via
    # HEAD /new-nonce before retrying — no need to burn a pool
    # connection here.
    if response.status_code >= 400:  # noqa: PLR2004
        response.headers["Link"] = f'<{container.urls.directory}>;rel="index"'
        response.headers["Cache-Control"] = "no-store"
        return response

    # Fresh nonce — uses create_if_healthy() which never blocks
    # waiting for a pool connection.  Returns None when the pool is
    # exhausted, so the response goes out without Replay-Nonce and
    # the client will request one explicitly via HEAD /new-nonce.
    try:
        nonce = container.nonce_service.create_if_healthy()
        if nonce is not None:
            response.headers["Replay-Nonce"] = nonce
    except Exception:
        log.exception("Failed to generate replay nonce")
        from acmeeh.db.init import log_pool_stats  # noqa: PLC0415

        log_pool_stats(container.db, "replay_nonce")

    # Directory link
    response.headers["Link"] = f'<{container.urls.directory}>;rel="index"'

    # Cache control
    response.headers["Cache-Control"] = "no-store"

    return response


def require_jws(
    *,
    use_kid: bool = True,
    allow_kid_or_jwk: bool = False,
):
    """Decorator that enforces JWS authentication on an ACME endpoint.

    Parameters
    ----------
    use_kid:
        If True, the request must use ``kid`` (account URL) for
        authentication.  If False, ``jwk`` is required.
    allow_kid_or_jwk:
        If True, either ``kid`` or ``jwk`` is accepted (used for
        ``revokeCert``).

    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            container = get_container()
            settings = container.settings

            # 1. Content-Type check
            content_type = request.content_type or ""
            if "application/jose+json" not in content_type:
                raise AcmeProblem(
                    MALFORMED,
                    "Content-Type must be application/jose+json",
                    status=415,
                )

            # 2. Parse JWS
            jws = parse_jws(request.get_data())

            # 3. Determine key mode
            require_kid = use_kid and not allow_kid_or_jwk
            require_jwk = not use_kid and not allow_kid_or_jwk

            # 4. Reconstruct request URL (proxy-safe)
            # Use external_url + path (never trust request.url directly)
            base_path = settings.api.base_path.rstrip("/")
            request_url = settings.server.external_url + base_path + request.path

            # 5. Validate protected header
            validate_protected_header(
                jws.protected_header,
                require_nonce=True,
                require_kid=require_kid,
                require_jwk=require_jwk,
                request_url=request_url,
                allowed_algorithms=settings.security.allowed_algorithms,
            )

            # 6. Consume nonce
            if not container.nonce_service.consume(jws.nonce):
                raise AcmeProblem(BAD_NONCE, "Invalid or expired nonce")

            # 7. Key resolution
            account = None
            jwk_dict = None

            if jws.kid:
                # Extract account ID from kid URL
                account_id = _extract_account_id(jws.kid, container.urls)
                acct = container.account_service.find_by_id(account_id)
                if acct.status != AccountStatus.VALID:
                    raise AcmeProblem(
                        UNAUTHORIZED,
                        "Account is deactivated or revoked",
                        status=403,
                    )
                account = acct
                jwk_dict = acct.jwk
                public_key = jwk_to_public_key(jwk_dict)

            elif jws.jwk:
                jwk_dict = jws.jwk
                public_key = jwk_to_public_key(jwk_dict)

            else:
                raise AcmeProblem(
                    MALFORMED,
                    "JWS must contain either 'kid' or 'jwk'",
                )

            # 8. Validate key policy
            validate_key_policy(jwk_dict, settings.security)

            # 9. Verify signature
            verify_signature(jws, public_key)

            # 10. Store on flask.g
            g.jws = jws
            g.account = account
            g.jwk_dict = jwk_dict
            g.payload = jws.payload

            return fn(*args, **kwargs)

        return wrapper

    return decorator


def _extract_account_id(kid_url: str, urls) -> UUID:
    """Extract the account UUID from a kid URL.

    Expected format: ``https://acme.example.com/.../acct/{uuid}``
    """
    # Find the "/acct/" segment and extract the UUID after it
    marker = "/acct/"
    idx = kid_url.rfind(marker)
    if idx == -1:
        raise AcmeProblem(
            ACCOUNT_DOES_NOT_EXIST,
            f"Cannot extract account ID from kid URL: {kid_url}",
        )

    raw_id = kid_url[idx + len(marker) :]
    # Strip any trailing path segments
    if "/" in raw_id:
        raw_id = raw_id.split("/")[0]

    try:
        return UUID(raw_id)
    except ValueError:
        raise AcmeProblem(
            ACCOUNT_DOES_NOT_EXIST,
            f"Invalid account ID in kid URL: {raw_id}",
        )
