"""Admin API Flask blueprint."""

from __future__ import annotations

import json as _json
import logging
import re as _re
import unicodedata as _unicodedata
from datetime import datetime as _datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID as _UUID

from flask import Blueprint, Response, current_app, g, jsonify, request

from acmeeh.admin.auth import (
    get_login_limiter,
    get_token_blacklist,
    require_admin_auth,
    require_role,
)
from acmeeh.admin.pagination import (
    build_link_header,
    decode_cursor,
    encode_cursor,
)
from acmeeh.admin.serializers import (
    serialize_admin_user,
    serialize_allowed_identifier,
    serialize_audit_log,
    serialize_certificate,
    serialize_csr_profile,
    serialize_eab_credential,
    serialize_login_response,
    serialize_notification,
)
from acmeeh.app.context import get_container
from acmeeh.app.errors import AcmeProblem
from acmeeh.core.types import AdminRole, RevocationReason
from acmeeh.logging import security_events

if TYPE_CHECKING:
    from collections.abc import Iterator
    from uuid import UUID

    from flask.typing import ResponseReturnValue

    from acmeeh.admin.service import AdminUserService

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

_USERNAME_BAD_RE = _re.compile(r"[\s\x00-\x1f\x7f]")
_EMAIL_RE = _re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _require_str(data: dict, field: str, *, max_length: int = 0) -> str:
    """Validate that a field is a string, optionally with max length."""
    val = data.get(field, "")
    if not isinstance(val, str):
        raise AcmeProblem("about:blank", f"'{field}' must be a string", status=400)
    if "\x00" in val:
        raise AcmeProblem(
            "about:blank", f"'{field}' contains invalid characters", status=400
        )
    if max_length and len(val) > max_length:
        raise AcmeProblem(
            "about:blank",
            f"'{field}' must not exceed {max_length} characters",
            status=400,
        )
    return val


def _require_strict_bool(data: dict, field: str) -> bool:
    """Validate that a field is strictly a boolean (not int/str)."""
    val = data[field]
    if not isinstance(val, bool):
        raise AcmeProblem(
            "about:blank", f"'{field}' must be a boolean (true/false)", status=400
        )
    return val


def _validate_username(val: str) -> None:
    """Reject control characters, whitespace, and invisible Unicode."""
    if _USERNAME_BAD_RE.search(val):
        raise AcmeProblem(
            "about:blank",
            "Username must not contain control characters or whitespace",
            status=400,
        )
    for ch in val:
        cat = _unicodedata.category(ch)
        if cat in ("Cf", "Cc", "Cs", "Co"):
            raise AcmeProblem(
                "about:blank",
                "Username must not contain control characters or whitespace",
                status=400,
            )


def _validate_email(val: str) -> None:
    """Basic email validation (must have @ and dot in domain)."""
    if not _EMAIL_RE.match(val):
        raise AcmeProblem("about:blank", "Invalid email address", status=400)


def _parse_iso_datetime(val: str, field: str) -> _datetime:
    """Parse an ISO 8601 datetime string, raising 400 on failure."""
    try:
        return _datetime.fromisoformat(val)
    except (ValueError, TypeError):
        raise AcmeProblem(  # noqa: B904
            "about:blank",
            f"'{field}' must be a valid ISO 8601 datetime",
            status=400,
        )


def _parse_int_param(name: str) -> int | None:
    """Parse an integer query parameter, raising 400 on non-integer."""
    raw = request.args.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except (ValueError, TypeError):
        raise AcmeProblem(  # noqa: B904
            "about:blank", f"'{name}' must be an integer", status=400
        )


def _validate_pagination_params(page_settings: Any) -> tuple[int, int]:
    """Parse and validate limit/offset from query string."""
    limit = _parse_int_param("limit")
    offset = _parse_int_param("offset")
    if limit is None:
        limit = page_settings.default_page_size
    if offset is None:
        offset = 0
    if limit < 1:
        raise AcmeProblem(
            "about:blank", "'limit' must be at least 1", status=400
        )
    if limit > page_settings.max_page_size:
        raise AcmeProblem(
            "about:blank",
            f"'limit' must not exceed {page_settings.max_page_size}",
            status=400,
        )
    if offset < 0:
        raise AcmeProblem(
            "about:blank", "'offset' must not be negative", status=400
        )
    return limit, offset

admin_bp = Blueprint("admin_api", __name__)


@admin_bp.before_request
def _require_json_object() -> None:
    """Reject non-dict JSON bodies on mutating requests."""
    if request.method in ("POST", "PATCH", "PUT"):
        ct = request.content_type or ""
        if "json" in ct:
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                raise AcmeProblem(
                    "about:blank",
                    "Request body must be a JSON object",
                    status=400,
                )


def _get_admin_service() -> AdminUserService:
    """Return the admin service, raising 503 if admin is not enabled."""
    svc = get_container().admin_service
    if svc is None:
        raise AcmeProblem(
            "about:blank",
            "Admin API is not enabled",
            status=503,
        )
    return svc


@admin_bp.route("/auth/login", methods=["POST"])
def login() -> ResponseReturnValue:
    """Authenticate and return a bearer token."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    username = _require_str(data, "username", max_length=128)
    password = _require_str(data, "password", max_length=1000)
    if not username or not password:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Both 'username' and 'password' are required",
            status=400,
        )
    _validate_username(username)

    limiter = get_login_limiter()
    rate_key = f"{request.remote_addr}:{username}"
    limiter.check(rate_key)

    container = get_container()
    try:
        user, token = _get_admin_service().authenticate(
            username,
            password,
            ip_address=request.remote_addr,
        )
    except AcmeProblem:
        limiter.record_failure(rate_key)
        raise
    limiter.record_success(rate_key)
    return jsonify(serialize_login_response(user, token))


@admin_bp.route("/auth/logout", methods=["POST"])
@require_admin_auth
def logout() -> ResponseReturnValue:
    """Revoke the current bearer token."""
    token = request.headers.get("Authorization", "")[7:]
    get_token_blacklist().revoke_token(token)
    return jsonify({"status": "logged_out"}), 200


@admin_bp.route("/users", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def list_users() -> ResponseReturnValue:
    """List all admin users."""
    container = get_container()
    users = _get_admin_service().list_users()
    return jsonify([serialize_admin_user(u) for u in users])


@admin_bp.route("/users", methods=["POST"])
@require_admin_auth
@require_role("admin")
def create_user() -> ResponseReturnValue:
    """Create a new admin user."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    username = _require_str(data, "username", max_length=128)
    email = _require_str(data, "email", max_length=512)
    role_str = _require_str(data, "role") if "role" in data else "auditor"

    if not username or not email:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Both 'username' and 'email' are required",
            status=400,
        )
    _validate_username(username)
    _validate_email(email)

    try:
        role = AdminRole(role_str)
    except ValueError:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            f"Invalid role '{role_str}'. Must be 'admin' or 'auditor'",
            status=400,
        ) from None

    container = get_container()
    user, password = _get_admin_service().create_user(
        username,
        email,
        role,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )

    resp = serialize_admin_user(user)
    resp["password"] = password
    return jsonify(resp), 201


@admin_bp.route("/users/<uuid:user_id>", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def get_user(user_id: UUID) -> ResponseReturnValue:
    """Get a specific admin user."""
    container = get_container()
    user = _get_admin_service().get_user(user_id)
    return jsonify(serialize_admin_user(user))


@admin_bp.route("/users/<uuid:user_id>", methods=["PATCH"])
@require_admin_auth
@require_role("admin")
def update_user(user_id: UUID) -> ResponseReturnValue:
    """Update an admin user (enable/disable, role change)."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    kwargs: dict[str, Any] = {}
    if "enabled" in data:
        kwargs["enabled"] = _require_strict_bool(data, "enabled")
    if "role" in data:
        try:
            kwargs["role"] = AdminRole(data["role"])
        except ValueError:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                f"Invalid role '{data['role']}'. Must be 'admin' or 'auditor'",
                status=400,
            ) from None

    container = get_container()
    user = _get_admin_service().update_user(
        user_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
        **kwargs,
    )
    return jsonify(serialize_admin_user(user))


@admin_bp.route("/users/<uuid:user_id>", methods=["DELETE"])
@require_admin_auth
@require_role("admin")
def delete_user(user_id: UUID) -> ResponseReturnValue:
    """Delete an admin user."""
    container = get_container()
    _get_admin_service().delete_user(
        user_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route("/me", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def get_me() -> ResponseReturnValue:
    """Get the current user's profile."""
    return jsonify(serialize_admin_user(g.admin_user))


@admin_bp.route("/me/reset-password", methods=["POST"])
@require_admin_auth
@require_role("admin", "auditor")
def reset_own_password() -> ResponseReturnValue:
    """Reset the current user's password."""
    container = get_container()
    user, password = _get_admin_service().reset_password(
        g.admin_user.id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    resp = serialize_admin_user(user)
    resp["password"] = password
    return jsonify(resp)


@admin_bp.route("/audit-log", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def get_audit_log() -> ResponseReturnValue:
    """View the admin audit log with optional filters.

    Supports cursor-based pagination via ``?cursor=...&limit=...``.
    Falls back to offset-based for backward compatibility.
    """
    container = get_container()
    page_settings = container.settings.admin_api

    # Validate limit
    limit_raw = _parse_int_param("limit")
    if limit_raw is not None:
        if limit_raw < 1:
            raise AcmeProblem("about:blank", "'limit' must be at least 1", status=400)
        if limit_raw > page_settings.max_page_size:
            raise AcmeProblem(
                "about:blank",
                f"'limit' must not exceed {page_settings.max_page_size}",
                status=400,
            )
        limit = limit_raw
    else:
        limit = page_settings.default_page_size

    filters = {}
    for key in ("action",):
        val = request.args.get(key)
        if val:
            filters[key] = val

    # Validate user_id as UUID
    user_id_raw = request.args.get("user_id")
    if user_id_raw:
        try:
            _UUID(user_id_raw)
        except ValueError:
            raise AcmeProblem(  # noqa: B904
                "about:blank", "'user_id' must be a valid UUID", status=400
            )
        filters["user_id"] = user_id_raw

    # Validate since/until as ISO 8601
    for dt_key in ("since", "until"):
        dt_val = request.args.get(dt_key)
        if dt_val:
            _parse_iso_datetime(dt_val, dt_key)
            filters[dt_key] = dt_val

    cursor_param = request.args.get("cursor")
    cursor_id = None
    if cursor_param:
        try:
            cursor_id = decode_cursor(cursor_param)
        except ValueError:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Invalid cursor parameter",
                status=400,
            ) from None

    if filters:
        entries = _get_admin_service().search_audit_log(
            filters,
            limit + 1,
        )
    else:
        entries = _get_admin_service().get_audit_log(limit + 1)

    # Apply cursor filter (repos don't natively support cursor)
    if cursor_id is not None:
        entries = [e for e in entries if e.id < cursor_id]

    has_next = len(entries) > limit
    entries = entries[:limit]

    data = [serialize_audit_log(e) for e in entries]
    response = jsonify(data)

    if has_next and entries:
        next_cursor = encode_cursor(entries[-1].id)
        link = build_link_header(
            request.base_url,
            next_cursor,
            limit,
        )
        if link:
            response.headers["Link"] = link
    return response


# -------------------------------------------------------------------
# EAB credential management
# -------------------------------------------------------------------


@admin_bp.route("/eab", methods=["GET"])
@require_admin_auth
@require_role("admin")
def list_eab() -> ResponseReturnValue:
    """List all EAB credentials."""
    container = get_container()
    creds = _get_admin_service().list_eab()
    return jsonify([serialize_eab_credential(c) for c in creds])


@admin_bp.route("/eab", methods=["POST"])
@require_admin_auth
@require_role("admin")
def create_eab() -> ResponseReturnValue:
    """Create an EAB credential.

    Kid is provided, HMAC key is generated.
    """
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    kid = _require_str(data, "kid", max_length=255)
    if not kid:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'kid' is required",
            status=400,
        )

    label = _require_str(data, "label") if "label" in data else ""

    container = get_container()
    cred = _get_admin_service().create_eab(
        kid,
        label=label,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )

    return jsonify(
        serialize_eab_credential(cred, include_hmac=True),
    ), 201


@admin_bp.route("/eab/<uuid:cred_id>", methods=["GET"])
@require_admin_auth
@require_role("admin")
def get_eab(cred_id: UUID) -> ResponseReturnValue:
    """Get a specific EAB credential."""
    container = get_container()
    cred = _get_admin_service().get_eab(cred_id)
    return jsonify(serialize_eab_credential(cred))


@admin_bp.route("/eab/<uuid:cred_id>/revoke", methods=["POST"])
@require_admin_auth
@require_role("admin")
def revoke_eab(cred_id: UUID) -> ResponseReturnValue:
    """Revoke an EAB credential."""
    container = get_container()
    cred = _get_admin_service().revoke_eab(
        cred_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return jsonify(serialize_eab_credential(cred))


# -------------------------------------------------------------------
# EAB ↔ Allowed Identifier linkage
# -------------------------------------------------------------------


@admin_bp.route(
    "/eab/<uuid:cred_id>/allowed-identifiers",
    methods=["GET"],
)
@require_admin_auth
@require_role("admin")
def list_eab_identifiers(
    cred_id: UUID,
) -> ResponseReturnValue:
    """List allowed identifiers linked to an EAB credential."""
    idents = _get_admin_service().list_eab_identifiers(cred_id)
    return jsonify([serialize_allowed_identifier(i) for i in idents])


@admin_bp.route(
    "/eab/<uuid:cred_id>/allowed-identifiers/<uuid:identifier_id>",
    methods=["PUT"],
)
@require_admin_auth
@require_role("admin")
def add_eab_identifier(
    cred_id: UUID,
    identifier_id: UUID,
) -> ResponseReturnValue:
    """Associate an allowed identifier with an EAB credential."""
    _get_admin_service().add_eab_identifier(
        cred_id,
        identifier_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/eab/<uuid:cred_id>/allowed-identifiers/<uuid:identifier_id>",
    methods=["DELETE"],
)
@require_admin_auth
@require_role("admin")
def remove_eab_identifier(
    cred_id: UUID,
    identifier_id: UUID,
) -> ResponseReturnValue:
    """Remove an identifier association from an EAB credential."""
    _get_admin_service().remove_eab_identifier(
        cred_id,
        identifier_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


# -------------------------------------------------------------------
# EAB ↔ CSR Profile linkage
# -------------------------------------------------------------------


@admin_bp.route(
    "/eab/<uuid:cred_id>/csr-profile/<uuid:profile_id>",
    methods=["PUT"],
)
@require_admin_auth
@require_role("admin")
def assign_eab_csr_profile(
    cred_id: UUID,
    profile_id: UUID,
) -> ResponseReturnValue:
    """Assign a CSR profile to an EAB credential."""
    _get_admin_service().assign_eab_csr_profile(
        cred_id,
        profile_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/eab/<uuid:cred_id>/csr-profile/<uuid:profile_id>",
    methods=["DELETE"],
)
@require_admin_auth
@require_role("admin")
def unassign_eab_csr_profile(
    cred_id: UUID,
    profile_id: UUID,
) -> ResponseReturnValue:
    """Remove the CSR profile assignment from an EAB credential."""
    _get_admin_service().unassign_eab_csr_profile(
        cred_id,
        profile_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/eab/<uuid:cred_id>/csr-profile",
    methods=["GET"],
)
@require_admin_auth
@require_role("admin")
def get_eab_csr_profile(
    cred_id: UUID,
) -> ResponseReturnValue:
    """Get the CSR profile assigned to an EAB credential."""
    profile = _get_admin_service().get_eab_csr_profile(cred_id)
    if profile is None:
        return jsonify(None)
    return jsonify(serialize_csr_profile(profile))


# -------------------------------------------------------------------
# Allowed identifier management
# -------------------------------------------------------------------


@admin_bp.route("/allowed-identifiers", methods=["GET"])
@require_admin_auth
@require_role("admin")
def list_allowed_identifiers() -> ResponseReturnValue:
    """List all allowed identifiers with associated accounts."""
    container = get_container()
    items = _get_admin_service().list_allowed_identifiers()
    return jsonify([serialize_allowed_identifier(ident, acct_ids) for ident, acct_ids in items])


@admin_bp.route("/allowed-identifiers", methods=["POST"])
@require_admin_auth
@require_role("admin")
def create_allowed_identifier() -> ResponseReturnValue:
    """Create a new allowed identifier."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    id_type = _require_str(data, "type")
    id_value = _require_str(data, "value")
    if not id_type or not id_value:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Both 'type' and 'value' are required",
            status=400,
        )

    container = get_container()
    ident = _get_admin_service().create_allowed_identifier(
        id_type,
        id_value,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return jsonify(serialize_allowed_identifier(ident)), 201


@admin_bp.route(
    "/allowed-identifiers/<uuid:identifier_id>",
    methods=["GET"],
)
@require_admin_auth
@require_role("admin")
def get_allowed_identifier(
    identifier_id: UUID,
) -> ResponseReturnValue:
    """Get an allowed identifier with its associated accounts."""
    container = get_container()
    ident, acct_ids = _get_admin_service().get_allowed_identifier(identifier_id)
    return jsonify(serialize_allowed_identifier(ident, acct_ids))


@admin_bp.route(
    "/allowed-identifiers/<uuid:identifier_id>",
    methods=["DELETE"],
)
@require_admin_auth
@require_role("admin")
def delete_allowed_identifier(
    identifier_id: UUID,
) -> ResponseReturnValue:
    """Delete an allowed identifier (cascades associations)."""
    container = get_container()
    _get_admin_service().delete_allowed_identifier(
        identifier_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/allowed-identifiers/<uuid:identifier_id>/accounts/<uuid:account_id>",
    methods=["PUT"],
)
@require_admin_auth
@require_role("admin")
def add_identifier_account(
    identifier_id: UUID,
    account_id: UUID,
) -> ResponseReturnValue:
    """Associate an allowed identifier with an ACME account."""
    container = get_container()
    _get_admin_service().add_identifier_account(
        identifier_id,
        account_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/allowed-identifiers/<uuid:identifier_id>/accounts/<uuid:account_id>",
    methods=["DELETE"],
)
@require_admin_auth
@require_role("admin")
def remove_identifier_account(
    identifier_id: UUID,
    account_id: UUID,
) -> ResponseReturnValue:
    """Remove an identifier-account association."""
    container = get_container()
    _get_admin_service().remove_identifier_account(
        identifier_id,
        account_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/accounts/<uuid:account_id>/allowed-identifiers",
    methods=["GET"],
)
@require_admin_auth
@require_role("admin")
def list_account_identifiers(
    account_id: UUID,
) -> ResponseReturnValue:
    """List allowed identifiers for a specific ACME account."""
    container = get_container()
    acct_repo = getattr(container, "accounts", None)
    if acct_repo is not None and acct_repo.find_by_id(account_id) is None:
        raise AcmeProblem(
            "about:blank", "Account not found", status=404
        )
    idents = _get_admin_service().list_account_identifiers(
        account_id,
    )
    return jsonify([serialize_allowed_identifier(i) for i in idents])


# -------------------------------------------------------------------
# CRL management
# -------------------------------------------------------------------


@admin_bp.route("/crl/rebuild", methods=["POST"])
@require_admin_auth
@require_role("admin")
def rebuild_crl() -> ResponseReturnValue:
    """Force a CRL rebuild."""
    container = get_container()
    if container.crl_manager is None:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "CRL is not enabled",
            status=503,
        )
    container.crl_manager.force_rebuild()

    _get_admin_service()._log_action(  # noqa: SLF001
        g.admin_user.id,
        "crl_rebuild",
        ip_address=request.remote_addr,
    )

    return jsonify(container.crl_manager.health_status())


# -------------------------------------------------------------------
# CSR profile management
# -------------------------------------------------------------------


@admin_bp.route("/csr-profiles", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def list_csr_profiles() -> ResponseReturnValue:
    """List all CSR profiles."""
    container = get_container()
    profiles = _get_admin_service().list_csr_profiles()
    return jsonify([serialize_csr_profile(p) for p in profiles])


@admin_bp.route("/csr-profiles", methods=["POST"])
@admin_bp.route("/csr-profile", methods=["POST"])
@require_admin_auth
@require_role("admin")
def create_csr_profile() -> ResponseReturnValue:
    """Create a new CSR profile."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    name = data.get("name", "")
    if not name:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'name' is required",
            status=400,
        )

    profile_data = data.get("profile_data")
    if not isinstance(profile_data, dict):
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'profile_data' must be a JSON object",
            status=400,
        )

    description = _require_str(data, "description", max_length=10000) if "description" in data else ""

    container = get_container()
    profile = _get_admin_service().create_csr_profile(
        name,
        profile_data,
        description=description,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return jsonify(serialize_csr_profile(profile)), 201


@admin_bp.route(
    "/csr-profiles/<uuid:profile_id>/validate",
    methods=["POST"],
)
@require_admin_auth
@require_role("admin", "auditor")
def validate_csr_profile(
    profile_id: UUID,
) -> ResponseReturnValue:
    """Dry-run validate a CSR against a profile without issuing."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    csr_b64 = data.get("csr", "")
    if not csr_b64:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'csr' (base64-DER) is required",
            status=400,
        )

    container = get_container()
    result = _get_admin_service().validate_csr(
        profile_id,
        csr_b64,
    )
    return jsonify(result)


@admin_bp.route(
    "/csr-profiles/<uuid:profile_id>",
    methods=["GET"],
)
@require_admin_auth
@require_role("admin", "auditor")
def get_csr_profile(
    profile_id: UUID,
) -> ResponseReturnValue:
    """Get a specific CSR profile with associated accounts."""
    container = get_container()
    profile, account_ids = _get_admin_service().get_csr_profile(profile_id)
    return jsonify(serialize_csr_profile(profile, account_ids))


@admin_bp.route(
    "/csr-profiles/<uuid:profile_id>",
    methods=["PUT"],
)
@admin_bp.route(
    "/csr-profile/<uuid:profile_id>",
    methods=["PUT"],
)
@require_admin_auth
@require_role("admin")
def update_csr_profile(
    profile_id: UUID,
) -> ResponseReturnValue:
    """Update a CSR profile (full replacement)."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    name = data.get("name", "")
    if not name:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'name' is required",
            status=400,
        )

    profile_data = data.get("profile_data")
    if not isinstance(profile_data, dict):
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'profile_data' must be a JSON object",
            status=400,
        )

    description = data.get("description", "")

    container = get_container()
    profile = _get_admin_service().update_csr_profile(
        profile_id,
        name,
        profile_data,
        description=description,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return jsonify(serialize_csr_profile(profile))


@admin_bp.route(
    "/csr-profiles/<uuid:profile_id>",
    methods=["DELETE"],
)
@require_admin_auth
@require_role("admin")
def delete_csr_profile(
    profile_id: UUID,
) -> ResponseReturnValue:
    """Delete a CSR profile."""
    container = get_container()
    _get_admin_service().delete_csr_profile(
        profile_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/csr-profiles/<uuid:profile_id>/accounts/<uuid:account_id>",
    methods=["PUT"],
)
@require_admin_auth
@require_role("admin")
def assign_profile_account(
    profile_id: UUID,
    account_id: UUID,
) -> ResponseReturnValue:
    """Assign a CSR profile to an ACME account."""
    container = get_container()
    _get_admin_service().assign_profile_to_account(
        profile_id,
        account_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/csr-profiles/<uuid:profile_id>/accounts/<uuid:account_id>",
    methods=["DELETE"],
)
@require_admin_auth
@require_role("admin")
def unassign_profile_account(
    profile_id: UUID,
    account_id: UUID,
) -> ResponseReturnValue:
    """Remove a CSR profile assignment from an account."""
    container = get_container()
    _get_admin_service().unassign_profile_from_account(
        profile_id,
        account_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/accounts/<uuid:account_id>/csr-profile",
    methods=["GET"],
)
@require_admin_auth
@require_role("admin", "auditor")
def get_account_csr_profile(
    account_id: UUID,
) -> ResponseReturnValue:
    """Get the CSR profile assigned to an ACME account."""
    container = get_container()
    acct_repo = getattr(container, "accounts", None)
    if acct_repo is not None and acct_repo.find_by_id(account_id) is None:
        raise AcmeProblem(
            "about:blank", "Account not found", status=404
        )
    profile = _get_admin_service().get_account_csr_profile(
        account_id,
    )
    if profile is None:
        return jsonify(None)
    return jsonify(serialize_csr_profile(profile))


# -------------------------------------------------------------------
# Notification management
# -------------------------------------------------------------------


@admin_bp.route("/notifications", methods=["GET"])
@require_admin_auth
@require_role("admin")
def list_notifications() -> ResponseReturnValue:
    """List notifications with optional filters and pagination."""
    container = get_container()
    page_settings = container.settings.admin_api

    status = request.args.get("status")
    valid_statuses = ("pending", "sent", "failed")
    if status is not None and status not in valid_statuses:
        raise AcmeProblem(
            "about:blank",
            f"Invalid status '{status}'. Must be one of: {', '.join(valid_statuses)}",
            status=400,
        )

    limit, offset = _validate_pagination_params(page_settings)
    notifications = _get_admin_service().list_notifications(
        status,
        limit + 1,
        offset,
    )

    has_next = len(notifications) > limit
    notifications = notifications[:limit]

    data = [serialize_notification(n) for n in notifications]
    response = jsonify(data)

    if has_next and notifications:
        next_cursor = encode_cursor(notifications[-1].id)
        link = build_link_header(
            request.base_url,
            next_cursor,
            limit,
        )
        if link:
            response.headers["Link"] = link
    return response


@admin_bp.route("/notifications/retry", methods=["POST"])
@require_admin_auth
@require_role("admin")
def retry_notifications() -> ResponseReturnValue:
    """Retry failed notifications."""
    container = get_container()
    count = _get_admin_service().retry_failed_notifications()

    _get_admin_service()._log_action(  # noqa: SLF001
        g.admin_user.id,
        "retry_notifications",
        details={"count": count},
        ip_address=request.remote_addr,
    )

    return jsonify({"retried": count})


@admin_bp.route("/notifications/purge", methods=["POST"])
@require_admin_auth
@require_role("admin")
def purge_notifications() -> ResponseReturnValue:
    """Purge old sent notifications."""
    data = request.get_json(silent=True) or {}
    days = data.get("days", 30)
    if not isinstance(days, int) or days < 1:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'days' must be a positive integer",
            status=400,
        )

    container = get_container()
    count = _get_admin_service().purge_notifications(days)

    _get_admin_service()._log_action(  # noqa: SLF001
        g.admin_user.id,
        "purge_notifications",
        details={"days": days, "count": count},
        ip_address=request.remote_addr,
    )

    return jsonify({"purged": count})


# -------------------------------------------------------------------
# Certificate search & inventory
# -------------------------------------------------------------------


@admin_bp.route("/certificates", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def search_certificates() -> ResponseReturnValue:
    """Search certificates with filters and pagination."""
    container = get_container()
    page_settings = container.settings.admin_api
    filters = {}
    for key in (
        "account_id",
        "serial",
        "fingerprint",
        "domain",
    ):
        val = request.args.get(key)
        if val:
            filters[key] = val

    # Validate status
    cert_status = request.args.get("status")
    valid_cert_statuses = ("active", "revoked", "expired")
    if cert_status is not None and cert_status not in valid_cert_statuses:
        raise AcmeProblem(
            "about:blank",
            f"Invalid status '{cert_status}'. Must be one of: {', '.join(valid_cert_statuses)}",
            status=400,
        )
    if cert_status:
        filters["status"] = cert_status

    # Validate expiring_before as ISO 8601
    expiring_before = request.args.get("expiring_before")
    if expiring_before:
        _parse_iso_datetime(expiring_before, "expiring_before")
        filters["expiring_before"] = expiring_before

    limit, offset = _validate_pagination_params(page_settings)

    certs = _get_admin_service().search_certificates(
        filters,
        limit + 1,
        offset,
    )

    has_next = len(certs) > limit
    certs = certs[:limit]

    data = [serialize_certificate(c) for c in certs]
    response = jsonify(data)

    if has_next and certs:
        next_cursor = encode_cursor(certs[-1].id)
        link = build_link_header(
            request.base_url,
            next_cursor,
            limit,
        )
        if link:
            response.headers["Link"] = link
    return response


@admin_bp.route("/certificates/<serial>", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def get_certificate_by_serial(
    serial: str,
) -> ResponseReturnValue:
    """Get a certificate by serial number."""
    container = get_container()
    cert = _get_admin_service().get_certificate_by_serial(
        serial,
    )
    return jsonify(serialize_certificate(cert))


@admin_bp.route(
    "/certificates/by-fingerprint/<fingerprint>",
    methods=["GET"],
)
@require_admin_auth
@require_role("admin", "auditor")
def get_certificate_by_fingerprint(
    fingerprint: str,
) -> ResponseReturnValue:
    """Get a certificate by its SHA-256 fingerprint (hex)."""
    container = get_container()
    cert = container.certificates.find_by_fingerprint(
        fingerprint,
    )
    if cert is None:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            f"Certificate with fingerprint '{fingerprint}' not found",
            status=404,
        )
    return jsonify(serialize_certificate(cert))


# -------------------------------------------------------------------
# Audit log export & enhanced search
# -------------------------------------------------------------------


@admin_bp.route("/audit-log/export", methods=["POST"])
@require_admin_auth
@require_role("admin")
def export_audit_log() -> ResponseReturnValue:
    """Export audit log as NDJSON."""
    data = request.get_json(silent=True) or {}
    filters = {}
    for key in ("action", "user_id", "since", "until"):
        if key in data:
            filters[key] = data[key]

    container = get_container()
    export_limit = container.settings.admin_api.max_page_size * 10
    entries = _get_admin_service().search_audit_log(
        filters,
        limit=export_limit,
    )

    def generate() -> Iterator[str]:
        for entry in entries:
            yield (_json.dumps(serialize_audit_log(entry)) + "\n")

    _get_admin_service()._log_action(  # noqa: SLF001
        g.admin_user.id,
        "export_audit_log",
        details={
            "filters": filters,
            "count": len(entries),
        },
        ip_address=request.remote_addr,
    )

    return Response(
        generate(),
        mimetype="application/x-ndjson",
    )


# -------------------------------------------------------------------
# Maintenance mode
# -------------------------------------------------------------------


@admin_bp.route("/maintenance", methods=["GET"])
@require_admin_auth
@require_role("admin")
def get_maintenance_status() -> ResponseReturnValue:
    """Get current maintenance mode status."""
    shutdown_coord = current_app.extensions.get(
        "shutdown_coordinator",
    )
    enabled = shutdown_coord.maintenance_mode if shutdown_coord else False
    return jsonify({"maintenance_mode": enabled})


@admin_bp.route("/maintenance", methods=["POST"])
@require_admin_auth
@require_role("admin")
def set_maintenance_mode() -> ResponseReturnValue:
    """Enable or disable maintenance mode.

    Body: ``{"enabled": true}`` or ``{"enabled": false}``.
    """
    data = request.get_json(silent=True)
    if not data or "enabled" not in data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must include 'enabled' (boolean)",
            status=400,
        )

    enabled = _require_strict_bool(data, "enabled")
    shutdown_coord = current_app.extensions.get(
        "shutdown_coordinator",
    )
    if shutdown_coord is None:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Shutdown coordinator not available",
            status=500,
        )

    shutdown_coord.set_maintenance(enabled)
    security_events.maintenance_mode_changed(
        enabled,
        g.admin_user.username,
    )

    container = get_container()
    _get_admin_service()._log_action(  # noqa: SLF001
        g.admin_user.id,
        "maintenance_mode",
        details={"enabled": enabled},
        ip_address=request.remote_addr,
    )

    return jsonify({"maintenance_mode": enabled})


# -------------------------------------------------------------------
# Bulk certificate revocation
# -------------------------------------------------------------------


@admin_bp.route(
    "/certificates/bulk-revoke",
    methods=["POST"],
)
@require_admin_auth
@require_role("admin")
def bulk_revoke_certificates() -> ResponseReturnValue:  # noqa: C901
    """Revoke multiple certificates matching a filter.

    Body::

        {
            "filter": {
                "account_id": "...",
                "serial_numbers": [...],
                "domain": "...",
                "issued_before": "...",
                "issued_after": "...",
            },
            "reason": 4,
            "dry_run": false
        }
    """
    data = request.get_json(silent=True)
    if not data or "filter" not in data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must include 'filter' object",
            status=400,
        )

    filt = data["filter"]
    if not isinstance(filt, dict):
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'filter' must be a JSON object",
            status=400,
        )
    reason_code = data.get("reason")
    dry_run = data.get("dry_run", False)

    rev_reason = None
    if reason_code is not None:
        try:
            rev_reason = RevocationReason(reason_code)
        except ValueError:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                f"Invalid revocation reason code: {reason_code}",
                status=400,
            ) from None

    container = get_container()
    cert_repo = container.certificates

    # Build query filters for certificate search
    search_filters: dict[str, Any] = {}
    if "account_id" in filt:
        search_filters["account_id"] = filt["account_id"]
    if "domain" in filt:
        search_filters["domain"] = filt["domain"]
    if "issued_before" in filt:
        search_filters["expiring_before"] = filt["issued_before"]

    # Normalize serial_number (singular string) → serial_numbers (list)
    serial_numbers = filt.get("serial_numbers")
    if serial_numbers is None and "serial_number" in filt:
        serial_numbers = [filt["serial_number"]]
    if serial_numbers:
        search_filters["serial_numbers"] = serial_numbers

    # Default to active (non-revoked, non-expired) certificates
    search_filters["status"] = "active"

    # Get matching certificates
    certs = _get_admin_service().search_certificates(
        search_filters,
        limit=10000,
        offset=0,
    )

    # Defence-in-depth: filter out already-revoked certificates
    certs = [c for c in certs if getattr(c, "revoked_at", None) is None]

    if dry_run:
        return jsonify(
            {
                "dry_run": True,
                "matching_certificates": len(certs),
                "serial_numbers": [c.serial_number for c in certs[:100]],
            }
        )

    # Perform revocation
    revoked_count = 0
    errors = []
    for cert in certs:
        try:
            result = cert_repo.revoke(cert.id, rev_reason)
            if result is not None:
                revoked_count += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(
                {
                    "serial_number": cert.serial_number,
                    "error": str(exc),
                }
            )

    filter_desc = ", ".join(f"{k}={v}" for k, v in filt.items())
    reason_name = rev_reason.name if rev_reason else "unspecified"
    security_events.bulk_revocation(
        g.admin_user.username,
        revoked_count,
        reason=reason_name,
        filter_desc=filter_desc,
    )

    _get_admin_service()._log_action(  # noqa: SLF001
        g.admin_user.id,
        "bulk_revoke",
        details={
            "filter": filt,
            "reason": reason_name,
            "revoked": revoked_count,
            "errors": len(errors),
        },
        ip_address=request.remote_addr,
    )

    return jsonify(
        {
            "revoked": revoked_count,
            "errors": errors[:50] if errors else [],
            "total_matched": len(certs),
        }
    )
