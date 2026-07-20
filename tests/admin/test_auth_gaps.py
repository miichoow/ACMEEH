"""Tests for admin auth functions and decorators that were previously untested.

Covers: LoginRateLimiter, require_admin_auth, require_role, get_login_limiter.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from flask import Flask, g, jsonify

from acmeeh.admin.auth import (
    LoginRateLimiter,
    create_token,
    get_login_limiter,
    get_token_blacklist,
    require_admin_auth,
    require_role,
)
from acmeeh.admin.models import AdminUser
from acmeeh.app.errors import AcmeProblem, register_error_handlers
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import AdminRole

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeSettings:
    def __init__(self, admin_api: AdminApiSettings) -> None:
        self.admin_api = admin_api


class _FakeContainer:
    def __init__(
        self,
        settings: _FakeSettings,
        user_repo: MagicMock,
    ) -> None:
        self.settings = settings
        self.admin_user_repo = user_repo


def _make_admin_user(
    *,
    enabled: bool = True,
    role: AdminRole = AdminRole.ADMIN,
    user_id=None,
) -> AdminUser:
    uid = user_id or uuid4()
    return AdminUser(
        id=uid,
        username="testadmin",
        email="testadmin@example.com",
        password_hash="fakehash",
        role=role,
        enabled=enabled,
    )


def _make_admin_api_settings(
    *,
    token_secret: str = "test-secret-for-auth-gaps",
    token_expiry_seconds: int = 3600,
) -> AdminApiSettings:
    return AdminApiSettings(
        enabled=True,
        base_path="/api",
        token_secret=token_secret,
        token_expiry_seconds=token_expiry_seconds,
        initial_admin_email="admin@example.com",
        password_length=20,
        default_page_size=50,
        max_page_size=200,
    )


def _build_test_app(
    admin_api_settings: AdminApiSettings,
    user_repo: MagicMock,
) -> Flask:
    """Create a minimal Flask app with routes protected by the decorators."""
    app = Flask(__name__)
    app.config["TESTING"] = True

    register_error_handlers(app)

    container = _FakeContainer(
        settings=_FakeSettings(admin_api_settings),
        user_repo=user_repo,
    )
    app.extensions["container"] = container

    @app.route("/protected")
    @require_admin_auth
    def protected_route():
        return jsonify({"user": str(g.admin_user.id)}), 200

    @app.route("/admin-only")
    @require_admin_auth
    @require_role("admin")
    def admin_only_route():
        return jsonify({"ok": True}), 200

    @app.route("/auditor-or-admin")
    @require_admin_auth
    @require_role("auditor", "admin")
    def auditor_or_admin_route():
        return jsonify({"ok": True}), 200

    return app


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOKEN_SECRET = "test-secret-for-auth-gaps"
TOKEN_EXPIRY = 3600


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def admin_api_settings():
    return _make_admin_api_settings()


@pytest.fixture()
def admin_user():
    return _make_admin_user()


@pytest.fixture()
def user_repo(admin_user):
    repo = MagicMock()
    repo.find_by_id.return_value = admin_user
    return repo


@pytest.fixture()
def app(admin_api_settings, user_repo):
    return _build_test_app(admin_api_settings, user_repo)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def valid_token(admin_user):
    return create_token(admin_user, TOKEN_SECRET, TOKEN_EXPIRY)


@pytest.fixture(autouse=True)
def _clear_blacklist():
    """Ensure the token blacklist is clean for every test."""
    yield
    # Clear the in-memory fallback dict directly since there is no .clear()
    bl = get_token_blacklist()
    with bl._lock:
        bl._revoked.clear()


# ===========================================================================
# LoginRateLimiter tests
# ===========================================================================


class TestLoginRateLimiter:
    """Tests for LoginRateLimiter.check, record_failure, record_success."""

    def test_check_not_locked_out(self):
        """check() should not raise when the key has no lockout."""
        limiter = LoginRateLimiter(
            max_attempts=3,
            window_seconds=60,
            lockout_seconds=120,
        )
        # Should complete without raising
        limiter.check("user@example.com")

    def test_check_locked_out_raises_429(self):
        """check() should raise AcmeProblem 429 with Retry-After when locked out."""
        limiter = LoginRateLimiter(
            max_attempts=2,
            window_seconds=60,
            lockout_seconds=120,
        )
        limiter.record_failure("user@example.com")
        limiter.record_failure("user@example.com")  # triggers lockout

        with pytest.raises(AcmeProblem) as exc_info:
            limiter.check("user@example.com")

        problem = exc_info.value
        assert problem.status == 429
        assert "Too many failed login attempts" in problem.detail
        assert "Retry-After" in problem.extra_headers

    def test_record_failure_below_threshold_no_lockout(self):
        """Failures below max_attempts should not trigger a lockout."""
        limiter = LoginRateLimiter(
            max_attempts=5,
            window_seconds=60,
            lockout_seconds=120,
        )
        for _ in range(4):
            limiter.record_failure("key1")

        # Should not raise -- still below threshold
        limiter.check("key1")

    def test_record_failure_reaching_threshold_triggers_lockout(self):
        """Hitting max_attempts should trigger lockout."""
        limiter = LoginRateLimiter(
            max_attempts=3,
            window_seconds=60,
            lockout_seconds=120,
        )
        for _ in range(3):
            limiter.record_failure("key2")

        with pytest.raises(AcmeProblem) as exc_info:
            limiter.check("key2")

        assert exc_info.value.status == 429

    def test_record_failure_prunes_old_attempts_outside_window(self):
        """Old attempts outside the window should be pruned and not count."""
        limiter = LoginRateLimiter(
            max_attempts=3,
            window_seconds=10,
            lockout_seconds=120,
        )

        # Record two failures at "now"
        limiter.record_failure("key3")
        limiter.record_failure("key3")

        # Advance time past the window so those two are stale
        future = time.monotonic() + 20
        with patch("time.monotonic", return_value=future):
            # This failure should prune the old two; only 1 recent attempt
            limiter.record_failure("key3")
            # Should NOT be locked out (only 1 recent attempt, threshold is 3)
            limiter.check("key3")

    def test_record_success_clears_attempts_and_lockout(self):
        """record_success should clear both attempts and lockout for the key."""
        limiter = LoginRateLimiter(
            max_attempts=2,
            window_seconds=60,
            lockout_seconds=120,
        )
        limiter.record_failure("key4")
        limiter.record_failure("key4")  # locked out now

        with pytest.raises(AcmeProblem):
            limiter.check("key4")

        # Clear via success
        limiter.record_success("key4")

        # Should no longer be locked out
        limiter.check("key4")

    def test_record_success_no_prior_state(self):
        """record_success on an unknown key should not raise."""
        limiter = LoginRateLimiter()
        limiter.record_success("never-seen-before")

    def test_lockout_retry_after_header_value(self):
        """Retry-After header should reflect remaining lockout seconds."""
        limiter = LoginRateLimiter(
            max_attempts=1,
            window_seconds=60,
            lockout_seconds=500,
        )
        limiter.record_failure("hdr-test")

        with pytest.raises(AcmeProblem) as exc_info:
            limiter.check("hdr-test")

        remaining = int(exc_info.value.extra_headers["Retry-After"])
        # The remaining time should be close to lockout_seconds
        assert 490 <= remaining <= 500


class TestGetLoginLimiter:
    """get_login_limiter() should return the module-level singleton."""

    def test_returns_login_rate_limiter_instance(self):
        limiter = get_login_limiter()
        assert isinstance(limiter, LoginRateLimiter)

    def test_returns_same_instance(self):
        assert get_login_limiter() is get_login_limiter()


# ===========================================================================
# require_admin_auth decorator tests
# ===========================================================================


class TestRequireAdminAuth:
    """Tests for the require_admin_auth decorator via a test Flask app."""

    def test_no_authorization_header(self, client):
        """Missing Authorization header should return 401."""
        resp = client.get("/protected")
        assert resp.status_code == 401
        data = resp.get_json()
        assert "Missing or invalid Authorization header" in data["detail"]

    def test_non_bearer_authorization_header(self, client):
        """Authorization header without 'Bearer ' prefix should return 401."""
        resp = client.get(
            "/protected",
            headers={"Authorization": "Basic abc123"},
        )
        assert resp.status_code == 401
        data = resp.get_json()
        assert "Missing or invalid Authorization header" in data["detail"]

    def test_revoked_token(self, client, valid_token):
        """A revoked token should return 401 with 'Token has been revoked'."""
        get_token_blacklist().revoke_token(valid_token)

        resp = client.get(
            "/protected",
            headers={
                "Authorization": f"Bearer {valid_token}",
            },
        )
        assert resp.status_code == 401
        data = resp.get_json()
        assert "Token has been revoked" in data["detail"]

    def test_invalid_token(self, client):
        """A garbage token should return 401."""
        resp = client.get(
            "/protected",
            headers={
                "Authorization": "Bearer not.a.valid.jwt",
            },
        )
        assert resp.status_code == 401
        data = resp.get_json()
        assert "Invalid or expired token" in data["detail"]

    def test_expired_token(self, client, admin_user):
        """An expired token should return 401."""
        # Use a structurally valid token but mock decode_token to return
        # None, simulating signature expiry without a slow sleep.
        token = create_token(admin_user, TOKEN_SECRET, TOKEN_EXPIRY)
        with patch(
            "acmeeh.admin.auth.decode_token",
            return_value=None,
        ):
            resp = client.get(
                "/protected",
                headers={
                    "Authorization": f"Bearer {token}",
                },
            )
        assert resp.status_code == 401
        data = resp.get_json()
        assert "Invalid or expired token" in data["detail"]

    def test_user_not_found(self, client, valid_token, user_repo):
        """When user_repo returns None, should return 401."""
        user_repo.find_by_id.return_value = None

        resp = client.get(
            "/protected",
            headers={
                "Authorization": f"Bearer {valid_token}",
            },
        )
        assert resp.status_code == 401
        data = resp.get_json()
        assert "Account disabled or not found" in data["detail"]

    def test_user_disabled(self, client, user_repo, admin_user):
        """A disabled user should return 401."""
        disabled_user = _make_admin_user(
            enabled=False,
            user_id=admin_user.id,
        )
        user_repo.find_by_id.return_value = disabled_user
        token = create_token(admin_user, TOKEN_SECRET, TOKEN_EXPIRY)

        resp = client.get(
            "/protected",
            headers={
                "Authorization": f"Bearer {token}",
            },
        )
        assert resp.status_code == 401
        data = resp.get_json()
        assert "Account disabled or not found" in data["detail"]

    def test_valid_token_enabled_user_succeeds(
        self,
        client,
        valid_token,
        admin_user,
    ):
        """A valid token for an enabled user should return 200."""
        resp = client.get(
            "/protected",
            headers={
                "Authorization": f"Bearer {valid_token}",
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["user"] == str(admin_user.id)

    def test_token_issued_before_password_reset_is_rejected(
        self,
        client,
        valid_token,
        user_repo,
        admin_user,
    ):
        """A password reset must invalidate tokens issued before it."""
        # Simulate the DB row after `reset_password` bumped
        # password_changed_at to a point after this token's iat.
        reset_user = _make_admin_user(user_id=admin_user.id)
        reset_user = reset_user.__class__(
            **{
                **reset_user.__dict__,
                "password_changed_at": datetime.now(UTC) + timedelta(seconds=60),
            }
        )
        user_repo.find_by_id.return_value = reset_user

        resp = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert resp.status_code == 401
        data = resp.get_json()
        assert "Token invalidated by password change" in data["detail"]

    def test_token_issued_after_password_reset_succeeds(
        self,
        client,
        user_repo,
        admin_user,
    ):
        """A token created after the reset (with a fresh iat) stays valid."""
        reset_user = _make_admin_user(user_id=admin_user.id)
        reset_user = reset_user.__class__(
            **{
                **reset_user.__dict__,
                "password_changed_at": datetime.now(UTC) - timedelta(seconds=60),
            }
        )
        user_repo.find_by_id.return_value = reset_user
        token = create_token(reset_user, TOKEN_SECRET, TOKEN_EXPIRY)

        resp = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200


# ===========================================================================
# require_role decorator tests
# ===========================================================================


class TestRequireRole:
    """Tests for the require_role decorator via a test Flask app."""

    def test_matching_role_succeeds(self, client, valid_token):
        """An admin user accessing an admin-only route should succeed."""
        resp = client.get(
            "/admin-only",
            headers={
                "Authorization": f"Bearer {valid_token}",
            },
        )
        assert resp.status_code == 200

    def test_non_matching_role_returns_403(
        self,
        app,
        user_repo,
        admin_user,
    ):
        """A user whose role is not in the allowed set should get 403."""
        auditor_user = _make_admin_user(
            role=AdminRole.AUDITOR,
            user_id=admin_user.id,
        )
        user_repo.find_by_id.return_value = auditor_user
        token = create_token(admin_user, TOKEN_SECRET, TOKEN_EXPIRY)

        with app.test_client() as c:
            # /admin-only only accepts "admin", auditor should be rejected
            resp = c.get(
                "/admin-only",
                headers={
                    "Authorization": f"Bearer {token}",
                },
            )
        assert resp.status_code == 403
        data = resp.get_json()
        assert "does not have permission" in data["detail"]

    def test_multiple_allowed_roles(self, app, user_repo, admin_user):
        """A route allowing multiple roles should accept any of them."""
        auditor_user = _make_admin_user(
            role=AdminRole.AUDITOR,
            user_id=admin_user.id,
        )
        user_repo.find_by_id.return_value = auditor_user
        token = create_token(admin_user, TOKEN_SECRET, TOKEN_EXPIRY)

        with app.test_client() as c:
            # /auditor-or-admin accepts "auditor" and "admin"
            resp = c.get(
                "/auditor-or-admin",
                headers={
                    "Authorization": f"Bearer {token}",
                },
            )
        assert resp.status_code == 200

    def test_role_mismatch_message_includes_role_name(
        self,
        app,
        user_repo,
        admin_user,
    ):
        """The 403 error message should mention the user's role."""
        auditor_user = _make_admin_user(
            role=AdminRole.AUDITOR,
            user_id=admin_user.id,
        )
        user_repo.find_by_id.return_value = auditor_user
        token = create_token(admin_user, TOKEN_SECRET, TOKEN_EXPIRY)

        with app.test_client() as c:
            resp = c.get(
                "/admin-only",
                headers={
                    "Authorization": f"Bearer {token}",
                },
            )
        data = resp.get_json()
        assert "auditor" in data["detail"].lower()
