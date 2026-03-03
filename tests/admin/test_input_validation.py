"""Tests for admin API input validation and safety hardening."""

from __future__ import annotations

from uuid import uuid4

import pytest
from flask import Flask

from acmeeh.admin.auth import create_token
from acmeeh.admin.models import AdminUser
from acmeeh.admin.routes import admin_bp
from acmeeh.app.errors import AcmeProblem, register_error_handlers
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import AdminRole

# ---------------------------------------------------------------------------
# Stub service (minimal, reused from test_routes)
# ---------------------------------------------------------------------------


class StubAdminUserService:
    """Minimal stub for driving route-level validation tests."""

    def __init__(self):
        self.users = {}
        self._eab_creds = {}
        self._audit_entries = []
        self._csr_profiles = {}
        self._notifications = []

    def add_user(self, **kwargs) -> AdminUser:
        defaults = dict(
            id=uuid4(),
            username="admin",
            email="admin@example.com",
            password_hash="hashed",
            role=AdminRole.ADMIN,
            enabled=True,
        )
        defaults.update(kwargs)
        user = AdminUser(**defaults)
        self.users[user.id] = user
        return user

    def authenticate(self, username, password, ip_address=None):
        for u in self.users.values():
            if u.username == username:
                return u, "stub-token"
        raise AcmeProblem("urn:acmeeh:admin:error:unauthorized", "Bad creds", 401)

    def create_user(
        self, username, email, role=AdminRole.AUDITOR, *, actor_id=None, ip_address=None
    ):
        user = self.add_user(username=username, email=email, role=role)
        return user, "generated-password-123"

    def update_user(self, user_id, *, enabled=None, role=None, actor_id=None, ip_address=None):
        user = self.users.get(user_id)
        if user is None:
            raise AcmeProblem("about:blank", "Not found", 404)
        return user

    def delete_user(self, user_id, *, actor_id=None, ip_address=None):
        if user_id not in self.users:
            raise AcmeProblem("about:blank", "Not found", 404)
        del self.users[user_id]

    def list_users(self):
        return list(self.users.values())

    def get_user(self, user_id):
        user = self.users.get(user_id)
        if user is None:
            raise AcmeProblem("about:blank", "Not found", 404)
        return user

    def reset_password(self, user_id, *, actor_id=None, ip_address=None):
        return self.users[user_id], "new-pw"

    def get_audit_log(self, limit=100):
        return []

    def search_audit_log(self, filters, limit=1000):
        return []

    def create_eab(self, kid, *, label="", actor_id=None, ip_address=None):
        from acmeeh.admin.models import EabCredential

        cred = EabCredential(id=uuid4(), kid=kid, hmac_key="key", label=label)
        self._eab_creds[cred.id] = cred
        return cred

    def list_eab(self):
        return list(self._eab_creds.values())

    def create_allowed_identifier(self, id_type, id_value, *, actor_id=None, ip_address=None):
        from acmeeh.admin.models import AllowedIdentifier

        return AllowedIdentifier(id=uuid4(), identifier_type=id_type, identifier_value=id_value)

    def list_allowed_identifiers(self):
        return []

    def create_csr_profile(
        self, name, profile_data, *, description="", actor_id=None, ip_address=None
    ):
        from acmeeh.admin.models import CsrProfile

        return CsrProfile(id=uuid4(), name=name, profile_data=profile_data, description=description)

    def list_csr_profiles(self):
        return []

    def update_csr_profile(
        self, profile_id, name, profile_data, *, description="", actor_id=None, ip_address=None
    ):
        from acmeeh.admin.models import CsrProfile

        return CsrProfile(
            id=profile_id, name=name, profile_data=profile_data, description=description
        )

    def list_notifications(self, status, limit, offset):
        return []

    def retry_failed_notifications(self):
        return 0

    def purge_notifications(self, days):
        return 0

    def search_certificates(self, filters, limit, offset):
        return []

    def list_account_identifiers(self, account_id):
        return []

    def get_account_csr_profile(self, account_id):
        return None

    def _log_action(self, user_id, action, *, target_user_id=None, details=None, ip_address=None):
        pass


# ---------------------------------------------------------------------------
# Stub container
# ---------------------------------------------------------------------------


class StubAccountRepo:
    """Minimal stub for ACME account existence checks."""

    def __init__(self):
        self._accounts = {}

    def add(self, account_id):
        self._accounts[account_id] = True

    def find_by_id(self, account_id):
        return self._accounts.get(account_id)


class StubContainer:
    def __init__(self, admin_service, settings):
        self.admin_service = admin_service
        self.settings = settings
        self.admin_user_repo = StubUserRepo(admin_service)
        self.crl_manager = None
        self.certificates = None
        self.accounts = StubAccountRepo()


class StubUserRepo:
    def __init__(self, service):
        self._service = service

    def find_by_id(self, user_id):
        return self._service.users.get(user_id)


# ---------------------------------------------------------------------------
# Settings / fixtures
# ---------------------------------------------------------------------------

_TOKEN_SECRET = "test-validation-secret"


def _make_settings() -> AdminApiSettings:
    return AdminApiSettings(
        enabled=True,
        base_path="/api",
        token_secret=_TOKEN_SECRET,
        token_expiry_seconds=3600,
        initial_admin_email="admin@example.com",
        password_length=20,
        default_page_size=50,
        max_page_size=1000,
    )


class _FakeSettings:
    def __init__(self, admin_api):
        self.admin_api = admin_api


@pytest.fixture()
def admin_service():
    return StubAdminUserService()


@pytest.fixture()
def app(admin_service):
    flask_app = Flask("test")
    flask_app.config["TESTING"] = True
    admin_settings = _make_settings()
    full_settings = _FakeSettings(admin_settings)
    container = StubContainer(admin_service, full_settings)
    flask_app.extensions["container"] = container
    register_error_handlers(flask_app)
    flask_app.register_blueprint(admin_bp, url_prefix="/api")
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


def _auth_header(user: AdminUser) -> dict:
    token = create_token(user, _TOKEN_SECRET, 3600)
    return {"Authorization": f"Bearer {token}"}


def _admin_user(admin_service) -> AdminUser:
    return admin_service.add_user(username="admin", role=AdminRole.ADMIN)


# ---------------------------------------------------------------------------
# Tests: _require_json_object — non-dict bodies rejected
# ---------------------------------------------------------------------------


class TestRequireJsonObject:
    """All POST/PATCH endpoints should reject non-dict JSON bodies."""

    def test_login_rejects_array(self, client):
        resp = client.post("/api/auth/login", json=["a", "b"])
        assert resp.status_code == 400
        assert "JSON object" in resp.get_json()["detail"]

    def test_login_rejects_string(self, client):
        resp = client.post(
            "/api/auth/login",
            data='"hello"',
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_login_rejects_null_body(self, client):
        resp = client.post("/api/auth/login", content_type="application/json")
        assert resp.status_code == 400

    def test_create_user_rejects_array(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post("/api/users", json=[1, 2], headers=_auth_header(admin))
        assert resp.status_code == 400

    def test_update_user_rejects_array(self, client, admin_service):
        admin = _admin_user(admin_service)
        target = admin_service.add_user(username="target")
        resp = client.patch(
            f"/api/users/{target.id}",
            json=[True],
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_eab_rejects_number(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/eab",
            data="42",
            content_type="application/json",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_maintenance_rejects_array(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post("/api/maintenance", json=[True], headers=_auth_header(admin))
        assert resp.status_code == 400

    def test_bulk_revoke_rejects_array(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/certificates/bulk-revoke",
            json=["x"],
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: strict boolean for `enabled`
# ---------------------------------------------------------------------------


class TestStrictBoolEnabled:
    """The 'enabled' field must be strictly true/false, not 0/1/'true'."""

    def test_update_user_rejects_int_enabled(self, client, admin_service):
        admin = _admin_user(admin_service)
        target = admin_service.add_user(username="target")
        resp = client.patch(
            f"/api/users/{target.id}",
            json={"enabled": 0},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "boolean" in resp.get_json()["detail"].lower()

    def test_update_user_rejects_string_enabled(self, client, admin_service):
        admin = _admin_user(admin_service)
        target = admin_service.add_user(username="target")
        resp = client.patch(
            f"/api/users/{target.id}",
            json={"enabled": "true"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_update_user_accepts_true(self, client, admin_service):
        admin = _admin_user(admin_service)
        target = admin_service.add_user(username="target")
        resp = client.patch(
            f"/api/users/{target.id}",
            json={"enabled": True},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200

    def test_maintenance_rejects_int_enabled(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/maintenance",
            json={"enabled": 1},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "boolean" in resp.get_json()["detail"].lower()

    def test_maintenance_rejects_string_enabled(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/maintenance",
            json={"enabled": "false"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: string type enforcement
# ---------------------------------------------------------------------------


class TestStringTypeEnforcement:
    """String fields must reject non-string values (int, bool, list)."""

    def test_login_rejects_int_username(self, client):
        resp = client.post("/api/auth/login", json={"username": 123, "password": "pw"})
        assert resp.status_code == 400
        assert "string" in resp.get_json()["detail"].lower()

    def test_create_user_rejects_int_username(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": 42, "email": "x@example.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_user_rejects_bool_email(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "valid", "email": True},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_user_rejects_list_role(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "valid", "email": "x@example.com", "role": ["admin"]},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_eab_rejects_int_kid(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/eab",
            json={"kid": 123},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_identifier_rejects_int_type(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/allowed-identifiers",
            json={"type": 1, "value": "example.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_login_rejects_int_password(self, client):
        resp = client.post("/api/auth/login", json={"username": "admin", "password": 12345})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: string length limits
# ---------------------------------------------------------------------------


class TestStringLengthLimits:
    """Fields must not exceed their max length."""

    def test_login_username_too_long(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"username": "x" * 200, "password": "pw"},
        )
        assert resp.status_code == 400
        assert "128" in resp.get_json()["detail"]

    def test_create_user_email_too_long(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "ok", "email": "a" * 600},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "512" in resp.get_json()["detail"]

    def test_create_eab_kid_too_long(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/eab",
            json={"kid": "k" * 300},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "255" in resp.get_json()["detail"]

    def test_create_csr_profile_description_too_long(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/csr-profile",
            json={
                "name": "test",
                "profile_data": {},
                "description": "d" * 11000,
            },
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "10000" in resp.get_json()["detail"]

    def test_login_password_too_long(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "p" * 1500},
        )
        assert resp.status_code == 400
        assert "1000" in resp.get_json()["detail"]


# ---------------------------------------------------------------------------
# Tests: profile_data must be dict
# ---------------------------------------------------------------------------


class TestProfileDataType:
    """'profile_data' must be a JSON object, not array/string/null."""

    def test_create_csr_profile_rejects_array(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/csr-profile",
            json={"name": "test", "profile_data": [1, 2, 3]},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "JSON object" in resp.get_json()["detail"]

    def test_create_csr_profile_rejects_string(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/csr-profile",
            json={"name": "test", "profile_data": "not-a-dict"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_csr_profile_rejects_null(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/csr-profile",
            json={"name": "test", "profile_data": None},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_update_csr_profile_rejects_array(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.put(
            f"/api/csr-profile/{uuid4()}",
            json={"name": "test", "profile_data": ["x"]},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: bulk-revoke filter type validation
# ---------------------------------------------------------------------------


class TestBulkRevokeFilterType:
    """'filter' in bulk-revoke must be a dict."""

    def test_rejects_string_filter(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/certificates/bulk-revoke",
            json={"filter": "not-a-dict"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "JSON object" in resp.get_json()["detail"]

    def test_rejects_array_filter(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/certificates/bulk-revoke",
            json={"filter": [1, 2]},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: query parameter validation
# ---------------------------------------------------------------------------


class TestQueryParamValidation:
    """Limit, offset, since, until, and status params are validated."""

    def test_audit_log_invalid_since(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/audit-log?since=not-a-date",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "ISO 8601" in resp.get_json()["detail"]

    def test_audit_log_invalid_until(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/audit-log?until=yesterday",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_audit_log_valid_since(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/audit-log?since=2024-01-01T00:00:00",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200

    def test_notifications_invalid_status(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/notifications?status=bogus",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "pending" in resp.get_json()["detail"]

    def test_notifications_valid_status(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/notifications?status=sent",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200

    def test_certificates_invalid_status(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/certificates?status=bogus",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "active" in resp.get_json()["detail"]

    def test_certificates_valid_status(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/certificates?status=revoked",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200

    def test_limit_non_integer(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/notifications?limit=abc",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "integer" in resp.get_json()["detail"]

    def test_limit_above_max_rejected(self, client, admin_service):
        """Limit above max_page_size is rejected."""
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/notifications?limit=9999",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "must not exceed" in resp.get_json()["detail"]

    def test_limit_zero_rejected(self, client, admin_service):
        """Limit of 0 is rejected."""
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/notifications?limit=0",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "at least 1" in resp.get_json()["detail"]

    def test_offset_non_integer(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/notifications?offset=abc",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_limit_negative_rejected(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/notifications?limit=-1",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "at least 1" in resp.get_json()["detail"]

    def test_offset_negative_rejected(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/notifications?offset=-5",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_certificates_limit_negative_rejected(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/certificates?limit=-1",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_certificates_offset_negative_rejected(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/certificates?offset=-10",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_audit_log_limit_negative_rejected(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/audit-log?limit=-1",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_audit_log_user_id_invalid_uuid(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/audit-log?user_id=not-a-uuid",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "UUID" in resp.get_json()["detail"]

    def test_audit_log_user_id_valid_uuid(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            f"/api/audit-log?user_id={uuid4()}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200

    def test_certificates_expiring_before_invalid(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/certificates?expiring_before=not-a-date",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "ISO 8601" in resp.get_json()["detail"]

    def test_certificates_expiring_before_valid(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.get(
            "/api/certificates?expiring_before=2025-12-31T23:59:59",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Tests: null byte rejection
# ---------------------------------------------------------------------------


class TestNullByteRejection:
    """Null bytes in string inputs must be rejected (not reach the DB)."""

    def test_login_username_null_byte(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin\x00evil", "password": "pw"},
        )
        assert resp.status_code == 400
        assert "invalid characters" in resp.get_json()["detail"]

    def test_create_user_username_null_byte(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "user\x00bad", "email": "ok@example.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_user_email_null_byte(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "ok", "email": "bad\x00@example.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_eab_kid_null_byte(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/eab",
            json={"kid": "my\x00kid"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_eab_label_null_byte(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/eab",
            json={"kid": "valid-kid", "label": "bad\x00label"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_identifier_value_null_byte(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "dns", "value": "example\x00.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: email format validation
# ---------------------------------------------------------------------------


class TestEmailFormatValidation:
    """Email field must look like a valid email address."""

    def test_create_user_email_no_at(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "newuser", "email": "not-an-email"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
        assert "email" in resp.get_json()["detail"].lower()

    def test_create_user_email_no_dot_in_domain(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "newuser", "email": "user@localhost"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_user_email_with_spaces(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "newuser", "email": "user @example.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_user_email_valid(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "newuser", "email": "user@example.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# Tests: username control character / whitespace rejection
# ---------------------------------------------------------------------------


class TestUsernameControlChars:
    """Usernames must not contain control characters or whitespace."""

    def test_login_username_with_tab(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin\tevil", "password": "pw"},
        )
        assert resp.status_code == 400
        assert "control characters" in resp.get_json()["detail"]

    def test_login_username_with_space(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin evil", "password": "pw"},
        )
        assert resp.status_code == 400

    def test_login_username_with_newline(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin\nevil", "password": "pw"},
        )
        assert resp.status_code == 400

    def test_create_user_username_with_space(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "new user", "email": "user@example.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_user_username_with_control_char(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "user\x07bell", "email": "user@example.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_login_username_with_zero_width_space(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin\u200bevil", "password": "pw"},
        )
        assert resp.status_code == 400
        assert "control characters" in resp.get_json()["detail"]

    def test_create_user_username_with_zero_width_joiner(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "user\u200d", "email": "user@example.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_user_username_with_bom(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "\ufeffadmin", "email": "user@example.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_create_user_username_with_soft_hyphen(self, client, admin_service):
        admin = _admin_user(admin_service)
        resp = client.post(
            "/api/users",
            json={"username": "ad\u00admin", "email": "user@example.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: 404 for nonexistent accounts on account-scoped endpoints
# ---------------------------------------------------------------------------


class TestAccountNotFound:
    """Account-scoped endpoints should 404 for nonexistent accounts."""

    def test_allowed_identifiers_nonexistent_account(self, client, admin_service):
        admin = _admin_user(admin_service)
        fake_id = uuid4()
        resp = client.get(
            f"/api/accounts/{fake_id}/allowed-identifiers",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 404
        assert "Account not found" in resp.get_json()["detail"]

    def test_csr_profile_nonexistent_account(self, client, admin_service):
        admin = _admin_user(admin_service)
        fake_id = uuid4()
        resp = client.get(
            f"/api/accounts/{fake_id}/csr-profile",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 404
        assert "Account not found" in resp.get_json()["detail"]

    def test_allowed_identifiers_existing_account(self, client, admin_service, app):
        admin = _admin_user(admin_service)
        acct_id = uuid4()
        app.extensions["container"].accounts.add(acct_id)
        resp = client.get(
            f"/api/accounts/{acct_id}/allowed-identifiers",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200

    def test_csr_profile_existing_account(self, client, admin_service, app):
        admin = _admin_user(admin_service)
        acct_id = uuid4()
        app.extensions["container"].accounts.add(acct_id)
        resp = client.get(
            f"/api/accounts/{acct_id}/csr-profile",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
