"""Tests for admin API routes."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from flask import Flask

from acmeeh.admin.auth import create_token
from acmeeh.admin.models import AdminUser, AuditLogEntry, EabCredential
from acmeeh.admin.routes import admin_bp
from acmeeh.app.errors import AcmeProblem, register_error_handlers
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import AdminRole

# ---------------------------------------------------------------------------
# Stub service
# ---------------------------------------------------------------------------


class StubAdminUserService:
    """Minimal stub to drive route tests without DB."""

    def __init__(self):
        self.users: dict[UUID, AdminUser] = {}
        self.audit_entries: list[AuditLogEntry] = []

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

    def get_user(self, user_id):
        user = self.users.get(user_id)
        if user is None:
            raise AcmeProblem("about:blank", "Not found", 404)
        return user

    def list_users(self):
        return list(self.users.values())

    def update_user(self, user_id, *, enabled=None, role=None, actor_id=None, ip_address=None):
        user = self.users.get(user_id)
        if user is None:
            raise AcmeProblem("about:blank", "Not found", 404)
        return user

    def delete_user(self, user_id, *, actor_id=None, ip_address=None):
        if user_id not in self.users:
            raise AcmeProblem("about:blank", "Not found", 404)
        del self.users[user_id]

    def reset_password(self, user_id, *, actor_id=None, ip_address=None):
        user = self.users.get(user_id)
        if user is None:
            raise AcmeProblem("about:blank", "Not found", 404)
        return user, "new-password-456"

    def get_audit_log(self, limit=100):
        return self.audit_entries

    # -- EAB stubs --

    def __init_eab(self):
        if not hasattr(self, "_eab_creds"):
            self._eab_creds: dict[UUID, EabCredential] = {}

    def create_eab(self, kid, *, label="", actor_id=None, ip_address=None):
        self.__init_eab()
        if not kid or not kid.strip():
            raise AcmeProblem("about:blank", "'kid' required", 400)
        for c in self._eab_creds.values():
            if c.kid == kid:
                raise AcmeProblem("urn:acmeeh:admin:error:conflict", "Duplicate kid", 409)
        cred = EabCredential(
            id=uuid4(),
            kid=kid,
            hmac_key="dGVzdC1obWFjLWtleQ",
            label=label,
            created_by=actor_id,
        )
        self._eab_creds[cred.id] = cred
        return cred

    def list_eab(self):
        self.__init_eab()
        return list(self._eab_creds.values())

    def get_eab(self, cred_id):
        self.__init_eab()
        cred = self._eab_creds.get(cred_id)
        if cred is None:
            raise AcmeProblem("about:blank", "Not found", 404)
        return cred

    def revoke_eab(self, cred_id, *, actor_id=None, ip_address=None):
        self.__init_eab()
        cred = self._eab_creds.get(cred_id)
        if cred is None:
            raise AcmeProblem("about:blank", "Not found", 404)
        from dataclasses import replace

        updated = replace(cred, revoked=True)
        self._eab_creds[cred_id] = updated
        return updated


# ---------------------------------------------------------------------------
# Stub container
# ---------------------------------------------------------------------------


class StubContainer:
    def __init__(self, admin_service, settings):
        self.admin_service = admin_service
        self.settings = settings
        self.admin_user_repo = StubUserRepo(admin_service)


class StubUserRepo:
    def __init__(self, service):
        self._service = service

    def find_by_id(self, user_id):
        return self._service.users.get(user_id)


# ---------------------------------------------------------------------------
# Settings helper
# ---------------------------------------------------------------------------

_TOKEN_SECRET = "test-route-secret-key-for-tests"


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
    """A minimal object standing in for AcmeehSettings."""

    def __init__(self, admin_api):
        self.admin_api = admin_api


# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLogin:
    def test_success(self, client, admin_service):
        admin_service.add_user(username="admin", email="a@example.com")
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "whatever"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "token" in data
        assert data["user"]["username"] == "admin"

    def test_missing_body(self, client):
        resp = client.post("/api/auth/login", content_type="application/json")
        assert resp.status_code == 400

    def test_missing_fields(self, client):
        resp = client.post("/api/auth/login", json={"username": "admin"})
        assert resp.status_code == 400


class TestListUsers:
    def test_admin_can_list(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.get("/api/users", headers=_auth_header(admin))
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_auditor_can_list(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.get("/api/users", headers=_auth_header(auditor))
        assert resp.status_code == 200

    def test_no_auth_returns_401(self, client):
        resp = client.get("/api/users")
        assert resp.status_code == 401


class TestCreateUser:
    def test_admin_can_create(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            "/api/users",
            json={"username": "newuser", "email": "new@example.com", "role": "auditor"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["username"] == "newuser"
        assert "password" in data

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.post(
            "/api/users",
            json={"username": "x", "email": "x@example.com"},
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 403

    def test_invalid_role(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            "/api/users",
            json={"username": "x", "email": "x@example.com", "role": "superadmin"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400


class TestGetUser:
    def test_get_existing(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        target = admin_service.add_user(username="target", email="t@example.com")
        resp = client.get(f"/api/users/{target.id}", headers=_auth_header(admin))
        assert resp.status_code == 200
        assert resp.get_json()["username"] == "target"

    def test_not_found(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.get(f"/api/users/{uuid4()}", headers=_auth_header(admin))
        assert resp.status_code == 404


class TestUpdateUser:
    def test_admin_can_update(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        target = admin_service.add_user(username="target")
        resp = client.patch(
            f"/api/users/{target.id}",
            json={"enabled": False},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        target = admin_service.add_user(username="target")
        resp = client.patch(
            f"/api/users/{target.id}",
            json={"enabled": False},
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 403


class TestDeleteUser:
    def test_admin_can_delete(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        target = admin_service.add_user(username="target")
        resp = client.delete(f"/api/users/{target.id}", headers=_auth_header(admin))
        assert resp.status_code == 204

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        target = admin_service.add_user(username="target")
        resp = client.delete(f"/api/users/{target.id}", headers=_auth_header(auditor))
        assert resp.status_code == 403


class TestMe:
    def test_get_me(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.get("/api/me", headers=_auth_header(admin))
        assert resp.status_code == 200
        assert resp.get_json()["username"] == "admin"

    def test_reset_own_password(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post("/api/me/reset-password", headers=_auth_header(admin))
        assert resp.status_code == 200
        assert "password" in resp.get_json()


class TestAuditLog:
    def test_admin_can_view(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.get("/api/audit-log", headers=_auth_header(admin))
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_auditor_can_view(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.get("/api/audit-log", headers=_auth_header(auditor))
        assert resp.status_code == 200


class TestInvalidToken:
    def test_expired_token(self, client):
        resp = client.get(
            "/api/users",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert resp.status_code == 401

    def test_no_bearer_prefix(self, client):
        resp = client.get(
            "/api/users",
            headers={"Authorization": "Token abc"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# EAB credential route tests
# ---------------------------------------------------------------------------


class TestListEab:
    def test_admin_can_list(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.get("/api/eab", headers=_auth_header(admin))
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.get("/api/eab", headers=_auth_header(auditor))
        assert resp.status_code == 403

    def test_no_auth_returns_401(self, client):
        resp = client.get("/api/eab")
        assert resp.status_code == 401


class TestCreateEab:
    def test_admin_can_create(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            "/api/eab",
            json={"kid": "my-new-kid", "label": "For client X"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["kid"] == "my-new-kid"
        assert data["label"] == "For client X"
        assert "hmac_key" in data  # only shown at creation
        assert data["used"] is False
        assert data["revoked"] is False

    def test_missing_kid(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            "/api/eab",
            json={"label": "no kid"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.post(
            "/api/eab",
            json={"kid": "x"},
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 403

    def test_duplicate_kid(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        client.post(
            "/api/eab",
            json={"kid": "dup-kid"},
            headers=_auth_header(admin),
        )
        resp = client.post(
            "/api/eab",
            json={"kid": "dup-kid"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 409


class TestGetEab:
    def test_get_existing(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/eab",
            json={"kid": "get-kid"},
            headers=_auth_header(admin),
        )
        cred_id = create_resp.get_json()["id"]
        resp = client.get(f"/api/eab/{cred_id}", headers=_auth_header(admin))
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["kid"] == "get-kid"
        assert "hmac_key" not in data  # not shown on GET

    def test_not_found(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.get(f"/api/eab/{uuid4()}", headers=_auth_header(admin))
        assert resp.status_code == 404


class TestRevokeEab:
    def test_admin_can_revoke(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/eab",
            json={"kid": "revoke-kid"},
            headers=_auth_header(admin),
        )
        cred_id = create_resp.get_json()["id"]
        resp = client.post(
            f"/api/eab/{cred_id}/revoke",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        assert resp.get_json()["revoked"] is True

    def test_not_found(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            f"/api/eab/{uuid4()}/revoke",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 404

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.post(
            f"/api/eab/{uuid4()}/revoke",
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 403
