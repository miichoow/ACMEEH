"""Tests for admin allowlist API routes."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from flask import Flask

from acmeeh.admin.auth import create_token
from acmeeh.admin.models import AdminUser, AllowedIdentifier, AuditLogEntry
from acmeeh.admin.routes import admin_bp
from acmeeh.app.errors import AcmeProblem, register_error_handlers
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import AdminRole

# ---------------------------------------------------------------------------
# Stub service — extends the one from test_routes.py with allowlist methods
# ---------------------------------------------------------------------------


class StubAdminUserService:
    """Minimal stub for route tests."""

    def __init__(self):
        self.users: dict[UUID, AdminUser] = {}
        self.audit_entries: list[AuditLogEntry] = []
        self._identifiers: dict[UUID, AllowedIdentifier] = {}
        self._associations: dict[UUID, set[UUID]] = {}

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

    # -- user stubs (for auth decorator) --

    def list_users(self):
        return list(self.users.values())

    def get_audit_log(self, limit=100):
        return self.audit_entries

    # -- allowlist stubs --

    def list_allowed_identifiers(self):
        result = []
        for ident in self._identifiers.values():
            acct_ids = list(self._associations.get(ident.id, set()))
            result.append((ident, acct_ids))
        return result

    def create_allowed_identifier(
        self,
        identifier_type,
        identifier_value,
        *,
        actor_id=None,
        ip_address=None,
    ):
        if identifier_type not in ("dns", "ip"):
            raise AcmeProblem("about:blank", "Invalid type", 400)
        for i in self._identifiers.values():
            if i.identifier_type == identifier_type and i.identifier_value == identifier_value:
                raise AcmeProblem("urn:acmeeh:admin:error:conflict", "Duplicate", 409)
        ident = AllowedIdentifier(
            id=uuid4(),
            identifier_type=identifier_type,
            identifier_value=identifier_value.lower()
            if identifier_type == "dns"
            else identifier_value,
            created_by=actor_id,
        )
        self._identifiers[ident.id] = ident
        return ident

    def get_allowed_identifier(self, identifier_id):
        ident = self._identifiers.get(identifier_id)
        if ident is None:
            raise AcmeProblem("about:blank", "Not found", 404)
        acct_ids = list(self._associations.get(ident.id, set()))
        return ident, acct_ids

    def delete_allowed_identifier(self, identifier_id, *, actor_id=None, ip_address=None):
        if identifier_id not in self._identifiers:
            raise AcmeProblem("about:blank", "Not found", 404)
        del self._identifiers[identifier_id]
        self._associations.pop(identifier_id, None)

    def add_identifier_account(
        self,
        identifier_id,
        account_id,
        *,
        actor_id=None,
        ip_address=None,
    ):
        if identifier_id not in self._identifiers:
            raise AcmeProblem("about:blank", "Not found", 404)
        self._associations.setdefault(identifier_id, set()).add(account_id)

    def remove_identifier_account(
        self,
        identifier_id,
        account_id,
        *,
        actor_id=None,
        ip_address=None,
    ):
        if identifier_id not in self._identifiers:
            raise AcmeProblem("about:blank", "Not found", 404)
        s = self._associations.get(identifier_id, set())
        s.discard(account_id)

    def list_account_identifiers(self, account_id):
        result = []
        for ident_id, acct_ids in self._associations.items():
            if account_id in acct_ids:
                ident = self._identifiers.get(ident_id)
                if ident:
                    result.append(ident)
        return result


# ---------------------------------------------------------------------------
# Stub container
# ---------------------------------------------------------------------------


class _AlwaysFoundAccountRepo:
    def find_by_id(self, _id):
        return True


class StubContainer:
    def __init__(self, admin_service, settings):
        self.admin_service = admin_service
        self.settings = settings
        self.admin_user_repo = _StubUserRepo(admin_service)
        self.accounts = _AlwaysFoundAccountRepo()


class _StubUserRepo:
    def __init__(self, service):
        self._service = service

    def find_by_id(self, user_id):
        return self._service.users.get(user_id)


# ---------------------------------------------------------------------------
# Settings / app fixtures
# ---------------------------------------------------------------------------

_TOKEN_SECRET = "test-allowlist-route-secret"


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


def _auth_header(user: AdminUser, role: AdminRole | None = None) -> dict:
    token = create_token(user, _TOKEN_SECRET, 3600)
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestListAllowedIdentifiers:
    def test_admin_can_list(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.get("/api/allowed-identifiers", headers=_auth_header(admin))
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.get("/api/allowed-identifiers", headers=_auth_header(auditor))
        assert resp.status_code == 403

    def test_no_auth_returns_401(self, client):
        resp = client.get("/api/allowed-identifiers")
        assert resp.status_code == 401


class TestCreateAllowedIdentifier:
    def test_admin_can_create_dns(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "dns", "value": "example.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["identifier_type"] == "dns"
        assert data["identifier_value"] == "example.com"

    def test_admin_can_create_ip(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "ip", "value": "10.0.0.1"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 201

    def test_missing_fields(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "dns"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_duplicate_returns_409(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        client.post(
            "/api/allowed-identifiers",
            json={"type": "dns", "value": "dup.com"},
            headers=_auth_header(admin),
        )
        resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "dns", "value": "dup.com"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 409

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "dns", "value": "x.com"},
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 403

    def test_invalid_type(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "ftp", "value": "bad"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400


class TestGetAllowedIdentifier:
    def test_get_existing(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "dns", "value": "get.com"},
            headers=_auth_header(admin),
        )
        ident_id = create_resp.get_json()["id"]
        resp = client.get(
            f"/api/allowed-identifiers/{ident_id}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["identifier_value"] == "get.com"
        assert "account_ids" in data

    def test_not_found(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.get(
            f"/api/allowed-identifiers/{uuid4()}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 404


class TestDeleteAllowedIdentifier:
    def test_admin_can_delete(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "dns", "value": "del.com"},
            headers=_auth_header(admin),
        )
        ident_id = create_resp.get_json()["id"]
        resp = client.delete(
            f"/api/allowed-identifiers/{ident_id}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 204

    def test_delete_not_found(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.delete(
            f"/api/allowed-identifiers/{uuid4()}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 404

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.delete(
            f"/api/allowed-identifiers/{uuid4()}",
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 403


class TestAddIdentifierAccount:
    def test_admin_can_add(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "dns", "value": "link.com"},
            headers=_auth_header(admin),
        )
        ident_id = create_resp.get_json()["id"]
        acct_id = uuid4()
        resp = client.put(
            f"/api/allowed-identifiers/{ident_id}/accounts/{acct_id}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 204

    def test_identifier_not_found(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.put(
            f"/api/allowed-identifiers/{uuid4()}/accounts/{uuid4()}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 404


class TestRemoveIdentifierAccount:
    def test_admin_can_remove(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "dns", "value": "unlink.com"},
            headers=_auth_header(admin),
        )
        ident_id = create_resp.get_json()["id"]
        acct_id = uuid4()
        # Add then remove
        client.put(
            f"/api/allowed-identifiers/{ident_id}/accounts/{acct_id}",
            headers=_auth_header(admin),
        )
        resp = client.delete(
            f"/api/allowed-identifiers/{ident_id}/accounts/{acct_id}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 204

    def test_identifier_not_found(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.delete(
            f"/api/allowed-identifiers/{uuid4()}/accounts/{uuid4()}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 404


class TestListAccountIdentifiers:
    def test_list_for_account(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "dns", "value": "acct-list.com"},
            headers=_auth_header(admin),
        )
        ident_id = create_resp.get_json()["id"]
        acct_id = uuid4()
        client.put(
            f"/api/allowed-identifiers/{ident_id}/accounts/{acct_id}",
            headers=_auth_header(admin),
        )
        resp = client.get(
            f"/api/accounts/{acct_id}/allowed-identifiers",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["identifier_value"] == "acct-list.com"

    def test_empty_list(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.get(
            f"/api/accounts/{uuid4()}/allowed-identifiers",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.get(
            f"/api/accounts/{uuid4()}/allowed-identifiers",
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 403
