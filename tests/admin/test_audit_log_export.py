"""Tests for audit log export admin API routes."""

from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest
from flask import Flask

from acmeeh.admin.auth import create_token
from acmeeh.admin.models import AdminUser, AuditLogEntry
from acmeeh.admin.routes import admin_bp
from acmeeh.app.errors import register_error_handlers
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import AdminRole

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

_TOKEN_SECRET = "test-audit-export-secret"


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


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class StubAdminService:
    """Stub admin service for audit log route tests."""

    def __init__(self):
        self.users: dict[UUID, AdminUser] = {}
        self._audit_entries: list[AuditLogEntry] = []

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

    def add_audit_entry(self, **kwargs) -> AuditLogEntry:
        defaults = dict(
            id=uuid4(),
            action="test_action",
            user_id=None,
            details={"key": "value"},
        )
        defaults.update(kwargs)
        entry = AuditLogEntry(**defaults)
        self._audit_entries.append(entry)
        return entry

    def get_audit_log(self, limit=100):
        return self._audit_entries[:limit]

    def search_audit_log(self, filters, limit=1000):
        results = self._audit_entries
        if "action" in filters:
            results = [e for e in results if e.action == filters["action"]]
        if "user_id" in filters:
            target_id = filters["user_id"]
            results = [e for e in results if str(e.user_id) == target_id]
        return results[:limit]

    def _log_action(self, user_id, action, *, target_user_id=None, details=None, ip_address=None):
        pass


class StubUserRepo:
    def __init__(self, service):
        self._service = service

    def find_by_id(self, user_id):
        return self._service.users.get(user_id)


class StubContainer:
    def __init__(self, admin_service, settings):
        self.admin_service = admin_service
        self.settings = settings
        self.admin_user_repo = StubUserRepo(admin_service)


class _FakeSettings:
    def __init__(self, admin_api):
        self.admin_api = admin_api


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def admin_service():
    return StubAdminService()


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


class TestGetAuditLog:
    """GET /audit-log with filters."""

    def test_list_audit_log(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_audit_entry(action="login")
        admin_service.add_audit_entry(action="create_user")

        resp = client.get("/api/audit-log", headers=_auth_header(admin))
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 2

    def test_filter_by_action(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_audit_entry(action="login")
        admin_service.add_audit_entry(action="create_user")

        resp = client.get(
            "/api/audit-log?action=login",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["action"] == "login"

    def test_with_since_filter(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_audit_entry(action="old_action")

        resp = client.get(
            "/api/audit-log?since=2020-01-01T00:00:00Z",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200

    def test_with_until_filter(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_audit_entry(action="test_action")

        resp = client.get(
            "/api/audit-log?until=2099-12-31T23:59:59Z",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200

    def test_with_limit(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        for i in range(5):
            admin_service.add_audit_entry(action=f"action_{i}")

        resp = client.get(
            "/api/audit-log?limit=3",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) <= 3

    def test_auditor_can_view(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.get("/api/audit-log", headers=_auth_header(auditor))
        assert resp.status_code == 200


class TestExportAuditLog:
    """POST /audit-log/export returns NDJSON format."""

    def test_export_returns_ndjson(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_audit_entry(action="login")
        admin_service.add_audit_entry(action="create_user")

        resp = client.post(
            "/api/audit-log/export",
            json={},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        assert resp.content_type.startswith("application/x-ndjson")

        # Parse NDJSON lines
        lines = resp.data.decode("utf-8").strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            obj = json.loads(line)
            assert "action" in obj
            assert "id" in obj

    def test_export_with_action_filter(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_audit_entry(action="login")
        admin_service.add_audit_entry(action="create_user")

        resp = client.post(
            "/api/audit-log/export",
            json={"action": "login"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        lines = resp.data.decode("utf-8").strip().split("\n")
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert obj["action"] == "login"

    def test_export_with_since_until_filters(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_audit_entry(action="test")

        resp = client.post(
            "/api/audit-log/export",
            json={"since": "2020-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200

    def test_export_empty_result(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)

        resp = client.post(
            "/api/audit-log/export",
            json={},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        # Empty NDJSON
        content = resp.data.decode("utf-8").strip()
        assert content == ""

    def test_auditor_cannot_export(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.post(
            "/api/audit-log/export",
            json={},
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 403
