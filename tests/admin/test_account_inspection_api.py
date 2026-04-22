"""Tests for ACME account inspection admin API routes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from flask import Flask

from acmeeh.admin.auth import create_token
from acmeeh.admin.models import AdminUser
from acmeeh.admin.routes import admin_bp
from acmeeh.app.errors import AcmeProblem, register_error_handlers
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import AccountStatus, AdminRole

_TOKEN_SECRET = "test-accounts-secret"


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


@dataclass(frozen=True)
class FakeAccount:
    id: UUID
    jwk_thumbprint: str
    jwk: dict
    status: AccountStatus = AccountStatus.VALID
    tos_agreed: bool = True
    created_at: datetime = datetime(2026, 1, 1, tzinfo=UTC)
    updated_at: datetime = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass(frozen=True)
class FakeContact:
    id: UUID
    account_id: UUID
    contact_uri: str
    created_at: datetime = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass
class _AccountRecord:
    account: FakeAccount
    eab_kid: str | None = None
    contacts: list[FakeContact] = field(default_factory=list)
    csr_profile_id: UUID | None = None


class StubAdminService:
    def __init__(self) -> None:
        self.users: dict[UUID, AdminUser] = {}
        self._accounts: dict[UUID, _AccountRecord] = {}

    def add_user(self, **kwargs) -> AdminUser:
        defaults = {
            "id": uuid4(),
            "username": "admin",
            "email": "admin@example.com",
            "password_hash": "hashed",
            "role": AdminRole.ADMIN,
            "enabled": True,
        }
        defaults.update(kwargs)
        user = AdminUser(**defaults)
        self.users[user.id] = user
        return user

    def add_account(
        self,
        *,
        eab_kid: str | None = None,
        contacts: list[str] | None = None,
        csr_profile_id: UUID | None = None,
        status: AccountStatus = AccountStatus.VALID,
        jwk: dict | None = None,
    ) -> FakeAccount:
        account_id = uuid4()
        account = FakeAccount(
            id=account_id,
            jwk_thumbprint=f"thumb-{account_id.hex[:8]}",
            jwk=jwk or {"kty": "RSA", "n": "xxx", "e": "AQAB"},
            status=status,
        )
        contact_objs = [
            FakeContact(id=uuid4(), account_id=account_id, contact_uri=uri)
            for uri in (contacts or [])
        ]
        self._accounts[account_id] = _AccountRecord(
            account=account,
            eab_kid=eab_kid,
            contacts=contact_objs,
            csr_profile_id=csr_profile_id,
        )
        return account

    def list_accounts(self, filters, limit=50, offset=0):
        results = list(self._accounts.values())
        if "status" in filters:
            results = [r for r in results if r.account.status.value == filters["status"]]
        if filters.get("eab_only"):
            results = [r for r in results if r.eab_kid is not None]
        if "eab_kid" in filters:
            results = [r for r in results if r.eab_kid == filters["eab_kid"]]
        if "contact" in filters:
            needle = filters["contact"]
            results = [r for r in results if any(needle in c.contact_uri for c in r.contacts)]
        page = results[offset : offset + limit]
        accounts = [r.account for r in page]
        eab_kids = {r.account.id: r.eab_kid for r in page if r.eab_kid is not None}
        return accounts, eab_kids

    def get_account(self, account_id):
        record = self._accounts.get(account_id)
        if record is None:
            raise AcmeProblem("about:blank", "ACME account not found", status=404)
        return (
            record.account,
            record.contacts,
            record.eab_kid,
            record.csr_profile_id,
        )

    def _log_action(self, *a, **kw):  # pragma: no cover
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


class TestListAccounts:
    def test_list_all(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_account()
        admin_service.add_account()

        resp = client.get("/api/accounts", headers=_auth_header(admin))
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 2

    def test_admin_sees_full_jwk(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_account(jwk={"kty": "EC", "crv": "P-256"})

        resp = client.get("/api/accounts", headers=_auth_header(admin))
        data = resp.get_json()
        assert data[0]["jwk"] == {"kty": "EC", "crv": "P-256"}
        assert "jwk_thumbprint" in data[0]

    def test_auditor_sees_redacted_jwk(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        admin_service.add_account(jwk={"kty": "EC", "crv": "P-256"})

        resp = client.get("/api/accounts", headers=_auth_header(auditor))
        assert resp.status_code == 200
        data = resp.get_json()
        assert "jwk" not in data[0]
        assert "jwk_thumbprint" in data[0]

    def test_filter_eab_only(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_account(eab_kid="kid-1")
        admin_service.add_account()

        resp = client.get("/api/accounts?eab_only=true", headers=_auth_header(admin))
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["eab_kid"] == "kid-1"

    def test_filter_eab_kid(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_account(eab_kid="kid-A")
        admin_service.add_account(eab_kid="kid-B")

        resp = client.get("/api/accounts?eab_kid=kid-B", headers=_auth_header(admin))
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["eab_kid"] == "kid-B"

    def test_filter_status(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_account(status=AccountStatus.VALID)
        admin_service.add_account(status=AccountStatus.DEACTIVATED)

        resp = client.get(
            "/api/accounts?status=deactivated",
            headers=_auth_header(admin),
        )
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["status"] == "deactivated"

    def test_invalid_status_returns_400(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        resp = client.get(
            "/api/accounts?status=bogus",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_invalid_eab_only_returns_400(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        resp = client.get(
            "/api/accounts?eab_only=maybe",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_invalid_created_before_returns_400(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        resp = client.get(
            "/api/accounts?created_before=not-a-date",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_no_auth_returns_401(self, client):
        resp = client.get("/api/accounts")
        assert resp.status_code == 401


class TestGetAccount:
    def test_get_existing(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        acc = admin_service.add_account(
            eab_kid="kid-xyz",
            contacts=["mailto:dev@example.com"],
        )

        resp = client.get(
            f"/api/accounts/{acc.id}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["id"] == str(acc.id)
        assert data["eab_kid"] == "kid-xyz"
        assert data["contacts"] == ["mailto:dev@example.com"]
        assert "jwk" in data

    def test_get_redacted_for_auditor(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        acc = admin_service.add_account(contacts=["mailto:ops@example.com"])

        resp = client.get(
            f"/api/accounts/{acc.id}",
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "jwk" not in data
        assert data["contacts"] == ["mailto:ops@example.com"]

    def test_csr_profile_id_included(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        profile_id = uuid4()
        acc = admin_service.add_account(csr_profile_id=profile_id)

        resp = client.get(
            f"/api/accounts/{acc.id}",
            headers=_auth_header(admin),
        )
        data = resp.get_json()
        assert data["csr_profile_id"] == str(profile_id)

    def test_unknown_id_returns_404(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        resp = client.get(
            f"/api/accounts/{uuid4()}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 404
