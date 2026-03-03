"""Tests covering remaining untested lines in admin/routes.py and admin/service.py.

Targets (routes.py):
  - Line 54: _get_admin_service() when admin_service is None -> 503
  - Lines 89-91: Login exception handler records failure
  - Lines 122-123, 132-133: Create user validation (no body, missing fields)
  - Lines 179-180, 188-192: Update user validation (no body, invalid role)
  - Lines 272-276, 291: Audit log cursor-based pagination & invalid cursor
  - Lines 334-335: EAB create with no body
  - Lines 410-411: Create allowed identifier with no body
  - Lines 623-641: CSR profile validate endpoint
  - Lines 673-674, 680-681, 687-688: Update CSR profile validation
  - Lines 815-820: Notification pagination Link header
  - Lines 906-911: Certificate search pagination Link header
  - Lines 939-951: Get certificate by fingerprint (found & not found)
  - Lines 1122, 1126, 1139-1140: Bulk revoke filter fields
  - Lines 1167-1168: Bulk revoke error handling

Targets (service.py):
  - Lines 235-236: reset_password when update_password returns None -> 500
  - Lines 475-476: get_eab when _eab is None -> 503
  - Lines 500-501: revoke_eab when _eab is None -> 503
  - Lines 516-517: revoke_eab when revoke() returns None -> 500
  - Lines 536, 553-554: create_allowed_identifier when _allowlist is None -> 503
  - Lines 635-636: get_allowed_identifier when _allowlist is None -> 503
  - Lines 663-664: delete_allowed_identifier when _allowlist is None -> 503
  - Lines 701-702: add_identifier_account when _allowlist is None -> 503
  - Lines 742-743, 751-752: remove_identifier_account when _allowlist is None -> 503
  - Lines 776: list_account_identifiers when _allowlist is None -> []
  - Lines 793-794: validate_csr when _csr_profiles is None -> 503
  - Lines 848, 868-869: create_csr_profile when _csr_profiles is None -> 503
  - Lines 917, 927-928: get_csr_profile when _csr_profiles is None -> 503
  - Lines 960-961, 975-976: update_csr_profile when _csr_profiles is None -> 503
  - Lines 999-1000: update_csr_profile when update_profile returns None -> 500
  - Lines 1026-1027: delete_csr_profile when _csr_profiles is None -> 503
  - Lines 1062-1063: assign_profile_to_account when _csr_profiles is None -> 503
  - Lines 1101-1102: unassign_profile_from_account when _csr_profiles is None -> 503
  - Lines 1133: get_account_csr_profile when _csr_profiles is None -> None
  - Lines 1146-1147, 1160-1161: _validate_profile_data edge cases
  - Lines 1188-1189: _validate_profile_data authorized_keys non-numeric value
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest
from flask import Flask

from acmeeh.admin.auth import create_token
from acmeeh.admin.models import (
    AdminUser,
    AllowedIdentifier,
    AuditLogEntry,
    CsrProfile,
    EabCredential,
)
from acmeeh.admin.routes import admin_bp
from acmeeh.admin.service import AdminUserService
from acmeeh.app.errors import AcmeProblem, register_error_handlers
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import (
    AdminRole,
    NotificationStatus,
    NotificationType,
    RevocationReason,
)
from acmeeh.models.notification import Notification

_TOKEN_SECRET = "test-remaining-gaps-secret"


# ---------------------------------------------------------------------------
# Settings & stubs (routes tests)
# ---------------------------------------------------------------------------


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
class FakeCertificate:
    """Lightweight certificate stand-in for route tests."""

    id: UUID
    account_id: UUID
    order_id: UUID
    serial_number: str
    fingerprint: str
    not_before_cert: datetime
    not_after_cert: datetime
    san_values: list | None = None
    revoked_at: datetime | None = None
    revocation_reason: RevocationReason | None = None
    created_at: datetime = datetime(1970, 1, 1)


class StubAdminService:
    """Service stub with sufficient methods for all route tests."""

    def __init__(self):
        self.users: dict[UUID, AdminUser] = {}
        self._audit_entries: list[AuditLogEntry] = []
        self._certificates: list[FakeCertificate] = []
        self._notifications: list[Notification] = []
        self._csr_profiles: dict[UUID, CsrProfile] = {}
        self._allowed_identifiers: dict[UUID, AllowedIdentifier] = {}

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

    # Auth
    def authenticate(self, username, password, ip_address=None):
        for u in self.users.values():
            if u.username == username:
                return u, "stub-token"
        raise AcmeProblem(
            "urn:acmeeh:admin:error:unauthorized",
            "Invalid username or password",
            status=401,
        )

    # Users
    def create_user(
        self, username, email, role=AdminRole.AUDITOR, *, actor_id=None, ip_address=None
    ):
        user = self.add_user(username=username, email=email, role=role)
        return user, "generated-pw"

    def list_users(self):
        return list(self.users.values())

    def get_user(self, user_id):
        user = self.users.get(user_id)
        if user is None:
            raise AcmeProblem("about:blank", "Not found", status=404)
        return user

    def update_user(self, user_id, *, enabled=None, role=None, actor_id=None, ip_address=None):
        user = self.users.get(user_id)
        if user is None:
            raise AcmeProblem("about:blank", "Not found", status=404)
        return user

    def delete_user(self, user_id, *, actor_id=None, ip_address=None):
        if user_id not in self.users:
            raise AcmeProblem("about:blank", "Not found", status=404)
        del self.users[user_id]

    def reset_password(self, user_id, *, actor_id=None, ip_address=None):
        user = self.users.get(user_id)
        if user is None:
            raise AcmeProblem("about:blank", "Not found", status=404)
        return user, "new-password-456"

    # Audit
    def get_audit_log(self, limit=100):
        return self._audit_entries[:limit]

    def search_audit_log(self, filters, limit=100):
        return self._audit_entries[:limit]

    # Notifications
    def list_notifications(self, status=None, limit=50, offset=0):
        results = self._notifications
        if status:
            results = [n for n in results if n.status.value == status]
        return results[offset : offset + limit]

    def retry_failed_notifications(self):
        return 3

    def purge_notifications(self, days):
        return 5

    # Certificates
    def search_certificates(self, filters, limit=50, offset=0):
        certs = self._certificates
        if "serial_numbers" in filters:
            serial_set = set(filters["serial_numbers"])
            certs = [c for c in certs if c.serial_number in serial_set]
        return certs[offset : offset + limit]

    def get_certificate_by_serial(self, serial):
        for c in self._certificates:
            if c.serial_number == serial:
                return c
        raise AcmeProblem("about:blank", "Certificate not found", status=404)

    # EAB
    def create_eab(self, kid, *, label="", actor_id=None, ip_address=None):
        cred = EabCredential(
            id=uuid4(),
            kid=kid,
            hmac_key="dGVzdC1obWFjLWtleQ",
            label=label,
            created_by=actor_id,
        )
        return cred

    def list_eab(self):
        return []

    def get_eab(self, cred_id):
        raise AcmeProblem("about:blank", "Not found", status=404)

    def revoke_eab(self, cred_id, *, actor_id=None, ip_address=None):
        raise AcmeProblem("about:blank", "Not found", status=404)

    # Allowed identifiers
    def list_allowed_identifiers(self):
        return [(ident, []) for ident in self._allowed_identifiers.values()]

    def create_allowed_identifier(self, id_type, id_value, *, actor_id=None, ip_address=None):
        ident = AllowedIdentifier(
            id=uuid4(),
            identifier_type=id_type,
            identifier_value=id_value,
            created_by=actor_id,
        )
        self._allowed_identifiers[ident.id] = ident
        return ident

    def get_allowed_identifier(self, identifier_id):
        ident = self._allowed_identifiers.get(identifier_id)
        if ident is None:
            raise AcmeProblem("about:blank", "Not found", status=404)
        return ident, []

    def delete_allowed_identifier(self, identifier_id, *, actor_id=None, ip_address=None):
        if identifier_id not in self._allowed_identifiers:
            raise AcmeProblem("about:blank", "Not found", status=404)
        del self._allowed_identifiers[identifier_id]

    def add_identifier_account(self, identifier_id, account_id, *, actor_id=None, ip_address=None):
        pass

    def remove_identifier_account(
        self, identifier_id, account_id, *, actor_id=None, ip_address=None
    ):
        pass

    def list_account_identifiers(self, account_id):
        return []

    # CSR profiles
    def list_csr_profiles(self):
        return list(self._csr_profiles.values())

    def create_csr_profile(
        self, name, profile_data, *, description="", actor_id=None, ip_address=None
    ):
        profile = CsrProfile(
            id=uuid4(),
            name=name,
            profile_data=profile_data,
            description=description,
            created_by=actor_id,
        )
        self._csr_profiles[profile.id] = profile
        return profile

    def get_csr_profile(self, profile_id):
        profile = self._csr_profiles.get(profile_id)
        if profile is None:
            raise AcmeProblem("about:blank", "CSR profile not found", status=404)
        return profile, []

    def update_csr_profile(
        self, profile_id, name, profile_data, *, description="", actor_id=None, ip_address=None
    ):
        profile = self._csr_profiles.get(profile_id)
        if profile is None:
            raise AcmeProblem("about:blank", "CSR profile not found", status=404)
        updated = CsrProfile(
            id=profile_id,
            name=name,
            profile_data=profile_data,
            description=description,
            created_by=profile.created_by,
        )
        self._csr_profiles[profile_id] = updated
        return updated

    def delete_csr_profile(self, profile_id, *, actor_id=None, ip_address=None):
        if profile_id not in self._csr_profiles:
            raise AcmeProblem("about:blank", "Not found", status=404)
        del self._csr_profiles[profile_id]

    def assign_profile_to_account(self, profile_id, account_id, *, actor_id=None, ip_address=None):
        pass

    def unassign_profile_from_account(
        self, profile_id, account_id, *, actor_id=None, ip_address=None
    ):
        pass

    def get_account_csr_profile(self, account_id):
        return None

    def validate_csr(self, profile_id, csr_b64):
        return {"valid": True, "violations": []}

    def _log_action(self, user_id, action, *, target_user_id=None, details=None, ip_address=None):
        pass


class StubUserRepo:
    def __init__(self, service):
        self._service = service

    def find_by_id(self, user_id):
        return self._service.users.get(user_id)


class StubCertificateRepo:
    """Stub supporting find_by_fingerprint and revoke."""

    def __init__(self):
        self.certs: dict[str, FakeCertificate] = {}
        self.revoked: list[tuple] = []
        self.revoke_raises: dict[UUID, Exception] = {}

    def find_by_fingerprint(self, fingerprint):
        return self.certs.get(fingerprint)

    def revoke(self, cert_id, reason):
        if cert_id in self.revoke_raises:
            raise self.revoke_raises[cert_id]
        self.revoked.append((cert_id, reason))
        return True


class StubContainer:
    def __init__(self, admin_service, settings, *, crl_manager=None, certificates=None):
        self.admin_service = admin_service
        self.settings = settings
        self.admin_user_repo = StubUserRepo(admin_service)
        self.crl_manager = crl_manager
        self.certificates = certificates


class _FakeSettings:
    def __init__(self, admin_api):
        self.admin_api = admin_api


# ---------------------------------------------------------------------------
# Route fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def admin_service():
    return StubAdminService()


@pytest.fixture()
def cert_repo():
    return StubCertificateRepo()


@pytest.fixture()
def app(admin_service, cert_repo):
    flask_app = Flask("test")
    flask_app.config["TESTING"] = True
    admin_settings = _make_settings()
    full_settings = _FakeSettings(admin_settings)
    container = StubContainer(
        admin_service,
        full_settings,
        certificates=cert_repo,
    )
    flask_app.extensions["container"] = container
    register_error_handlers(flask_app)
    flask_app.register_blueprint(admin_bp, url_prefix="/api")
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin_user(admin_service):
    return admin_service.add_user()


@pytest.fixture()
def auth_header(admin_user):
    token = create_token(admin_user, _TOKEN_SECRET, 3600)
    return {"Authorization": f"Bearer {token}"}


def _auth_header(user):
    token = create_token(user, _TOKEN_SECRET, 3600)
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# ROUTE TESTS
# ===========================================================================


# ---------------------------------------------------------------------------
# 1. _get_admin_service() returns 503 when admin_service is None (line 54)
# ---------------------------------------------------------------------------


class TestAdminServiceNone:
    """When admin_service is None, routes using _get_admin_service() -> 503."""

    def test_list_users_returns_503(self, app, admin_user, auth_header):
        app.extensions["container"].admin_service = None
        with app.test_client() as c:
            resp = c.get("/api/users", headers=auth_header)
        assert resp.status_code == 503
        data = resp.get_json()
        assert "not enabled" in data["detail"].lower()

    def test_eab_list_returns_503(self, app, admin_user, auth_header):
        app.extensions["container"].admin_service = None
        with app.test_client() as c:
            resp = c.get("/api/eab", headers=auth_header)
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# 2. Login exception records failure (lines 89-91)
# ---------------------------------------------------------------------------


class TestLoginFailureRecordsAttempt:
    """When authenticate raises AcmeProblem, limiter.record_failure is called."""

    @patch("acmeeh.admin.routes.get_login_limiter")
    def test_login_bad_credentials_records_failure(
        self,
        mock_get_limiter,
        client,
        admin_service,
    ):
        mock_limiter = MagicMock()
        mock_get_limiter.return_value = mock_limiter
        # No users -> authenticate raises AcmeProblem
        resp = client.post(
            "/api/auth/login",
            json={"username": "nobody", "password": "wrong"},
        )
        assert resp.status_code == 401
        mock_limiter.record_failure.assert_called_once()

    @patch("acmeeh.admin.routes.get_login_limiter")
    def test_login_success_records_success(
        self,
        mock_get_limiter,
        client,
        admin_service,
    ):
        mock_limiter = MagicMock()
        mock_get_limiter.return_value = mock_limiter
        admin_service.add_user(username="testuser")
        resp = client.post(
            "/api/auth/login",
            json={"username": "testuser", "password": "anything"},
        )
        assert resp.status_code == 200
        mock_limiter.record_success.assert_called_once()
        mock_limiter.record_failure.assert_not_called()


# ---------------------------------------------------------------------------
# 3. Create user validation (lines 122-123, 132-133)
# ---------------------------------------------------------------------------


class TestCreateUserValidation:
    """POST /api/users with invalid data."""

    def test_no_body_returns_400(self, client, admin_user, auth_header):
        resp = client.post(
            "/api/users",
            headers=auth_header,
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "JSON" in resp.get_json()["detail"]

    def test_missing_username_returns_400(self, client, admin_user, auth_header):
        resp = client.post(
            "/api/users",
            json={"email": "a@b.com"},
            headers=auth_header,
        )
        assert resp.status_code == 400
        assert "username" in resp.get_json()["detail"].lower()

    def test_missing_email_returns_400(self, client, admin_user, auth_header):
        resp = client.post(
            "/api/users",
            json={"username": "newuser"},
            headers=auth_header,
        )
        assert resp.status_code == 400
        assert "email" in resp.get_json()["detail"].lower()

    def test_empty_username_returns_400(self, client, admin_user, auth_header):
        resp = client.post(
            "/api/users",
            json={"username": "", "email": "a@b.com"},
            headers=auth_header,
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 4. Update user validation (lines 179-180, 188-192)
# ---------------------------------------------------------------------------


class TestUpdateUserValidation:
    """PATCH /api/users/<id> with invalid data."""

    def test_no_body_returns_400(self, client, admin_service, admin_user, auth_header):
        target = admin_service.add_user(username="target")
        resp = client.patch(
            f"/api/users/{target.id}",
            headers=auth_header,
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "JSON" in resp.get_json()["detail"]

    def test_invalid_role_returns_400(self, client, admin_service, admin_user, auth_header):
        target = admin_service.add_user(username="target2")
        resp = client.patch(
            f"/api/users/{target.id}",
            json={"role": "superadmin"},
            headers=auth_header,
        )
        assert resp.status_code == 400
        assert "superadmin" in resp.get_json()["detail"]

    def test_valid_role_accepted(self, client, admin_service, admin_user, auth_header):
        target = admin_service.add_user(username="target3")
        resp = client.patch(
            f"/api/users/{target.id}",
            json={"role": "auditor"},
            headers=auth_header,
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 5. Audit log cursor pagination (lines 272-276, 291)
# ---------------------------------------------------------------------------


class TestAuditLogCursorPagination:
    """GET /api/audit-log with cursor and filters."""

    def test_invalid_cursor_returns_400(self, client, admin_user, auth_header):
        resp = client.get(
            "/api/audit-log?cursor=not-valid-base64-uuid",
            headers=auth_header,
        )
        assert resp.status_code == 400
        assert "cursor" in resp.get_json()["detail"].lower()

    def test_valid_cursor_filters_entries(
        self,
        client,
        admin_service,
        admin_user,
        auth_header,
    ):
        """With cursor, entries with id < cursor_id are kept."""
        from acmeeh.admin.pagination import encode_cursor

        id1 = uuid4()
        id2 = uuid4()
        id3 = uuid4()
        entries = [
            AuditLogEntry(id=id1, action="a1"),
            AuditLogEntry(id=id2, action="a2"),
            AuditLogEntry(id=id3, action="a3"),
        ]
        admin_service._audit_entries = entries

        # Encode cursor that would filter to entries with id < id2
        cursor = encode_cursor(id2)
        resp = client.get(
            f"/api/audit-log?cursor={cursor}",
            headers=auth_header,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        # Only entries whose id < id2 survive the cursor filter
        returned_ids = {e["id"] for e in data}
        assert str(id2) not in returned_ids

    def test_with_action_filter_calls_search(
        self,
        client,
        admin_service,
        admin_user,
        auth_header,
    ):
        """When filters are present, search_audit_log is used instead of
        get_audit_log."""
        entry = AuditLogEntry(id=uuid4(), action="user.login")
        admin_service._audit_entries = [entry]

        resp = client.get(
            "/api/audit-log?action=user.login",
            headers=auth_header,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["action"] == "user.login"


# ---------------------------------------------------------------------------
# 6. EAB create with no body (lines 334-335)
# ---------------------------------------------------------------------------


class TestCreateEabNoBody:
    """POST /api/eab with no JSON body."""

    def test_no_body_returns_400(self, client, admin_user, auth_header):
        resp = client.post(
            "/api/eab",
            headers=auth_header,
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "JSON" in resp.get_json()["detail"]

    def test_empty_kid_returns_400(self, client, admin_user, auth_header):
        resp = client.post(
            "/api/eab",
            json={"kid": ""},
            headers=auth_header,
        )
        assert resp.status_code == 400
        assert "kid" in resp.get_json()["detail"].lower()


# ---------------------------------------------------------------------------
# 7. Create allowed identifier with no body (lines 410-411)
# ---------------------------------------------------------------------------


class TestCreateAllowedIdentifierValidation:
    """POST /api/allowed-identifiers with invalid data."""

    def test_no_body_returns_400(self, client, admin_user, auth_header):
        resp = client.post(
            "/api/allowed-identifiers",
            headers=auth_header,
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "JSON" in resp.get_json()["detail"]

    def test_missing_type_returns_400(self, client, admin_user, auth_header):
        resp = client.post(
            "/api/allowed-identifiers",
            json={"value": "example.com"},
            headers=auth_header,
        )
        assert resp.status_code == 400
        assert "type" in resp.get_json()["detail"].lower()

    def test_missing_value_returns_400(self, client, admin_user, auth_header):
        resp = client.post(
            "/api/allowed-identifiers",
            json={"type": "dns"},
            headers=auth_header,
        )
        assert resp.status_code == 400
        assert "value" in resp.get_json()["detail"].lower()


# ---------------------------------------------------------------------------
# 8. CSR profile validate endpoint (lines 623-641)
# ---------------------------------------------------------------------------


class TestValidateCsrProfile:
    """POST /api/csr-profiles/<id>/validate."""

    def test_no_body_returns_400(
        self,
        client,
        admin_service,
        admin_user,
        auth_header,
    ):
        profile = admin_service.create_csr_profile(
            "test-profile",
            {"common_name_regex": ".*"},
        )
        resp = client.post(
            f"/api/csr-profiles/{profile.id}/validate",
            headers=auth_header,
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "JSON" in resp.get_json()["detail"]

    def test_missing_csr_returns_400(
        self,
        client,
        admin_service,
        admin_user,
        auth_header,
    ):
        profile = admin_service.create_csr_profile(
            "test-profile2",
            {"common_name_regex": ".*"},
        )
        resp = client.post(
            f"/api/csr-profiles/{profile.id}/validate",
            json={"csr": ""},
            headers=auth_header,
        )
        assert resp.status_code == 400
        assert "csr" in resp.get_json()["detail"].lower()

    def test_valid_csr_calls_service(
        self,
        client,
        admin_service,
        admin_user,
        auth_header,
    ):
        profile = admin_service.create_csr_profile(
            "test-profile3",
            {"common_name_regex": ".*"},
        )
        resp = client.post(
            f"/api/csr-profiles/{profile.id}/validate",
            json={"csr": "dGVzdA=="},
            headers=auth_header,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["valid"] is True


# ---------------------------------------------------------------------------
# 9. Update CSR profile validation (lines 673-674, 680-681, 687-688)
# ---------------------------------------------------------------------------


class TestUpdateCsrProfileValidation:
    """PUT /api/csr-profiles/<id> with invalid data."""

    def test_no_body_returns_400(
        self,
        client,
        admin_service,
        admin_user,
        auth_header,
    ):
        profile = admin_service.create_csr_profile(
            "upd-profile1",
            {"common_name_regex": ".*"},
        )
        resp = client.put(
            f"/api/csr-profiles/{profile.id}",
            headers=auth_header,
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "JSON" in resp.get_json()["detail"]

    def test_missing_name_returns_400(
        self,
        client,
        admin_service,
        admin_user,
        auth_header,
    ):
        profile = admin_service.create_csr_profile(
            "upd-profile2",
            {"common_name_regex": ".*"},
        )
        resp = client.put(
            f"/api/csr-profiles/{profile.id}",
            json={"profile_data": {}},
            headers=auth_header,
        )
        assert resp.status_code == 400
        assert "name" in resp.get_json()["detail"].lower()

    def test_missing_profile_data_returns_400(
        self,
        client,
        admin_service,
        admin_user,
        auth_header,
    ):
        profile = admin_service.create_csr_profile(
            "upd-profile3",
            {"common_name_regex": ".*"},
        )
        resp = client.put(
            f"/api/csr-profiles/{profile.id}",
            json={"name": "new-name"},
            headers=auth_header,
        )
        assert resp.status_code == 400
        assert "profile_data" in resp.get_json()["detail"].lower()

    def test_valid_update_succeeds(
        self,
        client,
        admin_service,
        admin_user,
        auth_header,
    ):
        profile = admin_service.create_csr_profile(
            "upd-profile4",
            {"common_name_regex": ".*"},
        )
        resp = client.put(
            f"/api/csr-profiles/{profile.id}",
            json={
                "name": "renamed",
                "profile_data": {"common_name_regex": "^test\\."},
                "description": "Updated",
            },
            headers=auth_header,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["name"] == "renamed"


# ---------------------------------------------------------------------------
# 10. Notification pagination Link header (lines 815-820)
# ---------------------------------------------------------------------------


class TestNotificationPagination:
    """GET /api/notifications with pagination triggering Link header."""

    def test_link_header_present_when_has_next(
        self,
        client,
        admin_service,
        admin_user,
        auth_header,
    ):
        """When more than limit+1 notifications, a Link header is set."""
        # Create 3 notifications, request with limit=2
        for i in range(3):
            admin_service._notifications.append(
                Notification(
                    id=uuid4(),
                    notification_type=NotificationType.DELIVERY_SUCCEEDED,
                    recipient=f"user{i}@example.com",
                    subject=f"Test {i}",
                    body=f"Body {i}",
                    status=NotificationStatus.SENT,
                ),
            )

        resp = client.get(
            "/api/notifications?limit=2",
            headers=auth_header,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 2
        assert "Link" in resp.headers
        assert 'rel="next"' in resp.headers["Link"]

    def test_no_link_header_when_no_next(
        self,
        client,
        admin_service,
        admin_user,
        auth_header,
    ):
        """When results fit in one page, no Link header."""
        admin_service._notifications.append(
            Notification(
                id=uuid4(),
                notification_type=NotificationType.DELIVERY_SUCCEEDED,
                recipient="user@example.com",
                subject="Test",
                body="Body",
                status=NotificationStatus.SENT,
            ),
        )

        resp = client.get(
            "/api/notifications?limit=50",
            headers=auth_header,
        )
        assert resp.status_code == 200
        assert "Link" not in resp.headers


# ---------------------------------------------------------------------------
# 11. Certificate search pagination Link header (lines 906-911)
# ---------------------------------------------------------------------------


class TestCertificateSearchPagination:
    """GET /api/certificates with pagination triggering Link header."""

    def test_link_header_present_when_has_next(
        self,
        client,
        admin_service,
        admin_user,
        auth_header,
    ):
        now = datetime.now(UTC)
        for i in range(3):
            admin_service._certificates.append(
                FakeCertificate(
                    id=uuid4(),
                    account_id=uuid4(),
                    order_id=uuid4(),
                    serial_number=f"SN{i:04d}",
                    fingerprint=f"fp{i:032d}",
                    not_before_cert=now - timedelta(days=10),
                    not_after_cert=now + timedelta(days=80),
                    san_values=[f"host{i}.example.com"],
                ),
            )

        resp = client.get(
            "/api/certificates?limit=2",
            headers=auth_header,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 2
        assert "Link" in resp.headers
        assert 'rel="next"' in resp.headers["Link"]


# ---------------------------------------------------------------------------
# 12. Get certificate by fingerprint (lines 939-951)
# ---------------------------------------------------------------------------


class TestGetCertificateByFingerprint:
    """GET /api/certificates/by-fingerprint/<fp>."""

    def test_found_returns_cert(
        self,
        app,
        cert_repo,
        admin_user,
        auth_header,
    ):
        now = datetime.now(UTC)
        cert = FakeCertificate(
            id=uuid4(),
            account_id=uuid4(),
            order_id=uuid4(),
            serial_number="FP-SERIAL",
            fingerprint="aabbccdd1122334455",
            not_before_cert=now - timedelta(days=10),
            not_after_cert=now + timedelta(days=80),
            san_values=["fp.example.com"],
        )
        cert_repo.certs["aabbccdd1122334455"] = cert

        with app.test_client() as c:
            resp = c.get(
                "/api/certificates/by-fingerprint/aabbccdd1122334455",
                headers=auth_header,
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["serial_number"] == "FP-SERIAL"
        assert data["fingerprint"] == "aabbccdd1122334455"

    def test_not_found_returns_404(
        self,
        app,
        cert_repo,
        admin_user,
        auth_header,
    ):
        with app.test_client() as c:
            resp = c.get(
                "/api/certificates/by-fingerprint/nonexistent",
                headers=auth_header,
            )
        assert resp.status_code == 404
        data = resp.get_json()
        assert "nonexistent" in data["detail"]


# ---------------------------------------------------------------------------
# 13. Bulk revoke - account_id, issued_before, serial_numbers filters
#     (lines 1122, 1126, 1139-1140)
# ---------------------------------------------------------------------------


class TestBulkRevokeFilterFields:
    """POST /api/certificates/bulk-revoke with various filter fields."""

    @patch("acmeeh.admin.routes.security_events")
    def test_account_id_filter(
        self,
        _mock_sec,
        app,
        admin_service,
        cert_repo,
        admin_user,
        auth_header,
    ):
        cid = uuid4()
        admin_service._certificates = [
            FakeCertificate(
                id=cid,
                account_id=uuid4(),
                order_id=uuid4(),
                serial_number="ACC001",
                fingerprint="fp1",
                not_before_cert=datetime.now(UTC),
                not_after_cert=datetime.now(UTC),
            ),
        ]

        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                json={
                    "filter": {"account_id": str(uuid4())},
                    "dry_run": True,
                },
                headers=auth_header,
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["dry_run"] is True

    @patch("acmeeh.admin.routes.security_events")
    def test_issued_before_filter(
        self,
        _mock_sec,
        app,
        admin_service,
        cert_repo,
        admin_user,
        auth_header,
    ):
        cid = uuid4()
        admin_service._certificates = [
            FakeCertificate(
                id=cid,
                account_id=uuid4(),
                order_id=uuid4(),
                serial_number="IB001",
                fingerprint="fp2",
                not_before_cert=datetime.now(UTC),
                not_after_cert=datetime.now(UTC),
            ),
        ]

        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                json={
                    "filter": {"issued_before": "2026-01-01T00:00:00Z"},
                    "dry_run": True,
                },
                headers=auth_header,
            )
        assert resp.status_code == 200

    @patch("acmeeh.admin.routes.security_events")
    def test_serial_numbers_filter(
        self,
        _mock_sec,
        app,
        admin_service,
        cert_repo,
        admin_user,
        auth_header,
    ):
        cid1 = uuid4()
        cid2 = uuid4()
        admin_service._certificates = [
            FakeCertificate(
                id=cid1,
                account_id=uuid4(),
                order_id=uuid4(),
                serial_number="SN001",
                fingerprint="fp3",
                not_before_cert=datetime.now(UTC),
                not_after_cert=datetime.now(UTC),
            ),
            FakeCertificate(
                id=cid2,
                account_id=uuid4(),
                order_id=uuid4(),
                serial_number="SN002",
                fingerprint="fp4",
                not_before_cert=datetime.now(UTC),
                not_after_cert=datetime.now(UTC),
            ),
        ]

        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                json={
                    "filter": {"serial_numbers": ["SN001"]},
                    "dry_run": True,
                },
                headers=auth_header,
            )
        assert resp.status_code == 200
        data = resp.get_json()
        # Only SN001 should match the serial_numbers filter
        assert data["matching_certificates"] == 1
        assert "SN001" in data["serial_numbers"]

    @patch("acmeeh.admin.routes.security_events")
    def test_serial_numbers_filter_actual_revoke(
        self,
        _mock_sec,
        app,
        admin_service,
        cert_repo,
        admin_user,
        auth_header,
    ):
        """Non-dry-run with serial_numbers filter performs revocation."""
        cid1 = uuid4()
        cid2 = uuid4()
        admin_service._certificates = [
            FakeCertificate(
                id=cid1,
                account_id=uuid4(),
                order_id=uuid4(),
                serial_number="SN001",
                fingerprint="fp5",
                not_before_cert=datetime.now(UTC),
                not_after_cert=datetime.now(UTC),
            ),
            FakeCertificate(
                id=cid2,
                account_id=uuid4(),
                order_id=uuid4(),
                serial_number="SN002",
                fingerprint="fp6",
                not_before_cert=datetime.now(UTC),
                not_after_cert=datetime.now(UTC),
            ),
        ]

        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                json={
                    "filter": {"serial_numbers": ["SN001"]},
                    "dry_run": False,
                },
                headers=auth_header,
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["revoked"] == 1
        assert len(cert_repo.revoked) == 1
        assert cert_repo.revoked[0][0] == cid1


# ---------------------------------------------------------------------------
# 14. Bulk revoke error handling (lines 1167-1168)
# ---------------------------------------------------------------------------


class TestBulkRevokeErrorHandling:
    """POST /api/certificates/bulk-revoke when revoke() raises."""

    @patch("acmeeh.admin.routes.security_events")
    def test_revoke_error_captured_in_response(
        self,
        _mock_sec,
        app,
        admin_service,
        cert_repo,
        admin_user,
        auth_header,
    ):
        cid = uuid4()
        admin_service._certificates = [
            FakeCertificate(
                id=cid,
                account_id=uuid4(),
                order_id=uuid4(),
                serial_number="ERR001",
                fingerprint="fperr",
                not_before_cert=datetime.now(UTC),
                not_after_cert=datetime.now(UTC),
            ),
        ]
        cert_repo.revoke_raises[cid] = RuntimeError("DB connection lost")

        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                json={
                    "filter": {"domain": "example.com"},
                    "dry_run": False,
                },
                headers=auth_header,
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["revoked"] == 0
        assert len(data["errors"]) == 1
        assert data["errors"][0]["serial_number"] == "ERR001"
        assert "DB connection lost" in data["errors"][0]["error"]


# ===========================================================================
# SERVICE TESTS — AdminUserService missing-repo guards
# ===========================================================================


@pytest.fixture()
def svc_settings():
    return AdminApiSettings(
        enabled=True,
        base_path="/api",
        token_secret="test-svc-secret",
        token_expiry_seconds=3600,
        initial_admin_email="admin@example.com",
        password_length=20,
        default_page_size=50,
        max_page_size=1000,
    )


@pytest.fixture()
def svc_user_repo():
    return MagicMock()


@pytest.fixture()
def svc_audit_repo():
    return MagicMock()


@pytest.fixture()
def bare_service(svc_user_repo, svc_audit_repo, svc_settings):
    """Service with NO optional repos (all None)."""
    return AdminUserService(
        user_repo=svc_user_repo,
        audit_repo=svc_audit_repo,
        settings=svc_settings,
    )


@pytest.fixture()
def full_service(svc_user_repo, svc_audit_repo, svc_settings):
    """Service with all optional repos wired up as mocks."""
    return AdminUserService(
        user_repo=svc_user_repo,
        audit_repo=svc_audit_repo,
        settings=svc_settings,
        eab_repo=MagicMock(),
        allowlist_repo=MagicMock(),
        csr_profile_repo=MagicMock(),
        notification_repo=MagicMock(),
        cert_repo=MagicMock(),
    )


# ---------------------------------------------------------------------------
# reset_password when update_password returns None (lines 235-236)
# ---------------------------------------------------------------------------


class TestResetPasswordUpdateFails:
    """reset_password raises 500 when update_password returns None."""

    def test_update_password_returns_none_raises_500(
        self,
        bare_service,
        svc_user_repo,
    ):
        user = MagicMock()
        user.id = uuid4()
        svc_user_repo.find_by_id.return_value = user
        svc_user_repo.update_password.return_value = None

        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.reset_password(user.id)
        assert exc_info.value.status == 500
        assert "update password" in exc_info.value.detail.lower()


# ---------------------------------------------------------------------------
# EAB repo guards (lines 475-476, 500-501, 516-517)
# ---------------------------------------------------------------------------


class TestEabRepoGuards:
    """EAB methods raise 503 when _eab is None."""

    def test_get_eab_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.get_eab(uuid4())
        assert exc_info.value.status == 503
        assert "not available" in exc_info.value.detail.lower()

    def test_revoke_eab_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.revoke_eab(uuid4())
        assert exc_info.value.status == 503
        assert "not available" in exc_info.value.detail.lower()

    def test_revoke_eab_revoke_returns_none_raises_500(self, full_service):
        cred = MagicMock()
        full_service._eab.find_by_id.return_value = cred
        full_service._eab.revoke.return_value = None

        with pytest.raises(AcmeProblem) as exc_info:
            full_service.revoke_eab(uuid4())
        assert exc_info.value.status == 500
        assert "failed" in exc_info.value.detail.lower()


# ---------------------------------------------------------------------------
# Allowlist repo guards (lines 536, 553-554, 635-636, 663-664, 701-702,
# 742-743, 751-752, 776)
# ---------------------------------------------------------------------------


class TestAllowlistRepoGuards:
    """Allowlist methods raise 503 when _allowlist is None."""

    def test_create_allowed_identifier_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.create_allowed_identifier("dns", "example.com")
        assert exc_info.value.status == 503

    def test_get_allowed_identifier_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.get_allowed_identifier(uuid4())
        assert exc_info.value.status == 503

    def test_delete_allowed_identifier_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.delete_allowed_identifier(uuid4())
        assert exc_info.value.status == 503

    def test_add_identifier_account_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.add_identifier_account(uuid4(), uuid4())
        assert exc_info.value.status == 503

    def test_remove_identifier_account_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.remove_identifier_account(uuid4(), uuid4())
        assert exc_info.value.status == 503

    def test_list_account_identifiers_no_repo_returns_empty(self, bare_service):
        result = bare_service.list_account_identifiers(uuid4())
        assert result == []


# ---------------------------------------------------------------------------
# CSR profile repo guards (lines 793-794, 848, 868-869, 917, 927-928,
# 960-961, 975-976, 999-1000, 1026-1027, 1062-1063, 1101-1102, 1133)
# ---------------------------------------------------------------------------


class TestCsrProfileRepoGuards:
    """CSR profile methods raise 503 when _csr_profiles is None."""

    def test_validate_csr_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.validate_csr(uuid4(), "dGVzdA==")
        assert exc_info.value.status == 503

    def test_create_csr_profile_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.create_csr_profile("test", {})
        assert exc_info.value.status == 503

    def test_list_csr_profiles_no_repo_returns_empty(self, bare_service):
        result = bare_service.list_csr_profiles()
        assert result == []

    def test_get_csr_profile_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.get_csr_profile(uuid4())
        assert exc_info.value.status == 503

    def test_update_csr_profile_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.update_csr_profile(uuid4(), "name", {})
        assert exc_info.value.status == 503

    def test_update_csr_profile_returns_none_raises_500(self, full_service):
        """update_csr_profile raises 500 when update_profile returns None."""
        profile = MagicMock()
        profile.name = "existing"
        full_service._csr_profiles.find_by_id.return_value = profile
        full_service._csr_profiles.find_by_name.return_value = None
        full_service._csr_profiles.update_profile.return_value = None

        with pytest.raises(AcmeProblem) as exc_info:
            full_service.update_csr_profile(uuid4(), "newname", {})
        assert exc_info.value.status == 500
        assert "failed" in exc_info.value.detail.lower()

    def test_delete_csr_profile_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.delete_csr_profile(uuid4())
        assert exc_info.value.status == 503

    def test_assign_profile_to_account_no_repo_raises_503(self, bare_service):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.assign_profile_to_account(uuid4(), uuid4())
        assert exc_info.value.status == 503

    def test_unassign_profile_from_account_no_repo_raises_503(
        self,
        bare_service,
    ):
        with pytest.raises(AcmeProblem) as exc_info:
            bare_service.unassign_profile_from_account(uuid4(), uuid4())
        assert exc_info.value.status == 503

    def test_get_account_csr_profile_no_repo_returns_none(self, bare_service):
        result = bare_service.get_account_csr_profile(uuid4())
        assert result is None


# ---------------------------------------------------------------------------
# _validate_profile_data edge cases (lines 1146-1147, 1160-1161, 1188-1189)
# ---------------------------------------------------------------------------


class TestValidateProfileDataEdgeCases:
    """Cover edge cases in _validate_profile_data static method."""

    def test_profile_data_not_dict_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data("not a dict")
        assert exc_info.value.status == 400
        assert "JSON object" in exc_info.value.detail

    def test_regex_field_not_string_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data(
                {"common_name_regex": 123},
            )
        assert exc_info.value.status == 400
        assert "string" in exc_info.value.detail.lower()

    def test_invalid_regex_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data(
                {"common_name_regex": "[invalid"},
            )
        assert exc_info.value.status == 400
        assert "regex" in exc_info.value.detail.lower()

    def test_authorized_keys_non_numeric_value_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data(
                {"authorized_keys": {"RSA": "not-a-number"}},
            )
        assert exc_info.value.status == 400
        assert "number" in exc_info.value.detail.lower()

    def test_authorized_keys_valid_passes(self):
        # Should not raise
        AdminUserService._validate_profile_data(
            {"authorized_keys": {"RSA": 2048, "EC": 256}},
        )

    def test_list_field_not_list_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data(
                {"authorized_signature_algorithms": "not-a-list"},
            )
        assert exc_info.value.status == 400
        assert "JSON array" in exc_info.value.detail

    def test_integer_field_not_int_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data(
                {"common_name_minimum": "ten"},
            )
        assert exc_info.value.status == 400
        assert "integer" in exc_info.value.detail.lower()

    def test_boolean_field_not_bool_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data(
                {"wildcard_in_common_name": "yes"},
            )
        assert exc_info.value.status == 400
        assert "boolean" in exc_info.value.detail.lower()

    def test_max_subdomain_depth_negative_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data(
                {"max_subdomain_depth": -1},
            )
        assert exc_info.value.status == 400
        assert ">= 0" in exc_info.value.detail

    def test_depth_base_domains_bad_entry_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data(
                {"depth_base_domains": ["example.com", ""]},
            )
        assert exc_info.value.status == 400
        assert "non-empty string" in exc_info.value.detail

    def test_depth_base_domains_non_string_entry_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data(
                {"depth_base_domains": ["example.com", 42]},
            )
        assert exc_info.value.status == 400

    def test_san_regex_not_string_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data(
                {"san_regex": 999},
            )
        assert exc_info.value.status == 400
        assert "string" in exc_info.value.detail.lower()

    def test_subject_regex_invalid_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data(
                {"subject_regex": "(unclosed"},
            )
        assert exc_info.value.status == 400
        assert "regex" in exc_info.value.detail.lower()

    def test_authorized_keys_not_dict_raises_400(self):
        with pytest.raises(AcmeProblem) as exc_info:
            AdminUserService._validate_profile_data(
                {"authorized_keys": "not a dict"},
            )
        assert exc_info.value.status == 400
        assert "JSON object" in exc_info.value.detail

    def test_valid_complete_profile_passes(self):
        """A fully populated valid profile_data should not raise."""
        AdminUserService._validate_profile_data(
            {
                "common_name_regex": r"^[\w.]+\.example\.com$",
                "san_regex": r"^[\w.]+\.example\.com$",
                "subject_regex": r".*",
                "authorized_keys": {"RSA": 2048, "EC": 384},
                "authorized_signature_algorithms": ["sha256WithRSAEncryption"],
                "authorized_key_usages": ["digitalSignature"],
                "authorized_extended_key_usages": ["serverAuth"],
                "san_types": ["dns"],
                "depth_base_domains": ["example.com"],
                "common_name_minimum": 1,
                "common_name_maximum": 64,
                "san_minimum": 1,
                "san_maximum": 100,
                "renewal_window_days": 30,
                "max_subdomain_depth": 3,
                "wildcard_in_common_name": False,
                "wildcard_in_san": True,
                "reuse_key": False,
            }
        )


# ---------------------------------------------------------------------------
# Additional service.py coverage: allowlist not-found guards that go through
# the "repo exists but find_by_id returns None" paths
# ---------------------------------------------------------------------------


class TestAllowlistNotFoundGuards:
    """Allowlist methods raise 404 when entity not found (repo exists)."""

    def test_get_allowed_identifier_not_found(self, full_service):
        full_service._allowlist.find_one_with_accounts.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            full_service.get_allowed_identifier(uuid4())
        assert exc_info.value.status == 404

    def test_delete_allowed_identifier_not_found(self, full_service):
        full_service._allowlist.find_by_id.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            full_service.delete_allowed_identifier(uuid4())
        assert exc_info.value.status == 404

    def test_add_identifier_account_not_found(self, full_service):
        full_service._allowlist.find_by_id.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            full_service.add_identifier_account(uuid4(), uuid4())
        assert exc_info.value.status == 404

    def test_remove_identifier_account_not_found(self, full_service):
        full_service._allowlist.find_by_id.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            full_service.remove_identifier_account(uuid4(), uuid4())
        assert exc_info.value.status == 404


# ---------------------------------------------------------------------------
# Additional service.py coverage: CSR profile not-found guards
# ---------------------------------------------------------------------------


class TestCsrProfileNotFoundGuards:
    """CSR profile methods raise 404 when entity not found (repo exists)."""

    def test_get_csr_profile_not_found(self, full_service):
        full_service._csr_profiles.find_by_id.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            full_service.get_csr_profile(uuid4())
        assert exc_info.value.status == 404

    def test_update_csr_profile_not_found(self, full_service):
        full_service._csr_profiles.find_by_id.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            full_service.update_csr_profile(uuid4(), "name", {})
        assert exc_info.value.status == 404

    def test_update_csr_profile_empty_name_raises_400(self, full_service):
        profile = MagicMock()
        profile.name = "existing"
        full_service._csr_profiles.find_by_id.return_value = profile

        with pytest.raises(AcmeProblem) as exc_info:
            full_service.update_csr_profile(uuid4(), "", {})
        assert exc_info.value.status == 400
        assert "name" in exc_info.value.detail.lower()

    def test_delete_csr_profile_not_found(self, full_service):
        full_service._csr_profiles.find_by_id.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            full_service.delete_csr_profile(uuid4())
        assert exc_info.value.status == 404

    def test_assign_profile_to_account_not_found(self, full_service):
        full_service._csr_profiles.find_by_id.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            full_service.assign_profile_to_account(uuid4(), uuid4())
        assert exc_info.value.status == 404

    def test_unassign_profile_from_account_not_found(self, full_service):
        full_service._csr_profiles.find_by_id.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            full_service.unassign_profile_from_account(uuid4(), uuid4())
        assert exc_info.value.status == 404
