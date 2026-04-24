"""Tests for admin user service."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from acmeeh.admin.models import AdminUser, AuditLogEntry, EabCredential
from acmeeh.admin.service import AdminUserService
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import AdminRole

# ---------------------------------------------------------------------------
# Stub repositories (in-memory)
# ---------------------------------------------------------------------------


class StubAdminUserRepo:
    """In-memory stub for AdminUserRepository."""

    def __init__(self):
        self._users: dict[UUID, AdminUser] = {}

    def create(self, entity: AdminUser) -> AdminUser:
        self._users[entity.id] = entity
        return entity

    def find_by_id(self, id_: UUID) -> AdminUser | None:
        return self._users.get(id_)

    def find_by_username(self, username: str) -> AdminUser | None:
        for u in self._users.values():
            if u.username == username:
                return u
        return None

    def find_all(self) -> list[AdminUser]:
        return list(self._users.values())

    def delete(self, id_: UUID) -> bool:
        return self._users.pop(id_, None) is not None

    def count_all(self) -> int:
        return len(self._users)

    def update_password(self, user_id: UUID, password_hash: str) -> AdminUser | None:
        user = self._users.get(user_id)
        if user is None:
            return None
        from dataclasses import replace

        updated = replace(user, password_hash=password_hash)
        self._users[user_id] = updated
        return updated

    def update_enabled(self, user_id: UUID, enabled: bool) -> AdminUser | None:
        user = self._users.get(user_id)
        if user is None:
            return None
        from dataclasses import replace

        updated = replace(user, enabled=enabled)
        self._users[user_id] = updated
        return updated

    def update_role(self, user_id: UUID, role: AdminRole) -> AdminUser | None:
        user = self._users.get(user_id)
        if user is None:
            return None
        from dataclasses import replace

        updated = replace(user, role=role)
        self._users[user_id] = updated
        return updated

    def update_last_login(self, user_id: UUID) -> None:
        pass  # no-op for testing


class StubEabRepo:
    """In-memory stub for EabCredentialRepository."""

    def __init__(self):
        self._creds: dict[UUID, EabCredential] = {}

    def create(self, entity: EabCredential) -> EabCredential:
        self._creds[entity.id] = entity
        return entity

    def find_by_id(self, id_: UUID) -> EabCredential | None:
        return self._creds.get(id_)

    def find_by_kid(self, kid: str) -> EabCredential | None:
        for c in self._creds.values():
            if c.kid == kid:
                return c
        return None

    def find_all_ordered(self) -> list[EabCredential]:
        return sorted(self._creds.values(), key=lambda c: c.created_at, reverse=True)

    def mark_used(self, kid: str, account_id: UUID) -> EabCredential | None:
        for c in self._creds.values():
            if c.kid == kid and not c.used and not c.revoked:
                from dataclasses import replace

                updated = replace(c, used=True, account_id=account_id)
                self._creds[c.id] = updated
                return updated
        return None

    def revoke(self, cred_id: UUID) -> EabCredential | None:
        cred = self._creds.get(cred_id)
        if cred is None:
            return None
        from dataclasses import replace

        updated = replace(cred, revoked=True)
        self._creds[cred_id] = updated
        return updated


class StubAuditLogRepo:
    """In-memory stub for AuditLogRepository."""

    def __init__(self):
        self.entries: list[AuditLogEntry] = []

    def create(self, entity: AuditLogEntry) -> AuditLogEntry:
        self.entries.append(entity)
        return entity

    def find_recent(self, limit: int = 100) -> list[AuditLogEntry]:
        return sorted(self.entries, key=lambda e: e.created_at, reverse=True)[:limit]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_settings(**overrides) -> AdminApiSettings:
    defaults = dict(
        enabled=True,
        base_path="/api",
        token_secret="test-secret-for-tokens",
        token_expiry_seconds=3600,
        initial_admin_email="admin@example.com",
        password_length=20,
        default_page_size=50,
        max_page_size=1000,
    )
    defaults.update(overrides)
    return AdminApiSettings(**defaults)


@pytest.fixture()
def user_repo():
    return StubAdminUserRepo()


@pytest.fixture()
def audit_repo():
    return StubAuditLogRepo()


@pytest.fixture()
def settings():
    return _make_settings()


@pytest.fixture()
def eab_repo():
    return StubEabRepo()


@pytest.fixture()
def service(user_repo, audit_repo, settings):
    return AdminUserService(user_repo, audit_repo, settings)


@pytest.fixture()
def eab_service(user_repo, audit_repo, settings, eab_repo):
    return AdminUserService(user_repo, audit_repo, settings, eab_repo=eab_repo)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBootstrapAdmin:
    def test_creates_admin_when_empty(self, service, user_repo):
        pw = service.bootstrap_admin("admin@example.com")
        assert pw is not None
        assert len(pw) == 20
        assert user_repo.count_all() == 1
        user = user_repo.find_by_username("admin")
        assert user is not None
        assert user.role == AdminRole.ADMIN
        assert user.enabled is True

    def test_noop_when_users_exist(self, service, user_repo):
        service.bootstrap_admin("admin@example.com")
        pw = service.bootstrap_admin("admin2@example.com")
        assert pw is None
        assert user_repo.count_all() == 1

    def test_audit_log_entry(self, service, audit_repo):
        service.bootstrap_admin("admin@example.com")
        assert len(audit_repo.entries) == 1
        assert audit_repo.entries[0].action == "bootstrap_admin"


class TestAuthenticate:
    def test_valid_credentials(self, service):
        user, pw = service.create_user("testuser", "test@example.com")
        auth_user, token = service.authenticate("testuser", pw)
        assert auth_user.username == "testuser"
        assert token is not None

    def test_wrong_password(self, service):
        service.create_user("testuser", "test@example.com")
        with pytest.raises(Exception) as exc_info:
            service.authenticate("testuser", "wrongpassword")
        assert "401" in str(exc_info.value.status)

    def test_unknown_user(self, service):
        with pytest.raises(Exception):
            service.authenticate("nonexistent", "password")

    def test_disabled_user(self, service, user_repo):
        user, pw = service.create_user("testuser", "test@example.com")
        service.update_user(user.id, enabled=False)
        with pytest.raises(Exception) as exc_info:
            service.authenticate("testuser", pw)
        assert "401" in str(exc_info.value.status)


class TestCreateUser:
    def test_creates_user(self, service, user_repo):
        user, pw = service.create_user("newuser", "new@example.com", AdminRole.AUDITOR)
        assert user.username == "newuser"
        assert user.email == "new@example.com"
        assert user.role == AdminRole.AUDITOR
        assert user.enabled is True
        assert pw is not None
        assert len(pw) == 20

    def test_duplicate_username_fails(self, service):
        service.create_user("dupuser", "first@example.com")
        with pytest.raises(Exception) as exc_info:
            service.create_user("dupuser", "second@example.com")
        assert "409" in str(exc_info.value.status)

    def test_audit_log(self, service, audit_repo):
        user, _ = service.create_user("audituser", "audit@example.com", actor_id=uuid4())
        create_entries = [e for e in audit_repo.entries if e.action == "create_user"]
        assert len(create_entries) == 1
        assert create_entries[0].target_user_id == user.id


class TestUpdateUser:
    def test_disable_user(self, service):
        user, _ = service.create_user("target", "t@example.com")
        updated = service.update_user(user.id, enabled=False)
        assert updated.enabled is False

    def test_change_role(self, service):
        user, _ = service.create_user("target", "t@example.com", AdminRole.AUDITOR)
        updated = service.update_user(user.id, role=AdminRole.ADMIN)
        assert updated.role == AdminRole.ADMIN

    def test_not_found(self, service):
        with pytest.raises(Exception) as exc_info:
            service.update_user(uuid4(), enabled=False)
        assert "404" in str(exc_info.value.status)


class TestDeleteUser:
    def test_deletes_user(self, service, user_repo):
        user, _ = service.create_user("target", "t@example.com")
        service.delete_user(user.id)
        assert user_repo.find_by_id(user.id) is None

    def test_not_found(self, service):
        with pytest.raises(Exception) as exc_info:
            service.delete_user(uuid4())
        assert "404" in str(exc_info.value.status)

    def test_audit_log(self, service, audit_repo):
        user, _ = service.create_user("target", "t@example.com")
        service.delete_user(user.id, actor_id=uuid4())
        delete_entries = [e for e in audit_repo.entries if e.action == "delete_user"]
        assert len(delete_entries) == 1


class TestResetPassword:
    def test_resets_password(self, service):
        user, old_pw = service.create_user("target", "t@example.com")
        updated, new_pw = service.reset_password(user.id)
        assert new_pw != old_pw
        assert len(new_pw) == 20

    def test_old_password_invalid_after_reset(self, service):
        user, old_pw = service.create_user("target", "t@example.com")
        _, new_pw = service.reset_password(user.id)
        # Old password should fail
        with pytest.raises(Exception):
            service.authenticate("target", old_pw)
        # New password should work
        auth_user, token = service.authenticate("target", new_pw)
        assert auth_user.username == "target"

    def test_not_found(self, service):
        with pytest.raises(Exception) as exc_info:
            service.reset_password(uuid4())
        assert "404" in str(exc_info.value.status)


class TestListAndGet:
    def test_list_users(self, service):
        service.create_user("user1", "u1@example.com")
        service.create_user("user2", "u2@example.com")
        users = service.list_users()
        assert len(users) == 2

    def test_get_user(self, service):
        user, _ = service.create_user("target", "t@example.com")
        found = service.get_user(user.id)
        assert found.username == "target"

    def test_get_nonexistent(self, service):
        with pytest.raises(Exception) as exc_info:
            service.get_user(uuid4())
        assert "404" in str(exc_info.value.status)


class TestAuditLog:
    def test_get_audit_log(self, service):
        service.create_user("user1", "u1@example.com")
        service.create_user("user2", "u2@example.com")
        log = service.get_audit_log()
        assert len(log) >= 2


class TestCreateEab:
    def test_creates_eab_with_generated_hmac(self, eab_service, eab_repo):
        cred = eab_service.create_eab("my-kid-001", label="Test credential")
        assert cred.kid == "my-kid-001"
        assert cred.label == "Test credential"
        assert cred.hmac_key  # non-empty
        assert len(cred.hmac_key) > 20  # base64url of 32 bytes
        assert not cred.used
        assert not cred.revoked
        assert eab_repo.find_by_kid("my-kid-001") is not None

    def test_hmac_key_is_base64url(self, eab_service):
        import base64

        cred = eab_service.create_eab("kid-b64-test")
        # Should decode without error (add padding back)
        padded = cred.hmac_key + "=" * (4 - len(cred.hmac_key) % 4)
        raw = base64.urlsafe_b64decode(padded)
        assert len(raw) == 32  # 256-bit key

    def test_duplicate_kid_fails(self, eab_service):
        eab_service.create_eab("dup-kid")
        with pytest.raises(Exception) as exc_info:
            eab_service.create_eab("dup-kid")
        assert "409" in str(exc_info.value.status)

    def test_empty_kid_fails(self, eab_service):
        with pytest.raises(Exception) as exc_info:
            eab_service.create_eab("")
        assert "400" in str(exc_info.value.status)

    def test_whitespace_kid_fails(self, eab_service):
        with pytest.raises(Exception) as exc_info:
            eab_service.create_eab("   ")
        assert "400" in str(exc_info.value.status)

    def test_audit_log_entry(self, eab_service, audit_repo):
        actor = uuid4()
        eab_service.create_eab("audit-kid", actor_id=actor)
        eab_entries = [e for e in audit_repo.entries if e.action == "create_eab"]
        assert len(eab_entries) == 1
        assert eab_entries[0].details["kid"] == "audit-kid"

    def test_unique_hmac_keys(self, eab_service):
        c1 = eab_service.create_eab("kid-1")
        c2 = eab_service.create_eab("kid-2")
        assert c1.hmac_key != c2.hmac_key

    def test_no_eab_repo_returns_503(self, service):
        """Service without eab_repo raises 503."""
        with pytest.raises(Exception) as exc_info:
            service.create_eab("kid-x")
        assert "503" in str(exc_info.value.status)


class TestListEab:
    def test_list_empty(self, eab_service):
        assert eab_service.list_eab() == []

    def test_list_returns_all(self, eab_service):
        eab_service.create_eab("kid-a")
        eab_service.create_eab("kid-b")
        creds = eab_service.list_eab()
        assert len(creds) == 2

    def test_list_without_repo(self, service):
        assert service.list_eab() == []


class TestGetEab:
    def test_get_existing(self, eab_service):
        cred = eab_service.create_eab("kid-get")
        found = eab_service.get_eab(cred.id)
        assert found.kid == "kid-get"

    def test_get_nonexistent(self, eab_service):
        with pytest.raises(Exception) as exc_info:
            eab_service.get_eab(uuid4())
        assert "404" in str(exc_info.value.status)


class StubAccountService:
    """In-memory stub for AccountService used to observe revoke() calls."""

    def __init__(self):
        self.calls: list[tuple[UUID, str]] = []
        # Account IDs whose revoke() should report CAS miss (i.e. not valid).
        self.already_not_valid: set[UUID] = set()

    def revoke(self, account_id: UUID, *, reason: str = ""):
        self.calls.append((account_id, reason))
        if account_id in self.already_not_valid:
            return None
        # Caller only checks ``is not None``; a truthy sentinel is enough.
        return object()


class StubAccountRepo:
    """Minimal AccountRepository stub — only the call paths exercised by
    ``revoke_eab`` are implemented."""

    def __init__(self):
        # Registered accounts keyed by id. Each entry: (eab_credential_id, status).
        self._accounts: dict[UUID, tuple[UUID | None, str]] = {}

    def register(self, account_id: UUID, eab_credential_id: UUID | None, status: str = "valid"):
        self._accounts[account_id] = (eab_credential_id, status)

    def find_valid_by_eab_credential(self, eab_credential_id: UUID):
        from types import SimpleNamespace

        return [
            SimpleNamespace(id=acc_id)
            for acc_id, (eab_id, status) in self._accounts.items()
            if eab_id == eab_credential_id and status == "valid"
        ]


@pytest.fixture()
def account_service():
    return StubAccountService()


@pytest.fixture()
def account_repo():
    return StubAccountRepo()


@pytest.fixture()
def eab_service_with_accounts(
    user_repo,
    audit_repo,
    settings,
    eab_repo,
    account_service,
    account_repo,
):
    return AdminUserService(
        user_repo,
        audit_repo,
        settings,
        eab_repo=eab_repo,
        account_service=account_service,
        account_repo=account_repo,
    )


class TestRevokeEab:
    def test_revoke_credential(self, eab_service):
        cred = eab_service.create_eab("kid-revoke")
        revoked = eab_service.revoke_eab(cred.id, actor_id=uuid4())
        assert revoked.revoked is True

    def test_revoke_nonexistent(self, eab_service):
        with pytest.raises(Exception) as exc_info:
            eab_service.revoke_eab(uuid4())
        assert "404" in str(exc_info.value.status)

    def test_revoke_audit_log(self, eab_service, audit_repo):
        cred = eab_service.create_eab("kid-rev-audit")
        eab_service.revoke_eab(cred.id, actor_id=uuid4())
        rev_entries = [e for e in audit_repo.entries if e.action == "revoke_eab"]
        assert len(rev_entries) == 1
        assert rev_entries[0].details["kid"] == "kid-rev-audit"

    def test_revoke_eab_with_no_linked_accounts(
        self,
        eab_service_with_accounts,
        audit_repo,
        account_service,
    ):
        """Revoking an EAB that was never used must not invoke the cascade."""
        cred = eab_service_with_accounts.create_eab("kid-unlinked")
        eab_service_with_accounts.revoke_eab(cred.id, actor_id=uuid4())

        assert account_service.calls == []
        rev_entries = [e for e in audit_repo.entries if e.action == "revoke_eab"]
        assert rev_entries[0].details["linked_accounts"] == []
        assert rev_entries[0].details["revoked_accounts"] == []

    def test_revoke_eab_cascades_to_single_account(
        self,
        eab_service_with_accounts,
        audit_repo,
        account_service,
        account_repo,
    ):
        """Revoke path on a simple one-account EAB."""
        cred = eab_service_with_accounts.create_eab("kid-single")
        acc_id = uuid4()
        account_repo.register(acc_id, cred.id)

        eab_service_with_accounts.revoke_eab(cred.id, actor_id=uuid4())

        assert account_service.calls == [(acc_id, "eab_revoked:kid-single")]
        details = next(e.details for e in audit_repo.entries if e.action == "revoke_eab")
        assert details["linked_accounts"] == [str(acc_id)]
        assert details["revoked_accounts"] == [str(acc_id)]

    def test_revoke_eab_cascades_to_all_reused_accounts(
        self,
        eab_service_with_accounts,
        audit_repo,
        account_service,
        account_repo,
    ):
        """With ``acme.eab_reusable=true`` an EAB can register many accounts
        over time. Revoking it must cascade to every one of them — not just
        the most recent binding, which is the only one the mutable
        ``eab_credentials.account_id`` pointer tracks."""
        cred = eab_service_with_accounts.create_eab("kid-reusable")
        first = uuid4()
        second = uuid4()
        third = uuid4()
        for acc_id in (first, second, third):
            account_repo.register(acc_id, cred.id)

        eab_service_with_accounts.revoke_eab(cred.id, actor_id=uuid4())

        cascaded = {call[0] for call in account_service.calls}
        assert cascaded == {first, second, third}
        reasons = {call[1] for call in account_service.calls}
        assert reasons == {"eab_revoked:kid-reusable"}

        details = next(e.details for e in audit_repo.entries if e.action == "revoke_eab")
        assert set(details["linked_accounts"]) == {str(first), str(second), str(third)}
        assert set(details["revoked_accounts"]) == {str(first), str(second), str(third)}

    def test_revoke_eab_skips_other_eabs(
        self,
        eab_service_with_accounts,
        account_service,
        account_repo,
    ):
        """Accounts registered with a *different* EAB must not be touched."""
        target = eab_service_with_accounts.create_eab("kid-target")
        other = eab_service_with_accounts.create_eab("kid-other")
        target_acc = uuid4()
        other_acc = uuid4()
        account_repo.register(target_acc, target.id)
        account_repo.register(other_acc, other.id)

        eab_service_with_accounts.revoke_eab(target.id, actor_id=uuid4())

        assert [call[0] for call in account_service.calls] == [target_acc]

    def test_revoke_eab_records_only_successful_cascades(
        self,
        eab_service_with_accounts,
        audit_repo,
        account_service,
        account_repo,
    ):
        """CAS-miss accounts (already deactivated/revoked) still appear in
        ``linked_accounts`` but not in ``revoked_accounts`` so an auditor
        can tell which registrations transitioned on this admin action."""
        cred = eab_service_with_accounts.create_eab("kid-mixed")
        fresh = uuid4()
        stale = uuid4()
        account_repo.register(fresh, cred.id)
        account_repo.register(stale, cred.id)
        account_service.already_not_valid.add(stale)

        eab_service_with_accounts.revoke_eab(cred.id, actor_id=uuid4())

        details = next(e.details for e in audit_repo.entries if e.action == "revoke_eab")
        assert set(details["linked_accounts"]) == {str(fresh), str(stale)}
        assert details["revoked_accounts"] == [str(fresh)]

    def test_revoke_eab_without_account_service_logs_warning(
        self,
        user_repo,
        audit_repo,
        settings,
        eab_repo,
        account_repo,
        caplog,
    ):
        """A deployment without AccountService wired in must not crash and
        must surface a warning so the operator notices the stale accounts."""
        import logging

        svc = AdminUserService(
            user_repo,
            audit_repo,
            settings,
            eab_repo=eab_repo,
            account_repo=account_repo,
        )
        cred = svc.create_eab("kid-no-service")
        acc_id = uuid4()
        account_repo.register(acc_id, cred.id)

        with caplog.at_level(logging.WARNING, logger="acmeeh.admin.service"):
            svc.revoke_eab(cred.id, actor_id=uuid4())

        details = next(e.details for e in audit_repo.entries if e.action == "revoke_eab")
        assert details["linked_accounts"] == [str(acc_id)]
        assert details["revoked_accounts"] == []
        assert any("AccountService is unavailable" in record.message for record in caplog.records)
