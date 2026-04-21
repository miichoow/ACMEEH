"""Tests for allowlist management in AdminUserService."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from acmeeh.admin.models import AllowedIdentifier, AuditLogEntry
from acmeeh.admin.service import AdminUserService
from acmeeh.config.settings import AdminApiSettings

# ---------------------------------------------------------------------------
# Stub repositories
# ---------------------------------------------------------------------------


class StubAllowlistRepo:
    """In-memory stub for AllowedIdentifierRepository."""

    def __init__(self):
        self._idents: dict[UUID, AllowedIdentifier] = {}
        self._associations: dict[UUID, set[UUID]] = {}  # ident_id → {account_ids}

    def create(self, entity: AllowedIdentifier) -> AllowedIdentifier:
        self._idents[entity.id] = entity
        return entity

    def find_by_id(self, id_: UUID) -> AllowedIdentifier | None:
        return self._idents.get(id_)

    def delete(self, id_: UUID) -> bool:
        self._associations.pop(id_, None)
        return self._idents.pop(id_, None) is not None

    def find_by_type_value(
        self,
        identifier_type: str,
        identifier_value: str,
    ) -> AllowedIdentifier | None:
        for i in self._idents.values():
            if i.identifier_type == identifier_type and i.identifier_value == identifier_value:
                return i
        return None

    def find_all_with_accounts(self) -> list[tuple]:
        result = []
        for ident in self._idents.values():
            acct_ids = list(self._associations.get(ident.id, set()))
            result.append((ident, acct_ids))
        return result

    def find_one_with_accounts(self, identifier_id: UUID) -> tuple | None:
        ident = self._idents.get(identifier_id)
        if ident is None:
            return None
        acct_ids = list(self._associations.get(ident.id, set()))
        return (ident, acct_ids)

    def find_by_account(self, account_id: UUID) -> list[AllowedIdentifier]:
        result = []
        for ident_id, acct_ids in self._associations.items():
            if account_id in acct_ids:
                ident = self._idents.get(ident_id)
                if ident:
                    result.append(ident)
        return result

    def add_account_association(self, identifier_id: UUID, account_id: UUID) -> None:
        self._associations.setdefault(identifier_id, set()).add(account_id)

    def remove_account_association(self, identifier_id: UUID, account_id: UUID) -> None:
        s = self._associations.get(identifier_id)
        if s:
            s.discard(account_id)

    def find_allowed_values_for_account(self, account_id: UUID) -> list[tuple]:
        result = []
        for ident_id, acct_ids in self._associations.items():
            if account_id in acct_ids:
                ident = self._idents.get(ident_id)
                if ident:
                    result.append((ident.identifier_type, ident.identifier_value))
        return result


class StubAuditLogRepo:
    def __init__(self):
        self.entries: list[AuditLogEntry] = []

    def create(self, entity: AuditLogEntry) -> AuditLogEntry:
        self.entries.append(entity)
        return entity

    def find_recent(self, limit=100):
        return self.entries[:limit]


class StubAdminUserRepo:
    def __init__(self):
        self._users = {}

    def count_all(self):
        return 0

    def find_by_id(self, id_):
        return None

    def find_all(self):
        return []


class StubAccountRepo:
    """In-memory stub that treats every queried UUID as an existing account.

    Tests that need to assert the 404 path should use ``StubAccountRepo(known=set())``
    and query with a UUID not in that set.
    """

    def __init__(self, known: set[UUID] | None = None, accept_all: bool = True):
        self._known: set[UUID] = known if known is not None else set()
        self._accept_all = accept_all

    def find_by_id(self, id_: UUID):
        if self._accept_all or id_ in self._known:
            return object()
        return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_settings() -> AdminApiSettings:
    return AdminApiSettings(
        enabled=True,
        base_path="/api",
        token_secret="test-secret",
        token_expiry_seconds=3600,
        initial_admin_email="admin@example.com",
        password_length=20,
        default_page_size=50,
        max_page_size=1000,
    )


@pytest.fixture()
def allowlist_repo():
    return StubAllowlistRepo()


@pytest.fixture()
def audit_repo():
    return StubAuditLogRepo()


@pytest.fixture()
def account_repo():
    return StubAccountRepo(accept_all=True)


@pytest.fixture()
def service(allowlist_repo, audit_repo, account_repo):
    return AdminUserService(
        StubAdminUserRepo(),
        audit_repo,
        _make_settings(),
        allowlist_repo=allowlist_repo,
        account_repo=account_repo,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCreateAllowedIdentifier:
    def test_create_dns(self, service, allowlist_repo):
        ident = service.create_allowed_identifier("dns", "example.com")
        assert ident.identifier_type == "dns"
        assert ident.identifier_value == "example.com"
        assert allowlist_repo.find_by_id(ident.id) is not None

    def test_create_ip(self, service):
        ident = service.create_allowed_identifier("ip", "10.0.0.1")
        assert ident.identifier_type == "ip"
        assert ident.identifier_value == "10.0.0.1"

    def test_create_wildcard_dns(self, service):
        ident = service.create_allowed_identifier("dns", "*.corp.internal")
        assert ident.identifier_value == "*.corp.internal"

    def test_duplicate_rejected(self, service):
        service.create_allowed_identifier("dns", "dup.com")
        with pytest.raises(Exception) as exc_info:
            service.create_allowed_identifier("dns", "dup.com")
        assert "409" in str(exc_info.value.status)

    def test_invalid_type_rejected(self, service):
        with pytest.raises(Exception) as exc_info:
            service.create_allowed_identifier("ftp", "example.com")
        assert "400" in str(exc_info.value.status)

    def test_empty_value_rejected(self, service):
        with pytest.raises(Exception) as exc_info:
            service.create_allowed_identifier("dns", "")
        assert "400" in str(exc_info.value.status)

    def test_invalid_ip_rejected(self, service):
        with pytest.raises(Exception) as exc_info:
            service.create_allowed_identifier("ip", "not-an-ip")
        assert "400" in str(exc_info.value.status)

    def test_dns_lowercased(self, service):
        ident = service.create_allowed_identifier("dns", "UPPER.COM")
        assert ident.identifier_value == "upper.com"

    def test_audit_log_entry(self, service, audit_repo):
        actor = uuid4()
        service.create_allowed_identifier("dns", "audit.com", actor_id=actor)
        entries = [e for e in audit_repo.entries if e.action == "create_allowed_identifier"]
        assert len(entries) == 1
        assert entries[0].details["identifier_value"] == "audit.com"

    # --- DNS label validation ---

    def test_leading_dash_rejected(self, service):
        with pytest.raises(Exception) as exc_info:
            service.create_allowed_identifier("dns", "-leading-dash.com")
        assert "400" in str(exc_info.value.status)

    def test_trailing_dash_rejected(self, service):
        with pytest.raises(Exception) as exc_info:
            service.create_allowed_identifier("dns", "trailing-.com")
        assert "400" in str(exc_info.value.status)

    def test_invalid_wildcard_mid_label(self, service):
        with pytest.raises(Exception) as exc_info:
            service.create_allowed_identifier("dns", "foo.*.com")
        assert "400" in str(exc_info.value.status)

    def test_multi_level_wildcard_rejected(self, service):
        with pytest.raises(Exception) as exc_info:
            service.create_allowed_identifier("dns", "*.*.example.com")
        assert "400" in str(exc_info.value.status)

    # --- IP range validation ---

    def test_loopback_ipv4_rejected(self, service):
        with pytest.raises(Exception) as exc_info:
            service.create_allowed_identifier("ip", "127.0.0.1")
        assert "400" in str(exc_info.value.status)

    def test_loopback_ipv6_rejected(self, service):
        with pytest.raises(Exception) as exc_info:
            service.create_allowed_identifier("ip", "::1")
        assert "400" in str(exc_info.value.status)

    def test_unspecified_ipv4_rejected(self, service):
        with pytest.raises(Exception) as exc_info:
            service.create_allowed_identifier("ip", "0.0.0.0")
        assert "400" in str(exc_info.value.status)

    def test_multicast_rejected(self, service):
        with pytest.raises(Exception) as exc_info:
            service.create_allowed_identifier("ip", "224.0.0.1")
        assert "400" in str(exc_info.value.status)

    def test_private_ipv4_allowed(self, service):
        """Private ranges are fine for internal PKI."""
        ident = service.create_allowed_identifier("ip", "192.168.1.1")
        assert ident.identifier_value == "192.168.1.1"

    def test_valid_ipv6_allowed(self, service):
        ident = service.create_allowed_identifier("ip", "2001:db8::1")
        assert ident.identifier_value == "2001:db8::1"

    def test_single_label_dns_allowed(self, service):
        """Single-label names are valid for internal PKI."""
        ident = service.create_allowed_identifier("dns", "intranet")
        assert ident.identifier_value == "intranet"


class TestGetAllowedIdentifier:
    def test_get_existing(self, service):
        ident = service.create_allowed_identifier("dns", "get.com")
        found, acct_ids = service.get_allowed_identifier(ident.id)
        assert found.identifier_value == "get.com"
        assert acct_ids == []

    def test_get_nonexistent(self, service):
        with pytest.raises(Exception) as exc_info:
            service.get_allowed_identifier(uuid4())
        assert "404" in str(exc_info.value.status)


class TestDeleteAllowedIdentifier:
    def test_delete_existing(self, service, allowlist_repo):
        ident = service.create_allowed_identifier("dns", "delete.com")
        service.delete_allowed_identifier(ident.id)
        assert allowlist_repo.find_by_id(ident.id) is None

    def test_delete_nonexistent(self, service):
        with pytest.raises(Exception) as exc_info:
            service.delete_allowed_identifier(uuid4())
        assert "404" in str(exc_info.value.status)

    def test_audit_log(self, service, audit_repo):
        ident = service.create_allowed_identifier("dns", "del-audit.com")
        service.delete_allowed_identifier(ident.id, actor_id=uuid4())
        entries = [e for e in audit_repo.entries if e.action == "delete_allowed_identifier"]
        assert len(entries) == 1


class TestAccountAssociation:
    def test_add_association(self, service, allowlist_repo):
        ident = service.create_allowed_identifier("dns", "assoc.com")
        acct_id = uuid4()
        service.add_identifier_account(ident.id, acct_id)

        _, acct_ids = service.get_allowed_identifier(ident.id)
        assert acct_id in acct_ids

    def test_remove_association(self, service, allowlist_repo):
        ident = service.create_allowed_identifier("dns", "rm-assoc.com")
        acct_id = uuid4()
        service.add_identifier_account(ident.id, acct_id)
        service.remove_identifier_account(ident.id, acct_id)

        _, acct_ids = service.get_allowed_identifier(ident.id)
        assert acct_id not in acct_ids

    def test_add_to_nonexistent_identifier(self, service):
        with pytest.raises(Exception) as exc_info:
            service.add_identifier_account(uuid4(), uuid4())
        assert "404" in str(exc_info.value.status)

    def test_add_with_nonexistent_account_returns_404(
        self,
        allowlist_repo,
        audit_repo,
    ):
        """Regression: a non-existent account UUID must surface as 404, not 500.

        Previously the FK violation on ``admin.account_allowed_identifiers.account_id``
        escaped as an unhandled exception.
        """
        svc = AdminUserService(
            StubAdminUserRepo(),
            audit_repo,
            _make_settings(),
            allowlist_repo=allowlist_repo,
            account_repo=StubAccountRepo(accept_all=False),
        )
        ident = svc.create_allowed_identifier("dns", "no-such-account.com")
        with pytest.raises(Exception) as exc_info:
            svc.add_identifier_account(ident.id, uuid4())
        assert "404" in str(exc_info.value.status)

    def test_remove_with_nonexistent_account_returns_404(
        self,
        allowlist_repo,
        audit_repo,
    ):
        svc = AdminUserService(
            StubAdminUserRepo(),
            audit_repo,
            _make_settings(),
            allowlist_repo=allowlist_repo,
            account_repo=StubAccountRepo(accept_all=False),
        )
        ident = svc.create_allowed_identifier("dns", "rm-no-such.com")
        with pytest.raises(Exception) as exc_info:
            svc.remove_identifier_account(ident.id, uuid4())
        assert "404" in str(exc_info.value.status)

    def test_audit_log_on_add(self, service, audit_repo):
        ident = service.create_allowed_identifier("dns", "add-audit.com")
        service.add_identifier_account(ident.id, uuid4(), actor_id=uuid4())
        entries = [e for e in audit_repo.entries if e.action == "add_identifier_account"]
        assert len(entries) == 1

    def test_audit_log_on_remove(self, service, audit_repo):
        ident = service.create_allowed_identifier("dns", "rm-audit.com")
        acct_id = uuid4()
        service.add_identifier_account(ident.id, acct_id)
        service.remove_identifier_account(ident.id, acct_id, actor_id=uuid4())
        entries = [e for e in audit_repo.entries if e.action == "remove_identifier_account"]
        assert len(entries) == 1


class TestListAccountIdentifiers:
    def test_list_for_account(self, service, allowlist_repo):
        i1 = service.create_allowed_identifier("dns", "acct1.com")
        i2 = service.create_allowed_identifier("dns", "acct2.com")
        acct_id = uuid4()
        service.add_identifier_account(i1.id, acct_id)
        service.add_identifier_account(i2.id, acct_id)

        idents = service.list_account_identifiers(acct_id)
        assert len(idents) == 2

    def test_list_empty_account(self, service):
        idents = service.list_account_identifiers(uuid4())
        assert idents == []


class TestListAllIdentifiers:
    def test_list_all(self, service):
        service.create_allowed_identifier("dns", "list1.com")
        service.create_allowed_identifier("dns", "list2.com")
        items = service.list_allowed_identifiers()
        assert len(items) == 2
        for ident, acct_ids in items:
            assert isinstance(acct_ids, list)
