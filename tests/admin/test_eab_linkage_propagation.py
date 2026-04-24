"""Tests for EAB linkage propagation to the bound account.

When an admin edits the identifier or CSR profile linkage of an EAB credential
that is already bound to an account, the change must propagate to the
account's own allowlist / CSR-profile tables immediately. Otherwise the ACME
client would have to re-register (triggering ``sync_linkage_to_account``) for
the change to take effect, which is surprising and was the original bug.
"""

from __future__ import annotations

from dataclasses import replace
from uuid import UUID, uuid4

import pytest

from acmeeh.admin.models import (
    AllowedIdentifier,
    AuditLogEntry,
    CsrProfile,
    EabCredential,
)
from acmeeh.admin.service import AdminUserService
from acmeeh.config.settings import AdminApiSettings


class StubAdminUserRepo:
    def count_all(self) -> int:
        return 0

    def find_by_id(self, id_: UUID):
        return None

    def find_all(self):
        return []


class StubAuditLogRepo:
    def __init__(self) -> None:
        self.entries: list[AuditLogEntry] = []

    def create(self, entity: AuditLogEntry) -> AuditLogEntry:
        self.entries.append(entity)
        return entity

    def find_recent(self, limit: int = 100):
        return self.entries[:limit]


class StubAllowlistRepo:
    def __init__(self) -> None:
        self._idents: dict[UUID, AllowedIdentifier] = {}

    def seed(self, ident: AllowedIdentifier) -> None:
        self._idents[ident.id] = ident

    def find_by_id(self, id_: UUID) -> AllowedIdentifier | None:
        return self._idents.get(id_)


class StubCsrProfileRepo:
    def __init__(self) -> None:
        self._profiles: dict[UUID, CsrProfile] = {}

    def seed(self, profile: CsrProfile) -> None:
        self._profiles[profile.id] = profile

    def find_by_id(self, id_: UUID) -> CsrProfile | None:
        return self._profiles.get(id_)


class StubEabRepo:
    """Stub that records propagation calls for assertion.

    Also models the two sides of the EAB↔identifier linkage so the
    "only remove account row when no other EAB still grants it" invariant
    can be exercised end-to-end.
    """

    def __init__(self) -> None:
        self._creds: dict[UUID, EabCredential] = {}
        # EAB link tables
        self._eab_idents: set[tuple[UUID, UUID]] = set()
        self._eab_profiles: dict[UUID, UUID] = {}  # eab_id -> profile_id
        # Account tables (what propagation should maintain)
        self.account_idents: set[tuple[UUID, UUID]] = set()  # (account_id, ident_id)
        self.account_profiles: dict[UUID, UUID] = {}  # account_id -> profile_id
        # Call log for direct assertion
        self.propagate_add_calls: list[tuple[UUID, UUID]] = []
        self.propagate_remove_calls: list[tuple[UUID, UUID]] = []
        self.propagate_assign_calls: list[tuple[UUID, UUID, UUID | None]] = []
        self.propagate_unassign_calls: list[tuple[UUID, UUID]] = []

    def seed(self, cred: EabCredential) -> None:
        self._creds[cred.id] = cred

    def find_by_id(self, id_: UUID) -> EabCredential | None:
        return self._creds.get(id_)

    def add_identifier_association(self, eab_id: UUID, identifier_id: UUID) -> None:
        self._eab_idents.add((eab_id, identifier_id))

    def remove_identifier_association(self, eab_id: UUID, identifier_id: UUID) -> None:
        self._eab_idents.discard((eab_id, identifier_id))

    def assign_csr_profile(
        self,
        eab_id: UUID,
        profile_id: UUID,
        assigned_by: UUID | None = None,
    ) -> None:
        self._eab_profiles[eab_id] = profile_id

    def unassign_csr_profile(self, eab_id: UUID, profile_id: UUID) -> None:
        if self._eab_profiles.get(eab_id) == profile_id:
            del self._eab_profiles[eab_id]

    def propagate_identifier_add(self, eab_id: UUID, identifier_id: UUID) -> None:
        self.propagate_add_calls.append((eab_id, identifier_id))
        cred = self._creds.get(eab_id)
        if cred is None or cred.account_id is None:
            return
        self.account_idents.add((cred.account_id, identifier_id))

    def propagate_identifier_remove(self, eab_id: UUID, identifier_id: UUID) -> None:
        self.propagate_remove_calls.append((eab_id, identifier_id))
        cred = self._creds.get(eab_id)
        if cred is None or cred.account_id is None:
            return
        # Only drop the account row when no *other* EAB bound to the same
        # account still grants the identifier.
        still_granted = any(
            other_cred.account_id == cred.account_id
            and (other_cred.id, identifier_id) in self._eab_idents
            for other_cred in self._creds.values()
            if other_cred.id != eab_id
        )
        if not still_granted:
            self.account_idents.discard((cred.account_id, identifier_id))

    def propagate_csr_profile_assign(
        self,
        eab_id: UUID,
        profile_id: UUID,
        assigned_by: UUID | None = None,
    ) -> None:
        self.propagate_assign_calls.append((eab_id, profile_id, assigned_by))
        cred = self._creds.get(eab_id)
        if cred is None or cred.account_id is None:
            return
        self.account_profiles[cred.account_id] = profile_id

    def propagate_csr_profile_unassign(self, eab_id: UUID, profile_id: UUID) -> None:
        self.propagate_unassign_calls.append((eab_id, profile_id))
        cred = self._creds.get(eab_id)
        if cred is None or cred.account_id is None:
            return
        if self.account_profiles.get(cred.account_id) != profile_id:
            return
        still_assigned = any(
            other_cred.account_id == cred.account_id
            and self._eab_profiles.get(other_cred.id) == profile_id
            for other_cred in self._creds.values()
            if other_cred.id != eab_id
        )
        if not still_assigned:
            del self.account_profiles[cred.account_id]


def _settings() -> AdminApiSettings:
    return AdminApiSettings(
        enabled=True,
        base_path="/api",
        token_secret="test-secret-for-tokens",
        token_expiry_seconds=3600,
        initial_admin_email="admin@example.com",
        password_length=20,
        default_page_size=50,
        max_page_size=1000,
    )


@pytest.fixture()
def eab_repo() -> StubEabRepo:
    return StubEabRepo()


@pytest.fixture()
def allowlist_repo() -> StubAllowlistRepo:
    return StubAllowlistRepo()


@pytest.fixture()
def csr_profile_repo() -> StubCsrProfileRepo:
    return StubCsrProfileRepo()


@pytest.fixture()
def audit_repo() -> StubAuditLogRepo:
    return StubAuditLogRepo()


@pytest.fixture()
def service(
    eab_repo: StubEabRepo,
    allowlist_repo: StubAllowlistRepo,
    csr_profile_repo: StubCsrProfileRepo,
    audit_repo: StubAuditLogRepo,
) -> AdminUserService:
    return AdminUserService(
        StubAdminUserRepo(),
        audit_repo,
        _settings(),
        eab_repo=eab_repo,
        allowlist_repo=allowlist_repo,
        csr_profile_repo=csr_profile_repo,
    )


def _bound_cred(account_id: UUID | None = None) -> EabCredential:
    return EabCredential(
        id=uuid4(),
        kid="kid-bound",
        hmac_key="hmac",
        account_id=account_id,
        used=account_id is not None,
    )


def _ident(value: str = "*.ctie.etat.lu") -> AllowedIdentifier:
    return AllowedIdentifier(
        id=uuid4(),
        identifier_type="dns",
        identifier_value=value,
    )


def _profile(name: str = "web") -> CsrProfile:
    return CsrProfile(id=uuid4(), name=name, profile_data={"authorized_keys": {"RSA": 2048}})


class TestIdentifierAddPropagation:
    def test_propagates_to_bound_account(self, service, eab_repo, allowlist_repo):
        account_id = uuid4()
        cred = _bound_cred(account_id=account_id)
        ident = _ident()
        eab_repo.seed(cred)
        allowlist_repo.seed(ident)

        service.add_eab_identifier(cred.id, ident.id)

        assert eab_repo.propagate_add_calls == [(cred.id, ident.id)]
        assert (account_id, ident.id) in eab_repo.account_idents

    def test_no_op_when_eab_has_no_account(self, service, eab_repo, allowlist_repo):
        cred = _bound_cred(account_id=None)
        ident = _ident()
        eab_repo.seed(cred)
        allowlist_repo.seed(ident)

        service.add_eab_identifier(cred.id, ident.id)

        # Propagation must still be invoked so late-binding accounts are handled
        # uniformly; the underlying SQL is a no-op when account_id is NULL.
        assert eab_repo.propagate_add_calls == [(cred.id, ident.id)]
        assert eab_repo.account_idents == set()

    def test_propagation_failure_does_not_abort_write(
        self,
        service,
        eab_repo,
        allowlist_repo,
    ):
        account_id = uuid4()
        cred = _bound_cred(account_id=account_id)
        ident = _ident()
        eab_repo.seed(cred)
        allowlist_repo.seed(ident)

        def boom(_eab_id: UUID, _ident_id: UUID) -> None:
            msg = "db down"
            raise RuntimeError(msg)

        eab_repo.propagate_identifier_add = boom  # type: ignore[method-assign]

        # Must not raise — EAB link is already written, propagation is best effort.
        service.add_eab_identifier(cred.id, ident.id)

        assert (cred.id, ident.id) in eab_repo._eab_idents  # noqa: SLF001


class TestIdentifierRemovePropagation:
    def test_removes_from_bound_account(self, service, eab_repo, allowlist_repo):
        account_id = uuid4()
        cred = _bound_cred(account_id=account_id)
        ident = _ident()
        eab_repo.seed(cred)
        allowlist_repo.seed(ident)

        service.add_eab_identifier(cred.id, ident.id)
        assert (account_id, ident.id) in eab_repo.account_idents

        service.remove_eab_identifier(cred.id, ident.id)

        assert eab_repo.propagate_remove_calls == [(cred.id, ident.id)]
        assert (account_id, ident.id) not in eab_repo.account_idents

    def test_preserved_when_second_eab_still_grants(
        self,
        service,
        eab_repo,
        allowlist_repo,
    ):
        account_id = uuid4()
        cred_a = replace(_bound_cred(account_id=account_id), kid="kid-a")
        cred_b = replace(_bound_cred(account_id=account_id), kid="kid-b")
        ident = _ident()
        eab_repo.seed(cred_a)
        eab_repo.seed(cred_b)
        allowlist_repo.seed(ident)

        service.add_eab_identifier(cred_a.id, ident.id)
        service.add_eab_identifier(cred_b.id, ident.id)

        # Removing from A must not drop the account row while B still grants it.
        service.remove_eab_identifier(cred_a.id, ident.id)
        assert (account_id, ident.id) in eab_repo.account_idents

        # After B removes it too, the account row is cleared.
        service.remove_eab_identifier(cred_b.id, ident.id)
        assert (account_id, ident.id) not in eab_repo.account_idents


class TestCsrProfileAssignPropagation:
    def test_propagates_to_bound_account(
        self,
        service,
        eab_repo,
        csr_profile_repo,
    ):
        account_id = uuid4()
        cred = _bound_cred(account_id=account_id)
        profile = _profile()
        eab_repo.seed(cred)
        csr_profile_repo.seed(profile)

        actor = uuid4()
        service.assign_eab_csr_profile(cred.id, profile.id, actor_id=actor)

        assert eab_repo.propagate_assign_calls == [(cred.id, profile.id, actor)]
        assert eab_repo.account_profiles[account_id] == profile.id

    def test_assign_replaces_existing(self, service, eab_repo, csr_profile_repo):
        account_id = uuid4()
        cred = _bound_cred(account_id=account_id)
        p1 = _profile("first")
        p2 = _profile("second")
        eab_repo.seed(cred)
        csr_profile_repo.seed(p1)
        csr_profile_repo.seed(p2)

        service.assign_eab_csr_profile(cred.id, p1.id)
        service.assign_eab_csr_profile(cred.id, p2.id)

        assert eab_repo.account_profiles[account_id] == p2.id


class TestCsrProfileUnassignPropagation:
    def test_removes_from_bound_account(self, service, eab_repo, csr_profile_repo):
        account_id = uuid4()
        cred = _bound_cred(account_id=account_id)
        profile = _profile()
        eab_repo.seed(cred)
        csr_profile_repo.seed(profile)

        service.assign_eab_csr_profile(cred.id, profile.id)
        service.unassign_eab_csr_profile(cred.id, profile.id)

        assert eab_repo.propagate_unassign_calls == [(cred.id, profile.id)]
        assert account_id not in eab_repo.account_profiles

    def test_preserved_when_second_eab_still_assigns(
        self,
        service,
        eab_repo,
        csr_profile_repo,
    ):
        account_id = uuid4()
        cred_a = replace(_bound_cred(account_id=account_id), kid="kid-a")
        cred_b = replace(_bound_cred(account_id=account_id), kid="kid-b")
        profile = _profile()
        eab_repo.seed(cred_a)
        eab_repo.seed(cred_b)
        csr_profile_repo.seed(profile)

        service.assign_eab_csr_profile(cred_a.id, profile.id)
        service.assign_eab_csr_profile(cred_b.id, profile.id)

        service.unassign_eab_csr_profile(cred_a.id, profile.id)
        assert eab_repo.account_profiles.get(account_id) == profile.id

        service.unassign_eab_csr_profile(cred_b.id, profile.id)
        assert account_id not in eab_repo.account_profiles
