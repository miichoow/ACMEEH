"""SQL-level tests for EAB linkage propagation in ``EabCredentialRepository``.

The propagate_* methods must reach *every* account that holds the EAB
(``accounts.eab_credential_id``, set once at registration) and not only the
single account that ``eab_credentials.account_id`` currently points at.
With ``acme.eab_reusable`` that pointer is overwritten by each new
registration, so a join through it silently skips all earlier accounts.

The database is mocked, so these tests pin the shape and parameter order of
the statements; the behaviour against a real PostgreSQL is covered by the
end-to-end check described in the PR.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from acmeeh.admin.repository import EabCredentialRepository


def _squash(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()


@pytest.fixture()
def db():
    with patch("acmeeh.admin.repository.Database") as database:
        instance = MagicMock()
        database.get_instance.return_value = instance
        yield instance


def _executed(db) -> tuple[str, tuple]:
    db.execute.assert_called_once()
    sql, params = db.execute.call_args.args
    return _squash(sql), params


def _repo() -> EabCredentialRepository:
    return EabCredentialRepository(MagicMock())


class TestAccountScope:
    """Every statement must select accounts through ``accounts.eab_credential_id``."""

    @pytest.mark.parametrize(
        "call",
        [
            lambda r, e, x: r.propagate_identifier_add(e, x),
            lambda r, e, x: r.propagate_identifier_remove(e, x),
            lambda r, e, x: r.propagate_csr_profile_assign(e, x),
            lambda r, e, x: r.propagate_csr_profile_unassign(e, x),
        ],
        ids=["ident-add", "ident-remove", "profile-assign", "profile-unassign"],
    )
    def test_targets_all_registered_accounts_and_the_bound_one(self, db, call):
        call(_repo(), uuid4(), uuid4())
        sql, _ = _executed(db)

        assert "FROM accounts a" in sql or "USING accounts a" in sql
        assert "a.eab_credential_id = %s" in sql
        # The currently bound account is still covered (re-registered account).
        assert "SELECT ec.account_id FROM admin.eab_credentials ec WHERE ec.id = %s" in sql
        # Regression: the single-valued pointer must not be the only join.
        assert "ec.account_id = aai.account_id" not in sql
        assert "ec.account_id = acp.account_id" not in sql


class TestIdentifierAdd:
    def test_inserts_and_is_idempotent(self, db):
        eab_id, ident_id = uuid4(), uuid4()
        _repo().propagate_identifier_add(eab_id, ident_id)
        sql, params = _executed(db)

        assert sql.startswith("INSERT INTO admin.account_allowed_identifiers")
        assert "ON CONFLICT DO NOTHING" in sql
        assert params == (ident_id, eab_id, eab_id)
        assert sql.count("%s") == len(params)


class TestIdentifierRemove:
    def test_deletes_unless_another_eab_still_grants(self, db):
        eab_id, ident_id = uuid4(), uuid4()
        _repo().propagate_identifier_remove(eab_id, ident_id)
        sql, params = _executed(db)

        assert sql.startswith("DELETE FROM admin.account_allowed_identifiers aai")
        assert "NOT EXISTS" in sql
        assert "FROM admin.eab_allowed_identifiers eai2" in sql
        assert "ec2.id <> %s" in sql
        # The other EAB counts if registered with, or currently bound to, the account.
        assert "(ec2.id = a.eab_credential_id OR ec2.account_id = a.id)" in sql
        assert params == (ident_id, eab_id, eab_id, eab_id)
        assert sql.count("%s") == len(params)


class TestCsrProfileAssign:
    def test_upserts_for_all_accounts(self, db):
        eab_id, profile_id, actor = uuid4(), uuid4(), uuid4()
        _repo().propagate_csr_profile_assign(eab_id, profile_id, actor)
        sql, params = _executed(db)

        assert sql.startswith("INSERT INTO admin.account_csr_profiles")
        assert "ON CONFLICT (account_id) DO UPDATE" in sql
        assert params == (profile_id, actor, eab_id, eab_id)
        assert sql.count("%s") == len(params)

    def test_assigned_by_defaults_to_none(self, db):
        eab_id, profile_id = uuid4(), uuid4()
        _repo().propagate_csr_profile_assign(eab_id, profile_id)
        _, params = _executed(db)

        assert params == (profile_id, None, eab_id, eab_id)


class TestCsrProfileUnassign:
    def test_deletes_unless_another_eab_still_assigns(self, db):
        eab_id, profile_id = uuid4(), uuid4()
        _repo().propagate_csr_profile_unassign(eab_id, profile_id)
        sql, params = _executed(db)

        assert sql.startswith("DELETE FROM admin.account_csr_profiles acp")
        assert "acp.csr_profile_id = %s" in sql
        assert "NOT EXISTS" in sql
        assert "FROM admin.eab_csr_profiles ecp2" in sql
        assert "(ec2.id = a.eab_credential_id OR ec2.account_id = a.id)" in sql
        assert params == (profile_id, eab_id, eab_id, eab_id)
        assert sql.count("%s") == len(params)
