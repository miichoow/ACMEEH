"""Shutdown drain must only release challenges claimed by *this* process.

``drain_processing`` used to reset every PROCESSING challenge in the table.
Under gunicorn several workers (and instances) validate challenges at the
same time and workers are recycled regularly, so a global reset would hand
another worker's in-flight challenge back to PENDING: its result would be
lost (the completion UPDATE is guarded by ``locked_by``) and its retry
budget consumed.
"""

from __future__ import annotations

import re
import uuid
from unittest.mock import MagicMock, patch

import pytest

from acmeeh.core.types import ChallengeStatus
from acmeeh.repositories.challenge import ChallengeRepository

from .test_repository_coverage import _challenge_row


def _squash(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()


@pytest.fixture()
def db():
    with patch("acmeeh.repositories.challenge.Database") as database:
        instance = MagicMock()
        database.get_instance.return_value = instance
        yield instance


@pytest.fixture()
def repo(db) -> ChallengeRepository:
    return ChallengeRepository(MagicMock())


def _claim(repo, db, worker_id: str) -> None:
    db.fetch_one.return_value = _challenge_row(
        status=ChallengeStatus.PROCESSING.value, locked_by=worker_id
    )
    assert repo.claim_for_processing(uuid.uuid4(), worker_id) is not None


class TestDrainScope:
    def test_nothing_claimed_means_no_query(self, repo, db):
        assert repo.drain_processing() == 0
        db.execute.assert_not_called()

    def test_only_own_claims_are_released(self, repo, db):
        _claim(repo, db, "bg-aaaa")
        _claim(repo, db, "api-bbbb")
        db.execute.return_value = 2

        assert repo.drain_processing() == 2

        sql, params = db.execute.call_args.args
        sql = _squash(sql)
        assert "locked_by = ANY(%s)" in sql
        assert "WHERE status = %s AND" in sql
        assert params[2] == ["api-bbbb", "bg-aaaa"]

    def test_failed_claim_is_not_remembered(self, repo, db):
        db.fetch_one.return_value = None
        assert repo.claim_for_processing(uuid.uuid4(), "w-lost") is None

        assert repo.drain_processing() == 0
        db.execute.assert_not_called()

    def test_drained_ids_are_forgotten(self, repo, db):
        _claim(repo, db, "w-1")
        db.execute.return_value = 1
        repo.drain_processing()
        db.execute.reset_mock()

        assert repo.drain_processing() == 0
        db.execute.assert_not_called()


class TestClaimsAreForgottenWhenDone:
    def test_complete_validation(self, repo, db):
        _claim(repo, db, "w-1")
        db.fetch_one.return_value = _challenge_row(status=ChallengeStatus.VALID.value)

        repo.complete_validation(uuid.uuid4(), "w-1", success=True)

        assert repo.drain_processing() == 0
        db.execute.assert_not_called()

    def test_complete_validation_when_lock_was_lost(self, repo, db):
        """The UPDATE matched nothing (lock released elsewhere): still forget."""
        _claim(repo, db, "w-1")
        db.fetch_one.return_value = None

        assert repo.complete_validation(uuid.uuid4(), "w-1", success=False) is None

        assert repo.drain_processing() == 0

    @pytest.mark.parametrize("backoff", [0, 30])
    def test_retry_challenge(self, repo, db, backoff):
        _claim(repo, db, "w-1")
        db.fetch_one.return_value = _challenge_row(retry_count=1)

        repo.retry_challenge(uuid.uuid4(), "w-1", backoff_seconds=backoff)

        assert repo.drain_processing() == 0

    def test_other_claims_survive(self, repo, db):
        _claim(repo, db, "w-1")
        _claim(repo, db, "w-2")
        db.fetch_one.return_value = _challenge_row(status=ChallengeStatus.VALID.value)
        repo.complete_validation(uuid.uuid4(), "w-1", success=True)
        db.execute.return_value = 1

        repo.drain_processing()

        assert db.execute.call_args.args[1][2] == ["w-2"]
