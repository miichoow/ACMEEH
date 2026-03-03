"""Tests for repository methods that interact with Database.

Each repository method calls Database.get_instance() and then delegates to
fetch_one / fetch_all / fetch_value / execute.  We mock Database at the
module-boundary so no real DB is needed, but every repository code path
(including _row_to_entity / _entity_to_row) is exercised.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from acmeeh.core.types import (
    AccountStatus,
    AuthorizationStatus,
    ChallengeStatus,
    ChallengeType,
    IdentifierType,
    NotificationStatus,
    NotificationType,
    OrderStatus,
    RevocationReason,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow():
    return datetime.now(UTC)


def _uuid():
    return uuid.uuid4()


# -- shared row templates --

def _cert_row(**overrides):
    base = {
        "id": _uuid(),
        "account_id": _uuid(),
        "order_id": _uuid(),
        "serial_number": "AABB01",
        "fingerprint": "sha256:abc",
        "pem_chain": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
        "not_before_cert": _utcnow(),
        "not_after_cert": _utcnow(),
        "revoked_at": None,
        "revocation_reason": None,
        "public_key_fingerprint": None,
        "san_values": None,
        "created_at": _utcnow(),
        "updated_at": _utcnow(),
    }
    base.update(overrides)
    return base


def _challenge_row(**overrides):
    base = {
        "id": _uuid(),
        "authorization_id": _uuid(),
        "type": ChallengeType.HTTP_01.value,
        "token": "abc123token",
        "status": ChallengeStatus.PENDING.value,
        "error": None,
        "validated_at": None,
        "retry_count": 0,
        "next_retry_at": None,
        "locked_by": None,
        "locked_at": None,
        "created_at": _utcnow(),
        "updated_at": _utcnow(),
    }
    base.update(overrides)
    return base


def _order_row(**overrides):
    base = {
        "id": _uuid(),
        "account_id": _uuid(),
        "status": OrderStatus.PENDING.value,
        "identifiers": [{"type": "dns", "value": "example.com"}],
        "identifiers_hash": "hash123",
        "expires": _utcnow(),
        "not_before": None,
        "not_after": None,
        "error": None,
        "certificate_id": None,
        "created_at": _utcnow(),
        "updated_at": _utcnow(),
    }
    base.update(overrides)
    return base


def _authz_row(**overrides):
    base = {
        "id": _uuid(),
        "account_id": _uuid(),
        "identifier_type": IdentifierType.DNS.value,
        "identifier_value": "example.com",
        "status": AuthorizationStatus.PENDING.value,
        "expires": _utcnow(),
        "wildcard": False,
        "created_at": _utcnow(),
        "updated_at": _utcnow(),
    }
    base.update(overrides)
    return base


def _notification_row(**overrides):
    base = {
        "id": _uuid(),
        "notification_type": NotificationType.EXPIRATION_WARNING.value,
        "recipient": "admin@example.com",
        "subject": "Cert expiring",
        "body": "Your cert is expiring",
        "status": NotificationStatus.PENDING.value,
        "account_id": _uuid(),
        "error_detail": None,
        "retry_count": 0,
        "created_at": _utcnow(),
        "sent_at": None,
    }
    base.update(overrides)
    return base


def _account_row(**overrides):
    base = {
        "id": _uuid(),
        "jwk_thumbprint": "tp_test",
        "jwk": {"kty": "EC", "crv": "P-256"},
        "status": AccountStatus.VALID.value,
        "tos_agreed": True,
        "created_at": _utcnow(),
        "updated_at": _utcnow(),
    }
    base.update(overrides)
    return base


def _contact_row(**overrides):
    base = {
        "id": _uuid(),
        "account_id": _uuid(),
        "contact_uri": "mailto:test@example.com",
        "created_at": _utcnow(),
    }
    base.update(overrides)
    return base


def _nonce_row(**overrides):
    base = {
        "nonce": "nonce_value_1",
        "expires_at": _utcnow(),
        "created_at": _utcnow(),
    }
    base.update(overrides)
    return base


# ======================================================================
# CertificateRepository
# ======================================================================

class TestCertificateRepository:

    def _make_repo(self, mock_db):
        from acmeeh.repositories.certificate import CertificateRepository
        return CertificateRepository(mock_db)

    def test_row_to_entity(self):
        mock_db = MagicMock()
        repo = self._make_repo(mock_db)
        row = _cert_row(revocation_reason=RevocationReason.KEY_COMPROMISE.value)
        cert = repo._row_to_entity(row)
        assert cert.serial_number == row["serial_number"]
        assert cert.revocation_reason == RevocationReason.KEY_COMPROMISE

    def test_row_to_entity_no_revocation(self):
        mock_db = MagicMock()
        repo = self._make_repo(mock_db)
        row = _cert_row()
        cert = repo._row_to_entity(row)
        assert cert.revocation_reason is None

    def test_entity_to_row_with_revocation(self):
        mock_db = MagicMock()
        repo = self._make_repo(mock_db)
        from acmeeh.models.certificate import Certificate
        cert = Certificate(
            id=_uuid(), account_id=_uuid(), order_id=_uuid(),
            serial_number="AA01", fingerprint="fp",
            pem_chain="pem", not_before_cert=_utcnow(),
            not_after_cert=_utcnow(), revoked_at=_utcnow(),
            revocation_reason=RevocationReason.KEY_COMPROMISE,
            public_key_fingerprint="pk_fp",
            san_values=["example.com"],
            created_at=_utcnow(), updated_at=_utcnow(),
        )
        row = repo._entity_to_row(cert)
        assert row["revocation_reason"] == RevocationReason.KEY_COMPROMISE.value
        assert "public_key_fingerprint" in row
        assert "san_values" in row

    def test_entity_to_row_no_optional(self):
        mock_db = MagicMock()
        repo = self._make_repo(mock_db)
        from acmeeh.models.certificate import Certificate
        cert = Certificate(
            id=_uuid(), account_id=_uuid(), order_id=_uuid(),
            serial_number="AA01", fingerprint="fp",
            pem_chain="pem", not_before_cert=_utcnow(),
            not_after_cert=_utcnow(), revoked_at=None,
            revocation_reason=None,
            public_key_fingerprint=None,
            san_values=None,
            created_at=_utcnow(), updated_at=_utcnow(),
        )
        row = repo._entity_to_row(cert)
        assert row["revocation_reason"] is None
        assert "public_key_fingerprint" not in row
        assert "san_values" not in row

    @patch("acmeeh.repositories.certificate.Database")
    def test_find_by_serial(self, MockDB):
        db = MockDB.get_instance.return_value
        repo = self._make_repo(db)
        repo.find_one_by = MagicMock(return_value=None)
        result = repo.find_by_serial("AAB1")
        repo.find_one_by.assert_called_once_with({"serial_number": "AAB1"})

    @patch("acmeeh.repositories.certificate.Database")
    def test_find_by_fingerprint(self, MockDB):
        db = MockDB.get_instance.return_value
        repo = self._make_repo(db)
        repo.find_one_by = MagicMock(return_value=None)
        result = repo.find_by_fingerprint("fp123")
        repo.find_one_by.assert_called_once_with({"fingerprint": "fp123"})

    @patch("acmeeh.repositories.certificate.Database")
    def test_find_by_account(self, MockDB):
        db = MockDB.get_instance.return_value
        repo = self._make_repo(db)
        acct_id = _uuid()
        repo.find_by = MagicMock(return_value=[])
        result = repo.find_by_account(acct_id)
        repo.find_by.assert_called_once_with({"account_id": acct_id})

    @patch("acmeeh.repositories.certificate.Database")
    def test_revoke_success(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _cert_row(
            revoked_at=_utcnow(),
            revocation_reason=RevocationReason.KEY_COMPROMISE.value,
        )
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        cert_id = _uuid()
        result = repo.revoke(cert_id, RevocationReason.KEY_COMPROMISE)
        assert result is not None
        assert result.serial_number == row["serial_number"]
        db.fetch_one.assert_called_once()

    @patch("acmeeh.repositories.certificate.Database")
    def test_revoke_already_revoked(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.revoke(_uuid())
        assert result is None

    @patch("acmeeh.repositories.certificate.Database")
    def test_revoke_no_reason(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _cert_row(
            revoked_at=_utcnow(),
            revocation_reason=RevocationReason.UNSPECIFIED.value,
        )
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.revoke(_uuid(), None)
        assert result is not None

    @patch("acmeeh.repositories.certificate.Database")
    def test_next_serial(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_value.return_value = 42
        repo = self._make_repo(db)
        assert repo.next_serial() == 42

    @patch("acmeeh.repositories.certificate.Database")
    def test_find_expiring(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _cert_row()
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        result = repo.find_expiring(_utcnow())
        assert len(result) == 1

    @patch("acmeeh.repositories.certificate.Database")
    def test_find_expiring_with_conn(self, MockDB):
        conn = MagicMock()
        row = _cert_row()
        conn.fetch_all.return_value = [row]
        repo = self._make_repo(MagicMock())
        result = repo.find_expiring(_utcnow(), conn=conn)
        assert len(result) == 1
        conn.fetch_all.assert_called_once()

    @patch("acmeeh.repositories.certificate.Database")
    def test_find_revoked(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _cert_row(revoked_at=_utcnow(), revocation_reason=1)
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        result = repo.find_revoked()
        assert len(result) == 1

    @patch("acmeeh.repositories.certificate.Database")
    def test_count_revoked_since(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_value.return_value = 5
        repo = self._make_repo(db)
        assert repo.count_revoked_since(_utcnow()) == 5

    @patch("acmeeh.repositories.certificate.Database")
    def test_count_revoked_since_none(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_value.return_value = None
        repo = self._make_repo(db)
        assert repo.count_revoked_since(_utcnow()) == 0

    @patch("acmeeh.repositories.certificate.Database")
    def test_find_by_public_key_fingerprint(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _cert_row(public_key_fingerprint="pk_fp")
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        result = repo.find_by_public_key_fingerprint("pk_fp")
        assert len(result) == 1

    @patch("acmeeh.repositories.certificate.Database")
    def test_find_valid_certs_for_hosts(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _cert_row(san_values=["example.com"])
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        result = repo.find_valid_certs_for_hosts(["example.com"], _utcnow())
        assert len(result) == 1

    @patch("acmeeh.repositories.certificate.Database")
    def test_search_no_filters(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_all.return_value = []
        repo = self._make_repo(db)
        result = repo.search({})
        assert result == []

    @patch("acmeeh.repositories.certificate.Database")
    def test_search_all_filters(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _cert_row()
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        aid = _uuid()
        result = repo.search({
            "account_id": aid,
            "serial": "AA",
            "fingerprint": "fp",
            "status": "revoked",
            "serial_numbers": ["AA", "BB"],
            "domain": "example.com",
            "expiring_before": _utcnow(),
        })
        assert len(result) == 1

    @patch("acmeeh.repositories.certificate.Database")
    def test_search_status_active(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_all.return_value = []
        repo = self._make_repo(db)
        repo.search({"status": "active"})
        call_args = db.fetch_all.call_args
        assert "revoked_at IS NULL" in call_args[0][0]

    @patch("acmeeh.repositories.certificate.Database")
    def test_search_status_valid(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_all.return_value = []
        repo = self._make_repo(db)
        repo.search({"status": "valid"})
        call_args = db.fetch_all.call_args
        assert "revoked_at IS NULL" in call_args[0][0]

    @patch("acmeeh.repositories.certificate.Database")
    def test_search_status_expired(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_all.return_value = []
        repo = self._make_repo(db)
        repo.search({"status": "expired"})
        call_args = db.fetch_all.call_args
        assert "not_after_cert <= now()" in call_args[0][0]

    @patch("acmeeh.repositories.certificate.Database")
    def test_search_empty_serial_numbers(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_all.return_value = []
        repo = self._make_repo(db)
        repo.search({"serial_numbers": []})
        # Should not add IN clause for empty list
        call_args = db.fetch_all.call_args
        assert "serial_number IN" not in call_args[0][0]


# ======================================================================
# ChallengeRepository
# ======================================================================

class TestChallengeRepository:

    def _make_repo(self, mock_db):
        from acmeeh.repositories.challenge import ChallengeRepository
        return ChallengeRepository(mock_db)

    def test_row_to_entity(self):
        repo = self._make_repo(MagicMock())
        row = _challenge_row()
        ch = repo._row_to_entity(row)
        assert ch.type == ChallengeType.HTTP_01
        assert ch.status == ChallengeStatus.PENDING

    def test_entity_to_row(self):
        repo = self._make_repo(MagicMock())
        from acmeeh.models.challenge import Challenge
        ch = Challenge(
            id=_uuid(), authorization_id=_uuid(),
            type=ChallengeType.DNS_01, token="tok",
            status=ChallengeStatus.VALID, error={"detail": "err"},
            validated_at=_utcnow(), retry_count=2,
            next_retry_at=None, locked_by="w1", locked_at=_utcnow(),
            created_at=_utcnow(), updated_at=_utcnow(),
        )
        row = repo._entity_to_row(ch)
        assert row["type"] == ChallengeType.DNS_01.value
        assert row["status"] == ChallengeStatus.VALID.value

    def test_entity_to_row_no_error(self):
        repo = self._make_repo(MagicMock())
        from acmeeh.models.challenge import Challenge
        ch = Challenge(
            id=_uuid(), authorization_id=_uuid(),
            type=ChallengeType.HTTP_01, token="tok",
            status=ChallengeStatus.PENDING, error=None,
            validated_at=None, retry_count=0,
            next_retry_at=None, locked_by=None, locked_at=None,
            created_at=_utcnow(), updated_at=_utcnow(),
        )
        row = repo._entity_to_row(ch)
        assert row["error"] is None

    @patch("acmeeh.repositories.challenge.Database")
    def test_create_many_empty(self, MockDB):
        repo = self._make_repo(MagicMock())
        repo.create_many([])
        MockDB.get_instance.assert_not_called()

    @patch("acmeeh.repositories.challenge.Database")
    def test_create_many(self, MockDB):
        db = MockDB.get_instance.return_value
        repo = self._make_repo(db)
        from acmeeh.models.challenge import Challenge
        ch = Challenge(
            id=_uuid(), authorization_id=_uuid(),
            type=ChallengeType.HTTP_01, token="tok",
            status=ChallengeStatus.PENDING, error=None,
            validated_at=None, retry_count=0,
            next_retry_at=None, locked_by=None, locked_at=None,
            created_at=_utcnow(), updated_at=_utcnow(),
        )
        repo.create_many([ch])
        db.execute.assert_called_once()

    @patch("acmeeh.repositories.challenge.Database")
    def test_find_by_authorization(self, MockDB):
        repo = self._make_repo(MagicMock())
        authz_id = _uuid()
        repo.find_by = MagicMock(return_value=[])
        repo.find_by_authorization(authz_id)
        repo.find_by.assert_called_once_with({"authorization_id": authz_id})

    @patch("acmeeh.repositories.challenge.Database")
    def test_auto_accept_by_authorization(self, MockDB):
        db = MockDB.get_instance.return_value
        db.execute.return_value = 3
        repo = self._make_repo(db)
        result = repo.auto_accept_by_authorization(_uuid())
        assert result == 3

    @patch("acmeeh.repositories.challenge.Database")
    def test_find_retryable(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _challenge_row(retry_count=1)
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        result = repo.find_retryable(_utcnow())
        assert len(result) == 1

    @patch("acmeeh.repositories.challenge.Database")
    def test_find_retryable_with_conn(self, MockDB):
        conn = MagicMock()
        row = _challenge_row(retry_count=1)
        conn.fetch_all.return_value = [row]
        repo = self._make_repo(MagicMock())
        result = repo.find_retryable(_utcnow(), conn=conn)
        assert len(result) == 1
        conn.fetch_all.assert_called_once()

    @patch("acmeeh.repositories.challenge.Database")
    def test_claim_for_processing_success(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _challenge_row(status=ChallengeStatus.PROCESSING.value, locked_by="w1")
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.claim_for_processing(_uuid(), "w1")
        assert result is not None

    @patch("acmeeh.repositories.challenge.Database")
    def test_claim_for_processing_cas_failed(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.claim_for_processing(_uuid(), "w1")
        assert result is None

    @patch("acmeeh.repositories.challenge.Database")
    def test_complete_validation_success(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _challenge_row(status=ChallengeStatus.VALID.value, validated_at=_utcnow())
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.complete_validation(_uuid(), "w1", success=True)
        assert result is not None

    @patch("acmeeh.repositories.challenge.Database")
    def test_complete_validation_failure(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _challenge_row(status=ChallengeStatus.INVALID.value, error={"detail": "err"})
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.complete_validation(_uuid(), "w1", success=False, error={"detail": "err"})
        assert result is not None

    @patch("acmeeh.repositories.challenge.Database")
    def test_complete_validation_cas_failed(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.complete_validation(_uuid(), "w1", success=True)
        assert result is None

    @patch("acmeeh.repositories.challenge.Database")
    def test_release_stale_locks(self, MockDB):
        db = MockDB.get_instance.return_value
        db.execute.return_value = 2
        repo = self._make_repo(db)
        result = repo.release_stale_locks(_utcnow())
        assert result == 2

    @patch("acmeeh.repositories.challenge.Database")
    def test_release_stale_locks_zero(self, MockDB):
        db = MockDB.get_instance.return_value
        db.execute.return_value = 0
        repo = self._make_repo(db)
        result = repo.release_stale_locks(_utcnow())
        assert result == 0

    @patch("acmeeh.repositories.challenge.Database")
    def test_release_stale_locks_with_conn(self, MockDB):
        conn = MagicMock()
        conn.execute.return_value = 1
        repo = self._make_repo(MagicMock())
        result = repo.release_stale_locks(_utcnow(), conn=conn)
        assert result == 1

    @patch("acmeeh.repositories.challenge.Database")
    def test_claim_with_advisory_lock(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_value.return_value = True
        repo = self._make_repo(db)
        assert repo.claim_with_advisory_lock(_uuid()) is True

    @patch("acmeeh.repositories.challenge.Database")
    def test_claim_with_advisory_lock_not_acquired(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_value.return_value = False
        repo = self._make_repo(db)
        assert repo.claim_with_advisory_lock(_uuid()) is False

    @patch("acmeeh.repositories.challenge.Database")
    def test_drain_processing(self, MockDB):
        db = MockDB.get_instance.return_value
        db.execute.return_value = 5
        repo = self._make_repo(db)
        assert repo.drain_processing() == 5

    @patch("acmeeh.repositories.challenge.Database")
    def test_drain_processing_not_int(self, MockDB):
        db = MockDB.get_instance.return_value
        db.execute.return_value = None
        repo = self._make_repo(db)
        assert repo.drain_processing() == 0

    @patch("acmeeh.repositories.challenge.Database")
    def test_retry_challenge_with_backoff(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _challenge_row(status=ChallengeStatus.PENDING.value, retry_count=2)
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.retry_challenge(_uuid(), "w1", backoff_seconds=30)
        assert result is not None

    @patch("acmeeh.repositories.challenge.Database")
    def test_retry_challenge_no_backoff(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _challenge_row(status=ChallengeStatus.PENDING.value, retry_count=2)
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.retry_challenge(_uuid(), "w1", backoff_seconds=0)
        assert result is not None

    @patch("acmeeh.repositories.challenge.Database")
    def test_retry_challenge_cas_failed(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.retry_challenge(_uuid(), "w1")
        assert result is None


# ======================================================================
# OrderRepository
# ======================================================================

class TestOrderRepository:

    def _make_repo(self, mock_db):
        from acmeeh.repositories.order import OrderRepository
        return OrderRepository(mock_db)

    def test_row_to_entity(self):
        repo = self._make_repo(MagicMock())
        row = _order_row()
        order = repo._row_to_entity(row)
        assert order.status == OrderStatus.PENDING
        assert len(order.identifiers) == 1
        assert order.identifiers[0].type == IdentifierType.DNS

    def test_entity_to_row(self):
        repo = self._make_repo(MagicMock())
        from acmeeh.models.order import Identifier, Order
        order = Order(
            id=_uuid(), account_id=_uuid(), status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
            identifiers_hash="h", expires=_utcnow(), not_before=None,
            not_after=None, error={"detail": "err"}, certificate_id=None,
            created_at=_utcnow(), updated_at=_utcnow(),
        )
        row = repo._entity_to_row(order)
        assert row["status"] == OrderStatus.READY.value

    def test_entity_to_row_no_error(self):
        repo = self._make_repo(MagicMock())
        from acmeeh.models.order import Identifier, Order
        order = Order(
            id=_uuid(), account_id=_uuid(), status=OrderStatus.PENDING,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
            identifiers_hash="h", expires=None, not_before=None,
            not_after=None, error=None, certificate_id=None,
            created_at=_utcnow(), updated_at=_utcnow(),
        )
        row = repo._entity_to_row(order)
        assert row["error"] is None

    @patch("acmeeh.repositories.order.Database")
    def test_find_by_account_no_status(self, MockDB):
        repo = self._make_repo(MagicMock())
        acct_id = _uuid()
        repo.find_by = MagicMock(return_value=[])
        repo.find_by_account(acct_id)
        repo.find_by.assert_called_once_with({"account_id": acct_id})

    @patch("acmeeh.repositories.order.Database")
    def test_find_by_account_with_status(self, MockDB):
        repo = self._make_repo(MagicMock())
        acct_id = _uuid()
        repo.find_by = MagicMock(return_value=[])
        repo.find_by_account(acct_id, status=OrderStatus.VALID)
        repo.find_by.assert_called_once_with({"account_id": acct_id, "status": OrderStatus.VALID.value})

    @patch("acmeeh.repositories.order.Database")
    def test_find_by_account_paginated_no_cursor(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_all.return_value = [_order_row()]
        repo = self._make_repo(db)
        orders, cursor = repo.find_by_account_paginated(_uuid())
        assert len(orders) == 1
        assert cursor is None

    @patch("acmeeh.repositories.order.Database")
    def test_find_by_account_paginated_with_cursor(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_all.return_value = [_order_row()]
        repo = self._make_repo(db)
        orders, cursor = repo.find_by_account_paginated(_uuid(), cursor=_uuid())
        assert len(orders) == 1

    @patch("acmeeh.repositories.order.Database")
    def test_find_by_account_paginated_has_next(self, MockDB):
        db = MockDB.get_instance.return_value
        # Return limit+1 rows to indicate next page
        rows = [_order_row() for _ in range(51)]
        db.fetch_all.return_value = rows
        repo = self._make_repo(db)
        orders, cursor = repo.find_by_account_paginated(_uuid(), limit=50)
        assert len(orders) == 50
        assert cursor is not None

    @patch("acmeeh.repositories.order.Database")
    def test_find_pending_for_dedup_found(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _order_row()
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.find_pending_for_dedup(_uuid(), "hash")
        assert result is not None

    @patch("acmeeh.repositories.order.Database")
    def test_find_pending_for_dedup_not_found(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.find_pending_for_dedup(_uuid(), "hash")
        assert result is None

    @patch("acmeeh.repositories.order.Database")
    def test_find_stale_processing(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _order_row(status=OrderStatus.PROCESSING.value)
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        result = repo.find_stale_processing()
        assert len(result) == 1

    @patch("acmeeh.repositories.order.Database")
    def test_find_stale_processing_with_conn(self, MockDB):
        conn = MagicMock()
        row = _order_row(status=OrderStatus.PROCESSING.value)
        conn.fetch_all.return_value = [row]
        repo = self._make_repo(MagicMock())
        result = repo.find_stale_processing(conn=conn)
        assert len(result) == 1

    @patch("acmeeh.repositories.order.Database")
    def test_find_expired_actionable_with_cutoff(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _order_row()
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        result = repo.find_expired_actionable(cutoff=_utcnow())
        assert len(result) == 1

    @patch("acmeeh.repositories.order.Database")
    def test_find_expired_actionable_no_cutoff(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_all.return_value = []
        repo = self._make_repo(db)
        result = repo.find_expired_actionable()
        assert result == []

    @patch("acmeeh.repositories.order.Database")
    def test_find_expired_actionable_with_conn(self, MockDB):
        conn = MagicMock()
        conn.fetch_all.return_value = []
        repo = self._make_repo(MagicMock())
        result = repo.find_expired_actionable(conn=conn)
        assert result == []

    @patch("acmeeh.repositories.order.Database")
    def test_transition_status_success(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _order_row(status=OrderStatus.READY.value)
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.transition_status(_uuid(), OrderStatus.PENDING, OrderStatus.READY)
        assert result is not None

    @patch("acmeeh.repositories.order.Database")
    def test_transition_status_with_error_and_cert(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _order_row(status=OrderStatus.VALID.value, certificate_id=_uuid())
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.transition_status(
            _uuid(), OrderStatus.PROCESSING, OrderStatus.VALID,
            error={"detail": "err"}, certificate_id=_uuid(),
        )
        assert result is not None

    @patch("acmeeh.repositories.order.Database")
    def test_transition_status_cas_failed(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.transition_status(_uuid(), OrderStatus.PENDING, OrderStatus.READY)
        assert result is None

    @patch("acmeeh.repositories.order.Database")
    def test_transition_status_with_conn(self, MockDB):
        conn = MagicMock()
        row = _order_row(status=OrderStatus.READY.value)
        conn.fetch_one.return_value = row
        repo = self._make_repo(MagicMock())
        result = repo.transition_status(
            _uuid(), OrderStatus.PENDING, OrderStatus.READY, conn=conn,
        )
        assert result is not None

    @patch("acmeeh.repositories.order.Database")
    def test_link_authorization(self, MockDB):
        db = MockDB.get_instance.return_value
        repo = self._make_repo(db)
        repo.link_authorization(_uuid(), _uuid())
        db.execute.assert_called_once()

    @patch("acmeeh.repositories.order.Database")
    def test_find_authorization_ids(self, MockDB):
        db = MockDB.get_instance.return_value
        aid = _uuid()
        db.fetch_all.return_value = [{"authorization_id": aid}]
        repo = self._make_repo(db)
        result = repo.find_authorization_ids(_uuid())
        assert result == [aid]

    @patch("acmeeh.repositories.order.Database")
    def test_find_orders_by_authorization(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _order_row()
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        result = repo.find_orders_by_authorization(_uuid())
        assert len(result) == 1

    @patch("acmeeh.repositories.order.Database")
    def test_count_orders_since(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_value.return_value = 7
        repo = self._make_repo(db)
        assert repo.count_orders_since(_uuid(), _utcnow()) == 7

    @patch("acmeeh.repositories.order.Database")
    def test_count_orders_since_not_int(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_value.return_value = None
        repo = self._make_repo(db)
        assert repo.count_orders_since(_uuid(), _utcnow()) == 0


# ======================================================================
# AuthorizationRepository
# ======================================================================

class TestAuthorizationRepository:

    def _make_repo(self, mock_db):
        from acmeeh.repositories.authorization import AuthorizationRepository
        return AuthorizationRepository(mock_db)

    def test_row_to_entity(self):
        repo = self._make_repo(MagicMock())
        row = _authz_row()
        authz = repo._row_to_entity(row)
        assert authz.identifier_type == IdentifierType.DNS
        assert authz.status == AuthorizationStatus.PENDING

    def test_entity_to_row(self):
        repo = self._make_repo(MagicMock())
        from acmeeh.models.authorization import Authorization
        authz = Authorization(
            id=_uuid(), account_id=_uuid(),
            identifier_type=IdentifierType.IP, identifier_value="1.2.3.4",
            status=AuthorizationStatus.VALID, expires=_utcnow(),
            wildcard=True, created_at=_utcnow(), updated_at=_utcnow(),
        )
        row = repo._entity_to_row(authz)
        assert row["identifier_type"] == IdentifierType.IP.value
        assert row["wildcard"] is True

    @patch("acmeeh.repositories.authorization.Database")
    def test_find_reusable_found(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _authz_row(status=AuthorizationStatus.VALID.value)
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.find_reusable(_uuid(), IdentifierType.DNS, "example.com")
        assert result is not None

    @patch("acmeeh.repositories.authorization.Database")
    def test_find_reusable_not_found(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.find_reusable(_uuid(), IdentifierType.DNS, "example.com")
        assert result is None

    @patch("acmeeh.repositories.authorization.Database")
    def test_find_by_order(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _authz_row()
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        result = repo.find_by_order(_uuid())
        assert len(result) == 1

    @patch("acmeeh.repositories.authorization.Database")
    def test_all_valid_for_order_true(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = {"total": 2, "valid_count": 2}
        repo = self._make_repo(db)
        assert repo.all_valid_for_order(_uuid()) is True

    @patch("acmeeh.repositories.authorization.Database")
    def test_all_valid_for_order_false(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = {"total": 2, "valid_count": 1}
        repo = self._make_repo(db)
        assert repo.all_valid_for_order(_uuid()) is False

    @patch("acmeeh.repositories.authorization.Database")
    def test_all_valid_for_order_none_row(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        assert repo.all_valid_for_order(_uuid()) is False

    @patch("acmeeh.repositories.authorization.Database")
    def test_all_valid_for_order_zero_total(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = {"total": 0, "valid_count": 0}
        repo = self._make_repo(db)
        assert repo.all_valid_for_order(_uuid()) is False

    @patch("acmeeh.repositories.authorization.Database")
    def test_transition_status_success(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _authz_row(status=AuthorizationStatus.VALID.value)
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.transition_status(_uuid(), AuthorizationStatus.PENDING, AuthorizationStatus.VALID)
        assert result is not None

    @patch("acmeeh.repositories.authorization.Database")
    def test_transition_status_cas_failed(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.transition_status(_uuid(), AuthorizationStatus.PENDING, AuthorizationStatus.VALID)
        assert result is None

    @patch("acmeeh.repositories.authorization.Database")
    def test_deactivate_for_account(self, MockDB):
        db = MockDB.get_instance.return_value
        db.execute.return_value = 3
        repo = self._make_repo(db)
        assert repo.deactivate_for_account(_uuid()) == 3

    @patch("acmeeh.repositories.authorization.Database")
    def test_deactivate_for_account_not_int(self, MockDB):
        db = MockDB.get_instance.return_value
        db.execute.return_value = None
        repo = self._make_repo(db)
        assert repo.deactivate_for_account(_uuid()) == 0

    @patch("acmeeh.repositories.authorization.Database")
    def test_find_expired_pending_with_cutoff(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _authz_row(status=AuthorizationStatus.PENDING.value)
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        result = repo.find_expired_pending(cutoff=_utcnow())
        assert len(result) == 1

    @patch("acmeeh.repositories.authorization.Database")
    def test_find_expired_pending_no_cutoff(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_all.return_value = []
        repo = self._make_repo(db)
        result = repo.find_expired_pending()
        assert result == []


# ======================================================================
# NotificationRepository
# ======================================================================

class TestNotificationRepository:

    def _make_repo(self, mock_db):
        from acmeeh.repositories.notification import NotificationRepository
        return NotificationRepository(mock_db)

    def test_row_to_entity(self):
        repo = self._make_repo(MagicMock())
        row = _notification_row()
        notif = repo._row_to_entity(row)
        assert notif.notification_type == NotificationType.EXPIRATION_WARNING

    def test_entity_to_row(self):
        repo = self._make_repo(MagicMock())
        from acmeeh.models.notification import Notification
        notif = Notification(
            id=_uuid(), notification_type=NotificationType.EXPIRATION_WARNING,
            recipient="admin@test.com", subject="sub", body="bod",
            status=NotificationStatus.PENDING, account_id=_uuid(),
            error_detail=None, retry_count=0,
            created_at=_utcnow(), sent_at=None,
        )
        row = repo._entity_to_row(notif)
        assert row["notification_type"] == NotificationType.EXPIRATION_WARNING.value

    @patch("acmeeh.repositories.notification.Database")
    def test_find_pending_retry(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _notification_row(status=NotificationStatus.FAILED.value, retry_count=1)
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        result = repo.find_pending_retry(max_retries=5)
        assert len(result) == 1

    @patch("acmeeh.repositories.notification.Database")
    def test_mark_sent(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _notification_row(status=NotificationStatus.SENT.value, sent_at=_utcnow())
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.mark_sent(_uuid())
        assert result is not None

    @patch("acmeeh.repositories.notification.Database")
    def test_mark_sent_not_found(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.mark_sent(_uuid())
        assert result is None

    @patch("acmeeh.repositories.notification.Database")
    def test_mark_failed(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _notification_row(status=NotificationStatus.FAILED.value, error_detail="smtp err", retry_count=2)
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.mark_failed(_uuid(), "smtp err")
        assert result is not None

    @patch("acmeeh.repositories.notification.Database")
    def test_mark_failed_not_found(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.mark_failed(_uuid(), "error")
        assert result is None

    @patch("acmeeh.repositories.notification.Database")
    def test_reset_for_retry(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _notification_row(status=NotificationStatus.PENDING.value)
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.reset_for_retry(_uuid())
        assert result is not None

    @patch("acmeeh.repositories.notification.Database")
    def test_reset_for_retry_not_found(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.reset_for_retry(_uuid())
        assert result is None

    @patch("acmeeh.repositories.notification.Database")
    def test_find_all_paginated_with_status(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _notification_row()
        db.fetch_all.return_value = [row]
        repo = self._make_repo(db)
        result = repo.find_all_paginated(status="pending")
        assert len(result) == 1

    @patch("acmeeh.repositories.notification.Database")
    def test_find_all_paginated_no_status(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_all.return_value = []
        repo = self._make_repo(db)
        result = repo.find_all_paginated()
        assert result == []

    @patch("acmeeh.repositories.notification.Database")
    def test_purge_old(self, MockDB):
        db = MockDB.get_instance.return_value
        db.execute.return_value = 10
        repo = self._make_repo(db)
        assert repo.purge_old(30) == 10

    @patch("acmeeh.repositories.notification.Database")
    def test_reset_failed_for_retry(self, MockDB):
        db = MockDB.get_instance.return_value
        db.execute.return_value = 3
        repo = self._make_repo(db)
        assert repo.reset_failed_for_retry() == 3


# ======================================================================
# AccountRepository & AccountContactRepository
# ======================================================================

class TestAccountRepository:

    def _make_repo(self, mock_db):
        from acmeeh.repositories.account import AccountRepository
        return AccountRepository(mock_db)

    def test_row_to_entity(self):
        repo = self._make_repo(MagicMock())
        row = _account_row()
        acct = repo._row_to_entity(row)
        assert acct.status == AccountStatus.VALID

    def test_entity_to_row(self):
        repo = self._make_repo(MagicMock())
        from acmeeh.models.account import Account
        acct = Account(
            id=_uuid(), jwk_thumbprint="tp", jwk={"kty": "EC"},
            status=AccountStatus.VALID, tos_agreed=True,
            created_at=_utcnow(), updated_at=_utcnow(),
        )
        row = repo._entity_to_row(acct)
        assert row["status"] == AccountStatus.VALID.value

    @patch("acmeeh.repositories.account.Database")
    def test_find_by_thumbprint(self, MockDB):
        repo = self._make_repo(MagicMock())
        repo.find_one_by = MagicMock(return_value=None)
        repo.find_by_thumbprint("tp")
        repo.find_one_by.assert_called_once_with({"jwk_thumbprint": "tp"})

    @patch("acmeeh.repositories.account.Database")
    def test_update_jwk_success(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _account_row()
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.update_jwk(_uuid(), {"kty": "EC"}, "new_tp")
        assert result is not None

    @patch("acmeeh.repositories.account.Database")
    def test_update_jwk_cas_failed(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.update_jwk(_uuid(), {"kty": "EC"}, "new_tp")
        assert result is None

    @patch("acmeeh.repositories.account.Database")
    def test_deactivate_success(self, MockDB):
        db = MockDB.get_instance.return_value
        row = _account_row(status=AccountStatus.DEACTIVATED.value)
        db.fetch_one.return_value = row
        repo = self._make_repo(db)
        result = repo.deactivate(_uuid())
        assert result is not None

    @patch("acmeeh.repositories.account.Database")
    def test_deactivate_cas_failed(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        result = repo.deactivate(_uuid())
        assert result is None


class TestAccountContactRepository:

    def _make_repo(self, mock_db):
        from acmeeh.repositories.account import AccountContactRepository
        return AccountContactRepository(mock_db)

    def test_row_to_entity(self):
        repo = self._make_repo(MagicMock())
        row = _contact_row()
        contact = repo._row_to_entity(row)
        assert contact.contact_uri == row["contact_uri"]

    def test_entity_to_row(self):
        repo = self._make_repo(MagicMock())
        from acmeeh.models.account import AccountContact
        contact = AccountContact(
            id=_uuid(), account_id=_uuid(),
            contact_uri="mailto:test@example.com",
            created_at=_utcnow(),
        )
        row = repo._entity_to_row(contact)
        assert row["contact_uri"] == "mailto:test@example.com"

    @patch("acmeeh.repositories.account.Database")
    def test_find_by_account(self, MockDB):
        repo = self._make_repo(MagicMock())
        acct_id = _uuid()
        repo.find_by = MagicMock(return_value=[])
        repo.find_by_account(acct_id)
        repo.find_by.assert_called_once_with({"account_id": acct_id})

    @patch("acmeeh.repositories.account.Database")
    def test_replace_for_account(self, MockDB):
        db = MockDB.get_instance.return_value
        # Mock transaction context manager
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_cursor.fetchone.return_value = _contact_row()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        db.transaction.return_value = mock_conn

        repo = self._make_repo(db)
        from acmeeh.models.account import AccountContact
        contact = AccountContact(
            id=_uuid(), account_id=_uuid(),
            contact_uri="mailto:test@example.com",
            created_at=_utcnow(),
        )
        result = repo.replace_for_account(_uuid(), [contact])
        assert len(result) == 1

    @patch("acmeeh.repositories.account.Database")
    def test_delete_by_account(self, MockDB):
        repo = self._make_repo(MagicMock())
        acct_id = _uuid()
        repo.delete_by = MagicMock(return_value=2)
        result = repo.delete_by_account(acct_id)
        assert result == 2


# ======================================================================
# NonceRepository
# ======================================================================

class TestNonceRepository:

    def _make_repo(self, mock_db, audit=False):
        from acmeeh.repositories.nonce import NonceRepository
        return NonceRepository(mock_db, audit_consumed=audit)

    def test_row_to_entity(self):
        repo = self._make_repo(MagicMock())
        row = _nonce_row()
        nonce = repo._row_to_entity(row)
        assert nonce.nonce == "nonce_value_1"

    def test_entity_to_row(self):
        repo = self._make_repo(MagicMock())
        from acmeeh.models.nonce import Nonce
        nonce = Nonce(nonce="n1", expires_at=_utcnow(), created_at=_utcnow())
        row = repo._entity_to_row(nonce)
        assert row["nonce"] == "n1"

    @patch("acmeeh.repositories.nonce.Database")
    def test_consume_valid(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = {"nonce": "n1"}
        repo = self._make_repo(db)
        assert repo.consume("n1") is True

    @patch("acmeeh.repositories.nonce.Database")
    def test_consume_invalid(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = None
        repo = self._make_repo(db)
        assert repo.consume("n1") is False

    @patch("acmeeh.repositories.nonce.Database")
    def test_consume_with_audit(self, MockDB):
        db = MockDB.get_instance.return_value
        db.fetch_one.return_value = {"nonce": "n1"}
        repo = self._make_repo(db, audit=True)
        repo.consume("n1", client_ip="1.2.3.4")
        # Should insert audit row
        db.execute.assert_called_once()

    @patch("acmeeh.repositories.nonce.Database")
    def test_bulk_create_empty(self, MockDB):
        repo = self._make_repo(MagicMock())
        assert repo.bulk_create([]) == 0

    @patch("acmeeh.repositories.nonce.Database")
    def test_bulk_create(self, MockDB):
        db = MockDB.get_instance.return_value
        db.execute.return_value = 2
        repo = self._make_repo(db)
        from acmeeh.models.nonce import Nonce
        nonces = [
            Nonce(nonce="n1", expires_at=_utcnow(), created_at=_utcnow()),
            Nonce(nonce="n2", expires_at=_utcnow(), created_at=_utcnow()),
        ]
        result = repo.bulk_create(nonces)
        assert result == 2

    @patch("acmeeh.repositories.nonce.Database")
    def test_gc_expired(self, MockDB):
        db = MockDB.get_instance.return_value
        db.execute.return_value = 5
        repo = self._make_repo(db)
        assert repo.gc_expired() == 5

    @patch("acmeeh.repositories.nonce.Database")
    def test_gc_expired_with_conn(self, MockDB):
        conn = MagicMock()
        conn.execute.return_value = 3
        repo = self._make_repo(MagicMock())
        assert repo.gc_expired(conn=conn) == 3
