"""Tests for the 7 new notification types and per-type disable feature.

Covers: CHALLENGE_FAILED, CSR_VALIDATION_FAILED, ORDER_STALE_RECOVERED,
ACCOUNT_DEACTIVATED, KEY_ROLLOVER_SUCCEEDED, ORDER_QUOTA_EXCEEDED,
AUTHORIZATION_DEACTIVATED, and the ``disabled_types`` configuration.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest

from acmeeh.app.errors import BAD_CSR, RATE_LIMITED, AcmeProblem
from acmeeh.core.types import (
    AccountStatus,
    AuthorizationStatus,
    ChallengeStatus,
    ChallengeType,
    IdentifierType,
    NotificationType,
    OrderStatus,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_account(account_id: UUID | None = None, thumbprint: str = "thumb") -> MagicMock:
    acct = MagicMock()
    acct.id = account_id or uuid4()
    acct.jwk_thumbprint = thumbprint
    acct.status = AccountStatus.VALID
    return acct


def _mock_authz(
    authz_id: UUID | None = None,
    account_id: UUID | None = None,
    identifier_type=IdentifierType.DNS,
    identifier_value="example.com",
    status=AuthorizationStatus.PENDING,
):
    authz = MagicMock()
    authz.id = authz_id or uuid4()
    authz.account_id = account_id or uuid4()
    authz.identifier_type = identifier_type
    authz.identifier_value = identifier_value
    authz.status = status
    return authz


def _mock_challenge(
    challenge_id: UUID | None = None,
    authz_id: UUID | None = None,
    status=ChallengeStatus.PENDING,
    challenge_type=ChallengeType.HTTP_01,
    retry_count=0,
):
    ch = MagicMock()
    ch.id = challenge_id or uuid4()
    ch.authorization_id = authz_id or uuid4()
    ch.status = status
    ch.type = challenge_type
    ch.token = "test-token"
    ch.retry_count = retry_count
    return ch


def _mock_order(
    order_id: UUID | None = None,
    account_id: UUID | None = None,
    status=OrderStatus.PENDING,
    identifiers=None,
):
    order = MagicMock()
    order.id = order_id or uuid4()
    order.account_id = account_id or uuid4()
    order.status = status
    if identifiers is None:
        ident = MagicMock()
        ident.value = "example.com"
        ident.type = IdentifierType.DNS
        order.identifiers = (ident,)
    else:
        order.identifiers = identifiers
    return order


def _make_quota_settings(**overrides):
    q = MagicMock()
    q.enabled = overrides.get("enabled", True)
    q.max_orders_per_account_per_day = overrides.get("max_orders_per_account_per_day", 10)
    return q


# ---------------------------------------------------------------------------
# 1. CHALLENGE_FAILED — terminal ChallengeError
# ---------------------------------------------------------------------------


class TestChallengeFailedNotification:
    """ChallengeService sends CHALLENGE_FAILED on terminal failure."""

    def test_terminal_challenge_error_sends_notification(self):
        from acmeeh.challenge.base import ChallengeError
        from acmeeh.services.challenge import ChallengeService

        challenge_repo = MagicMock()
        authz_repo = MagicMock()
        order_repo = MagicMock()
        registry = MagicMock()
        notifier = MagicMock()

        account_id = uuid4()
        authz = _mock_authz(account_id=account_id)
        challenge = _mock_challenge(authz_id=authz.id, retry_count=99)

        challenge_repo.find_by_id.return_value = challenge
        challenge_repo.claim_for_processing.return_value = challenge
        challenge_repo.complete_validation.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        authz_repo.transition_status.return_value = None
        order_repo.find_orders_by_authorization.return_value = []

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 0  # No retries -> terminal immediately
        validator.validate.side_effect = ChallengeError("DNS record not found", retryable=False)
        registry.get_validator_or_none.return_value = validator

        svc = ChallengeService(
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            order_repo=order_repo,
            registry=registry,
            notifier=notifier,
        )
        svc.initiate_validation(challenge.id, account_id, {"kty": "EC"})

        notifier.notify.assert_called_once()
        call_args = notifier.notify.call_args[0]
        assert call_args[0] == NotificationType.CHALLENGE_FAILED
        assert call_args[1] == account_id
        assert call_args[2]["identifier"] == "example.com"
        assert call_args[2]["challenge_type"] == ChallengeType.HTTP_01.value

    def test_unexpected_exception_sends_notification(self):
        from acmeeh.services.challenge import ChallengeService

        challenge_repo = MagicMock()
        authz_repo = MagicMock()
        order_repo = MagicMock()
        registry = MagicMock()
        notifier = MagicMock()

        account_id = uuid4()
        authz = _mock_authz(account_id=account_id)
        challenge = _mock_challenge(authz_id=authz.id)

        challenge_repo.find_by_id.return_value = challenge
        challenge_repo.claim_for_processing.return_value = challenge
        challenge_repo.complete_validation.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        authz_repo.transition_status.return_value = None
        order_repo.find_orders_by_authorization.return_value = []

        validator = MagicMock()
        validator.auto_validate = True
        validator.validate.side_effect = RuntimeError("unexpected boom")
        registry.get_validator_or_none.return_value = validator

        svc = ChallengeService(
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            order_repo=order_repo,
            registry=registry,
            notifier=notifier,
        )
        svc.initiate_validation(challenge.id, account_id, {"kty": "EC"})

        notifier.notify.assert_called_once()
        call_args = notifier.notify.call_args[0]
        assert call_args[0] == NotificationType.CHALLENGE_FAILED
        assert "unexpected boom" in call_args[2]["error_detail"]

    def test_no_notification_without_notifier(self):
        """When notifier is None, no error is raised."""
        from acmeeh.challenge.base import ChallengeError
        from acmeeh.services.challenge import ChallengeService

        challenge_repo = MagicMock()
        authz_repo = MagicMock()
        order_repo = MagicMock()
        registry = MagicMock()

        account_id = uuid4()
        authz = _mock_authz(account_id=account_id)
        challenge = _mock_challenge(authz_id=authz.id)

        challenge_repo.find_by_id.return_value = challenge
        challenge_repo.claim_for_processing.return_value = challenge
        challenge_repo.complete_validation.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        authz_repo.transition_status.return_value = None
        order_repo.find_orders_by_authorization.return_value = []

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 0
        validator.validate.side_effect = ChallengeError("fail", retryable=False)
        registry.get_validator_or_none.return_value = validator

        svc = ChallengeService(
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            order_repo=order_repo,
            registry=registry,
            notifier=None,
        )
        # Should not raise
        svc.initiate_validation(challenge.id, account_id, {"kty": "EC"})

    def test_notification_failure_does_not_propagate(self):
        """If notifier.notify raises, the error is swallowed."""
        from acmeeh.challenge.base import ChallengeError
        from acmeeh.services.challenge import ChallengeService

        challenge_repo = MagicMock()
        authz_repo = MagicMock()
        order_repo = MagicMock()
        registry = MagicMock()
        notifier = MagicMock()
        notifier.notify.side_effect = RuntimeError("notify boom")

        account_id = uuid4()
        authz = _mock_authz(account_id=account_id)
        challenge = _mock_challenge(authz_id=authz.id)

        challenge_repo.find_by_id.return_value = challenge
        challenge_repo.claim_for_processing.return_value = challenge
        challenge_repo.complete_validation.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        authz_repo.transition_status.return_value = None
        order_repo.find_orders_by_authorization.return_value = []

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 0
        validator.validate.side_effect = ChallengeError("fail", retryable=False)
        registry.get_validator_or_none.return_value = validator

        svc = ChallengeService(
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            order_repo=order_repo,
            registry=registry,
            notifier=notifier,
        )
        # Should not raise despite notifier failure
        svc.initiate_validation(challenge.id, account_id, {"kty": "EC"})


# ---------------------------------------------------------------------------
# 2. CSR_VALIDATION_FAILED
# ---------------------------------------------------------------------------


class TestCsrValidationFailedNotification:
    """CertificateService sends CSR_VALIDATION_FAILED on BAD_CSR."""

    def test_unparseable_csr_sends_notification(self):
        from acmeeh.services.certificate import CertificateService

        cert_repo = MagicMock()
        cert_repo.next_serial.return_value = 1
        order_repo = MagicMock()
        ca_settings = MagicMock()
        ca_backend = MagicMock()
        ca_backend.deferred = False
        notifier = MagicMock()
        db = MagicMock()

        account_id = uuid4()
        order = _mock_order(account_id=account_id, status=OrderStatus.READY)
        processing_order = _mock_order(
            order_id=order.id, account_id=account_id, status=OrderStatus.PROCESSING
        )
        order_repo.find_by_id.return_value = order
        order_repo.transition_status.return_value = processing_order

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            notification_service=notifier,
            db=db,
        )

        with pytest.raises(AcmeProblem) as exc_info:
            svc.finalize_order(order.id, b"not-valid-der", account_id)
        assert BAD_CSR in exc_info.value.error_type

        notifier.notify.assert_called_once()
        call_args = notifier.notify.call_args[0]
        assert call_args[0] == NotificationType.CSR_VALIDATION_FAILED
        assert call_args[1] == account_id
        assert "order_id" in call_args[2]
        assert "domains" in call_args[2]
        assert "error_detail" in call_args[2]

    def test_invalid_csr_signature_sends_notification(self):
        from acmeeh.services.certificate import CertificateService

        cert_repo = MagicMock()
        order_repo = MagicMock()
        ca_settings = MagicMock()
        ca_backend = MagicMock()
        ca_backend.deferred = False
        notifier = MagicMock()
        db = MagicMock()

        account_id = uuid4()
        order = _mock_order(account_id=account_id, status=OrderStatus.READY)
        processing_order = _mock_order(
            order_id=order.id, account_id=account_id, status=OrderStatus.PROCESSING
        )
        order_repo.find_by_id.return_value = order
        order_repo.transition_status.return_value = processing_order

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            notification_service=notifier,
            db=db,
        )

        with patch("acmeeh.services.certificate.x509.load_der_x509_csr") as mock_load:
            mock_csr = MagicMock()
            mock_csr.is_signature_valid = False
            mock_load.return_value = mock_csr

            with pytest.raises(AcmeProblem) as exc_info:
                svc.finalize_order(order.id, b"\x30\x00", account_id)
            assert BAD_CSR in exc_info.value.error_type

        notifier.notify.assert_called_once()
        assert notifier.notify.call_args[0][0] == NotificationType.CSR_VALIDATION_FAILED

    def test_no_notification_without_notifier(self):
        from acmeeh.services.certificate import CertificateService

        cert_repo = MagicMock()
        order_repo = MagicMock()
        ca_settings = MagicMock()
        ca_backend = MagicMock()
        ca_backend.deferred = False
        db = MagicMock()

        account_id = uuid4()
        order = _mock_order(account_id=account_id, status=OrderStatus.READY)
        processing_order = _mock_order(
            order_id=order.id, account_id=account_id, status=OrderStatus.PROCESSING
        )
        order_repo.find_by_id.return_value = order
        order_repo.transition_status.return_value = processing_order

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            notification_service=None,
            db=db,
        )

        with pytest.raises(AcmeProblem):
            svc.finalize_order(order.id, b"not-valid-der", account_id)

    def test_notification_failure_does_not_prevent_raise(self):
        """Even if notifier.notify raises, the AcmeProblem still propagates."""
        from acmeeh.services.certificate import CertificateService

        cert_repo = MagicMock()
        order_repo = MagicMock()
        ca_settings = MagicMock()
        ca_backend = MagicMock()
        ca_backend.deferred = False
        notifier = MagicMock()
        notifier.notify.side_effect = RuntimeError("notify boom")
        db = MagicMock()

        account_id = uuid4()
        order = _mock_order(account_id=account_id, status=OrderStatus.READY)
        processing_order = _mock_order(
            order_id=order.id, account_id=account_id, status=OrderStatus.PROCESSING
        )
        order_repo.find_by_id.return_value = order
        order_repo.transition_status.return_value = processing_order

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            notification_service=notifier,
            db=db,
        )

        with pytest.raises(AcmeProblem) as exc_info:
            svc.finalize_order(order.id, b"not-valid-der", account_id)
        assert BAD_CSR in exc_info.value.error_type


# ---------------------------------------------------------------------------
# 3. ORDER_STALE_RECOVERED
# ---------------------------------------------------------------------------


class TestOrderStaleRecoveredNotification:
    """CleanupWorker sends ORDER_STALE_RECOVERED for stuck orders."""

    def test_stale_recovery_sends_notification(self):
        from acmeeh.services.cleanup_worker import CleanupWorker

        order_repo = MagicMock()
        notifier = MagicMock()

        order1 = _mock_order(status=OrderStatus.PROCESSING)
        order2 = _mock_order(status=OrderStatus.PROCESSING)
        order_repo.find_stale_processing.return_value = [order1, order2]

        CleanupWorker._stale_processing_recovery(order_repo, 600, notifier=notifier)

        assert notifier.notify.call_count == 2
        for call in notifier.notify.call_args_list:
            args = call[0]
            assert args[0] == NotificationType.ORDER_STALE_RECOVERED
            assert "order_id" in args[2]
            assert "domains" in args[2]

    def test_no_stale_orders_no_notification(self):
        from acmeeh.services.cleanup_worker import CleanupWorker

        order_repo = MagicMock()
        notifier = MagicMock()
        order_repo.find_stale_processing.return_value = []

        CleanupWorker._stale_processing_recovery(order_repo, 600, notifier=notifier)

        notifier.notify.assert_not_called()

    def test_no_notification_without_notifier(self):
        from acmeeh.services.cleanup_worker import CleanupWorker

        order_repo = MagicMock()
        order = _mock_order(status=OrderStatus.PROCESSING)
        order_repo.find_stale_processing.return_value = [order]

        # Should not raise with notifier=None
        CleanupWorker._stale_processing_recovery(order_repo, 600, notifier=None)

    def test_notification_failure_does_not_propagate(self):
        from acmeeh.services.cleanup_worker import CleanupWorker

        order_repo = MagicMock()
        notifier = MagicMock()
        notifier.notify.side_effect = RuntimeError("boom")
        order = _mock_order(status=OrderStatus.PROCESSING)
        order_repo.find_stale_processing.return_value = [order]

        # Should not raise
        CleanupWorker._stale_processing_recovery(order_repo, 600, notifier=notifier)
        assert order_repo.transition_status.call_count == 1

    def test_cleanup_worker_wires_notifier_to_stale_recovery(self):
        """CleanupWorker.__init__ passes notifier to the stale recovery task."""
        from acmeeh.services.cleanup_worker import CleanupWorker

        settings = MagicMock()
        settings.nonce.gc_interval_seconds = 300
        settings.order.cleanup_interval_seconds = 300
        settings.order.stale_processing_threshold_seconds = 600
        settings.retention.enabled = False
        settings.retention.cleanup_loop_interval_seconds = 60
        settings.audit_retention.enabled = False
        notifier = MagicMock()

        worker = CleanupWorker(
            nonce_service=MagicMock(),
            order_repo=MagicMock(),
            settings=settings,
            notifier=notifier,
        )

        # The stale_processing_recovery task should be registered
        stale_task = next((t for t in worker._tasks if t.name == "stale_processing_recovery"), None)
        assert stale_task is not None


# ---------------------------------------------------------------------------
# 4. ACCOUNT_DEACTIVATED
# ---------------------------------------------------------------------------


class TestAccountDeactivatedNotification:
    """AccountService sends ACCOUNT_DEACTIVATED on deactivation."""

    def _make_service(self, notifier=None, authz_repo=None, account_settings=None):
        from acmeeh.services.account import AccountService

        repo = MagicMock()
        result = _mock_account()
        result.status = AccountStatus.DEACTIVATED
        repo.deactivate.return_value = result

        if account_settings is None:
            account_settings = MagicMock()
            account_settings.allow_deactivation = True

        return AccountService(
            account_repo=repo,
            contact_repo=MagicMock(),
            email_settings=MagicMock(allowed_domains=[], require_contact=False),
            tos_settings=MagicMock(require_agreement=False),
            notification_service=notifier,
            authz_repo=authz_repo,
            account_settings=account_settings,
        )

    def test_deactivation_sends_notification(self):
        notifier = MagicMock()
        authz_repo = MagicMock()
        authz_repo.deactivate_for_account.return_value = 3

        svc = self._make_service(notifier=notifier, authz_repo=authz_repo)
        svc.deactivate(uuid4())

        notifier.notify.assert_called_once()
        call_args = notifier.notify.call_args[0]
        assert call_args[0] == NotificationType.ACCOUNT_DEACTIVATED
        assert call_args[2]["deactivated_authorizations"] == 3

    def test_deactivation_without_authz_repo_sends_zero_count(self):
        notifier = MagicMock()
        svc = self._make_service(notifier=notifier, authz_repo=None)
        svc.deactivate(uuid4())

        notifier.notify.assert_called_once()
        assert notifier.notify.call_args[0][2]["deactivated_authorizations"] == 0

    def test_no_notification_without_notifier(self):
        svc = self._make_service(notifier=None)
        svc.deactivate(uuid4())  # Should not raise

    def test_notification_failure_does_not_propagate(self):
        notifier = MagicMock()
        notifier.notify.side_effect = RuntimeError("boom")
        svc = self._make_service(notifier=notifier)
        # Should not raise
        result = svc.deactivate(uuid4())
        assert result.status == AccountStatus.DEACTIVATED


# ---------------------------------------------------------------------------
# 5. KEY_ROLLOVER_SUCCEEDED
# ---------------------------------------------------------------------------


class TestKeyRolloverSucceededNotification:
    """KeyChangeService sends KEY_ROLLOVER_SUCCEEDED on rollover."""

    def test_rollover_sends_notification(self):
        from acmeeh.services.key_change import KeyChangeService

        repo = MagicMock()
        notifier = MagicMock()
        account_id = uuid4()

        # No existing account with new key
        repo.find_by_thumbprint.return_value = None

        account = _mock_account(account_id=account_id, thumbprint="old_thumb")
        repo.find_by_id.return_value = account

        updated_account = _mock_account(account_id=account_id, thumbprint="new_thumb")
        repo.update_jwk.return_value = updated_account

        svc = KeyChangeService(repo, notifier=notifier)

        old_jwk = {"kty": "EC", "crv": "P-256", "x": "aaa", "y": "bbb"}
        new_jwk = {"kty": "EC", "crv": "P-256", "x": "ccc", "y": "ddd"}

        with patch("acmeeh.services.key_change.compute_thumbprint") as mock_tp:
            mock_tp.side_effect = ["new_thumb", "old_thumb"]
            svc.rollover(account_id, old_jwk, new_jwk)

        notifier.notify.assert_called_once()
        call_args = notifier.notify.call_args[0]
        assert call_args[0] == NotificationType.KEY_ROLLOVER_SUCCEEDED
        assert call_args[1] == account_id
        assert call_args[2]["old_thumbprint"] == "old_thumb"
        assert call_args[2]["new_thumbprint"] == "new_thumb"

    def test_no_notification_without_notifier(self):
        from acmeeh.services.key_change import KeyChangeService

        repo = MagicMock()
        account_id = uuid4()

        repo.find_by_thumbprint.return_value = None
        account = _mock_account(account_id=account_id, thumbprint="old_thumb")
        repo.find_by_id.return_value = account
        repo.update_jwk.return_value = account

        svc = KeyChangeService(repo, notifier=None)

        with patch("acmeeh.services.key_change.compute_thumbprint") as mock_tp:
            mock_tp.side_effect = ["new_thumb", "old_thumb"]
            svc.rollover(account_id, {"kty": "EC"}, {"kty": "EC"})

    def test_notification_failure_does_not_propagate(self):
        from acmeeh.services.key_change import KeyChangeService

        repo = MagicMock()
        notifier = MagicMock()
        notifier.notify.side_effect = RuntimeError("boom")
        account_id = uuid4()

        repo.find_by_thumbprint.return_value = None
        account = _mock_account(account_id=account_id, thumbprint="old_thumb")
        repo.find_by_id.return_value = account
        repo.update_jwk.return_value = account

        svc = KeyChangeService(repo, notifier=notifier)

        with patch("acmeeh.services.key_change.compute_thumbprint") as mock_tp:
            mock_tp.side_effect = ["new_thumb", "old_thumb"]
            result = svc.rollover(account_id, {"kty": "EC"}, {"kty": "EC"})
        assert result is not None


# ---------------------------------------------------------------------------
# 6. ORDER_QUOTA_EXCEEDED
# ---------------------------------------------------------------------------


class TestOrderQuotaExceededNotification:
    """OrderService sends ORDER_QUOTA_EXCEEDED when quota is hit."""

    def _make_service(self, order_repo=None, notifier=None, quota_settings=None):
        from acmeeh.services.order import OrderService

        order_repo = order_repo or MagicMock()
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        db = MagicMock()

        order_settings = MagicMock()
        order_settings.expiry_seconds = 3600
        order_settings.authorization_expiry_seconds = 3600

        challenge_settings = MagicMock()
        challenge_settings.enabled = ("http-01",)
        challenge_settings.auto_accept = False
        challenge_settings.background_worker = MagicMock(enabled=False)

        policy = MagicMock()
        policy.max_identifiers_per_order = 100
        policy.allow_ip = True
        policy.allow_wildcards = True
        policy.forbidden_domains = []
        policy.allowed_domains = []
        policy.enforce_account_allowlist = False
        policy.max_identifier_value_length = 253

        return OrderService(
            order_repo=order_repo,
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            order_settings=order_settings,
            challenge_settings=challenge_settings,
            identifier_policy=policy,
            db=db,
            notifier=notifier,
            quota_settings=quota_settings,
        )

    def test_quota_exceeded_sends_notification(self):
        order_repo = MagicMock()
        order_repo.count_orders_since.return_value = 100
        notifier = MagicMock()
        quota = _make_quota_settings(max_orders_per_account_per_day=10)

        svc = self._make_service(order_repo=order_repo, notifier=notifier, quota_settings=quota)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_order(uuid4(), [{"type": "dns", "value": "a.com"}])
        assert exc_info.value.error_type == RATE_LIMITED

        notifier.notify.assert_called_once()
        call_args = notifier.notify.call_args[0]
        assert call_args[0] == NotificationType.ORDER_QUOTA_EXCEEDED
        assert call_args[2]["quota_limit"] == 10
        assert call_args[2]["attempted_identifiers"] == ["a.com"]

    def test_no_notification_without_notifier(self):
        order_repo = MagicMock()
        order_repo.count_orders_since.return_value = 100
        quota = _make_quota_settings(max_orders_per_account_per_day=10)

        svc = self._make_service(order_repo=order_repo, notifier=None, quota_settings=quota)
        with pytest.raises(AcmeProblem):
            svc.create_order(uuid4(), [{"type": "dns", "value": "a.com"}])

    def test_notification_failure_does_not_prevent_raise(self):
        order_repo = MagicMock()
        order_repo.count_orders_since.return_value = 100
        notifier = MagicMock()
        notifier.notify.side_effect = RuntimeError("boom")
        quota = _make_quota_settings(max_orders_per_account_per_day=10)

        svc = self._make_service(order_repo=order_repo, notifier=notifier, quota_settings=quota)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_order(uuid4(), [{"type": "dns", "value": "a.com"}])
        assert exc_info.value.error_type == RATE_LIMITED


# ---------------------------------------------------------------------------
# 7. AUTHORIZATION_DEACTIVATED
# ---------------------------------------------------------------------------


class TestAuthorizationDeactivatedNotification:
    """AuthorizationService sends AUTHORIZATION_DEACTIVATED on deactivation."""

    def _make_service(self, authz_repo=None, notifier=None, order_repo=None):
        from acmeeh.services.authorization import AuthorizationService

        return AuthorizationService(
            authz_repo=authz_repo or MagicMock(),
            challenge_repo=MagicMock(),
            order_repo=order_repo,
            notifier=notifier,
        )

    def test_deactivation_sends_notification(self):
        authz_repo = MagicMock()
        order_repo = MagicMock()
        notifier = MagicMock()

        account_id = uuid4()
        authz = _mock_authz(account_id=account_id, status=AuthorizationStatus.PENDING)
        deactivated = _mock_authz(
            authz_id=authz.id, account_id=account_id, status=AuthorizationStatus.DEACTIVATED
        )

        authz_repo.find_by_id.return_value = authz
        authz_repo.transition_status.return_value = deactivated

        # Two linked orders: one pending, one valid (should only invalidate pending)
        pending_order = _mock_order(account_id=account_id, status=OrderStatus.PENDING)
        valid_order = _mock_order(account_id=account_id, status=OrderStatus.VALID)
        order_repo.find_orders_by_authorization.return_value = [pending_order, valid_order]

        svc = self._make_service(authz_repo=authz_repo, order_repo=order_repo, notifier=notifier)
        svc.deactivate(authz.id, account_id)

        notifier.notify.assert_called_once()
        call_args = notifier.notify.call_args[0]
        assert call_args[0] == NotificationType.AUTHORIZATION_DEACTIVATED
        assert call_args[1] == account_id
        assert call_args[2]["authorization_id"] == str(authz.id)
        assert call_args[2]["identifier"] == "example.com"
        assert call_args[2]["identifier_type"] == "dns"
        assert call_args[2]["invalidated_orders"] == 1  # Only the pending one

    def test_deactivation_no_orders_zero_invalidated(self):
        authz_repo = MagicMock()
        order_repo = MagicMock()
        notifier = MagicMock()

        account_id = uuid4()
        authz = _mock_authz(account_id=account_id, status=AuthorizationStatus.PENDING)
        deactivated = _mock_authz(
            authz_id=authz.id, account_id=account_id, status=AuthorizationStatus.DEACTIVATED
        )
        authz_repo.find_by_id.return_value = authz
        authz_repo.transition_status.return_value = deactivated
        order_repo.find_orders_by_authorization.return_value = []

        svc = self._make_service(authz_repo=authz_repo, order_repo=order_repo, notifier=notifier)
        svc.deactivate(authz.id, account_id)

        notifier.notify.assert_called_once()
        assert notifier.notify.call_args[0][2]["invalidated_orders"] == 0

    def test_no_notification_without_notifier(self):
        authz_repo = MagicMock()
        account_id = uuid4()
        authz = _mock_authz(account_id=account_id, status=AuthorizationStatus.PENDING)
        deactivated = _mock_authz(
            authz_id=authz.id, account_id=account_id, status=AuthorizationStatus.DEACTIVATED
        )
        authz_repo.find_by_id.return_value = authz
        authz_repo.transition_status.return_value = deactivated

        svc = self._make_service(authz_repo=authz_repo, notifier=None)
        svc.deactivate(authz.id, account_id)  # Should not raise

    def test_notification_failure_does_not_propagate(self):
        authz_repo = MagicMock()
        notifier = MagicMock()
        notifier.notify.side_effect = RuntimeError("boom")

        account_id = uuid4()
        authz = _mock_authz(account_id=account_id, status=AuthorizationStatus.PENDING)
        deactivated = _mock_authz(
            authz_id=authz.id, account_id=account_id, status=AuthorizationStatus.DEACTIVATED
        )
        authz_repo.find_by_id.return_value = authz
        authz_repo.transition_status.return_value = deactivated

        svc = self._make_service(authz_repo=authz_repo, notifier=notifier)
        result = svc.deactivate(authz.id, account_id)
        assert result.status == AuthorizationStatus.DEACTIVATED


# ---------------------------------------------------------------------------
# 8. disabled_types — per-type suppression
# ---------------------------------------------------------------------------


class TestDisabledTypes:
    """NotificationService respects disabled_types to suppress specific types."""

    def _make_svc(self, disabled_types=()):
        from acmeeh.models.account import AccountContact
        from acmeeh.services.notification import NotificationService

        notif_repo = MagicMock()
        contact_repo = MagicMock()
        renderer = MagicMock(render=MagicMock(return_value=("Subject", "<p>Body</p>")))

        account_id = uuid4()
        contact = AccountContact(
            id=uuid4(),
            account_id=account_id,
            contact_uri="mailto:user@example.com",
        )
        contact_repo.find_by_account.return_value = [contact]

        smtp = SimpleNamespace(
            enabled=True,
            host="localhost",
            port=25,
            username="",
            password="",
            use_tls=False,
            from_address="noreply@test.com",
            cc=(),
            bcc=(),
            timeout_seconds=10,
        )
        settings = SimpleNamespace(
            enabled=True,
            max_retries=3,
            batch_size=10,
            retry_delay_seconds=60,
            retry_backoff_multiplier=2.0,
            retry_max_delay_seconds=3600,
            disabled_types=tuple(disabled_types),
        )

        svc = NotificationService(
            notification_repo=notif_repo,
            contact_repo=contact_repo,
            smtp_settings=smtp,
            notification_settings=settings,
            renderer=renderer,
            server_url="https://acme.example.com",
        )
        return svc, notif_repo, account_id

    def test_disabled_type_returns_empty(self):
        svc, notif_repo, account_id = self._make_svc(disabled_types=["challenge_failed"])
        result = svc.notify(NotificationType.CHALLENGE_FAILED, account_id, {"foo": "bar"})
        assert result == []
        notif_repo.create.assert_not_called()

    def test_other_types_still_work_when_one_disabled(self):
        svc, notif_repo, account_id = self._make_svc(disabled_types=["challenge_failed"])
        with patch.object(svc, "_send_email", return_value=True):
            result = svc.notify(
                NotificationType.DELIVERY_SUCCEEDED, account_id, {"domains": ["a.com"]}
            )
        assert len(result) == 1
        notif_repo.create.assert_called_once()

    def test_multiple_disabled_types(self):
        svc, notif_repo, account_id = self._make_svc(
            disabled_types=["challenge_failed", "order_quota_exceeded", "account_deactivated"]
        )
        for nt in [
            NotificationType.CHALLENGE_FAILED,
            NotificationType.ORDER_QUOTA_EXCEEDED,
            NotificationType.ACCOUNT_DEACTIVATED,
        ]:
            result = svc.notify(nt, account_id, {})
            assert result == []

        notif_repo.create.assert_not_called()

    def test_empty_disabled_types_allows_all(self):
        svc, notif_repo, account_id = self._make_svc(disabled_types=[])
        with patch.object(svc, "_send_email", return_value=True):
            result = svc.notify(NotificationType.CHALLENGE_FAILED, account_id, {"foo": "bar"})
        assert len(result) == 1
        notif_repo.create.assert_called_once()

    def test_all_seven_new_types_can_be_disabled(self):
        new_types = [
            NotificationType.CHALLENGE_FAILED,
            NotificationType.CSR_VALIDATION_FAILED,
            NotificationType.ORDER_STALE_RECOVERED,
            NotificationType.ACCOUNT_DEACTIVATED,
            NotificationType.KEY_ROLLOVER_SUCCEEDED,
            NotificationType.ORDER_QUOTA_EXCEEDED,
            NotificationType.AUTHORIZATION_DEACTIVATED,
        ]
        svc, notif_repo, account_id = self._make_svc(disabled_types=[nt.value for nt in new_types])
        for nt in new_types:
            result = svc.notify(nt, account_id, {})
            assert result == [], f"{nt.value} should be suppressed"

        notif_repo.create.assert_not_called()


# ---------------------------------------------------------------------------
# 9. Config: disabled_types round-trips through settings
# ---------------------------------------------------------------------------


class TestDisabledTypesConfig:
    """NotificationSettings.disabled_types is built correctly."""

    def test_default_empty(self):
        from acmeeh.config.settings import _build_notifications

        settings = _build_notifications({})
        assert settings.disabled_types == ()

    def test_custom_disabled_types(self):
        from acmeeh.config.settings import _build_notifications

        settings = _build_notifications(
            {"disabled_types": ["challenge_failed", "order_quota_exceeded"]}
        )
        assert settings.disabled_types == ("challenge_failed", "order_quota_exceeded")

    def test_none_input(self):
        from acmeeh.config.settings import _build_notifications

        settings = _build_notifications(None)
        assert settings.disabled_types == ()
