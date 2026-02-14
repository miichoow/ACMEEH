"""Tests for business-logic metrics in services.

Verifies that services correctly increment MetricsCollector counters
when operations succeed, fail, or encounter errors.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest

from acmeeh.ca.base import CAError, IssuedCertificate
from acmeeh.challenge.base import ChallengeError
from acmeeh.core.types import (
    AccountStatus,
    AuthorizationStatus,
    ChallengeStatus,
    ChallengeType,
    IdentifierType,
    OrderStatus,
)
from acmeeh.metrics.collector import MetricsCollector
from acmeeh.models.account import Account
from acmeeh.models.authorization import Authorization
from acmeeh.models.certificate import Certificate
from acmeeh.models.challenge import Challenge
from acmeeh.models.order import Identifier, Order
from acmeeh.services.account import AccountService
from acmeeh.services.certificate import CertificateService
from acmeeh.services.challenge import ChallengeService
from acmeeh.services.order import OrderService

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

_ACCOUNT_ID = uuid4()
_ORDER_ID = uuid4()
_AUTHZ_ID = uuid4()
_CHALLENGE_ID = uuid4()
_CERT_ID = uuid4()
_THUMBPRINT = "test-thumbprint-abc123"

_SAMPLE_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
}


def _make_account(account_id: UUID = _ACCOUNT_ID) -> Account:
    return Account(
        id=account_id,
        jwk_thumbprint=_THUMBPRINT,
        jwk=_SAMPLE_JWK,
        status=AccountStatus.VALID,
        tos_agreed=True,
    )


def _make_order(
    order_id: UUID = _ORDER_ID,
    account_id: UUID = _ACCOUNT_ID,
    status: OrderStatus = OrderStatus.READY,
) -> Order:
    return Order(
        id=order_id,
        account_id=account_id,
        status=status,
        identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        identifiers_hash="abc123",
    )


def _make_challenge(
    challenge_id: UUID = _CHALLENGE_ID,
    authz_id: UUID = _AUTHZ_ID,
    status: ChallengeStatus = ChallengeStatus.PENDING,
    retry_count: int = 0,
) -> Challenge:
    return Challenge(
        id=challenge_id,
        authorization_id=authz_id,
        type=ChallengeType.HTTP_01,
        token="test-token-xyz",
        status=status,
        retry_count=retry_count,
    )


def _make_authorization(
    authz_id: UUID = _AUTHZ_ID,
    account_id: UUID = _ACCOUNT_ID,
) -> Authorization:
    return Authorization(
        id=authz_id,
        account_id=account_id,
        identifier_type=IdentifierType.DNS,
        identifier_value="example.com",
        status=AuthorizationStatus.PENDING,
    )


def _make_certificate(
    cert_id: UUID = _CERT_ID,
    account_id: UUID = _ACCOUNT_ID,
    order_id: UUID = _ORDER_ID,
) -> Certificate:
    return Certificate(
        id=cert_id,
        account_id=account_id,
        order_id=order_id,
        serial_number="AABBCCDD",
        fingerprint="deadbeef" * 8,
        pem_chain="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        not_before_cert=datetime(2025, 1, 1, tzinfo=UTC),
        not_after_cert=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _mock_email_settings(**overrides):
    settings = MagicMock()
    settings.require_contact = overrides.get("require_contact", False)
    settings.allowed_domains = overrides.get("allowed_domains", [])
    return settings


def _mock_tos_settings(**overrides):
    settings = MagicMock()
    settings.require_agreement = overrides.get("require_agreement", False)
    settings.url = overrides.get("url")
    return settings


def _mock_order_settings(**overrides):
    settings = MagicMock()
    settings.expiry_seconds = overrides.get("expiry_seconds", 86400)
    settings.authorization_expiry_seconds = overrides.get("authorization_expiry_seconds", 86400)
    return settings


def _mock_challenge_settings(**overrides):
    settings = MagicMock()
    settings.enabled = overrides.get("enabled", ["http-01"])
    return settings


def _mock_identifier_policy(**overrides):
    settings = MagicMock()
    settings.max_identifiers_per_order = overrides.get("max_identifiers_per_order", 100)
    settings.allow_wildcards = overrides.get("allow_wildcards", True)
    settings.allow_ip = overrides.get("allow_ip", False)
    settings.forbidden_domains = overrides.get("forbidden_domains", [])
    settings.allowed_domains = overrides.get("allowed_domains", [])
    settings.enforce_account_allowlist = overrides.get("enforce_account_allowlist", False)
    settings.max_identifier_value_length = overrides.get("max_identifier_value_length", 253)
    return settings


def _mock_ca_settings():
    settings = MagicMock()
    profile = MagicMock()
    profile.validity_days = None
    profile.max_validity_days = None
    settings.profiles = {"default": profile}
    settings.default_validity_days = 90
    settings.max_validity_days = 365
    settings.internal = MagicMock()
    settings.internal.serial_source = "random"
    return settings


# -----------------------------------------------------------------------
# AccountService metrics
# -----------------------------------------------------------------------


class TestAccountCreatedMetric:
    """test_account_created_metric: verify acmeeh_accounts_created_total."""

    @patch("acmeeh.services.account.compute_thumbprint", return_value=_THUMBPRINT)
    def test_account_created_metric(self, mock_thumbprint):
        metrics = MetricsCollector()
        account_repo = MagicMock()
        contact_repo = MagicMock()

        # No existing account with this key
        account_repo.find_by_thumbprint.return_value = None

        svc = AccountService(
            account_repo=account_repo,
            contact_repo=contact_repo,
            email_settings=_mock_email_settings(),
            tos_settings=_mock_tos_settings(),
            metrics=metrics,
        )

        account, contacts, created = svc.create_or_find(
            jwk=_SAMPLE_JWK,
            contact=None,
            tos_agreed=True,
        )

        assert created is True
        assert metrics.get("acmeeh_accounts_created_total") == 1

    @patch("acmeeh.services.account.compute_thumbprint", return_value=_THUMBPRINT)
    def test_account_found_existing_no_metric(self, mock_thumbprint):
        """When an existing account is returned, counter should NOT increment."""
        metrics = MetricsCollector()
        account_repo = MagicMock()
        contact_repo = MagicMock()

        existing = _make_account()
        account_repo.find_by_thumbprint.return_value = existing
        contact_repo.find_by_account.return_value = []

        svc = AccountService(
            account_repo=account_repo,
            contact_repo=contact_repo,
            email_settings=_mock_email_settings(),
            tos_settings=_mock_tos_settings(),
            metrics=metrics,
        )

        account, contacts, created = svc.create_or_find(
            jwk=_SAMPLE_JWK,
        )

        assert created is False
        assert metrics.get("acmeeh_accounts_created_total") == 0


class TestAccountDeactivatedMetric:
    """test_account_deactivated_metric: verify acmeeh_accounts_deactivated_total."""

    def test_account_deactivated_metric(self):
        metrics = MetricsCollector()
        account_repo = MagicMock()
        contact_repo = MagicMock()

        deactivated = _make_account()
        account_repo.deactivate.return_value = replace(
            deactivated, status=AccountStatus.DEACTIVATED
        )

        svc = AccountService(
            account_repo=account_repo,
            contact_repo=contact_repo,
            email_settings=_mock_email_settings(),
            tos_settings=_mock_tos_settings(),
            metrics=metrics,
        )

        result = svc.deactivate(_ACCOUNT_ID)

        assert result.status == AccountStatus.DEACTIVATED
        assert metrics.get("acmeeh_accounts_deactivated_total") == 1


# -----------------------------------------------------------------------
# OrderService metrics
# -----------------------------------------------------------------------


class TestOrderCreatedMetric:
    """test_order_created_metric: verify acmeeh_orders_created_total."""

    @patch("acmeeh.services.order.UnitOfWork")
    def test_order_created_metric(self, mock_uow_cls):
        metrics = MetricsCollector()
        order_repo = MagicMock()
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        db = MagicMock()

        # No existing dedup order
        order_repo.find_pending_for_dedup.return_value = None
        # No reusable authorization
        authz_repo.find_reusable.return_value = None

        # UnitOfWork context manager mock
        mock_uow_cls.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_uow_cls.return_value.__exit__ = MagicMock(return_value=False)

        svc = OrderService(
            order_repo=order_repo,
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            order_settings=_mock_order_settings(),
            challenge_settings=_mock_challenge_settings(),
            identifier_policy=_mock_identifier_policy(),
            db=db,
            metrics=metrics,
        )

        order, authz_ids = svc.create_order(
            account_id=_ACCOUNT_ID,
            identifiers=[{"type": "dns", "value": "example.com"}],
        )

        assert metrics.get("acmeeh_orders_created_total") == 1


# -----------------------------------------------------------------------
# ChallengeService metrics
# -----------------------------------------------------------------------


class TestChallengeSuccessMetric:
    """test_challenge_success_metric: verify {result=success}."""

    def test_challenge_success_metric(self):
        metrics = MetricsCollector()
        challenge_repo = MagicMock()
        authz_repo = MagicMock()
        order_repo = MagicMock()
        registry = MagicMock()

        challenge = _make_challenge()
        authz = _make_authorization()

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        # Claim returns the challenge in processing state
        claimed = replace(challenge, status=ChallengeStatus.PROCESSING)
        challenge_repo.claim_for_processing.return_value = claimed

        # Validator succeeds (no exception)
        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 3
        registry.get_validator_or_none.return_value = validator

        # complete_validation returns valid challenge
        valid_challenge = replace(challenge, status=ChallengeStatus.VALID)
        challenge_repo.complete_validation.return_value = valid_challenge

        # authz cascade helpers
        authz_repo.transition_status.return_value = None
        order_repo.find_orders_by_authorization.return_value = []

        svc = ChallengeService(
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            order_repo=order_repo,
            registry=registry,
            metrics=metrics,
        )

        result = svc.initiate_validation(
            challenge_id=_CHALLENGE_ID,
            account_id=_ACCOUNT_ID,
            jwk=_SAMPLE_JWK,
        )

        assert result.status == ChallengeStatus.VALID
        assert metrics.get("acmeeh_challenges_validated_total", labels={"result": "success"}) == 1
        assert metrics.get("acmeeh_challenges_validated_total", labels={"result": "failure"}) == 0
        assert metrics.get("acmeeh_challenges_validated_total", labels={"result": "retry"}) == 0


class TestChallengeFailureMetric:
    """test_challenge_failure_metric: verify {result=failure} on terminal error."""

    def test_challenge_failure_metric(self):
        metrics = MetricsCollector()
        challenge_repo = MagicMock()
        authz_repo = MagicMock()
        order_repo = MagicMock()
        registry = MagicMock()

        challenge = _make_challenge()
        authz = _make_authorization()

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        claimed = replace(challenge, status=ChallengeStatus.PROCESSING)
        challenge_repo.claim_for_processing.return_value = claimed

        # Validator raises non-retryable ChallengeError
        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 3
        validator.validate.side_effect = ChallengeError("Invalid response", retryable=False)
        registry.get_validator_or_none.return_value = validator

        invalid_challenge = replace(challenge, status=ChallengeStatus.INVALID)
        challenge_repo.complete_validation.return_value = invalid_challenge

        # Cascade helpers
        authz_repo.transition_status.return_value = None
        order_repo.find_orders_by_authorization.return_value = []

        svc = ChallengeService(
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            order_repo=order_repo,
            registry=registry,
            metrics=metrics,
        )

        result = svc.initiate_validation(
            challenge_id=_CHALLENGE_ID,
            account_id=_ACCOUNT_ID,
            jwk=_SAMPLE_JWK,
        )

        assert result.status == ChallengeStatus.INVALID
        assert metrics.get("acmeeh_challenges_validated_total", labels={"result": "failure"}) == 1
        assert metrics.get("acmeeh_challenges_validated_total", labels={"result": "success"}) == 0


class TestChallengeRetryMetric:
    """test_challenge_retry_metric: verify {result=retry} on retryable error."""

    def test_challenge_retry_metric(self):
        metrics = MetricsCollector()
        challenge_repo = MagicMock()
        authz_repo = MagicMock()
        order_repo = MagicMock()
        registry = MagicMock()

        # retry_count=0, so retry_count < max_retries (3) => retry path
        challenge = _make_challenge(retry_count=0)
        authz = _make_authorization()

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        claimed = replace(challenge, status=ChallengeStatus.PROCESSING)
        challenge_repo.claim_for_processing.return_value = claimed

        # Validator raises retryable ChallengeError
        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 3
        validator.validate.side_effect = ChallengeError("Temporary failure", retryable=True)
        registry.get_validator_or_none.return_value = validator

        retried = replace(challenge, status=ChallengeStatus.PENDING, retry_count=1)
        challenge_repo.retry_challenge.return_value = retried

        svc = ChallengeService(
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            order_repo=order_repo,
            registry=registry,
            metrics=metrics,
        )

        result = svc.initiate_validation(
            challenge_id=_CHALLENGE_ID,
            account_id=_ACCOUNT_ID,
            jwk=_SAMPLE_JWK,
        )

        assert metrics.get("acmeeh_challenges_validated_total", labels={"result": "retry"}) == 1
        assert metrics.get("acmeeh_challenges_validated_total", labels={"result": "failure"}) == 0
        assert metrics.get("acmeeh_challenges_validated_total", labels={"result": "success"}) == 0


# -----------------------------------------------------------------------
# CertificateService metrics
# -----------------------------------------------------------------------


class TestCertificateIssuedMetric:
    """test_certificate_issued_metric: verify acmeeh_certificates_issued_total."""

    @patch("acmeeh.services.certificate.UnitOfWork")
    @patch("acmeeh.services.certificate.x509")
    def test_certificate_issued_metric(self, mock_x509, mock_uow_cls):
        metrics = MetricsCollector()
        cert_repo = MagicMock()
        order_repo = MagicMock()
        ca_backend = MagicMock()
        ca_backend.deferred = False

        order = _make_order(status=OrderStatus.READY)
        order_repo.find_by_id.return_value = order

        # Transition to processing returns a processing order
        processing_order = replace(order, status=OrderStatus.PROCESSING)
        valid_order = replace(order, status=OrderStatus.VALID, certificate_id=_CERT_ID)

        def transition_side_effect(oid, from_status, to_status, **kwargs):
            if to_status == OrderStatus.PROCESSING:
                return processing_order
            if to_status == OrderStatus.VALID:
                return valid_order
            return None

        order_repo.transition_status.side_effect = transition_side_effect

        # Mock UnitOfWork context manager
        mock_uow = MagicMock()
        mock_uow.__enter__ = MagicMock(return_value=mock_uow)
        mock_uow.__exit__ = MagicMock(return_value=False)
        mock_uow.update_where.return_value = {"id": _ORDER_ID, "status": "valid"}
        mock_uow_cls.return_value = mock_uow

        # Mock CSR parsing
        mock_csr = MagicMock()
        mock_csr.is_signature_valid = True
        mock_csr.extensions.get_extension_for_class.return_value = MagicMock()
        mock_x509.load_der_x509_csr.return_value = mock_csr

        # Mock SAN matching: make CSR SANs match order identifiers
        san_ext = MagicMock()
        dns_names = ["example.com"]
        san_ext.value.get_values_for_type.side_effect = lambda t: (
            dns_names if t == mock_x509.DNSName else []
        )
        mock_csr.extensions.get_extension_for_class.return_value = san_ext

        # Mock public key bytes for fingerprint calculation
        mock_pub_key = MagicMock()
        mock_pub_key.public_bytes.return_value = b"fake-public-key-bytes"
        mock_csr.public_key.return_value = mock_pub_key

        # CA backend returns a signed certificate
        issued = IssuedCertificate(
            pem_chain="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
            not_before=datetime(2025, 1, 1, tzinfo=UTC),
            not_after=datetime(2026, 1, 1, tzinfo=UTC),
            serial_number="AABB",
            fingerprint="deadbeef" * 8,
        )
        ca_backend.sign.return_value = issued

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=_mock_ca_settings(),
            ca_backend=ca_backend,
            metrics=metrics,
        )

        result = svc.finalize_order(
            order_id=_ORDER_ID,
            csr_der=b"fake-csr-der",
            account_id=_ACCOUNT_ID,
        )

        assert metrics.get("acmeeh_certificates_issued_total") == 1


class TestCertificateRevokedMetric:
    """test_certificate_revoked_metric: verify acmeeh_certificates_revoked_total."""

    @patch("acmeeh.services.certificate.x509")
    @patch("acmeeh.services.certificate.hashlib")
    def test_certificate_revoked_metric(self, mock_hashlib, mock_x509):
        metrics = MetricsCollector()
        cert_repo = MagicMock()
        order_repo = MagicMock()
        ca_backend = MagicMock()

        cert_record = _make_certificate()
        mock_hashlib.sha256.return_value.hexdigest.return_value = cert_record.fingerprint
        cert_repo.find_by_fingerprint.return_value = cert_record
        cert_repo.revoke.return_value = replace(cert_record, revoked_at=datetime.now(UTC))

        # Mock x509 cert object
        mock_cert_obj = MagicMock()
        mock_x509.load_der_x509_certificate.return_value = mock_cert_obj

        # CA backend revoke succeeds
        ca_backend.revoke.return_value = None

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=_mock_ca_settings(),
            ca_backend=ca_backend,
            metrics=metrics,
        )

        svc.revoke(
            cert_der=b"fake-cert-der",
            reason=0,
            account_id=_ACCOUNT_ID,
        )

        assert metrics.get("acmeeh_certificates_revoked_total") == 1


class TestCASigningErrorMetric:
    """test_ca_signing_error_metric: verify acmeeh_ca_signing_errors_total."""

    @patch("acmeeh.services.certificate.x509")
    def test_ca_signing_error_metric(self, mock_x509):
        metrics = MetricsCollector()
        cert_repo = MagicMock()
        order_repo = MagicMock()
        ca_backend = MagicMock()
        ca_backend.deferred = False

        order = _make_order(status=OrderStatus.READY)
        order_repo.find_by_id.return_value = order

        processing_order = replace(order, status=OrderStatus.PROCESSING)
        order_repo.transition_status.return_value = processing_order

        # Mock CSR parsing
        mock_csr = MagicMock()
        mock_csr.is_signature_valid = True
        mock_x509.load_der_x509_csr.return_value = mock_csr

        # Mock SAN matching
        san_ext = MagicMock()
        dns_names = ["example.com"]
        san_ext.value.get_values_for_type.side_effect = lambda t: (
            dns_names if t == mock_x509.DNSName else []
        )
        mock_csr.extensions.get_extension_for_class.return_value = san_ext

        # Mock public key
        mock_pub_key = MagicMock()
        mock_pub_key.public_bytes.return_value = b"fake-public-key-bytes"
        mock_csr.public_key.return_value = mock_pub_key

        # CA backend raises CAError
        ca_backend.sign.side_effect = CAError("HSM not reachable")

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=_mock_ca_settings(),
            ca_backend=ca_backend,
            metrics=metrics,
        )

        from acmeeh.app.errors import AcmeProblem

        with pytest.raises(AcmeProblem):
            svc.finalize_order(
                order_id=_ORDER_ID,
                csr_der=b"fake-csr-der",
                account_id=_ACCOUNT_ID,
            )

        assert metrics.get("acmeeh_ca_signing_errors_total") == 1
        # Certificates issued should remain at 0
        assert metrics.get("acmeeh_certificates_issued_total") == 0


# -----------------------------------------------------------------------
# Metrics-None safety
# -----------------------------------------------------------------------


class TestMetricsNoneSafe:
    """test_metrics_none_safe: services with _metrics=None must not crash."""

    @patch("acmeeh.services.account.compute_thumbprint", return_value=_THUMBPRINT)
    def test_account_service_metrics_none(self, mock_thumbprint):
        """AccountService with metrics=None creates account without error."""
        account_repo = MagicMock()
        contact_repo = MagicMock()
        account_repo.find_by_thumbprint.return_value = None

        svc = AccountService(
            account_repo=account_repo,
            contact_repo=contact_repo,
            email_settings=_mock_email_settings(),
            tos_settings=_mock_tos_settings(),
            metrics=None,
        )

        account, contacts, created = svc.create_or_find(
            jwk=_SAMPLE_JWK,
            contact=None,
            tos_agreed=True,
        )

        assert created is True

    def test_account_deactivate_metrics_none(self):
        """AccountService.deactivate with metrics=None works."""
        account_repo = MagicMock()
        contact_repo = MagicMock()
        account_repo.deactivate.return_value = _make_account()

        svc = AccountService(
            account_repo=account_repo,
            contact_repo=contact_repo,
            email_settings=_mock_email_settings(),
            tos_settings=_mock_tos_settings(),
            metrics=None,
        )

        result = svc.deactivate(_ACCOUNT_ID)
        assert result is not None

    @patch("acmeeh.services.order.UnitOfWork")
    def test_order_service_metrics_none(self, mock_uow_cls):
        """OrderService with metrics=None creates order without error."""
        order_repo = MagicMock()
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        db = MagicMock()

        order_repo.find_pending_for_dedup.return_value = None
        authz_repo.find_reusable.return_value = None

        mock_uow_cls.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_uow_cls.return_value.__exit__ = MagicMock(return_value=False)

        svc = OrderService(
            order_repo=order_repo,
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            order_settings=_mock_order_settings(),
            challenge_settings=_mock_challenge_settings(),
            identifier_policy=_mock_identifier_policy(),
            db=db,
            metrics=None,
        )

        order, authz_ids = svc.create_order(
            account_id=_ACCOUNT_ID,
            identifiers=[{"type": "dns", "value": "example.com"}],
        )

        assert order is not None

    def test_challenge_service_metrics_none(self):
        """ChallengeService with metrics=None validates without error."""
        challenge_repo = MagicMock()
        authz_repo = MagicMock()
        order_repo = MagicMock()
        registry = MagicMock()

        challenge = _make_challenge()
        authz = _make_authorization()

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        claimed = replace(challenge, status=ChallengeStatus.PROCESSING)
        challenge_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 3
        registry.get_validator_or_none.return_value = validator

        valid_challenge = replace(challenge, status=ChallengeStatus.VALID)
        challenge_repo.complete_validation.return_value = valid_challenge
        authz_repo.transition_status.return_value = None
        order_repo.find_orders_by_authorization.return_value = []

        svc = ChallengeService(
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            order_repo=order_repo,
            registry=registry,
            metrics=None,
        )

        result = svc.initiate_validation(
            challenge_id=_CHALLENGE_ID,
            account_id=_ACCOUNT_ID,
            jwk=_SAMPLE_JWK,
        )

        assert result.status == ChallengeStatus.VALID

    @patch("acmeeh.services.certificate.UnitOfWork")
    @patch("acmeeh.services.certificate.x509")
    def test_certificate_service_metrics_none(self, mock_x509, mock_uow_cls):
        """CertificateService with metrics=None finalizes without error."""
        # Mock UnitOfWork context manager
        mock_uow = MagicMock()
        mock_uow.__enter__ = MagicMock(return_value=mock_uow)
        mock_uow.__exit__ = MagicMock(return_value=False)
        mock_uow.update_where.return_value = {"id": _ORDER_ID, "status": "valid"}
        mock_uow_cls.return_value = mock_uow

        cert_repo = MagicMock()
        order_repo = MagicMock()
        ca_backend = MagicMock()

        order = _make_order(status=OrderStatus.READY)
        order_repo.find_by_id.return_value = order

        processing_order = replace(order, status=OrderStatus.PROCESSING)
        valid_order = replace(order, status=OrderStatus.VALID, certificate_id=_CERT_ID)

        def transition_side_effect(oid, from_status, to_status, **kwargs):
            if to_status == OrderStatus.PROCESSING:
                return processing_order
            if to_status == OrderStatus.VALID:
                return valid_order
            return None

        order_repo.transition_status.side_effect = transition_side_effect

        mock_csr = MagicMock()
        mock_csr.is_signature_valid = True
        mock_x509.load_der_x509_csr.return_value = mock_csr

        san_ext = MagicMock()
        dns_names = ["example.com"]
        san_ext.value.get_values_for_type.side_effect = lambda t: (
            dns_names if t == mock_x509.DNSName else []
        )
        mock_csr.extensions.get_extension_for_class.return_value = san_ext

        mock_pub_key = MagicMock()
        mock_pub_key.public_bytes.return_value = b"fake-public-key-bytes"
        mock_csr.public_key.return_value = mock_pub_key

        issued = IssuedCertificate(
            pem_chain="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
            not_before=datetime(2025, 1, 1, tzinfo=UTC),
            not_after=datetime(2026, 1, 1, tzinfo=UTC),
            serial_number="AABB",
            fingerprint="deadbeef" * 8,
        )
        ca_backend.sign.return_value = issued

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=_mock_ca_settings(),
            ca_backend=ca_backend,
            metrics=None,
        )

        result = svc.finalize_order(
            order_id=_ORDER_ID,
            csr_der=b"fake-csr-der",
            account_id=_ACCOUNT_ID,
        )

        assert result is not None
