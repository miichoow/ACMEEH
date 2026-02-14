"""Tests for CA backend failure scenarios.

Verifies proper error handling when the CA backend encounters
timeouts, transient HTTP errors, permanent rejections, and
unexpected exceptions during certificate signing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from acmeeh.app.errors import AcmeProblem
from acmeeh.ca.base import CAError
from acmeeh.core.types import (
    IdentifierType,
    OrderStatus,
)
from acmeeh.models.order import Identifier, Order
from acmeeh.services.certificate import CertificateService


def _make_ready_order(order_id=None, account_id=None):
    """Build a minimal READY order for testing."""
    return Order(
        id=order_id or uuid4(),
        account_id=account_id or uuid4(),
        status=OrderStatus.READY,
        identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        identifiers_hash="test_hash",
        expires=datetime.now(UTC) + timedelta(hours=1),
    )


def _build_csr_der():
    """Build a real DER-encoded CSR for example.com."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    )
    san = x509.SubjectAlternativeName([x509.DNSName("example.com")])
    builder = builder.add_extension(san, critical=False)
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.DER)


def _make_service(
    ca_backend,
    order=None,
    transition_returns=None,
):
    """Build a CertificateService with mocked dependencies."""
    ca_backend.deferred = False
    order_id = order.id if order else uuid4()
    account_id = order.account_id if order else uuid4()

    if order is None:
        order = _make_ready_order(order_id=order_id, account_id=account_id)

    order_repo = MagicMock()
    order_repo.find_by_id.return_value = order

    # Default: transition succeeds (READY → PROCESSING)
    processing_order = Order(
        id=order.id,
        account_id=order.account_id,
        status=OrderStatus.PROCESSING,
        identifiers=order.identifiers,
        identifiers_hash=order.identifiers_hash,
        expires=order.expires,
    )

    if transition_returns is not None:
        order_repo.transition_status.return_value = transition_returns
    else:
        order_repo.transition_status.return_value = processing_order

    cert_repo = MagicMock()
    cert_repo.next_serial.return_value = 12345
    cert_repo._entity_to_row.return_value = {}

    ca_settings = MagicMock()
    ca_settings.profiles = {"default": MagicMock(validity_days=90, max_validity_days=None)}
    ca_settings.default_validity_days = 90
    ca_settings.max_validity_days = 825
    ca_settings.internal.serial_source = "random"

    metrics = MagicMock()

    mock_db = MagicMock()
    mock_db.cursor.return_value.__enter__ = MagicMock()
    mock_db.cursor.return_value.__exit__ = MagicMock()
    mock_db.transaction.return_value.__enter__ = MagicMock(return_value=mock_db)
    mock_db.transaction.return_value.__exit__ = MagicMock(return_value=False)

    svc = CertificateService(
        certificate_repo=cert_repo,
        order_repo=order_repo,
        ca_settings=ca_settings,
        ca_backend=ca_backend,
        metrics=metrics,
        db=mock_db,
    )
    return svc, order_repo, cert_repo, metrics


class TestCABackendTransientFailure:
    """CA backend fails with a retryable error."""

    def test_transient_error_transitions_order_to_invalid(self):
        """Transient CA failure should transition order to INVALID."""
        order = _make_ready_order()
        ca_backend = MagicMock()
        ca_backend.sign.side_effect = CAError(
            "Connection timeout to upstream CA",
            retryable=True,
        )

        svc, order_repo, cert_repo, metrics = _make_service(ca_backend, order=order)

        with pytest.raises(AcmeProblem) as exc_info:
            svc.finalize_order(order.id, _build_csr_der(), order.account_id)

        assert exc_info.value.status == 500

        # Order should have been transitioned to INVALID
        order_repo.transition_status.assert_any_call(
            order.id,
            OrderStatus.PROCESSING,
            OrderStatus.INVALID,
            error={
                "type": "urn:ietf:params:acme:error:serverInternal",
                "detail": "Certificate signing failed",
            },
        )

        # Metrics should record the error
        metrics.increment.assert_any_call("acmeeh_ca_signing_errors_total")

    def test_transient_error_detail_not_leaked_to_client(self):
        """Internal CA error details should not be exposed to ACME client."""
        order = _make_ready_order()
        ca_backend = MagicMock()
        ca_backend.sign.side_effect = CAError(
            "Internal: PKCS#11 session expired on slot 3",
            retryable=True,
        )

        svc, *_ = _make_service(ca_backend, order=order)

        with pytest.raises(AcmeProblem) as exc_info:
            svc.finalize_order(order.id, _build_csr_der(), order.account_id)

        # Client should see generic error, not internal details
        assert "PKCS#11" not in exc_info.value.detail
        assert "Certificate signing failed" in exc_info.value.detail


class TestCABackendPermanentFailure:
    """CA backend fails with a non-retryable error."""

    def test_permanent_error_transitions_order_to_invalid(self):
        """Permanent CA failure should transition order to INVALID."""
        order = _make_ready_order()
        ca_backend = MagicMock()
        ca_backend.sign.side_effect = CAError(
            "Policy violation: requested key usage not allowed",
            retryable=False,
        )

        svc, order_repo, *_ = _make_service(ca_backend, order=order)

        with pytest.raises(AcmeProblem):
            svc.finalize_order(order.id, _build_csr_der(), order.account_id)

        order_repo.transition_status.assert_any_call(
            order.id,
            OrderStatus.PROCESSING,
            OrderStatus.INVALID,
            error={
                "type": "urn:ietf:params:acme:error:serverInternal",
                "detail": "Certificate signing failed",
            },
        )


class TestCABackendNotification:
    """Notification behavior on CA backend failures."""

    def test_notification_sent_on_failure(self):
        """Notification service should be called when CA signing fails."""
        order = _make_ready_order()
        ca_backend = MagicMock()
        ca_backend.deferred = False
        ca_backend.sign.side_effect = CAError("HSM offline")

        notifier = MagicMock()

        order_repo = MagicMock()
        order_repo.find_by_id.return_value = order
        processing = Order(
            id=order.id,
            account_id=order.account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
            identifiers_hash=order.identifiers_hash,
            expires=order.expires,
        )
        order_repo.transition_status.return_value = processing

        cert_repo = MagicMock()
        cert_repo.next_serial.return_value = 1

        ca_settings = MagicMock()
        ca_settings.profiles = {"default": MagicMock(validity_days=90, max_validity_days=None)}
        ca_settings.default_validity_days = 90
        ca_settings.max_validity_days = 825
        ca_settings.internal.serial_source = "random"

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            notification_service=notifier,
        )

        with pytest.raises(AcmeProblem):
            svc.finalize_order(order.id, _build_csr_der(), order.account_id)

        notifier.notify.assert_called_once()
        call_args = notifier.notify.call_args
        from acmeeh.core.types import NotificationType

        assert call_args[0][0] == NotificationType.DELIVERY_FAILED


class TestCABackendRevocationFailure:
    """Revocation notification failures from CA backend."""

    def test_revocation_backend_failure_does_not_prevent_db_revocation(self):
        """If CA backend revocation fails, DB revocation should still succeed."""
        from acmeeh.models.certificate import Certificate

        cert_id = uuid4()
        account_id = uuid4()
        now = datetime.now(UTC)
        cert = Certificate(
            id=cert_id,
            account_id=account_id,
            order_id=uuid4(),
            serial_number="aabb",
            fingerprint="ff" * 32,
            pem_chain="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
            not_before_cert=now - timedelta(days=1),
            not_after_cert=now + timedelta(days=89),
        )

        cert_repo = MagicMock()
        cert_repo.find_by_fingerprint.return_value = cert
        cert_repo.revoke.return_value = cert  # DB revocation succeeds

        ca_backend = MagicMock()
        ca_backend.revoke.side_effect = CAError("Backend unreachable")

        order_repo = MagicMock()
        ca_settings = MagicMock()

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
        )

        cert_der = b"dummy-cert-der"

        # Patch the x509 loading to return a mock cert
        mock_cert_obj = MagicMock()
        with patch(
            "acmeeh.services.certificate.x509.load_der_x509_certificate", return_value=mock_cert_obj
        ):
            with patch("acmeeh.services.certificate.hashlib.sha256") as mock_sha:
                mock_sha.return_value.hexdigest.return_value = "ff" * 32
                # Should NOT raise — backend failure is best-effort
                svc.revoke(
                    cert_der=cert_der,
                    reason=0,
                    account_id=account_id,
                )

        # DB revocation was called
        cert_repo.revoke.assert_called_once()
        # CA backend revocation was attempted
        ca_backend.revoke.assert_called_once()
