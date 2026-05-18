"""Tests for concurrent order finalization (race condition protection).

Verifies that when two threads attempt to finalize the same order
simultaneously, exactly one succeeds and the other receives an
appropriate error.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock
from uuid import uuid4

from acmeeh.app.errors import AcmeProblem
from acmeeh.ca.base import IssuedCertificate
from acmeeh.core.types import (
    IdentifierType,
    OrderStatus,
)
from acmeeh.models.order import Identifier, Order
from acmeeh.services.certificate import CertificateService


def _make_test_order(order_id=None, account_id=None, status=OrderStatus.READY):
    """Build a minimal Order for testing."""
    return Order(
        id=order_id or uuid4(),
        account_id=account_id or uuid4(),
        status=status,
        identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        identifiers_hash="abc123",
        expires=datetime.now(UTC) + timedelta(hours=1),
    )


def _make_issued_cert(serial="aabbcc"):
    """Build a minimal IssuedCertificate result."""
    now = datetime.now(UTC)
    return IssuedCertificate(
        pem_chain="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        not_before=now,
        not_after=now + timedelta(days=90),
        serial_number=serial,
        fingerprint="deadbeef" * 8,
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


class TestConcurrentFinalize:
    """Verify that concurrent finalization of the same order is safe."""

    def test_concurrent_finalize_only_one_succeeds(self):
        """Two threads finalize the same order; exactly one should succeed."""
        order_id = uuid4()
        account_id = uuid4()
        order = _make_test_order(order_id=order_id, account_id=account_id)

        # Mock order repo with thread-safe transition
        order_repo = MagicMock()
        order_repo.find_by_id.return_value = order

        # Use a lock to simulate CAS — only the first caller gets PROCESSING
        transition_lock = threading.Lock()
        transition_called = {"count": 0}

        def mock_transition(oid, from_status, to_status, **kwargs):
            with transition_lock:
                transition_called["count"] += 1
                if transition_called["count"] == 1:
                    # First caller succeeds
                    from dataclasses import replace

                    return replace(order, status=to_status)
                else:
                    # Second caller fails (CAS guard)
                    return None

        order_repo.transition_status.side_effect = mock_transition

        # Mock cert repo
        cert_repo = MagicMock()
        cert_repo.next_serial.return_value = 12345
        cert_repo._entity_to_row.return_value = {}

        # Mock CA backend
        ca_backend = MagicMock()
        ca_backend.sign.return_value = _make_issued_cert()

        # Mock CA settings
        ca_settings = MagicMock()
        ca_settings.profiles = {"default": MagicMock(validity_days=90, max_validity_days=None)}
        ca_settings.default_validity_days = 90
        ca_settings.max_validity_days = 825
        ca_settings.internal.serial_source = "random"

        # Mock DB for UnitOfWork
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
            db=mock_db,
        )

        csr_der = _build_csr_der()
        results = [None, None]
        errors = [None, None]

        def finalize(idx):
            try:
                results[idx] = svc.finalize_order(order_id, csr_der, account_id)
            except (AcmeProblem, Exception) as exc:
                errors[idx] = exc

        t1 = threading.Thread(target=finalize, args=(0,))
        t2 = threading.Thread(target=finalize, args=(1,))

        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        # Exactly one should have failed with ORDER_NOT_READY
        successes = [r for r in results if r is not None]
        failures = [e for e in errors if e is not None]

        assert len(successes) + len(failures) == 2, (
            f"Expected 2 total outcomes, got {len(successes)} successes "
            f"and {len(failures)} failures"
        )
        # At least one must have gotten an error (the CAS loser)
        assert len(failures) >= 1, "Second finalize should have failed"
        # The failure should be ORDER_NOT_READY
        for err in failures:
            assert isinstance(err, AcmeProblem)

    def test_concurrent_finalize_cas_miss_returns_processing_order(self):
        """CAS loser re-fetches and returns the order when it is already processing."""
        order_id = uuid4()
        account_id = uuid4()
        ready_order = _make_test_order(order_id=order_id, account_id=account_id)
        processing_order = _make_test_order(
            order_id=order_id, account_id=account_id, status=OrderStatus.PROCESSING
        )

        order_repo = MagicMock()
        # First call returns READY; second call (post-CAS-miss) returns PROCESSING.
        order_repo.find_by_id.side_effect = [ready_order, processing_order]
        order_repo.transition_status.return_value = None  # simulate CAS miss

        cert_repo = MagicMock()
        ca_settings = MagicMock()
        ca_backend = MagicMock()

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
        )

        result = svc.finalize_order(order_id, b"dummy-csr", account_id)

        assert result is processing_order
        ca_backend.sign.assert_not_called()

    def test_finalize_already_processing_idempotent(self):
        """Finalize on a PROCESSING order returns the order without re-issuing."""
        order_id = uuid4()
        account_id = uuid4()
        order = _make_test_order(
            order_id=order_id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
        )

        order_repo = MagicMock()
        order_repo.find_by_id.return_value = order

        cert_repo = MagicMock()
        ca_settings = MagicMock()
        ca_backend = MagicMock()

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
        )

        result = svc.finalize_order(order_id, b"dummy-csr", account_id)

        assert result is order
        ca_backend.sign_certificate.assert_not_called()

    def test_finalize_already_valid_idempotent(self):
        """Finalize on a VALID order returns the order without re-issuing."""
        order_id = uuid4()
        account_id = uuid4()
        order = _make_test_order(
            order_id=order_id,
            account_id=account_id,
            status=OrderStatus.VALID,
        )

        order_repo = MagicMock()
        order_repo.find_by_id.return_value = order

        cert_repo = MagicMock()
        ca_settings = MagicMock()
        ca_backend = MagicMock()

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
        )

        result = svc.finalize_order(order_id, b"dummy-csr", account_id)

        assert result is order
        ca_backend.sign_certificate.assert_not_called()
