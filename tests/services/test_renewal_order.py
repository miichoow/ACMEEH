"""Tests for ARI certificate renewal orders.

Covers OrderService.create_renewal_order() — looking up a certificate by
serial, verifying ownership, extracting SAN values, and delegating to
create_order() — and RenewalInfoService.should_renew().
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest

from acmeeh.app.errors import MALFORMED, UNAUTHORIZED, AcmeProblem
from acmeeh.config.settings import (
    AriSettings,
    BackgroundWorkerSettings,
    ChallengeSettings,
    Dns01Settings,
    Http01Settings,
    IdentifierPolicySettings,
    OrderSettings,
    TlsAlpn01Settings,
)
from acmeeh.core.types import IdentifierType, OrderStatus
from acmeeh.models.order import Order
from acmeeh.services.order import OrderService
from acmeeh.services.renewal_info import RenewalInfoService

# ---------------------------------------------------------------------------
# Stubs (same pattern as test_order_allowlist.py)
# ---------------------------------------------------------------------------


class StubOrderRepo:
    def __init__(self):
        self._orders: dict[UUID, Order] = {}
        self._authz_links: dict[UUID, list[UUID]] = {}

    def create(self, order: Order) -> Order:
        self._orders[order.id] = order
        return order

    def find_by_id(self, id_: UUID) -> Order | None:
        return self._orders.get(id_)

    def find_pending_for_dedup(self, account_id, id_hash):
        return None

    def find_authorization_ids(self, order_id):
        return self._authz_links.get(order_id, [])

    def link_authorization(self, order_id, authz_id):
        self._authz_links.setdefault(order_id, []).append(authz_id)

    def find_by_account(self, account_id):
        return [o for o in self._orders.values() if o.account_id == account_id]


class StubAuthzRepo:
    def __init__(self):
        self._authzs = {}

    def create(self, authz):
        self._authzs[authz.id] = authz
        return authz

    def find_reusable(self, account_id, id_type, id_value):
        return None


class StubChallengeRepo:
    def __init__(self):
        self._challenges = {}

    def create(self, challenge):
        self._challenges[challenge.id] = challenge
        return challenge


class StubDatabase:
    """Fake database that provides a no-op transaction context manager."""

    def transaction(self):
        return _NoOpTx()


class _NoOpTx:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


@dataclass(frozen=True)
class FakeCert:
    """Lightweight certificate stand-in for renewal tests."""

    id: UUID
    account_id: UUID
    order_id: UUID
    serial_number: str
    fingerprint: str
    pem_chain: str
    not_before_cert: datetime
    not_after_cert: datetime
    revoked_at: datetime | None = None
    san_values: list | None = None


class StubCertRepo:
    """In-memory certificate repository keyed by serial number."""

    def __init__(self):
        self._by_serial: dict[str, FakeCert] = {}

    def add(self, cert: FakeCert):
        self._by_serial[cert.serial_number] = cert

    def find_by_serial(self, serial_hex: str) -> FakeCert | None:
        return self._by_serial.get(serial_hex)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _order_settings() -> OrderSettings:
    return OrderSettings(
        expiry_seconds=604800,
        authorization_expiry_seconds=2592000,
        cleanup_interval_seconds=3600,
        stale_processing_threshold_seconds=600,
        pre_authorization_lifetime_days=30,
        retry_after_seconds=3,
    )


def _challenge_settings() -> ChallengeSettings:
    return ChallengeSettings(
        enabled=("http-01",),
        auto_accept=False,
        http01=Http01Settings(
            port=80,
            timeout_seconds=10,
            max_retries=3,
            auto_validate=True,
            blocked_networks=("127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10"),
            max_response_bytes=1048576,
        ),
        dns01=Dns01Settings(
            resolvers=(),
            timeout_seconds=30,
            propagation_wait_seconds=10,
            max_retries=5,
            auto_validate=False,
            require_dnssec=False,
            require_authoritative=False,
        ),
        tlsalpn01=TlsAlpn01Settings(
            port=443, timeout_seconds=10, max_retries=3, auto_validate=True
        ),
        background_worker=BackgroundWorkerSettings(
            enabled=False, poll_seconds=10, stale_seconds=300
        ),
        retry_after_seconds=3,
        backoff_base_seconds=5,
        backoff_max_seconds=300,
    )


def _id_policy(allow_ip: bool = False) -> IdentifierPolicySettings:
    return IdentifierPolicySettings(
        allowed_domains=(),
        forbidden_domains=(),
        allow_wildcards=True,
        allow_ip=allow_ip,
        max_identifiers_per_order=100,
        max_identifier_value_length=253,
        enforce_account_allowlist=False,
    )


def _make_service(allow_ip: bool = False) -> OrderService:
    return OrderService(
        order_repo=StubOrderRepo(),
        authz_repo=StubAuthzRepo(),
        challenge_repo=StubChallengeRepo(),
        order_settings=_order_settings(),
        challenge_settings=_challenge_settings(),
        identifier_policy=_id_policy(allow_ip=allow_ip),
        db=StubDatabase(),
    )


def _make_cert(
    account_id: UUID,
    serial: str = "abc123",
    san_values: list | None = None,
) -> FakeCert:
    now = datetime.now(UTC)
    return FakeCert(
        id=uuid4(),
        account_id=account_id,
        order_id=uuid4(),
        serial_number=serial,
        fingerprint="sha256:fake",
        pem_chain="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
        not_before_cert=now - timedelta(days=30),
        not_after_cert=now + timedelta(days=60),
        san_values=san_values,
    )


def _ari_settings(**kwargs) -> AriSettings:
    defaults = dict(enabled=True, renewal_percentage=0.6667, path="/renewalInfo")
    defaults.update(kwargs)
    return AriSettings(**defaults)


# ---------------------------------------------------------------------------
# OrderService.create_renewal_order tests
# ---------------------------------------------------------------------------


class TestCreateRenewalOrder:
    """Tests for OrderService.create_renewal_order()."""

    @patch("acmeeh.services.order.UnitOfWork")
    def test_create_renewal_order_success(self, mock_uow):
        """Renewal order from a cert with san_values=['example.com'] succeeds.

        Verifies the returned order has PENDING status and the identifiers
        contain a DNS entry for 'example.com'.
        """
        mock_uow.return_value.__enter__ = lambda self: self
        mock_uow.return_value.__exit__ = lambda self, *a: None

        account_id = uuid4()
        cert_repo = StubCertRepo()
        cert = _make_cert(account_id, serial="serial001", san_values=["example.com"])
        cert_repo.add(cert)

        svc = _make_service()
        order, authz_ids = svc.create_renewal_order(
            account_id=account_id,
            replacing_cert_id="serial001",
            cert_repo=cert_repo,
        )

        assert order.status == OrderStatus.PENDING
        assert order.replaces == "serial001"
        assert len(order.identifiers) == 1
        assert order.identifiers[0].type == IdentifierType.DNS
        assert order.identifiers[0].value == "example.com"
        assert len(authz_ids) >= 1

    @patch("acmeeh.services.order.UnitOfWork")
    def test_create_renewal_order_cert_not_found(self, mock_uow):
        """Renewal with a non-existent serial raises MALFORMED (404)."""
        mock_uow.return_value.__enter__ = lambda self: self
        mock_uow.return_value.__exit__ = lambda self, *a: None

        account_id = uuid4()
        cert_repo = StubCertRepo()
        # No certificate added -- find_by_serial will return None

        svc = _make_service()
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_renewal_order(
                account_id=account_id,
                replacing_cert_id="nonexistent",
                cert_repo=cert_repo,
            )

        assert exc_info.value.error_type == MALFORMED
        assert exc_info.value.status == 404
        assert "not found" in exc_info.value.detail.lower()

    @patch("acmeeh.services.order.UnitOfWork")
    def test_create_renewal_order_wrong_account(self, mock_uow):
        """Renewal for a cert owned by a different account raises UNAUTHORIZED."""
        mock_uow.return_value.__enter__ = lambda self: self
        mock_uow.return_value.__exit__ = lambda self, *a: None

        owner_id = uuid4()
        requester_id = uuid4()
        cert_repo = StubCertRepo()
        cert = _make_cert(owner_id, serial="serial002", san_values=["owned.example.com"])
        cert_repo.add(cert)

        svc = _make_service()
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_renewal_order(
                account_id=requester_id,
                replacing_cert_id="serial002",
                cert_repo=cert_repo,
            )

        assert exc_info.value.error_type == UNAUTHORIZED
        assert exc_info.value.status == 403
        assert "does not belong" in exc_info.value.detail.lower()

    @patch("acmeeh.services.order.UnitOfWork")
    def test_create_renewal_order_no_sans(self, mock_uow):
        """Renewal for a cert with no SAN values raises MALFORMED."""
        mock_uow.return_value.__enter__ = lambda self: self
        mock_uow.return_value.__exit__ = lambda self, *a: None

        account_id = uuid4()
        cert_repo = StubCertRepo()
        cert = _make_cert(account_id, serial="serial003", san_values=[])
        cert_repo.add(cert)

        svc = _make_service()
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_renewal_order(
                account_id=account_id,
                replacing_cert_id="serial003",
                cert_repo=cert_repo,
            )

        assert exc_info.value.error_type == MALFORMED
        assert "no san values" in exc_info.value.detail.lower()

    @patch("acmeeh.services.order.UnitOfWork")
    def test_create_renewal_order_no_sans_none(self, mock_uow):
        """Renewal for a cert with san_values=None also raises MALFORMED."""
        mock_uow.return_value.__enter__ = lambda self: self
        mock_uow.return_value.__exit__ = lambda self, *a: None

        account_id = uuid4()
        cert_repo = StubCertRepo()
        cert = _make_cert(account_id, serial="serial004", san_values=None)
        cert_repo.add(cert)

        svc = _make_service()
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_renewal_order(
                account_id=account_id,
                replacing_cert_id="serial004",
                cert_repo=cert_repo,
            )

        assert exc_info.value.error_type == MALFORMED
        assert "no san values" in exc_info.value.detail.lower()

    @patch("acmeeh.services.order.UnitOfWork")
    def test_create_renewal_order_mixed_sans(self, mock_uow):
        """Renewal for a cert with both DNS and IP SANs produces correct
        identifier types (dns -> DNS, valid IP -> IP).
        """
        mock_uow.return_value.__enter__ = lambda self: self
        mock_uow.return_value.__exit__ = lambda self, *a: None

        account_id = uuid4()
        cert_repo = StubCertRepo()
        cert = _make_cert(
            account_id,
            serial="serial005",
            san_values=["web.example.com", "10.0.0.1", "api.example.com", "192.168.1.100"],
        )
        cert_repo.add(cert)

        # allow_ip=True so IP identifiers are accepted by the policy
        svc = _make_service(allow_ip=True)
        order, authz_ids = svc.create_renewal_order(
            account_id=account_id,
            replacing_cert_id="serial005",
            cert_repo=cert_repo,
        )

        assert order.status == OrderStatus.PENDING
        assert order.replaces == "serial005"
        assert len(order.identifiers) == 4

        # Build a lookup by value for easy assertion
        id_map = {ident.value: ident.type for ident in order.identifiers}

        assert id_map["web.example.com"] == IdentifierType.DNS
        assert id_map["api.example.com"] == IdentifierType.DNS
        assert id_map["10.0.0.1"] == IdentifierType.IP
        assert id_map["192.168.1.100"] == IdentifierType.IP


# ---------------------------------------------------------------------------
# RenewalInfoService.should_renew tests
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FakeRenewalCert:
    """Minimal cert for RenewalInfoService tests."""

    id: UUID
    serial_number: str
    not_before_cert: datetime
    not_after_cert: datetime
    revoked_at: datetime | None = None


class RenewalCertRepo:
    """In-memory cert repo for RenewalInfoService tests."""

    def __init__(self):
        self._by_serial: dict[str, FakeRenewalCert] = {}

    def add(self, cert: FakeRenewalCert):
        self._by_serial[cert.serial_number] = cert

    def find_by_serial(self, serial_hex: str) -> FakeRenewalCert | None:
        return self._by_serial.get(serial_hex)


class TestShouldRenew:
    """Tests for RenewalInfoService.should_renew()."""

    def test_should_renew_within_window(self):
        """Certificate in the renewal window: should_renew returns True.

        A 90-day cert with 66.67% renewal_percentage has a window starting
        at notAfter - 60 days.  If we are 50 days before expiry (i.e. past
        the window start), should_renew must be True.
        """
        now = datetime.now(UTC)
        not_before = now - timedelta(days=80)
        not_after = now + timedelta(days=10)
        # validity = 90 days, window offset = 90 * 0.6667 ~ 60 days
        # window_start = not_after - 60 days = now - 50 days  (in the past)

        cert_repo = RenewalCertRepo()
        cert = FakeRenewalCert(
            id=uuid4(),
            serial_number="renew01",
            not_before_cert=not_before,
            not_after_cert=not_after,
        )
        cert_repo.add(cert)

        settings = _ari_settings(renewal_percentage=0.6667)
        service = RenewalInfoService(cert_repo, settings)

        assert service.should_renew("renew01") is True

    def test_should_renew_before_window(self):
        """Certificate NOT yet in the renewal window: should_renew returns False.

        A 90-day cert with 66.67% renewal percentage has a window starting
        at notAfter - 60 days.  If we are 70 days before expiry (i.e. still
        before the window start), should_renew must be False.
        """
        now = datetime.now(UTC)
        not_before = now - timedelta(days=20)
        not_after = now + timedelta(days=70)
        # validity = 90 days, window offset = 90 * 0.6667 ~ 60 days
        # window_start = not_after - 60 days = now + 10 days  (in the future)

        cert_repo = RenewalCertRepo()
        cert = FakeRenewalCert(
            id=uuid4(),
            serial_number="renew02",
            not_before_cert=not_before,
            not_after_cert=not_after,
        )
        cert_repo.add(cert)

        settings = _ari_settings(renewal_percentage=0.6667)
        service = RenewalInfoService(cert_repo, settings)

        assert service.should_renew("renew02") is False

    def test_should_renew_cert_not_found(self):
        """Unknown cert ID: should_renew returns False."""
        cert_repo = RenewalCertRepo()
        settings = _ari_settings()
        service = RenewalInfoService(cert_repo, settings)

        assert service.should_renew("does-not-exist") is False
