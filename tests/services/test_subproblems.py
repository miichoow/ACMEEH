"""Tests for subproblem expansion in validation errors.

Verifies that ChallengeService, OrderService, and CertificateService
include per-identifier subproblem details in AcmeProblem exceptions
as described in RFC 8555 section 6.7.1.
"""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acmeeh.app.errors import BAD_CSR, REJECTED_IDENTIFIER, AcmeProblem
from acmeeh.core.types import (
    AuthorizationStatus,
    IdentifierType,
    OrderStatus,
)
from acmeeh.models.authorization import Authorization
from acmeeh.models.order import Identifier, Order
from acmeeh.services.certificate import CertificateService
from acmeeh.services.challenge import ChallengeService
from acmeeh.services.order import OrderService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_authz(
    identifier_type=IdentifierType.DNS,
    identifier_value="example.com",
    status=AuthorizationStatus.PENDING,
    account_id=None,
):
    """Create an Authorization instance for testing."""
    return Authorization(
        id=uuid4(),
        account_id=account_id or uuid4(),
        identifier_type=identifier_type,
        identifier_value=identifier_value,
        status=status,
    )


def _make_order(
    identifiers=None,
    status=OrderStatus.PENDING,
    account_id=None,
):
    """Create an Order instance for testing."""
    if identifiers is None:
        identifiers = (Identifier(type=IdentifierType.DNS, value="example.com"),)
    return Order(
        id=uuid4(),
        account_id=account_id or uuid4(),
        status=status,
        identifiers=tuple(identifiers),
        identifiers_hash="fakehash",
    )


def _rsa_key(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _build_csr(sans=None, san_ips=None, cn="example.com"):
    """Build a CSR with given SANs for testing."""
    key = _rsa_key()
    subject_attrs = []
    if cn is not None:
        subject_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))

    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject_attrs))

    san_names = []
    if sans:
        for s in sans:
            san_names.append(x509.DNSName(s))
    if san_ips:
        import ipaddress

        for ip_str in san_ips:
            san_names.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
    if san_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )

    return builder.sign(key, hashes.SHA256())


# ---------------------------------------------------------------------------
# Stubs for OrderService tests
# ---------------------------------------------------------------------------


class StubOrderRepo:
    def __init__(self):
        self._orders = {}
        self._authz_links = {}

    def create(self, order):
        self._orders[order.id] = order
        return order

    def find_by_id(self, id_):
        return self._orders.get(id_)

    def find_pending_for_dedup(self, account_id, id_hash):
        return None

    def find_authorization_ids(self, order_id):
        return self._authz_links.get(order_id, [])

    def link_authorization(self, order_id, authz_id):
        self._authz_links.setdefault(order_id, []).append(authz_id)

    def transition_status(self, order_id, from_status, to_status, **kwargs):
        return None


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
    def transaction(self):
        return _NoOpTx()


class _NoOpTx:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class StubAllowlistRepo:
    def __init__(self):
        self._allowed = {}

    def set_allowed(self, account_id, entries):
        self._allowed[account_id] = entries

    def find_allowed_values_for_account(self, account_id):
        return self._allowed.get(account_id, [])


def _order_settings():
    from acmeeh.config.settings import OrderSettings

    return OrderSettings(
        expiry_seconds=604800,
        authorization_expiry_seconds=2592000,
        cleanup_interval_seconds=3600,
        stale_processing_threshold_seconds=600,
        pre_authorization_lifetime_days=30,
        retry_after_seconds=3,
    )


def _challenge_settings():
    from acmeeh.config.settings import (
        BackgroundWorkerSettings,
        ChallengeSettings,
        Dns01Settings,
        Http01Settings,
        TlsAlpn01Settings,
    )

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
            port=443,
            timeout_seconds=10,
            max_retries=3,
            auto_validate=True,
        ),
        background_worker=BackgroundWorkerSettings(
            enabled=False,
            poll_seconds=10,
            stale_seconds=300,
        ),
        retry_after_seconds=3,
        backoff_base_seconds=5,
        backoff_max_seconds=300,
    )


def _id_policy(enforce=False, allow_ip=False):
    from acmeeh.config.settings import IdentifierPolicySettings

    return IdentifierPolicySettings(
        allowed_domains=(),
        forbidden_domains=(),
        allow_wildcards=True,
        allow_ip=allow_ip,
        max_identifiers_per_order=100,
        max_identifier_value_length=253,
        enforce_account_allowlist=enforce,
    )


# ---------------------------------------------------------------------------
# 1. ChallengeService._invalidate_orders_for_authz with subproblems
# ---------------------------------------------------------------------------


class TestChallengeInvalidationSubproblems:
    """Verify that _invalidate_orders_for_authz includes subproblems
    when an authorization object is provided."""

    def test_challenge_invalidation_includes_subproblems(self):
        """When authz is provided, the error passed to
        transition_status must include a subproblems list with the
        identifier from the failed authorization."""
        mock_order_repo = MagicMock()
        authz_id = uuid4()
        order = _make_order(status=OrderStatus.PENDING)
        mock_order_repo.find_orders_by_authorization.return_value = [order]
        mock_order_repo.transition_status.return_value = order

        service = ChallengeService(
            challenge_repo=MagicMock(),
            authz_repo=MagicMock(),
            order_repo=mock_order_repo,
            registry=MagicMock(),
        )

        authz = _make_authz(
            identifier_type=IdentifierType.DNS,
            identifier_value="fail.example.com",
        )

        service._invalidate_orders_for_authz(authz_id, authz=authz)

        mock_order_repo.transition_status.assert_called_once()
        call_kwargs = mock_order_repo.transition_status.call_args
        error = call_kwargs.kwargs.get("error") or call_kwargs[1].get("error")
        if error is None:
            # Might be passed as positional; check args
            # transition_status(order_id, from, to, error=...)
            error = call_kwargs[1]["error"] if len(call_kwargs) > 1 else None

        assert error is not None, "error kwarg must be passed to transition_status"
        assert "subproblems" in error
        assert len(error["subproblems"]) == 1

        sub = error["subproblems"][0]
        assert sub["identifier"]["type"] == "dns"
        assert sub["identifier"]["value"] == "fail.example.com"
        assert "unauthorized" in sub["type"]

    def test_challenge_invalidation_without_authz(self):
        """When authz is not provided (None), the error must NOT
        contain a subproblems key."""
        mock_order_repo = MagicMock()
        authz_id = uuid4()
        order = _make_order(status=OrderStatus.PENDING)
        mock_order_repo.find_orders_by_authorization.return_value = [order]
        mock_order_repo.transition_status.return_value = order

        service = ChallengeService(
            challenge_repo=MagicMock(),
            authz_repo=MagicMock(),
            order_repo=mock_order_repo,
            registry=MagicMock(),
        )

        service._invalidate_orders_for_authz(authz_id)

        mock_order_repo.transition_status.assert_called_once()
        call_kwargs = mock_order_repo.transition_status.call_args
        error = call_kwargs.kwargs.get("error") or call_kwargs[1].get("error")
        if error is None:
            error = call_kwargs[1]["error"] if len(call_kwargs) > 1 else None

        assert error is not None
        assert "subproblems" not in error

    def test_cascade_authz_invalid_passes_authz_to_invalidate(self):
        """_cascade_authz_invalid should look up the authz and pass it
        to _invalidate_orders_for_authz so subproblems are populated."""
        mock_authz_repo = MagicMock()
        mock_order_repo = MagicMock()
        authz_id = uuid4()

        authz = _make_authz(
            identifier_type=IdentifierType.DNS,
            identifier_value="cascaded.example.com",
        )
        mock_authz_repo.find_by_id.return_value = authz

        order = _make_order(status=OrderStatus.PENDING)
        mock_order_repo.find_orders_by_authorization.return_value = [order]
        mock_order_repo.transition_status.return_value = order

        service = ChallengeService(
            challenge_repo=MagicMock(),
            authz_repo=mock_authz_repo,
            order_repo=mock_order_repo,
            registry=MagicMock(),
        )

        service._cascade_authz_invalid(authz_id)

        # Verify authz was looked up
        mock_authz_repo.find_by_id.assert_called_once_with(authz_id)

        # Verify the error contains subproblems
        call_kwargs = mock_order_repo.transition_status.call_args
        error = call_kwargs.kwargs.get("error") or call_kwargs[1].get("error")
        if error is None:
            error = call_kwargs[1]["error"] if len(call_kwargs) > 1 else None

        assert error is not None
        assert "subproblems" in error
        assert error["subproblems"][0]["identifier"]["value"] == "cascaded.example.com"

    def test_invalidation_skips_non_pending_orders(self):
        """Orders that are not PENDING should not be transitioned."""
        mock_order_repo = MagicMock()
        authz_id = uuid4()
        valid_order = _make_order(status=OrderStatus.VALID)
        mock_order_repo.find_orders_by_authorization.return_value = [valid_order]

        service = ChallengeService(
            challenge_repo=MagicMock(),
            authz_repo=MagicMock(),
            order_repo=mock_order_repo,
            registry=MagicMock(),
        )

        authz = _make_authz(
            identifier_type=IdentifierType.DNS,
            identifier_value="skip.example.com",
        )

        service._invalidate_orders_for_authz(authz_id, authz=authz)
        mock_order_repo.transition_status.assert_not_called()

    def test_ip_identifier_subproblem(self):
        """Subproblems should correctly reflect IP identifier type."""
        mock_order_repo = MagicMock()
        authz_id = uuid4()
        order = _make_order(status=OrderStatus.PENDING)
        mock_order_repo.find_orders_by_authorization.return_value = [order]
        mock_order_repo.transition_status.return_value = order

        service = ChallengeService(
            challenge_repo=MagicMock(),
            authz_repo=MagicMock(),
            order_repo=mock_order_repo,
            registry=MagicMock(),
        )

        authz = _make_authz(
            identifier_type=IdentifierType.IP,
            identifier_value="10.0.0.1",
        )

        service._invalidate_orders_for_authz(authz_id, authz=authz)

        call_kwargs = mock_order_repo.transition_status.call_args
        error = call_kwargs.kwargs.get("error") or call_kwargs[1].get("error")
        if error is None:
            error = call_kwargs[1]["error"] if len(call_kwargs) > 1 else None

        sub = error["subproblems"][0]
        assert sub["identifier"]["type"] == "ip"
        assert sub["identifier"]["value"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# 2. OrderService._enforce_account_allowlist subproblems
# ---------------------------------------------------------------------------


class TestAllowlistRejectionSubproblems:
    """Verify that _enforce_account_allowlist raises AcmeProblem
    with per-identifier subproblems for rejected identifiers."""

    def test_allowlist_rejection_subproblems(self):
        """When multiple identifiers are rejected, each should appear
        as a subproblem in the raised AcmeProblem."""
        allowlist_repo = StubAllowlistRepo()
        account_id = uuid4()
        # Empty allowlist -- nothing is allowed
        allowlist_repo.set_allowed(account_id, [])

        svc = OrderService(
            order_repo=StubOrderRepo(),
            authz_repo=StubAuthzRepo(),
            challenge_repo=StubChallengeRepo(),
            order_settings=_order_settings(),
            challenge_settings=_challenge_settings(),
            identifier_policy=_id_policy(enforce=True),
            db=StubDatabase(),
            allowlist_repo=allowlist_repo,
        )

        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_order(
                account_id,
                [
                    {"type": "dns", "value": "foo.example.com"},
                    {"type": "dns", "value": "bar.example.com"},
                ],
            )

        problem = exc_info.value
        assert problem.subproblems is not None
        assert len(problem.subproblems) == 2

        values = {sp["identifier"]["value"] for sp in problem.subproblems}
        assert "foo.example.com" in values
        assert "bar.example.com" in values

        for sp in problem.subproblems:
            assert sp["type"] == REJECTED_IDENTIFIER
            assert "identifier" in sp
            assert sp["identifier"]["type"] == "dns"

    def test_allowlist_partial_rejection_subproblems(self):
        """When some identifiers are allowed and some are not, only
        the rejected ones should appear as subproblems."""
        allowlist_repo = StubAllowlistRepo()
        account_id = uuid4()
        allowlist_repo.set_allowed(account_id, [("dns", "allowed.com")])

        svc = OrderService(
            order_repo=StubOrderRepo(),
            authz_repo=StubAuthzRepo(),
            challenge_repo=StubChallengeRepo(),
            order_settings=_order_settings(),
            challenge_settings=_challenge_settings(),
            identifier_policy=_id_policy(enforce=True),
            db=StubDatabase(),
            allowlist_repo=allowlist_repo,
        )

        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_order(
                account_id,
                [
                    {"type": "dns", "value": "allowed.com"},
                    {"type": "dns", "value": "rejected.com"},
                ],
            )

        problem = exc_info.value
        assert problem.subproblems is not None
        assert len(problem.subproblems) == 1
        assert problem.subproblems[0]["identifier"]["value"] == "rejected.com"

    def test_allowlist_rejection_ip_subproblem(self):
        """IP identifiers that are rejected should have type 'ip'
        in the subproblem identifier."""
        allowlist_repo = StubAllowlistRepo()
        account_id = uuid4()
        allowlist_repo.set_allowed(account_id, [("ip", "10.0.0.1")])

        svc = OrderService(
            order_repo=StubOrderRepo(),
            authz_repo=StubAuthzRepo(),
            challenge_repo=StubChallengeRepo(),
            order_settings=_order_settings(),
            challenge_settings=_challenge_settings(),
            identifier_policy=_id_policy(enforce=True, allow_ip=True),
            db=StubDatabase(),
            allowlist_repo=allowlist_repo,
        )

        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_order(
                account_id,
                [
                    {"type": "ip", "value": "10.0.0.1"},
                    {"type": "ip", "value": "10.0.0.2"},
                ],
            )

        problem = exc_info.value
        assert problem.subproblems is not None
        assert len(problem.subproblems) == 1
        assert problem.subproblems[0]["identifier"]["type"] == "ip"
        assert problem.subproblems[0]["identifier"]["value"] == "10.0.0.2"

    def test_allowlist_subproblems_contain_detail(self):
        """Each subproblem should have a human-readable detail message."""
        allowlist_repo = StubAllowlistRepo()
        account_id = uuid4()
        allowlist_repo.set_allowed(account_id, [])

        svc = OrderService(
            order_repo=StubOrderRepo(),
            authz_repo=StubAuthzRepo(),
            challenge_repo=StubChallengeRepo(),
            order_settings=_order_settings(),
            challenge_settings=_challenge_settings(),
            identifier_policy=_id_policy(enforce=True),
            db=StubDatabase(),
            allowlist_repo=allowlist_repo,
        )

        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_order(
                account_id,
                [{"type": "dns", "value": "nope.com"}],
            )

        problem = exc_info.value
        assert problem.subproblems is not None
        assert len(problem.subproblems) == 1
        assert "nope.com" in problem.subproblems[0]["detail"]


# ---------------------------------------------------------------------------
# 3. CertificateService._validate_csr_identifiers subproblems
# ---------------------------------------------------------------------------


class TestCsrIdentifierMismatchSubproblems:
    """Verify that _validate_csr_identifiers raises AcmeProblem
    with per-identifier subproblems for CSR/order mismatches."""

    def test_csr_missing_identifier_subproblems(self):
        """When the CSR is missing identifiers that are in the order,
        subproblems should list each missing one."""
        order = _make_order(
            identifiers=[
                Identifier(type=IdentifierType.DNS, value="a.example.com"),
                Identifier(type=IdentifierType.DNS, value="b.example.com"),
            ],
            status=OrderStatus.READY,
        )

        # CSR only has a.example.com, missing b.example.com
        csr = _build_csr(sans=["a.example.com"])

        service = CertificateService(
            certificate_repo=MagicMock(),
            order_repo=MagicMock(),
            ca_settings=MagicMock(),
            ca_backend=MagicMock(),
        )

        with pytest.raises(AcmeProblem) as exc_info:
            service._validate_csr_identifiers(csr, order)

        problem = exc_info.value
        assert problem.error_type == BAD_CSR
        assert problem.subproblems is not None
        assert len(problem.subproblems) >= 1

        # Find the subproblem for the missing identifier
        missing_subs = [
            sp for sp in problem.subproblems if sp["identifier"]["value"] == "b.example.com"
        ]
        assert len(missing_subs) == 1
        assert "missing" in missing_subs[0]["detail"].lower()

    def test_csr_extra_identifier_subproblems(self):
        """When the CSR has extra identifiers not in the order,
        subproblems should list each extra one."""
        order = _make_order(
            identifiers=[
                Identifier(type=IdentifierType.DNS, value="a.example.com"),
            ],
            status=OrderStatus.READY,
        )

        # CSR has both a.example.com and extra.example.com
        csr = _build_csr(sans=["a.example.com", "extra.example.com"])

        service = CertificateService(
            certificate_repo=MagicMock(),
            order_repo=MagicMock(),
            ca_settings=MagicMock(),
            ca_backend=MagicMock(),
        )

        with pytest.raises(AcmeProblem) as exc_info:
            service._validate_csr_identifiers(csr, order)

        problem = exc_info.value
        assert problem.subproblems is not None

        extra_subs = [
            sp for sp in problem.subproblems if sp["identifier"]["value"] == "extra.example.com"
        ]
        assert len(extra_subs) == 1
        assert "not present in order" in extra_subs[0]["detail"].lower()

    def test_csr_both_missing_and_extra_subproblems(self):
        """When the CSR has both missing and extra identifiers,
        subproblems should contain entries for each."""
        order = _make_order(
            identifiers=[
                Identifier(type=IdentifierType.DNS, value="expected.com"),
            ],
            status=OrderStatus.READY,
        )

        # CSR has wrong.com instead of expected.com
        csr = _build_csr(sans=["wrong.com"])

        service = CertificateService(
            certificate_repo=MagicMock(),
            order_repo=MagicMock(),
            ca_settings=MagicMock(),
            ca_backend=MagicMock(),
        )

        with pytest.raises(AcmeProblem) as exc_info:
            service._validate_csr_identifiers(csr, order)

        problem = exc_info.value
        assert problem.subproblems is not None
        # One for missing (expected.com) and one for extra (wrong.com)
        assert len(problem.subproblems) == 2

        sub_values = {sp["identifier"]["value"] for sp in problem.subproblems}
        assert "expected.com" in sub_values
        assert "wrong.com" in sub_values

    def test_csr_ip_mismatch_subproblems(self):
        """IP identifier mismatches should also produce subproblems
        with the correct type."""
        order = _make_order(
            identifiers=[
                Identifier(type=IdentifierType.IP, value="10.0.0.1"),
            ],
            status=OrderStatus.READY,
        )

        # CSR has a different IP
        csr = _build_csr(sans=[], san_ips=["10.0.0.2"], cn=None)

        service = CertificateService(
            certificate_repo=MagicMock(),
            order_repo=MagicMock(),
            ca_settings=MagicMock(),
            ca_backend=MagicMock(),
        )

        with pytest.raises(AcmeProblem) as exc_info:
            service._validate_csr_identifiers(csr, order)

        problem = exc_info.value
        assert problem.subproblems is not None

        ip_subs = [sp for sp in problem.subproblems if sp["identifier"]["type"] == "ip"]
        assert len(ip_subs) >= 1

    def test_csr_matching_identifiers_no_error(self):
        """When CSR identifiers exactly match the order, no error
        should be raised."""
        order = _make_order(
            identifiers=[
                Identifier(type=IdentifierType.DNS, value="match.example.com"),
            ],
            status=OrderStatus.READY,
        )

        csr = _build_csr(sans=["match.example.com"])

        service = CertificateService(
            certificate_repo=MagicMock(),
            order_repo=MagicMock(),
            ca_settings=MagicMock(),
            ca_backend=MagicMock(),
        )

        # Should not raise
        service._validate_csr_identifiers(csr, order)

    def test_subproblem_type_is_bad_csr(self):
        """Each subproblem's type field should be the BAD_CSR URN."""
        order = _make_order(
            identifiers=[
                Identifier(type=IdentifierType.DNS, value="ordered.com"),
            ],
            status=OrderStatus.READY,
        )

        csr = _build_csr(sans=["different.com"])

        service = CertificateService(
            certificate_repo=MagicMock(),
            order_repo=MagicMock(),
            ca_settings=MagicMock(),
            ca_backend=MagicMock(),
        )

        with pytest.raises(AcmeProblem) as exc_info:
            service._validate_csr_identifiers(csr, order)

        problem = exc_info.value
        for sp in problem.subproblems:
            assert sp["type"] == BAD_CSR
