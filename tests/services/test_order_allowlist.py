"""Tests for account allowlist enforcement in OrderService."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from acmeeh.app.errors import AcmeProblem
from acmeeh.config.settings import (
    ChallengeSettings,
    Dns01Settings,
    Http01Settings,
    IdentifierPolicySettings,
    OrderSettings,
    TlsAlpn01Settings,
)
from acmeeh.core.types import (
    OrderStatus,
)
from acmeeh.models.authorization import Authorization
from acmeeh.models.challenge import Challenge
from acmeeh.models.order import Order
from acmeeh.services.order import OrderService

# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class StubOrderRepo:
    def __init__(self):
        self._orders = {}
        self._authz_links = {}

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

    def create(self, authz: Authorization) -> Authorization:
        self._authzs[authz.id] = authz
        return authz

    def find_reusable(self, account_id, id_type, id_value):
        return None


class StubChallengeRepo:
    def __init__(self):
        self._challenges = {}

    def create(self, challenge: Challenge) -> Challenge:
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


class StubAllowlistRepo:
    """In-memory stub for AllowedIdentifierRepository."""

    def __init__(self):
        self._allowed: dict[UUID, list[tuple[str, str]]] = {}

    def set_allowed(self, account_id: UUID, entries: list[tuple[str, str]]):
        """Test helper: set the allowed entries for an account."""
        self._allowed[account_id] = entries

    def find_allowed_values_for_account(self, account_id: UUID) -> list[tuple[str, str]]:
        return self._allowed.get(account_id, [])


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
    from acmeeh.config.settings import BackgroundWorkerSettings

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


def _id_policy(enforce: bool = False, allow_ip: bool = False) -> IdentifierPolicySettings:
    return IdentifierPolicySettings(
        allowed_domains=(),
        forbidden_domains=(),
        allow_wildcards=True,
        allow_ip=allow_ip,
        max_identifiers_per_order=100,
        max_identifier_value_length=253,
        enforce_account_allowlist=enforce,
    )


def _make_service(
    enforce: bool = False,
    allowlist_repo=None,
    allow_ip: bool = False,
) -> OrderService:
    return OrderService(
        order_repo=StubOrderRepo(),
        authz_repo=StubAuthzRepo(),
        challenge_repo=StubChallengeRepo(),
        order_settings=_order_settings(),
        challenge_settings=_challenge_settings(),
        identifier_policy=_id_policy(enforce=enforce, allow_ip=allow_ip),
        db=StubDatabase(),
        allowlist_repo=allowlist_repo,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEnforcementDisabled:
    def test_any_domain_passes_when_disabled(self):
        svc = _make_service(enforce=False)
        order, authz_ids = svc.create_order(
            uuid4(),
            [{"type": "dns", "value": "anything.example.com"}],
        )
        assert order.status == OrderStatus.PENDING
        assert len(authz_ids) == 1

    def test_no_repo_needed_when_disabled(self):
        svc = _make_service(enforce=False, allowlist_repo=None)
        order, _ = svc.create_order(
            uuid4(),
            [{"type": "dns", "value": "test.example.com"}],
        )
        assert order is not None


class TestEnforcementEnabled:
    def test_allowed_domain_succeeds(self):
        repo = StubAllowlistRepo()
        account_id = uuid4()
        repo.set_allowed(account_id, [("dns", "example.com")])

        svc = _make_service(enforce=True, allowlist_repo=repo)
        order, authz_ids = svc.create_order(
            account_id,
            [{"type": "dns", "value": "example.com"}],
        )
        assert order.status == OrderStatus.PENDING

    def test_disallowed_domain_rejected(self):
        repo = StubAllowlistRepo()
        account_id = uuid4()
        repo.set_allowed(account_id, [("dns", "other.com")])

        svc = _make_service(enforce=True, allowlist_repo=repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_order(
                account_id,
                [{"type": "dns", "value": "evil.com"}],
            )
        assert exc_info.value.status == 400
        assert "not authorized" in exc_info.value.detail

    def test_wildcard_allowlist_matches_subdomain(self):
        repo = StubAllowlistRepo()
        account_id = uuid4()
        repo.set_allowed(account_id, [("dns", "*.example.com")])

        svc = _make_service(enforce=True, allowlist_repo=repo)
        order, _ = svc.create_order(
            account_id,
            [{"type": "dns", "value": "sub.example.com"}],
        )
        assert order.status == OrderStatus.PENDING

    def test_wildcard_allowlist_matches_base(self):
        repo = StubAllowlistRepo()
        account_id = uuid4()
        repo.set_allowed(account_id, [("dns", "*.example.com")])

        svc = _make_service(enforce=True, allowlist_repo=repo)
        order, _ = svc.create_order(
            account_id,
            [{"type": "dns", "value": "example.com"}],
        )
        assert order.status == OrderStatus.PENDING

    def test_wildcard_order_with_allowlist(self):
        """Wildcard order *.corp.com should match allowlist *.corp.com."""
        repo = StubAllowlistRepo()
        account_id = uuid4()
        repo.set_allowed(account_id, [("dns", "*.corp.com")])

        svc = _make_service(enforce=True, allowlist_repo=repo)
        order, _ = svc.create_order(
            account_id,
            [{"type": "dns", "value": "*.corp.com"}],
        )
        assert order.status == OrderStatus.PENDING

    def test_ip_exact_match_succeeds(self):
        repo = StubAllowlistRepo()
        account_id = uuid4()
        repo.set_allowed(account_id, [("ip", "10.0.0.1")])

        svc = _make_service(enforce=True, allowlist_repo=repo, allow_ip=True)
        order, _ = svc.create_order(
            account_id,
            [{"type": "ip", "value": "10.0.0.1"}],
        )
        assert order.status == OrderStatus.PENDING

    def test_ip_mismatch_rejected(self):
        repo = StubAllowlistRepo()
        account_id = uuid4()
        repo.set_allowed(account_id, [("ip", "10.0.0.1")])

        svc = _make_service(enforce=True, allowlist_repo=repo, allow_ip=True)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_order(
                account_id,
                [{"type": "ip", "value": "10.0.0.2"}],
            )
        assert "not authorized" in exc_info.value.detail

    def test_empty_allowlist_rejects_all(self):
        repo = StubAllowlistRepo()
        account_id = uuid4()
        # No entries set → empty

        svc = _make_service(enforce=True, allowlist_repo=repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_order(
                account_id,
                [{"type": "dns", "value": "any.com"}],
            )
        assert "not authorized" in exc_info.value.detail

    def test_no_repo_raises_server_error(self):
        """Enforcement enabled but no repo → 500."""
        svc = _make_service(enforce=True, allowlist_repo=None)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_order(
                uuid4(),
                [{"type": "dns", "value": "test.com"}],
            )
        assert exc_info.value.status == 500
        assert "not available" in exc_info.value.detail

    def test_multiple_identifiers_all_must_match(self):
        repo = StubAllowlistRepo()
        account_id = uuid4()
        repo.set_allowed(account_id, [("dns", "a.com"), ("dns", "b.com")])

        svc = _make_service(enforce=True, allowlist_repo=repo)
        order, _ = svc.create_order(
            account_id,
            [
                {"type": "dns", "value": "a.com"},
                {"type": "dns", "value": "b.com"},
            ],
        )
        assert len(order.identifiers) == 2

    def test_partial_match_rejects(self):
        repo = StubAllowlistRepo()
        account_id = uuid4()
        repo.set_allowed(account_id, [("dns", "a.com")])

        svc = _make_service(enforce=True, allowlist_repo=repo)
        with pytest.raises(AcmeProblem):
            svc.create_order(
                account_id,
                [
                    {"type": "dns", "value": "a.com"},
                    {"type": "dns", "value": "c.com"},
                ],
            )
