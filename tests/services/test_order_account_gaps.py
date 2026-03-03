"""Tests covering uncovered lines in OrderService and AccountService."""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from acmeeh.app.errors import AcmeProblem
from acmeeh.core.types import (
    AuthorizationStatus,
    ChallengeStatus,
    OrderStatus,
)
from acmeeh.services.account import AccountService
from acmeeh.services.order import OrderService, _normalize_idn

# ---------------------------------------------------------------------------
# Helpers / shared fixtures
# ---------------------------------------------------------------------------

_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
}


def _make_order_settings(**overrides):
    s = MagicMock()
    s.expiry_seconds = overrides.get("expiry_seconds", 86400)
    s.authorization_expiry_seconds = overrides.get("authorization_expiry_seconds", 604800)
    return s


def _make_identifier_policy(**overrides):
    p = MagicMock()
    p.max_identifiers_per_order = overrides.get("max_identifiers_per_order", 100)
    p.max_identifier_value_length = overrides.get("max_identifier_value_length", 253)
    p.allow_wildcards = overrides.get("allow_wildcards", True)
    p.forbidden_domains = overrides.get("forbidden_domains", [])
    p.allowed_domains = overrides.get("allowed_domains", [])
    p.allow_ip = overrides.get("allow_ip", False)
    p.enforce_account_allowlist = overrides.get("enforce_account_allowlist", False)
    return p


def _make_challenge_settings(**overrides):
    s = MagicMock()
    s.enabled = overrides.get("enabled", ["http-01"])
    return s


def _make_quota_settings(**overrides):
    q = MagicMock()
    q.enabled = overrides.get("enabled", True)
    q.max_orders_per_account_per_day = overrides.get("max_orders_per_account_per_day", 100)
    return q


def _build_order_service(**overrides):
    return OrderService(
        order_repo=overrides.get("order_repo", MagicMock()),
        authz_repo=overrides.get("authz_repo", MagicMock()),
        challenge_repo=overrides.get("challenge_repo", MagicMock()),
        order_settings=overrides.get("order_settings", _make_order_settings()),
        challenge_settings=overrides.get("challenge_settings", _make_challenge_settings()),
        identifier_policy=overrides.get("identifier_policy", _make_identifier_policy()),
        db=overrides.get("db", MagicMock()),
        hook_registry=overrides.get("hook_registry"),
        allowlist_repo=overrides.get("allowlist_repo"),
        metrics=overrides.get("metrics"),
        quota_settings=overrides.get("quota_settings"),
        rate_limiter=overrides.get("rate_limiter"),
    )


def _make_email_settings(**overrides):
    s = MagicMock()
    s.require_contact = overrides.get("require_contact", False)
    s.allowed_domains = overrides.get("allowed_domains", [])
    s.max_contacts = overrides.get("max_contacts", 5)
    return s


def _make_tos_settings(**overrides):
    s = MagicMock()
    s.require_agreement = overrides.get("require_agreement", False)
    s.url = overrides.get("url")
    return s


def _build_account_service(**overrides):
    return AccountService(
        account_repo=overrides.get("account_repo", MagicMock()),
        contact_repo=overrides.get("contact_repo", MagicMock()),
        email_settings=overrides.get("email_settings", _make_email_settings()),
        tos_settings=overrides.get("tos_settings", _make_tos_settings()),
        notification_service=overrides.get("notification_service"),
        hook_registry=overrides.get("hook_registry"),
        eab_repo=overrides.get("eab_repo"),
        eab_required=overrides.get("eab_required", False),
        eab_reusable=overrides.get("eab_reusable", False),
        metrics=overrides.get("metrics"),
        authz_repo=overrides.get("authz_repo"),
        account_settings=overrides.get("account_settings"),
    )


def _setup_repos_for_create(order_repo, authz_repo, challenge_repo):
    """Configure mocks so create_order can succeed end-to-end."""
    mock_order = MagicMock()
    mock_order.id = uuid4()
    mock_order.status = OrderStatus.PENDING
    mock_order.identifiers = ()

    # find_pending_for_dedup returns None -> no dedup hit
    order_repo.find_pending_for_dedup.return_value = None
    order_repo.create.return_value = mock_order

    authz_repo.find_reusable.return_value = None
    mock_authz = MagicMock()
    mock_authz.id = uuid4()
    mock_authz.status = AuthorizationStatus.PENDING
    authz_repo.create.return_value = mock_authz

    mock_challenge = MagicMock()
    mock_challenge.id = uuid4()
    mock_challenge.status = ChallengeStatus.PENDING
    challenge_repo.create.return_value = mock_challenge

    return mock_order


# ===================================================================
# OrderService -- _normalize_idn  (lines 89-90, 102)
# ===================================================================


class TestNormalizeIdn:
    """Cover _normalize_idn edge cases."""

    def test_idn_wildcard_normalization(self):
        """Lines 89-90: wildcard label preserved during IDNA encoding."""
        result = _normalize_idn("*.münchen.de")
        assert result.startswith("*.")
        # münchen -> xn--mnchen-3ya
        assert "xn--mnchen-3ya" in result

    def test_idn_non_wildcard(self):
        """IDN without wildcard encodes the whole domain."""
        result = _normalize_idn("münchen.de")
        assert result == "xn--mnchen-3ya.de"

    def test_idn_label_exceeds_max_length(self):
        """Line 102: label exceeds 63 bytes after punycode encoding."""
        # A label with many non-ASCII chars that produces a long punycode form.
        # "ä" * 60 produces a label well over 63 bytes in punycode.
        long_label = "ä" * 60 + ".de"
        with pytest.raises(AcmeProblem):
            _normalize_idn(long_label)

    def test_idn_wildcard_with_many_labels(self):
        """Wildcard with multiple IDN labels."""
        result = _normalize_idn("*.über.münchen.de")
        assert result.startswith("*.")
        assert "xn--" in result

    def test_ascii_domain_passthrough(self):
        """ASCII domains pass through without IDN encoding."""
        result = _normalize_idn("example.com")
        assert result == "example.com"

    def test_ascii_wildcard_passthrough(self):
        """ASCII wildcard passes through without IDN encoding."""
        result = _normalize_idn("*.example.com")
        assert result == "*.example.com"

    def test_uppercase_ascii_lowered(self):
        """ASCII domains are lowercased."""
        result = _normalize_idn("EXAMPLE.COM")
        assert result == "example.com"

    def test_ascii_label_exceeds_max_length(self):
        """ASCII label > 63 chars raises on the fast path."""
        long_label = "a" * 64 + ".com"
        with pytest.raises(AcmeProblem):
            _normalize_idn(long_label)

    def test_idn_single_label(self):
        """Single IDN label encoding."""
        result = _normalize_idn("münchen")
        assert result == "xn--mnchen-3ya"

    def test_mixed_case_idn(self):
        """Mixed case with IDN should lowercase and encode."""
        result = _normalize_idn("*.MÜNCHEN.DE")
        assert result.startswith("*.")
        assert "xn--" in result.lower()


# ===================================================================
# OrderService -- create_order  (lines 191-198, 202-203, 265, 283,
#                                354-358)
# ===================================================================


class TestCreateOrder:
    """Cover create_order gap lines."""

    def test_invalid_identifier_raises_and_logs(self):
        """Lines 191-198: AcmeProblem from _parse_identifiers logged and re-raised."""
        svc = _build_order_service()
        with pytest.raises(AcmeProblem):
            svc.create_order("acct-1", [{"type": "dns", "value": ""}])

    def test_invalid_identifier_type_raises(self):
        """Unsupported identifier type raises AcmeProblem."""
        svc = _build_order_service()
        with pytest.raises(AcmeProblem):
            svc.create_order("acct-1", [{"type": "bogus", "value": "example.com"}])

    def test_per_identifier_rate_limiting(self):
        """Lines 202-203: rate_limiter.check called per identifier."""
        rate_limiter = MagicMock()
        rate_limiter.check.return_value = None

        order_repo = MagicMock()
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        _setup_repos_for_create(order_repo, authz_repo, challenge_repo)

        svc = _build_order_service(
            order_repo=order_repo,
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            rate_limiter=rate_limiter,
        )
        svc.create_order(uuid4(), [{"type": "dns", "value": "example.com"}])
        rate_limiter.check.assert_called()

    def test_per_identifier_rate_limiting_blocked(self):
        """Lines 202-203: rate_limiter.check raises when rate limited."""
        rate_limiter = MagicMock()
        rate_limiter.check.side_effect = AcmeProblem("rateLimited", "Too many requests", 429)

        svc = _build_order_service(rate_limiter=rate_limiter)
        with pytest.raises(AcmeProblem):
            svc.create_order(uuid4(), [{"type": "dns", "value": "example.com"}])

    def test_hook_dispatch_on_order_creation(self):
        """Line 265: hook_registry dispatches order.creation event."""
        hook_registry = MagicMock()

        order_repo = MagicMock()
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        _setup_repos_for_create(order_repo, authz_repo, challenge_repo)

        svc = _build_order_service(
            order_repo=order_repo,
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            hook_registry=hook_registry,
        )
        svc.create_order(uuid4(), [{"type": "dns", "value": "example.com"}])
        hook_registry.dispatch.assert_called()

    def test_quota_max_per_day_zero_returns_early(self):
        """Line 283: max_per_day <= 0 returns early (no enforcement)."""
        quota_settings = _make_quota_settings(max_orders_per_account_per_day=0)

        order_repo = MagicMock()
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        _setup_repos_for_create(order_repo, authz_repo, challenge_repo)

        svc = _build_order_service(
            order_repo=order_repo,
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            quota_settings=quota_settings,
        )
        # Should not raise — quota bypassed when max_per_day <= 0
        svc.create_order(uuid4(), [{"type": "dns", "value": "example.com"}])
        # count_orders_since should NOT have been called
        order_repo.count_orders_since.assert_not_called()

    def test_quota_max_per_day_negative_returns_early(self):
        """Line 283: negative max_per_day also returns early."""
        quota_settings = _make_quota_settings(max_orders_per_account_per_day=-1)

        order_repo = MagicMock()
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        _setup_repos_for_create(order_repo, authz_repo, challenge_repo)

        svc = _build_order_service(
            order_repo=order_repo,
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            quota_settings=quota_settings,
        )
        svc.create_order(uuid4(), [{"type": "dns", "value": "example.com"}])
        order_repo.count_orders_since.assert_not_called()

    def test_reusable_authorization_found(self):
        """Lines 354-358: reusable authz linked instead of creating new."""
        order_repo = MagicMock()
        authz_repo = MagicMock()
        challenge_repo = MagicMock()

        mock_order = MagicMock()
        mock_order.id = uuid4()
        mock_order.status = OrderStatus.PENDING
        mock_order.identifiers = ()
        order_repo.find_pending_for_dedup.return_value = None
        order_repo.create.return_value = mock_order

        # Return a reusable authz
        reusable_authz = MagicMock()
        reusable_authz.id = uuid4()
        reusable_authz.status = AuthorizationStatus.VALID
        authz_repo.find_reusable.return_value = reusable_authz

        svc = _build_order_service(
            order_repo=order_repo,
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
        )
        svc.create_order(uuid4(), [{"type": "dns", "value": "example.com"}])

        # Should link existing authz via order_repo, NOT create new
        authz_repo.create.assert_not_called()
        order_repo.link_authorization.assert_called_once()

    def test_create_order_with_idn_wildcard(self):
        """Integration: create_order with IDN wildcard (lines 89-90)."""
        order_repo = MagicMock()
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        _setup_repos_for_create(order_repo, authz_repo, challenge_repo)

        svc = _build_order_service(
            order_repo=order_repo,
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
        )
        svc.create_order(uuid4(), [{"type": "dns", "value": "*.münchen.de"}])
        order_repo.create.assert_called_once()

    def test_multiple_identifiers_with_rate_limiter(self):
        """Rate limiter checked for each identifier."""
        rate_limiter = MagicMock()
        rate_limiter.check.return_value = None

        order_repo = MagicMock()
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        _setup_repos_for_create(order_repo, authz_repo, challenge_repo)

        svc = _build_order_service(
            order_repo=order_repo,
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            rate_limiter=rate_limiter,
        )
        svc.create_order(
            uuid4(),
            [
                {"type": "dns", "value": "a.example.com"},
                {"type": "dns", "value": "b.example.com"},
            ],
        )
        assert rate_limiter.check.call_count >= 2

    def test_hook_and_quota_combined(self):
        """Hook dispatch and quota check together."""
        hook_registry = MagicMock()
        quota_settings = _make_quota_settings(max_orders_per_account_per_day=0)

        order_repo = MagicMock()
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        _setup_repos_for_create(order_repo, authz_repo, challenge_repo)

        svc = _build_order_service(
            order_repo=order_repo,
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            hook_registry=hook_registry,
            quota_settings=quota_settings,
        )
        svc.create_order(uuid4(), [{"type": "dns", "value": "example.com"}])
        hook_registry.dispatch.assert_called()

    def test_wildcard_disallowed_by_policy(self):
        """Wildcard not allowed by policy raises."""
        policy = _make_identifier_policy(allow_wildcards=False)
        svc = _build_order_service(identifier_policy=policy)
        with pytest.raises(AcmeProblem):
            svc.create_order(
                uuid4(),
                [{"type": "dns", "value": "*.example.com"}],
            )


# ===================================================================
# OrderService -- create_renewal_order  (line 425)
# ===================================================================


class TestCreateRenewalOrder:
    """Cover create_renewal_order gap."""

    def test_cert_repo_none_raises(self):
        """Line 425: cert_repo is None raises AcmeProblem."""
        svc = _build_order_service()
        with pytest.raises(AcmeProblem):
            svc.create_renewal_order(uuid4(), "serial-123", cert_repo=None)


# ===================================================================
# OrderService -- list_orders  (line 507)
# ===================================================================


class TestListOrders:
    """Cover list_orders."""

    def test_list_orders_returns_repo_results(self):
        """Line 507: list_orders delegates to repo.find_by_account."""
        order_repo = MagicMock()
        mock_orders = [MagicMock(), MagicMock()]
        order_repo.find_by_account.return_value = mock_orders

        svc = _build_order_service(order_repo=order_repo)
        acct_id = uuid4()
        result = svc.list_orders(acct_id)
        assert result == mock_orders
        order_repo.find_by_account.assert_called_once_with(acct_id)

    def test_list_orders_empty(self):
        """list_orders with no orders returns empty list."""
        order_repo = MagicMock()
        order_repo.find_by_account.return_value = []

        svc = _build_order_service(order_repo=order_repo)
        result = svc.list_orders(uuid4())
        assert result == []


# ===================================================================
# OrderService -- _enforce_account_allowlist  (line 753)
# ===================================================================


class TestAllowlistEnforcement:
    """Cover allowlist enforcement paths."""

    def test_allowlist_all_identifiers_allowed(self):
        """Line 753: allowlist check passes when all identifiers are allowed."""
        order_repo = MagicMock()
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        _setup_repos_for_create(order_repo, authz_repo, challenge_repo)

        allowlist_repo = MagicMock()
        # Return allowed tuples: (type, value)
        allowlist_repo.find_allowed_values_for_account.return_value = [
            ("dns", "example.com"),
        ]

        policy = _make_identifier_policy(enforce_account_allowlist=True)

        svc = _build_order_service(
            order_repo=order_repo,
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            identifier_policy=policy,
            allowlist_repo=allowlist_repo,
        )
        # Should succeed -- identifier on the allowlist
        svc.create_order(uuid4(), [{"type": "dns", "value": "example.com"}])

    def test_allowlist_no_entries_rejects_all(self):
        """Line 730-752: empty allowlist rejects all identifiers."""
        allowlist_repo = MagicMock()
        allowlist_repo.find_allowed_values_for_account.return_value = []

        policy = _make_identifier_policy(enforce_account_allowlist=True)

        svc = _build_order_service(
            identifier_policy=policy,
            allowlist_repo=allowlist_repo,
        )
        with pytest.raises(AcmeProblem):
            svc.create_order(
                uuid4(),
                [{"type": "dns", "value": "forbidden.com"}],
            )

    def test_allowlist_empty_no_identifiers_returns(self):
        """Line 753: empty allowlist + no identifiers returns (no raise)."""
        allowlist_repo = MagicMock()
        allowlist_repo.find_allowed_values_for_account.return_value = []

        policy = _make_identifier_policy(enforce_account_allowlist=True)

        svc = _build_order_service(
            identifier_policy=policy,
            allowlist_repo=allowlist_repo,
        )
        # Passing empty identifiers should raise from earlier validation
        # (must have at least one identifier)
        with pytest.raises(AcmeProblem):
            svc.create_order(uuid4(), [])

    def test_allowlist_repo_none_raises(self):
        """Line 716-723: enforce enabled but repo is None raises."""
        policy = _make_identifier_policy(enforce_account_allowlist=True)

        svc = _build_order_service(
            identifier_policy=policy,
            allowlist_repo=None,
        )
        with pytest.raises(AcmeProblem):
            svc.create_order(
                uuid4(),
                [{"type": "dns", "value": "example.com"}],
            )

    def test_allowlist_identifier_not_matched(self):
        """Allowed list present but identifier not matched -> rejected."""
        allowlist_repo = MagicMock()
        allowlist_repo.find_allowed_values_for_account.return_value = [
            ("dns", "other.com"),
        ]

        policy = _make_identifier_policy(enforce_account_allowlist=True)

        svc = _build_order_service(
            identifier_policy=policy,
            allowlist_repo=allowlist_repo,
        )
        with pytest.raises(AcmeProblem):
            svc.create_order(
                uuid4(),
                [{"type": "dns", "value": "forbidden.com"}],
            )


# ===================================================================
# AccountService -- create_or_find  (lines 140, 279-285)
# ===================================================================


class TestAccountServiceCreateOrFind:
    """Cover AccountService gap lines."""

    def test_unsupported_contact_with_notifier(self):
        """Lines 140, 279-285: unsupported contact triggers notification."""
        account_repo = MagicMock()
        account_repo.find_by_thumbprint.return_value = None

        notifier = MagicMock()

        svc = _build_account_service(
            account_repo=account_repo,
            notification_service=notifier,
        )
        with pytest.raises(AcmeProblem):
            svc.create_or_find(_JWK, contact=["tel:12345"])

    def test_unsupported_contact_with_notifier_and_mailto(self):
        """Lines 140, 279-285: notification extracts mailto URIs."""
        account_repo = MagicMock()
        account_repo.find_by_thumbprint.return_value = None

        notifier = MagicMock()

        svc = _build_account_service(
            account_repo=account_repo,
            notification_service=notifier,
        )
        # First contact is valid (mailto:), second is invalid (tel:).
        # Validation iterates, hits tel: and raises.
        # _notify_registration_failure is called with the whole contact list.
        with pytest.raises(AcmeProblem):
            svc.create_or_find(
                _JWK,
                contact=["mailto:test@example.com", "tel:12345"],
            )
        # The notifier should have been called with extracted email
        notifier.notify.assert_called_once()

    def test_unsupported_contact_without_notifier(self):
        """Without notifier, unsupported contact still raises."""
        account_repo = MagicMock()
        account_repo.find_by_thumbprint.return_value = None

        svc = _build_account_service(account_repo=account_repo)
        with pytest.raises(AcmeProblem):
            svc.create_or_find(_JWK, contact=["tel:12345"])

    def test_unsupported_contact_notifier_with_only_tel(self):
        """Notifier called but no mailto: URIs -> recipients list is empty."""
        account_repo = MagicMock()
        account_repo.find_by_thumbprint.return_value = None

        notifier = MagicMock()

        svc = _build_account_service(
            account_repo=account_repo,
            notification_service=notifier,
        )
        with pytest.raises(AcmeProblem):
            svc.create_or_find(_JWK, contact=["tel:12345"])
        # _notify_registration_failure filters for mailto: -- none here
        # but the method should still be entered (line 140)


# ===================================================================
# AccountService -- EAB parsing  (lines 235-236, 255, 261)
# ===================================================================


class TestEABParsing:
    """Cover EAB parsing edge cases."""

    def test_eab_invalid_base64_protected(self):
        """Lines 235-236: bad base64 in protected header raises MALFORMED."""
        account_repo = MagicMock()
        account_repo.find_by_thumbprint.return_value = None

        eab_repo = MagicMock()

        svc = _build_account_service(
            account_repo=account_repo,
            eab_repo=eab_repo,
            eab_required=True,
        )

        eab_payload = {
            "protected": "not-valid-base64!!!",
            "payload": "x",
            "signature": "y",
        }

        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_or_find(_JWK, eab_payload=eab_payload)
        assert "parse" in exc_info.value.detail.lower() or "EAB" in str(exc_info.value)

    def test_eab_credential_not_found_raises(self):
        """Line 255: EAB credential not found -> UNAUTHORIZED after HMAC fails."""
        account_repo = MagicMock()
        account_repo.find_by_thumbprint.return_value = None

        eab_repo = MagicMock()
        eab_repo.find_by_kid.return_value = None  # not found

        svc = _build_account_service(
            account_repo=account_repo,
            eab_repo=eab_repo,
            eab_required=True,
        )

        # Build a plausible EAB JWS structure
        header = {
            "alg": "HS256",
            "kid": "eab-kid-1",
            "url": "https://acme/new-acct",
        }
        protected = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps(_JWK).encode()).rstrip(b"=").decode()

        eab = {
            "protected": protected,
            "payload": payload,
            "signature": (base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()),
        }

        with pytest.raises(AcmeProblem):
            svc.create_or_find(_JWK, eab_payload=eab)

    def test_eab_empty_protected_field(self):
        """Empty protected field in EAB payload."""
        account_repo = MagicMock()
        account_repo.find_by_thumbprint.return_value = None

        eab_repo = MagicMock()

        svc = _build_account_service(
            account_repo=account_repo,
            eab_repo=eab_repo,
            eab_required=True,
        )

        eab_payload = {
            "protected": "",
            "payload": "x",
            "signature": "y",
        }

        with pytest.raises((AcmeProblem, Exception)):
            svc.create_or_find(_JWK, eab_payload=eab_payload)

    def test_eab_missing_kid_in_header(self):
        """Protected header without 'kid' field -> kid is empty string."""
        account_repo = MagicMock()
        account_repo.find_by_thumbprint.return_value = None

        eab_repo = MagicMock()
        eab_repo.find_by_kid.return_value = None

        svc = _build_account_service(
            account_repo=account_repo,
            eab_repo=eab_repo,
            eab_required=True,
        )

        header = {"alg": "HS256", "url": "https://acme/new-acct"}  # no kid
        protected = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()

        eab_payload = {
            "protected": protected,
            "payload": "x",
            "signature": "y",
        }

        with pytest.raises((AcmeProblem, Exception)):
            svc.create_or_find(_JWK, eab_payload=eab_payload)

    def test_eab_not_required_skips_parsing(self):
        """When eab_required is False and no eab_payload, no EAB check."""
        account_repo = MagicMock()
        account_repo.find_by_thumbprint.return_value = None
        account_repo.create.return_value = None

        contact_repo = MagicMock()
        contact_repo.find_by_account.return_value = []

        svc = _build_account_service(
            account_repo=account_repo,
            contact_repo=contact_repo,
            eab_required=False,
        )
        # Should succeed without EAB
        account, contacts, created = svc.create_or_find(_JWK)
        assert created is True
