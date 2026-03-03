"""Unit tests for acmeeh.services.order — Order service."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from acmeeh.app.errors import (
    RATE_LIMITED,
    UNSUPPORTED_IDENTIFIER,
    AcmeProblem,
)
from acmeeh.core.types import ChallengeType, IdentifierType
from acmeeh.models.order import Identifier
from acmeeh.services.order import OrderService, _normalize_idn, _parse_optional_datetime

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _policy(
    max_identifiers=100,
    max_value_length=253,
    allow_wildcards=True,
    allow_ip=True,
    forbidden_domains=(),
    allowed_domains=(),
    enforce_account_allowlist=False,
):
    return SimpleNamespace(
        max_identifiers_per_order=max_identifiers,
        max_identifier_value_length=max_value_length,
        allow_wildcards=allow_wildcards,
        allow_ip=allow_ip,
        forbidden_domains=list(forbidden_domains),
        allowed_domains=list(allowed_domains),
        enforce_account_allowlist=enforce_account_allowlist,
    )


def _order_settings(expiry=3600, authz_expiry=3600):
    return SimpleNamespace(
        expiry_seconds=expiry,
        authorization_expiry_seconds=authz_expiry,
    )


def _challenge_settings(enabled=("http-01", "dns-01", "tls-alpn-01"), auto_accept=False):
    return SimpleNamespace(enabled=list(enabled), auto_accept=auto_accept)


def _make_service(
    order_repo=None,
    authz_repo=None,
    challenge_repo=None,
    identifier_policy=None,
    order_settings=None,
    challenge_settings=None,
    db=None,
    quota_settings=None,
    **kwargs,
):
    return OrderService(
        order_repo=order_repo or MagicMock(),
        authz_repo=authz_repo or MagicMock(),
        challenge_repo=challenge_repo or MagicMock(),
        order_settings=order_settings or _order_settings(),
        challenge_settings=challenge_settings or _challenge_settings(),
        identifier_policy=identifier_policy or _policy(),
        db=db or MagicMock(),
        quota_settings=quota_settings,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# TestNormalizeIdn
# ---------------------------------------------------------------------------


class TestNormalizeIdn:
    def test_ascii_passthrough_lowercased(self):
        assert _normalize_idn("Example.COM") == "example.com"

    def test_idn_punycode_encoding(self):
        # "münchen.de" → "xn--mnchen-3ya.de"
        result = _normalize_idn("münchen.de")
        assert result.startswith("xn--")
        assert result.endswith(".de")

    def test_label_over_63_bytes_rejected(self):
        long_label = "a" * 64
        with pytest.raises(AcmeProblem, match="63-byte limit"):
            _normalize_idn(f"{long_label}.example.com")

    def test_wildcard_preserved(self):
        assert _normalize_idn("*.example.com") == "*.example.com"

    def test_invalid_idn_label(self):
        # Construct a string that will fail IDNA encoding
        with pytest.raises(AcmeProblem):
            _normalize_idn("xn--invalid\ud800.com")


# ---------------------------------------------------------------------------
# TestParseIdentifiers
# ---------------------------------------------------------------------------


class TestParseIdentifiers:
    @patch("acmeeh.services.order.security_events")
    def test_valid_dns(self, mock_se):
        svc = _make_service()
        result = svc._parse_identifiers([{"type": "dns", "value": "example.com"}])
        assert len(result) == 1
        assert result[0].type == IdentifierType.DNS
        assert result[0].value == "example.com"

    @patch("acmeeh.services.order.security_events")
    def test_valid_ip(self, mock_se):
        svc = _make_service()
        result = svc._parse_identifiers([{"type": "ip", "value": "192.168.1.1"}])
        assert result[0].type == IdentifierType.IP

    def test_missing_type(self):
        svc = _make_service()
        with pytest.raises(AcmeProblem, match="must have 'type' and 'value'"):
            svc._parse_identifiers([{"value": "example.com"}])

    def test_missing_value(self):
        svc = _make_service()
        with pytest.raises(AcmeProblem, match="must have 'type' and 'value'"):
            svc._parse_identifiers([{"type": "dns"}])

    def test_unsupported_type(self):
        svc = _make_service()
        with pytest.raises(AcmeProblem) as exc_info:
            svc._parse_identifiers([{"type": "foobar", "value": "x"}])
        assert exc_info.value.error_type == UNSUPPORTED_IDENTIFIER

    def test_ip_when_policy_disallows(self):
        svc = _make_service(identifier_policy=_policy(allow_ip=False))
        with pytest.raises(AcmeProblem) as exc_info:
            svc._parse_identifiers([{"type": "ip", "value": "1.2.3.4"}])
        assert exc_info.value.error_type == UNSUPPORTED_IDENTIFIER

    def test_multiple_failures_produce_subproblems(self):
        svc = _make_service()
        with pytest.raises(AcmeProblem) as exc_info:
            svc._parse_identifiers(
                [
                    {"type": "foobar", "value": "a"},
                    {"type": "foobar", "value": "b"},
                ]
            )
        assert exc_info.value.subproblems is not None
        assert len(exc_info.value.subproblems) == 2

    def test_single_failure_raises_directly(self):
        svc = _make_service()
        with pytest.raises(AcmeProblem) as exc_info:
            svc._parse_identifiers([{"type": "foobar", "value": "x"}])
        assert exc_info.value.subproblems is None

    def test_max_identifier_value_length_enforced(self):
        svc = _make_service(identifier_policy=_policy(max_value_length=10))
        with pytest.raises(AcmeProblem, match="too long"):
            svc._parse_identifiers([{"type": "dns", "value": "a" * 11}])


# ---------------------------------------------------------------------------
# TestValidateDnsIdentifier
# ---------------------------------------------------------------------------


class TestValidateDnsIdentifier:
    def test_multi_level_wildcard_rejected(self):
        svc = _make_service()
        with pytest.raises(AcmeProblem, match="Multi-level wildcard"):
            svc._validate_dns_identifier("*.*.example.com")

    def test_wildcard_when_policy_disallows(self):
        svc = _make_service(identifier_policy=_policy(allow_wildcards=False))
        with pytest.raises(AcmeProblem, match="not allowed"):
            svc._validate_dns_identifier("*.example.com")

    def test_forbidden_domain_match(self):
        svc = _make_service(
            identifier_policy=_policy(forbidden_domains=["evil.com"]),
        )
        with pytest.raises(AcmeProblem, match="forbidden"):
            svc._validate_dns_identifier("evil.com")

    def test_allowed_domains_enforcement(self):
        svc = _make_service(
            identifier_policy=_policy(allowed_domains=["corp.internal"]),
        )
        with pytest.raises(AcmeProblem, match="not in the allowed"):
            svc._validate_dns_identifier("other.com")

    def test_allowed_domains_with_wildcard_pattern(self):
        svc = _make_service(
            identifier_policy=_policy(allowed_domains=["*.corp.internal"]),
        )
        svc._validate_dns_identifier("sub.corp.internal")  # should pass
        svc._validate_dns_identifier("corp.internal")  # should pass


# ---------------------------------------------------------------------------
# TestValidateIpIdentifier
# ---------------------------------------------------------------------------


class TestValidateIpIdentifier:
    def test_valid_ipv4(self):
        svc = _make_service()
        svc._validate_ip_identifier("192.168.1.1")  # no exception

    def test_valid_ipv6(self):
        svc = _make_service()
        svc._validate_ip_identifier("::1")  # no exception

    def test_invalid_ip(self):
        svc = _make_service()
        with pytest.raises(AcmeProblem, match="Invalid IP address"):
            svc._validate_ip_identifier("not-an-ip")


# ---------------------------------------------------------------------------
# TestDomainMatches
# ---------------------------------------------------------------------------


class TestDomainMatches:
    def test_exact_match(self):
        assert OrderService._domain_matches("example.com", "example.com")

    def test_wildcard_subdomain(self):
        assert OrderService._domain_matches("sub.corp.internal", "*.corp.internal")

    def test_wildcard_base(self):
        assert OrderService._domain_matches("corp.internal", "*.corp.internal")

    def test_non_match(self):
        assert not OrderService._domain_matches("other.com", "example.com")

    def test_trailing_dot(self):
        assert OrderService._domain_matches("example.com.", "example.com")

    def test_case_insensitive(self):
        assert OrderService._domain_matches("EXAMPLE.COM", "example.com")


# ---------------------------------------------------------------------------
# TestChallengeApplicable
# ---------------------------------------------------------------------------


class TestChallengeApplicable:
    def test_http01_not_for_wildcards(self):
        ident = Identifier(type=IdentifierType.DNS, value="*.example.com")
        assert not OrderService._challenge_applicable(ChallengeType.HTTP_01, ident, True)

    def test_http01_not_for_ip(self):
        ident = Identifier(type=IdentifierType.IP, value="1.2.3.4")
        assert not OrderService._challenge_applicable(ChallengeType.HTTP_01, ident, False)

    def test_dns01_not_for_ip(self):
        ident = Identifier(type=IdentifierType.IP, value="1.2.3.4")
        assert not OrderService._challenge_applicable(ChallengeType.DNS_01, ident, False)

    def test_tls_alpn01_for_dns(self):
        ident = Identifier(type=IdentifierType.DNS, value="example.com")
        assert OrderService._challenge_applicable(ChallengeType.TLS_ALPN_01, ident, False)

    def test_tls_alpn01_for_ip(self):
        ident = Identifier(type=IdentifierType.IP, value="1.2.3.4")
        assert OrderService._challenge_applicable(ChallengeType.TLS_ALPN_01, ident, False)

    def test_http01_for_dns(self):
        ident = Identifier(type=IdentifierType.DNS, value="example.com")
        assert OrderService._challenge_applicable(ChallengeType.HTTP_01, ident, False)

    def test_dns01_for_dns(self):
        ident = Identifier(type=IdentifierType.DNS, value="example.com")
        assert OrderService._challenge_applicable(ChallengeType.DNS_01, ident, False)


# ---------------------------------------------------------------------------
# TestComputeHash
# ---------------------------------------------------------------------------


class TestComputeHash:
    def test_deterministic(self):
        ids = [
            Identifier(type=IdentifierType.DNS, value="a.com"),
            Identifier(type=IdentifierType.DNS, value="b.com"),
        ]
        assert OrderService._compute_hash(ids) == OrderService._compute_hash(ids)

    def test_order_independent(self):
        a = [
            Identifier(type=IdentifierType.DNS, value="a.com"),
            Identifier(type=IdentifierType.DNS, value="b.com"),
        ]
        b = [
            Identifier(type=IdentifierType.DNS, value="b.com"),
            Identifier(type=IdentifierType.DNS, value="a.com"),
        ]
        assert OrderService._compute_hash(a) == OrderService._compute_hash(b)


# ---------------------------------------------------------------------------
# TestCreateOrder
# ---------------------------------------------------------------------------


class TestCreateOrder:
    @patch("acmeeh.services.order.security_events")
    def test_empty_identifiers_rejected(self, mock_se):
        svc = _make_service()
        with pytest.raises(AcmeProblem, match="at least one identifier"):
            svc.create_order(uuid4(), [])

    @patch("acmeeh.services.order.security_events")
    def test_too_many_identifiers_rejected(self, mock_se):
        svc = _make_service(identifier_policy=_policy(max_identifiers=1))
        with pytest.raises(AcmeProblem, match="Too many identifiers"):
            svc.create_order(
                uuid4(),
                [
                    {"type": "dns", "value": "a.com"},
                    {"type": "dns", "value": "b.com"},
                ],
            )

    @patch("acmeeh.services.order.security_events")
    def test_quota_exceeded(self, mock_se):
        order_repo = MagicMock()
        order_repo.count_orders_since.return_value = 100
        quota = SimpleNamespace(enabled=True, max_orders_per_account_per_day=10)

        svc = _make_service(order_repo=order_repo, quota_settings=quota)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_order(uuid4(), [{"type": "dns", "value": "a.com"}])
        assert exc_info.value.error_type == RATE_LIMITED

    @patch("acmeeh.services.order.security_events")
    def test_dedup_returns_existing(self, mock_se):
        from acmeeh.models.order import Order

        existing_order = Order(
            id=uuid4(),
            account_id=uuid4(),
            status="pending",
            identifiers=(Identifier(type=IdentifierType.DNS, value="a.com"),),
            identifiers_hash="h",
        )
        order_repo = MagicMock()
        order_repo.find_pending_for_dedup.return_value = existing_order
        order_repo.find_authorization_ids.return_value = []

        svc = _make_service(order_repo=order_repo)
        order, authz_ids = svc.create_order(uuid4(), [{"type": "dns", "value": "a.com"}])
        assert order is existing_order
        order_repo.create.assert_not_called()


# ---------------------------------------------------------------------------
# TestGetOrder
# ---------------------------------------------------------------------------


class TestGetOrder:
    def test_ownership_check(self):
        from acmeeh.models.order import Order

        aid = uuid4()
        other_aid = uuid4()
        order = Order(
            id=uuid4(),
            account_id=aid,
            status="pending",
            identifiers=(),
            identifiers_hash="h",
        )
        repo = MagicMock()
        repo.find_by_id.return_value = order

        svc = _make_service(order_repo=repo)
        with pytest.raises(AcmeProblem, match="does not belong"):
            svc.get_order(order.id, other_aid)

    def test_not_found(self):
        repo = MagicMock()
        repo.find_by_id.return_value = None

        svc = _make_service(order_repo=repo)
        with pytest.raises(AcmeProblem, match="not found"):
            svc.get_order(uuid4(), uuid4())


# ---------------------------------------------------------------------------
# TestParseOptionalDatetime
# ---------------------------------------------------------------------------


class TestParseOptionalDatetime:
    def test_valid_iso8601(self):
        dt = _parse_optional_datetime("2025-01-15T10:30:00+00:00")
        assert dt.year == 2025
        assert dt.month == 1

    def test_invalid_format(self):
        with pytest.raises(AcmeProblem, match="Invalid datetime"):
            _parse_optional_datetime("not-a-date")
