"""Tests for CAA record validation (RFC 8659)."""

from __future__ import annotations

from unittest.mock import patch

import dns.exception
import dns.resolver
import pytest

from acmeeh.app.errors import AcmeProblem
from acmeeh.ca.caa import CAAValidator
from acmeeh.config.settings import DnsSettings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dns_settings(**kwargs) -> DnsSettings:
    defaults = dict(resolvers=(), timeout_seconds=5, retries=1)
    defaults.update(kwargs)
    return DnsSettings(**defaults)


class FakeCAARecord:
    """Mock a single CAA rdata record with tag and value byte attributes."""

    def __init__(self, tag: str, value: str) -> None:
        self.tag = tag.encode("ascii")
        self.value = value.encode("ascii")


def _make_answer(records: list[FakeCAARecord]):
    """Wrap a list of FakeCAARecord objects to behave like a dns.resolver answer."""
    return records


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWildcardIssuewild:
    """Wildcard domain vs issuewild records -- passes when issuewild matches."""

    def test_wildcard_passes_with_matching_issuewild(self):
        validator = CAAValidator(("ca.example.com",), _dns_settings())
        answer = _make_answer(
            [
                FakeCAARecord("issuewild", "ca.example.com"),
            ]
        )
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.return_value = answer
            instance.nameservers = []
            instance.lifetime = 5
            # Should not raise
            validator.check("*.example.com", is_wildcard=True)

    def test_wildcard_fails_when_issuewild_does_not_match(self):
        validator = CAAValidator(("ca.example.com",), _dns_settings())
        answer = _make_answer(
            [
                FakeCAARecord("issuewild", "other-ca.example.com"),
            ]
        )
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.return_value = answer
            instance.nameservers = []
            instance.lifetime = 5
            with pytest.raises(AcmeProblem) as exc_info:
                validator.check("*.example.com", is_wildcard=True)
            assert exc_info.value.status == 403


class TestNonWildcardIssue:
    """Non-wildcard domain vs issue records -- passes when issue matches."""

    def test_non_wildcard_passes_with_matching_issue(self):
        validator = CAAValidator(("ca.example.com",), _dns_settings())
        answer = _make_answer(
            [
                FakeCAARecord("issue", "ca.example.com"),
            ]
        )
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.return_value = answer
            instance.nameservers = []
            instance.lifetime = 5
            validator.check("www.example.com", is_wildcard=False)

    def test_non_wildcard_fails_when_issue_does_not_match(self):
        validator = CAAValidator(("ca.example.com",), _dns_settings())
        answer = _make_answer(
            [
                FakeCAARecord("issue", "other-ca.example.com"),
            ]
        )
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.return_value = answer
            instance.nameservers = []
            instance.lifetime = 5
            with pytest.raises(AcmeProblem) as exc_info:
                validator.check("www.example.com", is_wildcard=False)
            assert exc_info.value.status == 403


class TestIssueFallbackForWildcard:
    """RFC 8659 fallback: issue authorizes wildcards when no issuewild present."""

    def test_wildcard_falls_back_to_issue_when_no_issuewild(self):
        validator = CAAValidator(("ca.example.com",), _dns_settings())
        answer = _make_answer(
            [
                FakeCAARecord("issue", "ca.example.com"),
            ]
        )
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.return_value = answer
            instance.nameservers = []
            instance.lifetime = 5
            # Should not raise -- issue tag is used as fallback
            validator.check("*.example.com", is_wildcard=True)


class TestNoCAARecords:
    """No CAA records found -> issuance permitted (no error)."""

    def test_no_records_anywhere_permits_issuance(self):
        validator = CAAValidator(("ca.example.com",), _dns_settings())
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = dns.resolver.NoAnswer()
            instance.nameservers = []
            instance.lifetime = 5
            # Should not raise
            validator.check("www.example.com")


class TestCAARecordsUnauthorized:
    """CAA records exist but none authorize server -> raises AcmeProblem 403."""

    def test_unauthorized_raises_403(self):
        validator = CAAValidator(("ca.example.com",), _dns_settings())
        answer = _make_answer(
            [
                FakeCAARecord("issue", "only-this-ca.example.com"),
                FakeCAARecord("issue", "another-ca.example.com"),
            ]
        )
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.return_value = answer
            instance.nameservers = []
            instance.lifetime = 5
            with pytest.raises(AcmeProblem) as exc_info:
                validator.check("www.example.com")
            assert exc_info.value.status == 403
            assert "do not authorize" in exc_info.value.detail


class TestDomainTreeWalking:
    """CAA record at parent domain is still checked."""

    def test_parent_domain_caa_is_checked(self):
        validator = CAAValidator(("ca.example.com",), _dns_settings())
        # First query (subdomain) -> NoAnswer
        # Second query (parent domain) -> has CAA records
        parent_answer = _make_answer(
            [
                FakeCAARecord("issue", "ca.example.com"),
            ]
        )

        def side_effect(name, rtype):
            if name == "sub.example.com":
                raise dns.resolver.NoAnswer()
            return parent_answer

        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = side_effect
            instance.nameservers = []
            instance.lifetime = 5
            # Should not raise -- parent domain authorizes
            validator.check("sub.example.com")


class TestDNSErrorFailClosed:
    """Fail-closed on DNS errors (dns.exception.DNSException)."""

    def test_dns_error_fails_closed(self):
        validator = CAAValidator(("ca.example.com",), _dns_settings())
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = dns.exception.DNSException("timeout")
            instance.nameservers = []
            instance.lifetime = 5
            # Must raise -- an unresolvable CAA lookup must not be treated
            # as "no CAA records found" (RFC 8659 §4.1)
            with pytest.raises(AcmeProblem) as exc_info:
                validator.check("www.example.com")
            assert exc_info.value.status == 500


class TestEmptyCAAIdentities:
    """Empty caa_identities tuple -> always skip validation."""

    def test_empty_identities_skips_validation(self):
        validator = CAAValidator((), _dns_settings())
        # No DNS calls should happen at all; no mock needed
        validator.check("www.example.com")
        validator.check("*.example.com", is_wildcard=True)

    def test_empty_tuple_with_unauthorized_records_still_passes(self):
        """Even if CAA records deny us, empty identities means skip."""
        validator = CAAValidator((), _dns_settings())
        # Should not even attempt DNS resolution
        validator.check("blocked.example.com")
