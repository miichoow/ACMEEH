"""DNS-PERSIST-01 challenge validator tests (draft-ietf-acme-dns-persist)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import dns.exception
import dns.flags
import dns.resolver
import pytest

from acmeeh.challenge.base import ChallengeContext, ChallengeError
from acmeeh.challenge.dns_persist01 import (
    PERSIST_LABEL,
    DnsPersist01Validator,
    PersistRecord,
    PersistRecordError,
    ancestors,
    parse_record,
    validation_domain_name,
)
from acmeeh.core.types import ChallengeType

ACCOUNT_URI = "https://acme.example/acct/1"
ISSUER = "ca.example"


def _settings(**overrides) -> SimpleNamespace:
    """Build DNS-PERSIST-01 settings with test-friendly defaults."""
    base = {
        "issuer_domain_names": (ISSUER,),
        "resolvers": (),
        "timeout_seconds": 30,
        "propagation_wait_seconds": 10,
        "max_retries": 5,
        "auto_validate": False,
        "require_dnssec": False,
        "require_authoritative": False,
        "allow_wildcard_policy": True,
        "allow_subdomain_policy": True,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _make_txt_rdata(value: str) -> MagicMock:
    rdata = MagicMock()
    rdata.strings = (value.encode("ascii"),)
    return rdata


def _make_answer(txt_values: list[str], *, ad_flag: bool = False) -> MagicMock:
    answer = MagicMock()
    answer.__iter__ = lambda self: iter([_make_txt_rdata(v) for v in txt_values])
    response = MagicMock()
    response.flags = dns.flags.AD if ad_flag else 0
    answer.response = response
    return answer


def _validate(
    validator: DnsPersist01Validator,
    *,
    identifier_value: str = "example.com",
    identifier_type: str = "dns",
    account_uri: str | None = ACCOUNT_URI,
    is_wildcard: bool = False,
) -> None:
    validator.validate(
        token="unused",
        jwk={"kty": "EC"},
        identifier_type=identifier_type,
        identifier_value=identifier_value,
        context=ChallengeContext(account_uri=account_uri, is_wildcard=is_wildcard),
    )


# ---------------------------------------------------------------------------
# Validation Domain Name
# ---------------------------------------------------------------------------


class TestValidationDomainName:
    def test_plain_domain(self):
        assert validation_domain_name("example.com") == f"{PERSIST_LABEL}.example.com"

    def test_wildcard_uses_base_domain(self):
        """A wildcard is authorized by policy=wildcard, not by a distinct name."""
        assert validation_domain_name("*.example.com") == f"{PERSIST_LABEL}.example.com"

    def test_trailing_dot_stripped(self):
        assert validation_domain_name("example.com.") == f"{PERSIST_LABEL}.example.com"

    def test_label_matches_iana_registration(self):
        assert PERSIST_LABEL == "_validation-persist"


class TestAncestors:
    def test_multi_label(self):
        assert ancestors("a.b.example.com") == ["b.example.com", "example.com"]

    def test_registrable_domain_has_no_ancestors(self):
        assert ancestors("example.com") == []

    def test_stops_before_tld(self):
        """The walk never reaches a bare TLD, where nobody can publish."""
        assert "com" not in ancestors("a.b.c.example.com")

    def test_wildcard_prefix_ignored(self):
        assert ancestors("*.a.example.com") == ["example.com"]

    def test_single_label(self):
        assert ancestors("localhost") == []


# ---------------------------------------------------------------------------
# Record parsing (RFC 8659 issue-value syntax)
# ---------------------------------------------------------------------------


class TestParseRecord:
    def test_minimal_record(self):
        record = parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}")
        assert record.issuer_domain_name == ISSUER
        assert record.accounturi == ACCOUNT_URI
        assert record.policy is None
        assert record.persist_until is None
        assert not record.allows_wildcard

    def test_wildcard_policy(self):
        record = parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; policy=wildcard")
        assert record.allows_wildcard

    def test_persist_until(self):
        record = parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; persistUntil=1893456000")
        assert record.persist_until == 1893456000

    def test_unknown_parameters_preserved(self):
        record = parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; foo=bar; baz=qux")
        assert record.parameters == (("foo", "bar"), ("baz", "qux"))

    def test_issuer_normalized_to_lowercase(self):
        record = parse_record(f"CA.Example.; accounturi={ACCOUNT_URI}")
        assert record.issuer_domain_name == "ca.example"

    def test_whitespace_tolerated(self):
        record = parse_record(f"  {ISSUER}  ;  accounturi = {ACCOUNT_URI}  ")
        assert record.accounturi == ACCOUNT_URI

    def test_empty_trailing_separator_tolerated(self):
        record = parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI};")
        assert record.accounturi == ACCOUNT_URI

    @pytest.mark.parametrize(
        "tag", ["persistUntil", "persistuntil", "PERSISTUNTIL", "PersistUntil"]
    )
    def test_persist_until_tag_is_case_insensitive(self, tag):
        """RFC 8659 matches tags case-insensitively.

        Comparing the raw spelling let an expired record parse as
        never-expiring, so the expiry was silently skipped.
        """
        record = parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; {tag}=1000000")
        assert record.persist_until == 1000000
        assert record.parameters == ()

    @pytest.mark.parametrize("tag", ["accounturi", "ACCOUNTURI", "AccountURI"])
    def test_accounturi_tag_is_case_insensitive(self, tag):
        record = parse_record(f"{ISSUER}; {tag}={ACCOUNT_URI}")
        assert record.accounturi == ACCOUNT_URI

    @pytest.mark.parametrize("value", ["wildcard", "WILDCARD", "WildCard"])
    def test_policy_value_is_case_insensitive(self, value):
        record = parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; policy={value}")
        assert record.allows_wildcard

    @pytest.mark.parametrize("tag", ["policy", "POLICY", "Policy"])
    def test_policy_tag_is_case_insensitive(self, tag):
        record = parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; {tag}=wildcard")
        assert record.allows_wildcard

    def test_duplicate_detected_across_tag_casing(self):
        """Otherwise two spellings smuggle in two different account bindings."""
        with pytest.raises(PersistRecordError, match="duplicate parameter"):
            parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; ACCOUNTURI=https://evil.example/a/9")

    def test_unrecognized_policy_treated_as_absent(self):
        record = parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; policy=something-else")
        assert not record.allows_wildcard

    def test_empty_policy_treated_as_absent(self):
        record = parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; policy=")
        assert record.policy is None
        assert not record.allows_wildcard

    def test_empty_accounturi_rejected(self):
        with pytest.raises(PersistRecordError, match="empty value for mandatory accounturi"):
            parse_record(f"{ISSUER}; accounturi=")

    def test_empty_unknown_parameter_tolerated(self):
        record = parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; foo=")
        assert record.parameters == (("foo", ""),)

    def test_missing_accounturi_rejected(self):
        with pytest.raises(PersistRecordError, match="mandatory accounturi"):
            parse_record(ISSUER)

    def test_empty_issuer_rejected(self):
        """A bare ';' means 'no issuer permitted' in CAA — never valid here."""
        with pytest.raises(PersistRecordError, match="invalid issuer-domain-name"):
            parse_record(f"; accounturi={ACCOUNT_URI}")

    def test_invalid_issuer_rejected(self):
        with pytest.raises(PersistRecordError, match="invalid issuer-domain-name"):
            parse_record(f"-bad-.example; accounturi={ACCOUNT_URI}")

    def test_duplicate_parameter_rejected(self):
        """Last-wins would silently pick one of two account bindings."""
        with pytest.raises(PersistRecordError, match="duplicate parameter"):
            parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; accounturi=https://evil.example/a/9")

    def test_parameter_without_value_rejected(self):
        with pytest.raises(PersistRecordError, match="not a tag=value pair"):
            parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; policy")

    def test_invalid_tag_rejected(self):
        with pytest.raises(PersistRecordError, match="invalid parameter tag"):
            parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; bad-tag=x")

    @pytest.mark.parametrize("raw", ["notanumber", "-1", "+5", "1_0", "12.5", ""])
    def test_invalid_persist_until_rejected(self, raw):
        with pytest.raises(PersistRecordError, match="persistUntil"):
            parse_record(f"{ISSUER}; accounturi={ACCOUNT_URI}; persistUntil={raw}")

    def test_value_with_whitespace_rejected(self):
        with pytest.raises(PersistRecordError, match="invalid value"):
            parse_record(f"{ISSUER}; accounturi=https://a.example/ b")


class TestPersistRecordExpiry:
    def _record(self, persist_until: int | None) -> PersistRecord:
        return PersistRecord(
            issuer_domain_name=ISSUER,
            accounturi=ACCOUNT_URI,
            persist_until=persist_until,
        )

    def test_no_persist_until_never_expires(self):
        assert not self._record(None).is_expired()

    def test_future_timestamp_not_expired(self):
        future = datetime.now(UTC) + timedelta(days=365)
        assert not self._record(int(future.timestamp())).is_expired()

    def test_past_timestamp_expired(self):
        past = datetime.now(UTC) - timedelta(days=1)
        assert self._record(int(past.timestamp())).is_expired()

    def test_explicit_now_is_honoured(self):
        record = self._record(1_000_000)
        assert record.is_expired(datetime.fromtimestamp(1_000_001, tz=UTC))
        assert not record.is_expired(datetime.fromtimestamp(999_999, tz=UTC))


# ---------------------------------------------------------------------------
# Validator metadata
# ---------------------------------------------------------------------------


class TestValidatorMetadata:
    def test_challenge_type(self):
        assert DnsPersist01Validator.challenge_type is ChallengeType.DNS_PERSIST_01

    def test_dns_identifiers_only(self):
        assert DnsPersist01Validator.supported_identifier_types == frozenset({"dns"})

    def test_declares_context_requirement(self):
        assert DnsPersist01Validator.requires_context is True

    def test_declares_no_token(self):
        """The challenge object must not carry a token for this type."""
        assert DnsPersist01Validator.uses_token is False

    def test_issuer_domain_names_from_settings(self):
        validator = DnsPersist01Validator(settings=_settings())
        assert validator.issuer_domain_names == (ISSUER,)

    def test_issuer_domain_names_without_settings(self):
        assert DnsPersist01Validator(settings=None).issuer_domain_names == ()


# ---------------------------------------------------------------------------
# Validation — preconditions
# ---------------------------------------------------------------------------


class TestValidationPreconditions:
    def test_ip_identifier_rejected(self):
        validator = DnsPersist01Validator(settings=_settings())
        with pytest.raises(ChallengeError, match="only supports 'dns'") as exc:
            _validate(validator, identifier_type="ip", identifier_value="192.0.2.1")
        assert exc.value.retryable is False

    def test_no_issuer_domain_names_configured(self):
        """A server misconfiguration must not read as a subscriber failure."""
        validator = DnsPersist01Validator(settings=_settings(issuer_domain_names=()))
        with pytest.raises(ChallengeError, match="no issuer_domain_names") as exc:
            _validate(validator)
        assert exc.value.retryable is False

    def test_missing_account_uri(self):
        validator = DnsPersist01Validator(settings=_settings())
        with pytest.raises(ChallengeError, match="no account URI") as exc:
            _validate(validator, account_uri=None)
        assert exc.value.retryable is False

    def test_missing_context_entirely(self):
        validator = DnsPersist01Validator(settings=_settings())
        with pytest.raises(ChallengeError, match="no account URI"):
            validator.validate(
                token="unused",
                jwk={},
                identifier_type="dns",
                identifier_value="example.com",
            )


# ---------------------------------------------------------------------------
# Validation — record matching
# ---------------------------------------------------------------------------


class TestValidationMatching:
    def _run(self, txt_values: list[str], settings=None, **kwargs) -> None:
        validator = DnsPersist01Validator(settings=settings or _settings())
        with patch.object(
            dns.resolver.Resolver,
            "resolve",
            return_value=_make_answer(txt_values),
        ):
            _validate(validator, **kwargs)

    def test_matching_record_succeeds(self):
        self._run([f"{ISSUER}; accounturi={ACCOUNT_URI}"])

    def test_queries_the_validation_domain_name(self):
        validator = DnsPersist01Validator(settings=_settings())
        with patch.object(
            dns.resolver.Resolver,
            "resolve",
            return_value=_make_answer([f"{ISSUER}; accounturi={ACCOUNT_URI}"]),
        ) as resolve:
            _validate(validator)
        assert resolve.call_args[0][0] == "_validation-persist.example.com"
        assert resolve.call_args[0][1] == "TXT"

    def test_unrelated_txt_records_ignored(self):
        """Other TXT records at the same name must not block a valid one."""
        self._run(
            [
                "v=spf1 -all",
                "totally unrelated",
                f"{ISSUER}; accounturi={ACCOUNT_URI}",
            ]
        )

    def test_other_issuer_records_ignored(self):
        self._run(
            [
                f"other.example; accounturi={ACCOUNT_URI}",
                f"{ISSUER}; accounturi={ACCOUNT_URI}",
            ]
        )

    def test_issuer_case_insensitive(self):
        self._run([f"CA.EXAMPLE; accounturi={ACCOUNT_URI}"])

    def test_multiple_configured_issuers(self):
        self._run(
            [f"alt.example; accounturi={ACCOUNT_URI}"],
            settings=_settings(issuer_domain_names=(ISSUER, "alt.example")),
        )

    def test_no_record_for_our_issuer(self):
        validator = DnsPersist01Validator(settings=_settings())
        with (
            patch.object(
                dns.resolver.Resolver,
                "resolve",
                return_value=_make_answer([f"other.example; accounturi={ACCOUNT_URI}"]),
            ),
            pytest.raises(ChallengeError, match="names an Issuer Domain Name") as exc,
        ):
            _validate(validator)
        # Retryable: the subscriber may still add our issuer to the record.
        assert exc.value.retryable is True

    def test_account_uri_mismatch_rejected(self):
        """The account binding is the whole point of the method."""
        validator = DnsPersist01Validator(settings=_settings())
        with (
            patch.object(
                dns.resolver.Resolver,
                "resolve",
                return_value=_make_answer([f"{ISSUER}; accounturi=https://acme.example/acct/999"]),
            ),
            pytest.raises(ChallengeError, match="does not match") as exc,
        ):
            _validate(validator)
        assert exc.value.retryable is False

    def test_account_uri_compared_without_normalization(self):
        """RFC 3986 Simple String Comparison: no case folding, no normalizing."""
        validator = DnsPersist01Validator(settings=_settings())
        with (
            patch.object(
                dns.resolver.Resolver,
                "resolve",
                return_value=_make_answer([f"{ISSUER}; accounturi=HTTPS://ACME.EXAMPLE/acct/1"]),
            ),
            pytest.raises(ChallengeError, match="does not match"),
        ):
            _validate(validator)

    def test_expired_persist_until_rejected(self):
        past = int((datetime.now(UTC) - timedelta(days=1)).timestamp())
        validator = DnsPersist01Validator(settings=_settings())
        with (
            patch.object(
                dns.resolver.Resolver,
                "resolve",
                return_value=_make_answer(
                    [f"{ISSUER}; accounturi={ACCOUNT_URI}; persistUntil={past}"]
                ),
            ),
            pytest.raises(ChallengeError, match="has passed"),
        ):
            _validate(validator)

    def test_future_persist_until_accepted(self):
        future = int((datetime.now(UTC) + timedelta(days=365)).timestamp())
        self._run([f"{ISSUER}; accounturi={ACCOUNT_URI}; persistUntil={future}"])

    def test_malformed_record_does_not_block_valid_one(self):
        self._run(
            [
                f"{ISSUER}; accounturi={ACCOUNT_URI}; accounturi=dup",
                f"{ISSUER}; accounturi={ACCOUNT_URI}",
            ]
        )

    def test_multi_segment_txt_record_joined(self):
        """Long TXT records arrive as multiple 255-byte strings."""
        validator = DnsPersist01Validator(settings=_settings())
        rdata = MagicMock()
        rdata.strings = (f"{ISSUER}; accou".encode(), f"nturi={ACCOUNT_URI}".encode())
        answer = MagicMock()
        answer.__iter__ = lambda self: iter([rdata])
        answer.response = MagicMock(flags=0)
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
            _validate(validator)


# ---------------------------------------------------------------------------
# Validation — wildcard and subdomain policy
# ---------------------------------------------------------------------------


class TestWildcardPolicy:
    def test_wildcard_requires_policy(self):
        validator = DnsPersist01Validator(settings=_settings(allow_subdomain_policy=False))
        with (
            patch.object(
                dns.resolver.Resolver,
                "resolve",
                return_value=_make_answer([f"{ISSUER}; accounturi={ACCOUNT_URI}"]),
            ),
            pytest.raises(ChallengeError, match="needs policy=wildcard"),
        ):
            _validate(validator, identifier_value="example.com", is_wildcard=True)

    def test_wildcard_with_policy_succeeds(self):
        validator = DnsPersist01Validator(settings=_settings())
        with patch.object(
            dns.resolver.Resolver,
            "resolve",
            return_value=_make_answer([f"{ISSUER}; accounturi={ACCOUNT_URI}; policy=wildcard"]),
        ):
            _validate(validator, identifier_value="example.com", is_wildcard=True)

    def test_wildcard_policy_can_be_disabled_by_the_server(self):
        validator = DnsPersist01Validator(
            settings=_settings(allow_wildcard_policy=False, allow_subdomain_policy=False)
        )
        with (
            patch.object(
                dns.resolver.Resolver,
                "resolve",
                return_value=_make_answer([f"{ISSUER}; accounturi={ACCOUNT_URI}; policy=wildcard"]),
            ),
            pytest.raises(ChallengeError, match="does not honour the wildcard policy"),
        ):
            _validate(validator, identifier_value="example.com", is_wildcard=True)

    def test_exact_record_does_not_need_wildcard_policy(self):
        validator = DnsPersist01Validator(settings=_settings())
        with patch.object(
            dns.resolver.Resolver,
            "resolve",
            return_value=_make_answer([f"{ISSUER}; accounturi={ACCOUNT_URI}"]),
        ):
            _validate(validator, identifier_value="www.example.com")


class TestSubdomainPolicy:
    """A policy=wildcard record on an ancestor authorizes names below it."""

    def _resolver_map(self, mapping: dict[str, list[str]]):
        def _resolve(self, qname, rdtype, *args, **kwargs):  # noqa: ANN001, ARG001
            name = str(qname).rstrip(".")
            if name not in mapping:
                raise dns.resolver.NXDOMAIN
            return _make_answer(mapping[name])

        return _resolve

    def test_ancestor_wildcard_record_authorizes_subdomain(self):
        validator = DnsPersist01Validator(settings=_settings())
        mapping = {
            "_validation-persist.example.com": [
                f"{ISSUER}; accounturi={ACCOUNT_URI}; policy=wildcard"
            ],
        }
        with patch.object(dns.resolver.Resolver, "resolve", self._resolver_map(mapping)):
            _validate(validator, identifier_value="a.b.example.com")

    def test_ancestor_without_wildcard_policy_does_not_authorize(self):
        validator = DnsPersist01Validator(settings=_settings())
        mapping = {
            "_validation-persist.example.com": [f"{ISSUER}; accounturi={ACCOUNT_URI}"],
        }
        with (
            patch.object(dns.resolver.Resolver, "resolve", self._resolver_map(mapping)),
            pytest.raises(ChallengeError),
        ):
            _validate(validator, identifier_value="a.b.example.com")

    def test_exact_record_preferred_over_ancestor_walk(self):
        validator = DnsPersist01Validator(settings=_settings())
        mapping = {
            "_validation-persist.www.example.com": [f"{ISSUER}; accounturi={ACCOUNT_URI}"],
        }
        with patch.object(dns.resolver.Resolver, "resolve", self._resolver_map(mapping)):
            _validate(validator, identifier_value="www.example.com")

    def test_ancestor_walk_can_be_disabled(self):
        validator = DnsPersist01Validator(settings=_settings(allow_subdomain_policy=False))
        mapping = {
            "_validation-persist.example.com": [
                f"{ISSUER}; accounturi={ACCOUNT_URI}; policy=wildcard"
            ],
        }
        with (
            patch.object(dns.resolver.Resolver, "resolve", self._resolver_map(mapping)),
            pytest.raises(ChallengeError, match="does not exist"),
        ):
            _validate(validator, identifier_value="a.b.example.com")

    def test_ancestor_wildcard_authorizes_a_wildcard_identifier(self):
        validator = DnsPersist01Validator(settings=_settings())
        mapping = {
            "_validation-persist.example.com": [
                f"{ISSUER}; accounturi={ACCOUNT_URI}; policy=wildcard"
            ],
        }
        with patch.object(dns.resolver.Resolver, "resolve", self._resolver_map(mapping)):
            _validate(validator, identifier_value="sub.example.com", is_wildcard=True)


# ---------------------------------------------------------------------------
# Validation — DNS errors
# ---------------------------------------------------------------------------


class TestDnsErrors:
    @pytest.mark.parametrize(
        ("exc", "match"),
        [
            (dns.resolver.NXDOMAIN(), "does not exist"),
            (dns.resolver.NoAnswer(), "no TXT records"),
            (dns.resolver.NoNameservers(), "no nameservers available"),
            (dns.exception.Timeout(), "timed out"),
            (dns.exception.DNSException("boom"), "DNS error"),
        ],
    )
    def test_dns_failures_are_retryable(self, exc, match):
        """A long-lived record is far likelier absent from a blip than never published."""
        validator = DnsPersist01Validator(
            settings=_settings(allow_subdomain_policy=False),
        )
        with (
            patch.object(dns.resolver.Resolver, "resolve", side_effect=exc),
            pytest.raises(ChallengeError, match=match) as exc_info,
        ):
            _validate(validator)
        assert exc_info.value.retryable is True

    def test_dnssec_required_and_ad_flag_missing(self):
        validator = DnsPersist01Validator(
            settings=_settings(require_dnssec=True, allow_subdomain_policy=False),
        )
        with (
            patch.object(
                dns.resolver.Resolver,
                "resolve",
                return_value=_make_answer(
                    [f"{ISSUER}; accounturi={ACCOUNT_URI}"],
                    ad_flag=False,
                ),
            ),
            pytest.raises(ChallengeError, match="DNSSEC validation failed") as exc,
        ):
            _validate(validator)
        assert exc.value.retryable is True

    def test_dnssec_required_and_ad_flag_present(self):
        validator = DnsPersist01Validator(settings=_settings(require_dnssec=True))
        with patch.object(
            dns.resolver.Resolver,
            "resolve",
            return_value=_make_answer([f"{ISSUER}; accounturi={ACCOUNT_URI}"], ad_flag=True),
        ):
            _validate(validator)

    def test_custom_resolvers_are_used(self):
        validator = DnsPersist01Validator(settings=_settings(resolvers=("192.0.2.53",)))
        captured = {}

        def _resolve(self, qname, rdtype, *args, **kwargs):  # noqa: ANN001, ARG001
            captured["nameservers"] = self.nameservers
            return _make_answer([f"{ISSUER}; accounturi={ACCOUNT_URI}"])

        with patch.object(dns.resolver.Resolver, "resolve", _resolve):
            _validate(validator)
        assert captured["nameservers"] == ["192.0.2.53"]

    def test_authoritative_lookup_failure_falls_back(self):
        validator = DnsPersist01Validator(settings=_settings(require_authoritative=True))
        with (
            patch(
                "dns.resolver.zone_for_name",
                side_effect=dns.exception.DNSException("nope"),
            ),
            patch.object(
                dns.resolver.Resolver,
                "resolve",
                return_value=_make_answer([f"{ISSUER}; accounturi={ACCOUNT_URI}"]),
            ),
        ):
            _validate(validator)
