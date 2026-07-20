"""DNS-PERSIST-01 integration: registry, serialization and service wiring."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import dns.exception
import dns.flags
import dns.resolver
import pytest

from acmeeh.api.serializers import serialize_authorization, serialize_challenge
from acmeeh.challenge.auto_accept import AutoAcceptDnsPersistValidator
from acmeeh.challenge.base import ChallengeContext
from acmeeh.challenge.dns_persist01 import DnsPersist01Validator
from acmeeh.challenge.registry import ChallengeRegistry
from acmeeh.config.settings import DnsPersist01Settings
from acmeeh.core.types import (
    AuthorizationStatus,
    ChallengeStatus,
    ChallengeType,
    IdentifierType,
)
from acmeeh.models.authorization import Authorization
from acmeeh.models.challenge import Challenge
from acmeeh.services.challenge import ChallengeService

ACCOUNT_ID = uuid4()
ACCOUNT_URI = f"https://acme.example/acct/{ACCOUNT_ID}"
ISSUER = "ca.example"


def _persist_settings(**overrides) -> DnsPersist01Settings:
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
    return DnsPersist01Settings(**base)


def _challenge_settings(enabled, *, auto_accept=False) -> SimpleNamespace:
    return SimpleNamespace(
        enabled=tuple(enabled),
        auto_accept=auto_accept,
        http01=None,
        dns01=None,
        tlsalpn01=None,
        dnspersist01=_persist_settings(),
        background_worker=None,
        retry_after_seconds=3,
        backoff_base_seconds=5,
        backoff_max_seconds=300,
    )


def _urls() -> SimpleNamespace:
    return SimpleNamespace(
        challenge_url=lambda cid: f"https://acme.example/chall/{cid}",
        account_url=lambda aid: f"https://acme.example/acct/{aid}",
        authorization_url=lambda aid: f"https://acme.example/authz/{aid}",
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_loads_dns_persist_validator(self):
        registry = ChallengeRegistry(_challenge_settings(["dns-persist-01"]))
        validator = registry.get_validator(ChallengeType.DNS_PERSIST_01)
        assert isinstance(validator, DnsPersist01Validator)

    def test_receives_its_per_type_settings(self):
        registry = ChallengeRegistry(_challenge_settings(["dns-persist-01"]))
        validator = registry.get_validator(ChallengeType.DNS_PERSIST_01)
        assert validator.issuer_domain_names == (ISSUER,)

    def test_reports_enabled(self):
        registry = ChallengeRegistry(_challenge_settings(["dns-persist-01"]))
        assert registry.is_enabled(ChallengeType.DNS_PERSIST_01)

    def test_absent_when_not_enabled(self):
        registry = ChallengeRegistry(_challenge_settings(["http-01"]))
        assert not registry.is_enabled(ChallengeType.DNS_PERSIST_01)
        assert registry.get_validator_or_none(ChallengeType.DNS_PERSIST_01) is None

    def test_auto_accept_substitutes_validator(self):
        registry = ChallengeRegistry(_challenge_settings(["dns-persist-01"], auto_accept=True))
        validator = registry.get_validator(ChallengeType.DNS_PERSIST_01)
        assert isinstance(validator, AutoAcceptDnsPersistValidator)

    def test_auto_accept_keeps_issuer_domain_names(self):
        """The challenge object must still advertise issuers when auto-accepting."""
        registry = ChallengeRegistry(_challenge_settings(["dns-persist-01"], auto_accept=True))
        validator = registry.get_validator(ChallengeType.DNS_PERSIST_01)
        assert validator.issuer_domain_names == (ISSUER,)

    def test_auto_accept_validator_passes(self):
        validator = AutoAcceptDnsPersistValidator(settings=_persist_settings())
        validator.validate(
            token="t",
            jwk={},
            identifier_type="dns",
            identifier_value="example.com",
        )

    def test_coexists_with_other_types(self):
        registry = ChallengeRegistry(_challenge_settings(["http-01", "dns-persist-01"]))
        assert set(registry.enabled_types) == {
            ChallengeType.HTTP_01,
            ChallengeType.DNS_PERSIST_01,
        }


# ---------------------------------------------------------------------------
# Serialization (draft §4.3.1)
# ---------------------------------------------------------------------------


def _challenge(ctype: ChallengeType) -> Challenge:
    return Challenge(
        id=uuid4(),
        authorization_id=uuid4(),
        type=ctype,
        token="tok-abc",
        status=ChallengeStatus.PENDING,
    )


class TestSerialization:
    def test_omits_token(self):
        """DNS-PERSIST-01 has no token; leaving one in invites DNS-01 handling."""
        body = serialize_challenge(
            _challenge(ChallengeType.DNS_PERSIST_01),
            _urls(),
            account_uri=ACCOUNT_URI,
            issuer_domain_names=(ISSUER,),
        )
        assert "token" not in body

    def test_includes_accounturi_and_issuers(self):
        body = serialize_challenge(
            _challenge(ChallengeType.DNS_PERSIST_01),
            _urls(),
            account_uri=ACCOUNT_URI,
            issuer_domain_names=(ISSUER, "alt.example"),
        )
        assert body["accounturi"] == ACCOUNT_URI
        assert body["issuer-domain-names"] == [ISSUER, "alt.example"]
        assert body["type"] == "dns-persist-01"

    def test_issuer_list_capped_at_ten(self):
        names = tuple(f"ca{i}.example" for i in range(15))
        body = serialize_challenge(
            _challenge(ChallengeType.DNS_PERSIST_01),
            _urls(),
            account_uri=ACCOUNT_URI,
            issuer_domain_names=names,
        )
        assert len(body["issuer-domain-names"]) == 10

    def test_accounturi_omitted_when_unknown(self):
        body = serialize_challenge(
            _challenge(ChallengeType.DNS_PERSIST_01),
            _urls(),
            account_uri=None,
            issuer_domain_names=(ISSUER,),
        )
        assert "accounturi" not in body

    def test_other_types_keep_their_token(self):
        for ctype in (ChallengeType.HTTP_01, ChallengeType.DNS_01, ChallengeType.TLS_ALPN_01):
            body = serialize_challenge(
                _challenge(ctype),
                _urls(),
                account_uri=ACCOUNT_URI,
                issuer_domain_names=(ISSUER,),
            )
            assert body["token"] == "tok-abc"
            assert "issuer-domain-names" not in body
            assert "accounturi" not in body

    def test_authorization_propagates_account_uri(self):
        authz = Authorization(
            id=uuid4(),
            account_id=ACCOUNT_ID,
            identifier_type=IdentifierType.DNS,
            identifier_value="example.com",
            status=AuthorizationStatus.PENDING,
        )
        body = serialize_authorization(
            authz,
            [_challenge(ChallengeType.DNS_PERSIST_01)],
            _urls(),
            (ISSUER,),
        )
        challenge = body["challenges"][0]
        assert challenge["accounturi"] == ACCOUNT_URI
        assert challenge["issuer-domain-names"] == [ISSUER]

    def test_authorization_without_issuers_still_emits_the_key(self):
        """Clients can then see the CA offered nothing, rather than guessing."""
        authz = Authorization(
            id=uuid4(),
            account_id=ACCOUNT_ID,
            identifier_type=IdentifierType.DNS,
            identifier_value="example.com",
            status=AuthorizationStatus.PENDING,
        )
        body = serialize_authorization(
            authz,
            [_challenge(ChallengeType.DNS_PERSIST_01)],
            _urls(),
        )
        assert body["challenges"][0]["issuer-domain-names"] == []


# ---------------------------------------------------------------------------
# ChallengeService context plumbing
# ---------------------------------------------------------------------------


class _StubValidator:
    challenge_type = ChallengeType.DNS_PERSIST_01
    requires_context = True
    auto_validate = True
    max_retries = 0

    def __init__(self):
        self.seen = None

    def validate(self, **kwargs):
        self.seen = kwargs

    def cleanup(self, **kwargs):
        pass


class _StubValidatorNoContext(_StubValidator):
    requires_context = False


def _service(validator, *, wildcard=False, urls=None):
    authz = Authorization(
        id=uuid4(),
        account_id=ACCOUNT_ID,
        identifier_type=IdentifierType.DNS,
        identifier_value="example.com",
        status=AuthorizationStatus.PENDING,
        wildcard=wildcard,
    )
    challenge = Challenge(
        id=uuid4(),
        authorization_id=authz.id,
        type=ChallengeType.DNS_PERSIST_01,
        token="tok",
        status=ChallengeStatus.PENDING,
    )

    challenges = MagicMock()
    challenges.find_by_id.return_value = challenge
    challenges.claim_for_processing.return_value = challenge
    challenges.complete_validation.return_value = challenge

    authzs = MagicMock()
    authzs.find_by_id.return_value = authz
    authzs.transition_status.return_value = None

    orders = MagicMock()
    orders.find_orders_by_authorization.return_value = []

    registry = MagicMock()
    registry.get_validator_or_none.return_value = validator

    service = ChallengeService(
        challenges,
        authzs,
        orders,
        registry,
        urls=urls if urls is not None else _urls(),
    )
    return service, challenge


class TestServiceContext:
    def test_passes_account_uri_and_wildcard(self):
        validator = _StubValidator()
        service, challenge = _service(validator, wildcard=True)
        service.initiate_validation(challenge.id, ACCOUNT_ID, {"kty": "EC"})

        context = validator.seen["context"]
        assert context.account_uri == ACCOUNT_URI
        assert context.is_wildcard is True

    def test_non_wildcard_authorization(self):
        validator = _StubValidator()
        service, challenge = _service(validator, wildcard=False)
        service.initiate_validation(challenge.id, ACCOUNT_ID, {"kty": "EC"})
        assert validator.seen["context"].is_wildcard is False

    def test_context_withheld_from_validators_that_do_not_ask(self):
        """Existing and third-party validators keep their original signature."""
        validator = _StubValidatorNoContext()
        service, challenge = _service(validator)
        service.initiate_validation(challenge.id, ACCOUNT_ID, {"kty": "EC"})
        assert "context" not in validator.seen

    def test_missing_url_builder_yields_no_account_uri(self):
        validator = _StubValidator()
        service, challenge = _service(validator, urls=None)
        # Explicitly drop the builder to mimic a container without one.
        service._urls = None  # noqa: SLF001
        service.initiate_validation(challenge.id, ACCOUNT_ID, {"kty": "EC"})
        assert validator.seen["context"].account_uri is None

    def test_url_builder_failure_is_not_fatal(self):
        validator = _StubValidator()
        broken = SimpleNamespace(
            account_url=MagicMock(side_effect=RuntimeError("boom")),
            challenge_url=lambda cid: "",
            authorization_url=lambda aid: "",
        )
        service, challenge = _service(validator, urls=broken)
        service.initiate_validation(challenge.id, ACCOUNT_ID, {"kty": "EC"})
        assert validator.seen["context"].account_uri is None

    def test_process_pending_also_passes_context(self):
        validator = _StubValidator()
        service, challenge = _service(validator, wildcard=True)
        service.process_pending(challenge.id, "worker-1", {"kty": "EC"})
        assert validator.seen["context"].account_uri == ACCOUNT_URI
        assert validator.seen["context"].is_wildcard is True


# ---------------------------------------------------------------------------
# Authoritative resolution
# ---------------------------------------------------------------------------


class TestAuthoritativeResolution:
    def test_pins_resolver_to_authoritative_nameservers(self):
        validator = DnsPersist01Validator(
            settings=replace(_persist_settings(), require_authoritative=True)
        )
        captured = {}

        def _resolve(self, qname, rdtype, *args, **kwargs):  # noqa: ANN001, ARG001
            captured["nameservers"] = list(self.nameservers)
            answer = MagicMock()
            rdata = MagicMock()
            rdata.strings = (f"{ISSUER}; accounturi={ACCOUNT_URI}".encode(),)
            answer.__iter__ = lambda self: iter([rdata])
            answer.response = MagicMock(flags=0)
            return answer

        ns_record = MagicMock()
        ns_record.target.to_text.return_value = "ns1.example.com."
        a_record = MagicMock(address="192.0.2.10")

        def _module_resolve(qname, rdtype, *args, **kwargs):  # noqa: ANN001, ARG001
            if rdtype == "NS":
                return [ns_record]
            if rdtype == "A":
                return [a_record]
            raise dns.exception.DNSException

        with (
            patch("dns.resolver.zone_for_name", return_value="example.com."),
            patch("dns.resolver.resolve", side_effect=_module_resolve),
            patch.object(dns.resolver.Resolver, "resolve", _resolve),
        ):
            validator.validate(
                token="unused",
                jwk={},
                identifier_type="dns",
                identifier_value="example.com",
                context=ChallengeContext(account_uri=ACCOUNT_URI),
            )

        assert captured["nameservers"] == ["192.0.2.10"]

    def test_dnssec_stays_enabled_on_the_pinned_resolver(self):
        """Pinning to the authoritative NS must not silently drop DNSSEC."""
        validator = DnsPersist01Validator(
            settings=replace(
                _persist_settings(),
                require_authoritative=True,
                require_dnssec=True,
            )
        )
        captured = {}

        def _resolve(self, qname, rdtype, *args, **kwargs):  # noqa: ANN001, ARG001
            captured["edns"] = self.edns
            captured["ednsflags"] = self.ednsflags
            answer = MagicMock()
            rdata = MagicMock()
            rdata.strings = (f"{ISSUER}; accounturi={ACCOUNT_URI}".encode(),)
            answer.__iter__ = lambda self: iter([rdata])
            answer.response = MagicMock(flags=dns.flags.AD)
            return answer

        ns_record = MagicMock()
        ns_record.target.to_text.return_value = "ns1.example.com."
        a_record = MagicMock(address="192.0.2.10")

        def _module_resolve(qname, rdtype, *args, **kwargs):  # noqa: ANN001, ARG001
            if rdtype == "NS":
                return [ns_record]
            if rdtype == "A":
                return [a_record]
            raise dns.exception.DNSException

        with (
            patch("dns.resolver.zone_for_name", return_value="example.com."),
            patch("dns.resolver.resolve", side_effect=_module_resolve),
            patch.object(dns.resolver.Resolver, "resolve", _resolve),
        ):
            validator.validate(
                token="unused",
                jwk={},
                identifier_type="dns",
                identifier_value="example.com",
                context=ChallengeContext(account_uri=ACCOUNT_URI),
            )

        assert captured["edns"] == 0
        assert captured["ednsflags"] & dns.flags.DO


@pytest.mark.parametrize(
    ("identifier_type", "expected"),
    [("dns", True), ("ip", False)],
)
def test_identifier_support(identifier_type, expected):
    validator = DnsPersist01Validator(settings=_persist_settings())
    assert validator.supports_identifier(identifier_type) is expected
