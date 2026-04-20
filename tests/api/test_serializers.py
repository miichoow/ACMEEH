"""Unit tests for acmeeh.api.serializers — ACME response serialization."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from acmeeh.api.serializers import (
    serialize_account,
    serialize_authorization,
    serialize_challenge,
    serialize_directory,
    serialize_order,
)
from acmeeh.core.types import (
    AccountStatus,
    AuthorizationStatus,
    ChallengeStatus,
    ChallengeType,
    IdentifierType,
    OrderStatus,
)
from acmeeh.models.account import Account, AccountContact
from acmeeh.models.authorization import Authorization
from acmeeh.models.challenge import Challenge
from acmeeh.models.order import Identifier, Order

# ---------------------------------------------------------------------------
# Stub helpers
# ---------------------------------------------------------------------------


def _stub_urls():
    """Build a minimal AcmeUrls-like object."""
    ROOT = "https://acme.example.com/acme"

    class StubUrls:
        new_nonce = ROOT + "/new-nonce"
        new_account = ROOT + "/new-acct"
        new_order = ROOT + "/new-order"
        new_authz = ROOT + "/new-authz"
        revoke_cert = ROOT + "/revoke-cert"
        key_change = ROOT + "/key-change"
        renewal_info = ""

        def account_url(self, aid):
            return f"{ROOT}/acct/{aid}"

        def order_url(self, oid):
            return f"{ROOT}/order/{oid}"

        def finalize_url(self, oid):
            return f"{ROOT}/order/{oid}/finalize"

        def authorization_url(self, aid):
            return f"{ROOT}/authz/{aid}"

        def challenge_url(self, cid):
            return f"{ROOT}/chall/{cid}"

        def certificate_url(self, cid):
            return f"{ROOT}/cert/{cid}"

        def orders_url(self, aid):
            return f"{ROOT}/acct/{aid}/orders"

    return StubUrls()


def _stub_settings(
    tos_url="",
    website_url="",
    caa_identities=(),
    eab_required=False,
    pre_authz_days=0,
    profiles=None,
):
    return SimpleNamespace(
        tos=SimpleNamespace(url=tos_url),
        acme=SimpleNamespace(
            website_url=website_url,
            caa_identities=caa_identities,
            eab_required=eab_required,
        ),
        order=SimpleNamespace(pre_authorization_lifetime_days=pre_authz_days),
        ca=SimpleNamespace(profiles=profiles or {}),
    )


# ---------------------------------------------------------------------------
# TestSerializeDirectory
# ---------------------------------------------------------------------------


class TestSerializeDirectory:
    def test_required_fields(self):
        d = serialize_directory(_stub_urls(), _stub_settings())
        assert "newNonce" in d
        assert "newAccount" in d
        assert "newOrder" in d
        assert "newAuthz" in d
        assert "revokeCert" in d
        assert "keyChange" in d

    def test_tos_url(self):
        d = serialize_directory(_stub_urls(), _stub_settings(tos_url="https://tos.example.com"))
        assert d["meta"]["termsOfService"] == "https://tos.example.com"

    def test_eab_required(self):
        d = serialize_directory(_stub_urls(), _stub_settings(eab_required=True))
        assert d["meta"]["externalAccountRequired"] is True

    def test_caa_identities(self):
        d = serialize_directory(_stub_urls(), _stub_settings(caa_identities=["ca.example.com"]))
        assert d["meta"]["caaIdentities"] == ["ca.example.com"]

    def test_profiles(self):
        d = serialize_directory(
            _stub_urls(),
            _stub_settings(profiles={"default": {}, "tlsServer": {}}),
        )
        assert "profiles" in d["meta"]
        assert isinstance(d["meta"]["profiles"], dict)
        assert sorted(d["meta"]["profiles"].keys()) == ["default", "tlsServer"]

    def test_profiles_only_default_omitted(self):
        d = serialize_directory(
            _stub_urls(),
            _stub_settings(profiles={"default": {}}),
        )
        assert "meta" not in d or "profiles" not in d.get("meta", {})

    def test_renewal_info_included(self):
        urls = _stub_urls()
        urls.renewal_info = "https://acme.example.com/acme/renewalInfo"
        d = serialize_directory(urls, _stub_settings())
        assert d["renewalInfo"] == "https://acme.example.com/acme/renewalInfo"

    def test_renewal_info_omitted(self):
        d = serialize_directory(_stub_urls(), _stub_settings())
        assert "renewalInfo" not in d

    def test_meta_omitted_when_empty(self):
        d = serialize_directory(_stub_urls(), _stub_settings())
        assert "meta" not in d


# ---------------------------------------------------------------------------
# TestSerializeAccount
# ---------------------------------------------------------------------------


class TestSerializeAccount:
    def test_basic(self):
        aid = uuid4()
        account = Account(id=aid, jwk_thumbprint="tp", jwk={}, status=AccountStatus.VALID)
        d = serialize_account(account, [], _stub_urls())
        assert d["status"] == "valid"
        assert d["orders"].endswith("/orders")

    def test_contacts_included(self):
        aid = uuid4()
        account = Account(id=aid, jwk_thumbprint="tp", jwk={}, status=AccountStatus.VALID)
        contacts = [
            AccountContact(id=uuid4(), account_id=aid, contact_uri="mailto:a@b.com"),
        ]
        d = serialize_account(account, contacts, _stub_urls())
        assert d["contact"] == ["mailto:a@b.com"]

    def test_contacts_omitted_when_empty(self):
        aid = uuid4()
        account = Account(id=aid, jwk_thumbprint="tp", jwk={}, status=AccountStatus.VALID)
        d = serialize_account(account, [], _stub_urls())
        assert "contact" not in d

    def test_tos_agreed(self):
        account = Account(
            id=uuid4(),
            jwk_thumbprint="tp",
            jwk={},
            status=AccountStatus.VALID,
            tos_agreed=True,
        )
        d = serialize_account(account, [], _stub_urls())
        assert d["termsOfServiceAgreed"] is True

    def test_tos_not_agreed_omitted(self):
        account = Account(
            id=uuid4(),
            jwk_thumbprint="tp",
            jwk={},
            status=AccountStatus.VALID,
            tos_agreed=False,
        )
        d = serialize_account(account, [], _stub_urls())
        assert "termsOfServiceAgreed" not in d


# ---------------------------------------------------------------------------
# TestSerializeOrder
# ---------------------------------------------------------------------------


class TestSerializeOrder:
    def _make_order(self, **kwargs):
        defaults = dict(
            id=uuid4(),
            account_id=uuid4(),
            status=OrderStatus.PENDING,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
            identifiers_hash="hash",
        )
        defaults.update(kwargs)
        return Order(**defaults)

    def test_basic(self):
        order = self._make_order()
        authz_ids = [uuid4()]
        urls = _stub_urls()
        d = serialize_order(order, authz_ids, urls)
        assert d["status"] == "pending"
        assert d["identifiers"] == [{"type": "dns", "value": "example.com"}]
        assert len(d["authorizations"]) == 1
        assert "finalize" in d

    def test_expires_included(self):
        now = datetime.now(UTC)
        order = self._make_order(expires=now)
        d = serialize_order(order, [], _stub_urls())
        assert d["expires"] == now.isoformat()

    def test_not_before_not_after(self):
        now = datetime.now(UTC)
        order = self._make_order(not_before=now, not_after=now)
        d = serialize_order(order, [], _stub_urls())
        assert d["notBefore"] == now.isoformat()
        assert d["notAfter"] == now.isoformat()

    def test_certificate_included(self):
        cert_id = uuid4()
        order = self._make_order(certificate_id=cert_id)
        d = serialize_order(order, [], _stub_urls())
        assert "certificate" in d
        assert str(cert_id) in d["certificate"]

    def test_error_included(self):
        order = self._make_order(error={"type": "urn:...", "detail": "oops"})
        d = serialize_order(order, [], _stub_urls())
        assert d["error"] == {"type": "urn:...", "detail": "oops"}

    def test_optional_fields_omitted(self):
        order = self._make_order()
        d = serialize_order(order, [], _stub_urls())
        for key in ("expires", "notBefore", "notAfter", "certificate", "error"):
            assert key not in d


# ---------------------------------------------------------------------------
# TestSerializeAuthorization
# ---------------------------------------------------------------------------


class TestSerializeAuthorization:
    def test_basic(self):
        authz = Authorization(
            id=uuid4(),
            account_id=uuid4(),
            identifier_type=IdentifierType.DNS,
            identifier_value="example.com",
            status=AuthorizationStatus.PENDING,
        )
        chall = Challenge(
            id=uuid4(),
            authorization_id=authz.id,
            type=ChallengeType.HTTP_01,
            token="tok",
            status=ChallengeStatus.PENDING,
        )
        d = serialize_authorization(authz, [chall], _stub_urls())
        assert d["status"] == "pending"
        assert d["identifier"] == {"type": "dns", "value": "example.com"}
        assert len(d["challenges"]) == 1

    def test_expires(self):
        now = datetime.now(UTC)
        authz = Authorization(
            id=uuid4(),
            account_id=uuid4(),
            identifier_type=IdentifierType.DNS,
            identifier_value="example.com",
            status=AuthorizationStatus.PENDING,
            expires=now,
        )
        d = serialize_authorization(authz, [], _stub_urls())
        assert d["expires"] == now.isoformat()

    def test_wildcard(self):
        authz = Authorization(
            id=uuid4(),
            account_id=uuid4(),
            identifier_type=IdentifierType.DNS,
            identifier_value="example.com",
            status=AuthorizationStatus.PENDING,
            wildcard=True,
        )
        d = serialize_authorization(authz, [], _stub_urls())
        assert d["wildcard"] is True

    def test_wildcard_false_omitted(self):
        authz = Authorization(
            id=uuid4(),
            account_id=uuid4(),
            identifier_type=IdentifierType.DNS,
            identifier_value="example.com",
            status=AuthorizationStatus.PENDING,
            wildcard=False,
        )
        d = serialize_authorization(authz, [], _stub_urls())
        assert "wildcard" not in d


# ---------------------------------------------------------------------------
# TestSerializeChallenge
# ---------------------------------------------------------------------------


class TestSerializeChallenge:
    def test_basic(self):
        cid = uuid4()
        c = Challenge(
            id=cid,
            authorization_id=uuid4(),
            type=ChallengeType.DNS_01,
            token="mytoken",
            status=ChallengeStatus.PENDING,
        )
        d = serialize_challenge(c, _stub_urls())
        assert d["type"] == "dns-01"
        assert d["token"] == "mytoken"
        assert d["status"] == "pending"
        assert str(cid) in d["url"]

    def test_validated_included(self):
        now = datetime.now(UTC)
        c = Challenge(
            id=uuid4(),
            authorization_id=uuid4(),
            type=ChallengeType.HTTP_01,
            token="t",
            status=ChallengeStatus.VALID,
            validated_at=now,
        )
        d = serialize_challenge(c, _stub_urls())
        assert d["validated"] == now.isoformat()

    def test_error_included(self):
        c = Challenge(
            id=uuid4(),
            authorization_id=uuid4(),
            type=ChallengeType.HTTP_01,
            token="t",
            status=ChallengeStatus.INVALID,
            error={"type": "urn:...", "detail": "fail"},
        )
        d = serialize_challenge(c, _stub_urls())
        assert d["error"] == {"type": "urn:...", "detail": "fail"}

    def test_optional_fields_omitted(self):
        c = Challenge(
            id=uuid4(),
            authorization_id=uuid4(),
            type=ChallengeType.HTTP_01,
            token="t",
            status=ChallengeStatus.PENDING,
        )
        d = serialize_challenge(c, _stub_urls())
        assert "validated" not in d
        assert "error" not in d
