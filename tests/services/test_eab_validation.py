"""Tests for EAB (External Account Binding) validation."""

from __future__ import annotations

import base64
import hmac
import json
from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from acmeeh.app.errors import AcmeProblem
from acmeeh.core.jws import validate_eab_jws
from acmeeh.core.types import AccountStatus
from acmeeh.services.account import AccountService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_json(obj) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _make_eab_jws(kid: str, hmac_key_b64: str, outer_jwk: dict) -> dict:
    """Build a valid EAB inner JWS."""
    hmac_key = base64.urlsafe_b64decode(hmac_key_b64 + "==")
    protected = {"alg": "HS256", "kid": kid, "url": "https://acme.test/new-account"}
    protected_b64 = _b64url_json(protected)
    payload_b64 = _b64url_json(outer_jwk)
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(hmac_key, signing_input, "sha256").digest()
    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": _b64url(sig),
    }


def _make_ec_jwk():
    """Generate a fresh EC key and return (private_key, jwk_dict)."""
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key()
    nums = pub.public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
    }
    return key, jwk


def _make_hmac_key() -> str:
    """Generate a random base64url HMAC key."""
    import secrets

    raw = secrets.token_bytes(32)
    return _b64url(raw)


# ---------------------------------------------------------------------------
# Stub EAB repository
# ---------------------------------------------------------------------------


@dataclass
class FakeEabCredential:
    id: UUID
    kid: str
    hmac_key: str
    revoked: bool = False
    used: bool = False
    account_id: UUID | None = None


class StubEabRepo:
    def __init__(self):
        self._creds: dict[str, FakeEabCredential] = {}

    def add(self, cred: FakeEabCredential):
        self._creds[cred.kid] = cred

    def find_by_kid(self, kid: str) -> FakeEabCredential | None:
        return self._creds.get(kid)

    def mark_used(self, kid: str, account_id: UUID):
        cred = self._creds.get(kid)
        if cred:
            cred.used = True
            cred.account_id = account_id

    def bind_account(self, kid: str, account_id: UUID):
        cred = self._creds.get(kid)
        if cred:
            cred.account_id = account_id

    def copy_to_account_by_kid(self, kid: str, account_id: UUID):
        pass

    def sync_linkage_to_account(self, account_id: UUID):
        pass


# ---------------------------------------------------------------------------
# Stub repos for AccountService
# ---------------------------------------------------------------------------


@dataclass
class FakeAccount:
    id: UUID
    jwk_thumbprint: str
    jwk: dict
    status: AccountStatus
    tos_agreed: bool = True

    # Make it look like a frozen dataclass to the replace() calls
    __dataclass_fields__ = {}


class StubAccountRepo:
    def __init__(self):
        self._accounts: dict[UUID, FakeAccount] = {}

    def find_by_thumbprint(self, thumbprint):
        for a in self._accounts.values():
            if a.jwk_thumbprint == thumbprint:
                return a
        return None

    def create(self, entity):
        self._accounts[entity.id] = entity


class StubContactRepo:
    def __init__(self):
        self._contacts = []

    def find_by_account(self, account_id):
        return []

    def create(self, entity):
        self._contacts.append(entity)

    def replace_for_account(self, account_id, entities):
        return entities


@dataclass(frozen=True)
class FakeEmailSettings:
    require_contact: bool = False
    allowed_domains: tuple = ()


@dataclass(frozen=True)
class FakeTosSettings:
    require_agreement: bool = False
    url: str = ""


# ---------------------------------------------------------------------------
# Tests for validate_eab_jws directly
# ---------------------------------------------------------------------------


class TestValidateEabJws:
    """Test the low-level EAB JWS validation function."""

    def test_valid_eab_succeeds(self):
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()
        eab_jws = _make_eab_jws("test-kid", hmac_key, jwk)
        result = validate_eab_jws(eab_jws, jwk, hmac_key)
        assert result == "test-kid"

    def test_invalid_hmac_signature_fails(self):
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()
        eab_jws = _make_eab_jws("test-kid", hmac_key, jwk)
        # Tamper with the signature
        eab_jws["signature"] = _b64url(b"\x00" * 32)
        with pytest.raises(AcmeProblem) as exc_info:
            validate_eab_jws(eab_jws, jwk, hmac_key)
        assert "HMAC" in exc_info.value.detail or "signature" in exc_info.value.detail

    def test_wrong_algorithm_fails(self):
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()
        # Build EAB with wrong algorithm
        protected = {"alg": "HS384", "kid": "test-kid", "url": "https://acme.test/new-account"}
        protected_b64 = _b64url_json(protected)
        payload_b64 = _b64url_json(jwk)
        eab_jws = {"protected": protected_b64, "payload": payload_b64, "signature": _b64url(b"x")}
        with pytest.raises(AcmeProblem) as exc_info:
            validate_eab_jws(eab_jws, jwk, hmac_key)
        assert "HS256" in exc_info.value.detail

    def test_missing_kid_fails(self):
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()
        protected = {"alg": "HS256", "url": "https://acme.test/new-account"}
        protected_b64 = _b64url_json(protected)
        payload_b64 = _b64url_json(jwk)
        eab_jws = {"protected": protected_b64, "payload": payload_b64, "signature": _b64url(b"x")}
        with pytest.raises(AcmeProblem) as exc_info:
            validate_eab_jws(eab_jws, jwk, hmac_key)
        assert "kid" in exc_info.value.detail.lower()

    def test_payload_mismatch_fails(self):
        _, jwk = _make_ec_jwk()
        _, other_jwk = _make_ec_jwk()  # Different key
        hmac_key = _make_hmac_key()
        # Build EAB with the other JWK as payload
        eab_jws = _make_eab_jws("test-kid", hmac_key, other_jwk)
        with pytest.raises(AcmeProblem) as exc_info:
            validate_eab_jws(eab_jws, jwk, hmac_key)
        assert "does not match" in exc_info.value.detail


# ---------------------------------------------------------------------------
# Tests for EAB flow through AccountService
# ---------------------------------------------------------------------------


class TestEabRequiredFlow:
    """Valid EAB with eab_required=True succeeds."""

    def test_valid_eab_creates_account(self):
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()

        eab_repo = StubEabRepo()
        eab_repo.add(FakeEabCredential(id=uuid4(), kid="my-kid", hmac_key=hmac_key))

        service = AccountService(
            account_repo=StubAccountRepo(),
            contact_repo=StubContactRepo(),
            email_settings=FakeEmailSettings(),
            tos_settings=FakeTosSettings(),
            eab_repo=eab_repo,
            eab_required=True,
        )

        eab_payload = _make_eab_jws("my-kid", hmac_key, jwk)
        account, contacts, created = service.create_or_find(
            jwk,
            tos_agreed=True,
            eab_payload=eab_payload,
        )
        assert created is True

    def test_missing_eab_when_required_raises(self):
        _, jwk = _make_ec_jwk()
        service = AccountService(
            account_repo=StubAccountRepo(),
            contact_repo=StubContactRepo(),
            email_settings=FakeEmailSettings(),
            tos_settings=FakeTosSettings(),
            eab_required=True,
        )
        with pytest.raises(AcmeProblem) as exc_info:
            service.create_or_find(jwk, tos_agreed=True, eab_payload=None)
        assert "externalAccountRequired" in exc_info.value.error_type


class TestEabRequiredButRepoUnavailable:
    """EAB payload provided but eab_repo is None (admin API disabled)."""

    def test_eab_payload_without_repo_raises(self):
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()
        service = AccountService(
            account_repo=StubAccountRepo(),
            contact_repo=StubContactRepo(),
            email_settings=FakeEmailSettings(),
            tos_settings=FakeTosSettings(),
            eab_repo=None,
            eab_required=True,
        )
        eab_payload = _make_eab_jws("some-kid", hmac_key, jwk)
        with pytest.raises(AcmeProblem) as exc_info:
            service.create_or_find(jwk, tos_agreed=True, eab_payload=eab_payload)
        assert "externalAccountRequired" in exc_info.value.error_type


class TestEabInvalidHmac:
    """Invalid HMAC signature -> error."""

    def test_tampered_signature_raises(self):
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()
        wrong_key = _make_hmac_key()  # Different key

        eab_repo = StubEabRepo()
        eab_repo.add(FakeEabCredential(id=uuid4(), kid="my-kid", hmac_key=hmac_key))

        service = AccountService(
            account_repo=StubAccountRepo(),
            contact_repo=StubContactRepo(),
            email_settings=FakeEmailSettings(),
            tos_settings=FakeTosSettings(),
            eab_repo=eab_repo,
            eab_required=True,
        )

        # Build EAB signed with the wrong key
        eab_payload = _make_eab_jws("my-kid", wrong_key, jwk)
        with pytest.raises(AcmeProblem) as exc_info:
            service.create_or_find(jwk, tos_agreed=True, eab_payload=eab_payload)
        assert "HMAC" in exc_info.value.detail or "unauthorized" in exc_info.value.error_type


class TestEabRevokedCredential:
    """Revoked credential -> error."""

    def test_revoked_eab_raises(self):
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()

        eab_repo = StubEabRepo()
        eab_repo.add(
            FakeEabCredential(
                id=uuid4(),
                kid="revoked-kid",
                hmac_key=hmac_key,
                revoked=True,
            )
        )

        service = AccountService(
            account_repo=StubAccountRepo(),
            contact_repo=StubContactRepo(),
            email_settings=FakeEmailSettings(),
            tos_settings=FakeTosSettings(),
            eab_repo=eab_repo,
            eab_required=True,
        )

        eab_payload = _make_eab_jws("revoked-kid", hmac_key, jwk)
        with pytest.raises(AcmeProblem) as exc_info:
            service.create_or_find(jwk, tos_agreed=True, eab_payload=eab_payload)
        assert "revoked" in exc_info.value.detail.lower()


class TestEabAlreadyUsed:
    """Already-used credential -> error."""

    def test_used_eab_raises(self):
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()

        eab_repo = StubEabRepo()
        eab_repo.add(
            FakeEabCredential(
                id=uuid4(),
                kid="used-kid",
                hmac_key=hmac_key,
                used=True,
            )
        )

        service = AccountService(
            account_repo=StubAccountRepo(),
            contact_repo=StubContactRepo(),
            email_settings=FakeEmailSettings(),
            tos_settings=FakeTosSettings(),
            eab_repo=eab_repo,
            eab_required=True,
        )

        eab_payload = _make_eab_jws("used-kid", hmac_key, jwk)
        with pytest.raises(AcmeProblem) as exc_info:
            service.create_or_find(jwk, tos_agreed=True, eab_payload=eab_payload)
        assert "already been used" in exc_info.value.detail.lower()


class TestEabOptional:
    """EAB optional when eab_required=False (no EAB provided -> still works)."""

    def test_no_eab_when_not_required_succeeds(self):
        _, jwk = _make_ec_jwk()
        service = AccountService(
            account_repo=StubAccountRepo(),
            contact_repo=StubContactRepo(),
            email_settings=FakeEmailSettings(),
            tos_settings=FakeTosSettings(),
            eab_required=False,
        )
        account, contacts, created = service.create_or_find(
            jwk,
            tos_agreed=True,
            eab_payload=None,
        )
        assert created is True

    def test_eab_still_validated_when_provided_and_not_required(self):
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()

        eab_repo = StubEabRepo()
        eab_repo.add(FakeEabCredential(id=uuid4(), kid="opt-kid", hmac_key=hmac_key))

        service = AccountService(
            account_repo=StubAccountRepo(),
            contact_repo=StubContactRepo(),
            email_settings=FakeEmailSettings(),
            tos_settings=FakeTosSettings(),
            eab_repo=eab_repo,
            eab_required=False,
        )

        eab_payload = _make_eab_jws("opt-kid", hmac_key, jwk)
        account, contacts, created = service.create_or_find(
            jwk,
            tos_agreed=True,
            eab_payload=eab_payload,
        )
        assert created is True


# ---------------------------------------------------------------------------
# Tests for reusable EAB credentials
# ---------------------------------------------------------------------------


class TestEabReusable:
    """Tests for the eab_reusable configuration option."""

    def test_used_eab_accepted_when_reusable(self):
        """A used credential should be accepted when eab_reusable=True."""
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()

        eab_repo = StubEabRepo()
        eab_repo.add(
            FakeEabCredential(
                id=uuid4(),
                kid="reuse-kid",
                hmac_key=hmac_key,
                used=True,
            )
        )

        service = AccountService(
            account_repo=StubAccountRepo(),
            contact_repo=StubContactRepo(),
            email_settings=FakeEmailSettings(),
            tos_settings=FakeTosSettings(),
            eab_repo=eab_repo,
            eab_required=True,
            eab_reusable=True,
        )

        eab_payload = _make_eab_jws("reuse-kid", hmac_key, jwk)
        account, contacts, created = service.create_or_find(
            jwk,
            tos_agreed=True,
            eab_payload=eab_payload,
        )
        assert created is True

    def test_mark_used_not_called_when_reusable(self):
        """Credential should not be marked used when eab_reusable=True."""
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()

        eab_repo = StubEabRepo()
        eab_repo.add(
            FakeEabCredential(
                id=uuid4(),
                kid="stay-fresh",
                hmac_key=hmac_key,
            )
        )

        service = AccountService(
            account_repo=StubAccountRepo(),
            contact_repo=StubContactRepo(),
            email_settings=FakeEmailSettings(),
            tos_settings=FakeTosSettings(),
            eab_repo=eab_repo,
            eab_required=True,
            eab_reusable=True,
        )

        eab_payload = _make_eab_jws("stay-fresh", hmac_key, jwk)
        service.create_or_find(jwk, tos_agreed=True, eab_payload=eab_payload)

        cred = eab_repo.find_by_kid("stay-fresh")
        assert cred.used is False

    def test_used_eab_still_rejected_when_not_reusable(self):
        """Default behaviour: used credential is rejected when eab_reusable=False."""
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()

        eab_repo = StubEabRepo()
        eab_repo.add(
            FakeEabCredential(
                id=uuid4(),
                kid="single-use",
                hmac_key=hmac_key,
                used=True,
            )
        )

        service = AccountService(
            account_repo=StubAccountRepo(),
            contact_repo=StubContactRepo(),
            email_settings=FakeEmailSettings(),
            tos_settings=FakeTosSettings(),
            eab_repo=eab_repo,
            eab_required=True,
            eab_reusable=False,
        )

        eab_payload = _make_eab_jws("single-use", hmac_key, jwk)
        with pytest.raises(AcmeProblem) as exc_info:
            service.create_or_find(jwk, tos_agreed=True, eab_payload=eab_payload)
        assert "already been used" in exc_info.value.detail.lower()

    def test_revoked_still_rejected_when_reusable(self):
        """Revoked credentials must always be rejected, even when reusable."""
        _, jwk = _make_ec_jwk()
        hmac_key = _make_hmac_key()

        eab_repo = StubEabRepo()
        eab_repo.add(
            FakeEabCredential(
                id=uuid4(),
                kid="revoked-reuse",
                hmac_key=hmac_key,
                revoked=True,
            )
        )

        service = AccountService(
            account_repo=StubAccountRepo(),
            contact_repo=StubContactRepo(),
            email_settings=FakeEmailSettings(),
            tos_settings=FakeTosSettings(),
            eab_repo=eab_repo,
            eab_required=True,
            eab_reusable=True,
        )

        eab_payload = _make_eab_jws("revoked-reuse", hmac_key, jwk)
        with pytest.raises(AcmeProblem) as exc_info:
            service.create_or_find(jwk, tos_agreed=True, eab_payload=eab_payload)
        assert "revoked" in exc_info.value.detail.lower()
