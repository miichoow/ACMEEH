"""Additional coverage tests for ChallengeService and CertificateService.

Targets paths with low coverage:
- ChallengeService: expire_challenges edge cases, _handle_challenge_error
  retry/terminal branches, _cascade_authz_valid/_cascade_authz_invalid
  with transition_status returning None, _check_orders_for_authz
  multiple orders, _invalidate_orders_for_authz with authz=None,
  process_pending no-validator with complete_validation returning None,
  initiate_validation claim-fail with find_by_id returning None
- CertificateService: finalize_order error paths, CSR validation failures,
  revocation dual-auth paths, CAA validation, CT submission, serial
  generation
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from unittest.mock import ANY, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from acmeeh.app.errors import (
    ALREADY_REVOKED,
    BAD_CSR,
    BAD_REVOCATION_REASON,
    MALFORMED,
    ORDER_NOT_READY,
    SERVER_INTERNAL,
    UNAUTHORIZED,
    AcmeProblem,
)
from acmeeh.ca.base import CAError, IssuedCertificate
from acmeeh.challenge.base import ChallengeError
from acmeeh.core.types import (
    AuthorizationStatus,
    ChallengeStatus,
    ChallengeType,
    IdentifierType,
    NotificationType,
    OrderStatus,
    RevocationReason,
)
from acmeeh.models.authorization import Authorization
from acmeeh.models.certificate import Certificate
from acmeeh.models.challenge import Challenge
from acmeeh.models.order import Identifier, Order
from acmeeh.services.certificate import CertificateService
from acmeeh.services.challenge import ChallengeService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_challenge(
    *,
    challenge_id: UUID | None = None,
    authz_id: UUID | None = None,
    status: ChallengeStatus = ChallengeStatus.PENDING,
    ctype: ChallengeType = ChallengeType.HTTP_01,
    token: str = "test-token",
    retry_count: int = 0,
    error: dict | None = None,
    locked_by: str | None = None,
) -> Challenge:
    return Challenge(
        id=challenge_id or uuid4(),
        authorization_id=authz_id or uuid4(),
        type=ctype,
        token=token,
        status=status,
        retry_count=retry_count,
        error=error,
        locked_by=locked_by,
    )


def _make_authz(
    *,
    authz_id: UUID | None = None,
    account_id: UUID | None = None,
    status: AuthorizationStatus = AuthorizationStatus.PENDING,
    identifier_type: IdentifierType = IdentifierType.DNS,
    identifier_value: str = "example.com",
) -> Authorization:
    return Authorization(
        id=authz_id or uuid4(),
        account_id=account_id or uuid4(),
        identifier_type=identifier_type,
        identifier_value=identifier_value,
        status=status,
    )


def _make_order(
    *,
    order_id: UUID | None = None,
    account_id: UUID | None = None,
    status: OrderStatus = OrderStatus.PENDING,
    identifiers: tuple[Identifier, ...] | None = None,
) -> Order:
    return Order(
        id=order_id or uuid4(),
        account_id=account_id or uuid4(),
        status=status,
        identifiers=identifiers or (Identifier(type=IdentifierType.DNS, value="example.com"),),
        identifiers_hash="abc123",
    )


def _make_certificate(
    *,
    cert_id: UUID | None = None,
    account_id: UUID | None = None,
    order_id: UUID | None = None,
    serial_number: str = "AABB00",
    fingerprint: str = "deadbeef",
    pem_chain: str = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    revoked_at: datetime | None = None,
    revocation_reason: RevocationReason | None = None,
    public_key_fingerprint: str | None = None,
) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        id=cert_id or uuid4(),
        account_id=account_id or uuid4(),
        order_id=order_id or uuid4(),
        serial_number=serial_number,
        fingerprint=fingerprint,
        pem_chain=pem_chain,
        not_before_cert=not_before or now,
        not_after_cert=not_after or (now + timedelta(days=90)),
        revoked_at=revoked_at,
        revocation_reason=revocation_reason,
        public_key_fingerprint=public_key_fingerprint,
    )


def _b64url(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ec_key_to_jwk(private_key) -> dict:
    """Convert an EC private key to a JWK dict (public component only)."""
    pub = private_key.public_key()
    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(x),
        "y": _b64url(y),
    }


def _gen_ec_key():
    """Generate an EC P-256 private key."""
    return ec.generate_private_key(ec.SECP256R1())


def _gen_rsa_key(key_size=2048):
    """Generate an RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _build_csr(private_key, domains: list[str]) -> x509.CertificateSigningRequest:
    """Build and sign a CSR for the given domains."""
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]),
    )
    san = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])
    builder = builder.add_extension(san, critical=False)
    return builder.sign(private_key, hashes.SHA256())


def _csr_der(csr: x509.CertificateSigningRequest) -> bytes:
    return csr.public_bytes(serialization.Encoding.DER)


def _build_self_signed_cert(private_key, domains: list[str]):
    """Build a self-signed certificate and return DER bytes."""
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]),
    )
    builder = builder.issuer_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]),
    )
    builder = builder.not_valid_before(datetime.now(UTC))
    builder = builder.not_valid_after(
        datetime.now(UTC) + timedelta(days=90),
    )
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(private_key.public_key())
    san = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])
    builder = builder.add_extension(san, critical=False)
    cert = builder.sign(private_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


# ===========================================================================
#
#  PART 1 -- ChallengeService coverage gaps
#
# ===========================================================================


# ---------------------------------------------------------------------------
# Fixtures for ChallengeService
# ---------------------------------------------------------------------------


@pytest.fixture()
def ch_repo():
    repo = MagicMock()
    repo.find_by_id.return_value = None
    repo.claim_for_processing.return_value = None
    repo.complete_validation.return_value = None
    repo.retry_challenge.return_value = None
    repo.find_by_authorization.return_value = []
    return repo


@pytest.fixture()
def az_repo():
    repo = MagicMock()
    repo.find_by_id.return_value = None
    repo.transition_status.return_value = None
    repo.find_expired_pending.return_value = []
    repo.find_by_order.return_value = []
    return repo


@pytest.fixture()
def ord_repo():
    repo = MagicMock()
    repo.find_orders_by_authorization.return_value = []
    repo.transition_status.return_value = None
    return repo


@pytest.fixture()
def ch_registry():
    return MagicMock()


@pytest.fixture()
def ch_hooks():
    return MagicMock()


@pytest.fixture()
def ch_metrics():
    return MagicMock()


@pytest.fixture()
def ch_settings():
    settings = MagicMock()
    settings.backoff_base_seconds = 5
    settings.backoff_max_seconds = 300
    return settings


@pytest.fixture()
def ch_svc(ch_repo, az_repo, ord_repo, ch_registry, ch_hooks, ch_metrics, ch_settings):
    return ChallengeService(
        challenge_repo=ch_repo,
        authz_repo=az_repo,
        order_repo=ord_repo,
        registry=ch_registry,
        hook_registry=ch_hooks,
        metrics=ch_metrics,
        challenge_settings=ch_settings,
    )


@pytest.fixture()
def jwk():
    return {"kty": "EC", "crv": "P-256", "x": "aaa", "y": "bbb"}


# ---------------------------------------------------------------------------
# expire_challenges — additional edge cases
# ---------------------------------------------------------------------------


class TestExpireChallengesEdgeCases:
    """Cover expire_challenges branches not in the existing tests."""

    def test_expire_multiple_authzs(
        self,
        ch_svc,
        ch_repo,
        az_repo,
        ord_repo,
        ch_metrics,
    ):
        """Expire challenges across multiple expired authorizations."""
        authz1_id = uuid4()
        authz2_id = uuid4()
        authz1 = _make_authz(authz_id=authz1_id)
        authz2 = _make_authz(authz_id=authz2_id)
        az_repo.find_expired_pending.return_value = [authz1, authz2]

        ch1 = _make_challenge(authz_id=authz1_id, status=ChallengeStatus.PENDING)
        ch2 = _make_challenge(authz_id=authz2_id, status=ChallengeStatus.PROCESSING)
        ch_repo.find_by_authorization.side_effect = [[ch1], [ch2]]
        ch_repo.claim_for_processing.return_value = _make_challenge(
            status=ChallengeStatus.PROCESSING,
        )
        ord_repo.find_orders_by_authorization.return_value = []

        count = ch_svc.expire_challenges()
        assert count == 2

        # Both authzs should have been transitioned to EXPIRED
        assert az_repo.transition_status.call_count == 2
        az_repo.transition_status.assert_any_call(
            authz1_id,
            AuthorizationStatus.PENDING,
            AuthorizationStatus.EXPIRED,
        )
        az_repo.transition_status.assert_any_call(
            authz2_id,
            AuthorizationStatus.PENDING,
            AuthorizationStatus.EXPIRED,
        )

    def test_expire_skips_already_valid_and_invalid(
        self,
        ch_svc,
        ch_repo,
        az_repo,
        ord_repo,
    ):
        """Challenges that are already VALID or INVALID are skipped (count=0)."""
        authz_id = uuid4()
        authz = _make_authz(authz_id=authz_id)
        az_repo.find_expired_pending.return_value = [authz]

        ch_valid = _make_challenge(authz_id=authz_id, status=ChallengeStatus.VALID)
        ch_invalid = _make_challenge(authz_id=authz_id, status=ChallengeStatus.INVALID)
        ch_repo.find_by_authorization.return_value = [ch_valid, ch_invalid]
        ord_repo.find_orders_by_authorization.return_value = []

        count = ch_svc.expire_challenges()
        assert count == 0
        ch_repo.claim_for_processing.assert_not_called()

    def test_expire_invalidates_multiple_pending_orders(
        self,
        ch_svc,
        ch_repo,
        az_repo,
        ord_repo,
    ):
        """Multiple pending orders linked to an expired authz are all invalidated."""
        authz_id = uuid4()
        authz = _make_authz(authz_id=authz_id)
        az_repo.find_expired_pending.return_value = [authz]
        ch_repo.find_by_authorization.return_value = []

        o1 = _make_order(status=OrderStatus.PENDING)
        o2 = _make_order(status=OrderStatus.PENDING)
        o3 = _make_order(status=OrderStatus.VALID)  # should be skipped
        ord_repo.find_orders_by_authorization.return_value = [o1, o2, o3]
        ord_repo.transition_status.return_value = None

        ch_svc.expire_challenges()

        # o1 and o2 should get transition calls, o3 should not
        assert ord_repo.transition_status.call_count == 2

    def test_expire_without_metrics_does_not_fail(
        self,
        ch_repo,
        az_repo,
        ord_repo,
        ch_registry,
    ):
        """Verify expiry works when metrics is None."""
        svc = ChallengeService(
            challenge_repo=ch_repo,
            authz_repo=az_repo,
            order_repo=ord_repo,
            registry=ch_registry,
            metrics=None,
        )

        authz_id = uuid4()
        authz = _make_authz(authz_id=authz_id)
        az_repo.find_expired_pending.return_value = [authz]

        ch = _make_challenge(authz_id=authz_id, status=ChallengeStatus.PENDING)
        ch_repo.find_by_authorization.return_value = [ch]
        ch_repo.claim_for_processing.return_value = _make_challenge(
            status=ChallengeStatus.PROCESSING,
        )
        ord_repo.find_orders_by_authorization.return_value = []

        count = svc.expire_challenges()
        assert count == 1


# ---------------------------------------------------------------------------
# _handle_challenge_error — retry logic edge cases
# ---------------------------------------------------------------------------


class TestHandleChallengeErrorEdgeCases:
    """Cover _handle_challenge_error branches."""

    def test_retry_backoff_exponential_growth(
        self,
        ch_svc,
        ch_repo,
        az_repo,
        ch_registry,
        ch_hooks,
        ch_metrics,
        jwk,
    ):
        """Verify exponential backoff: 5 * 2^retry_count, capped at max."""
        account_id = uuid4()
        authz_id = uuid4()
        # retry_count=4 -> backoff = 5 * 2^4 = 80
        challenge = _make_challenge(authz_id=authz_id, retry_count=4)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
            retry_count=4,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        ch_repo.find_by_id.return_value = challenge
        az_repo.find_by_id.return_value = authz
        ch_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 10
        validator.validate.side_effect = ChallengeError("timeout", retryable=True)
        validator.cleanup.return_value = None
        ch_registry.get_validator_or_none.return_value = validator

        retried = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PENDING,
            retry_count=5,
        )
        ch_repo.retry_challenge.return_value = retried

        result = ch_svc.initiate_validation(challenge.id, account_id, jwk)
        assert result is retried
        ch_repo.retry_challenge.assert_called_once_with(
            challenge.id,
            ANY,
            backoff_seconds=80,
        )

    def test_retry_backoff_capped_at_max(
        self,
        ch_svc,
        ch_repo,
        az_repo,
        ch_registry,
        ch_hooks,
        ch_metrics,
        jwk,
    ):
        """Verify backoff is capped at backoff_max_seconds (300)."""
        account_id = uuid4()
        authz_id = uuid4()
        # retry_count=10 -> 5 * 2^10 = 5120 -> capped to 300
        challenge = _make_challenge(authz_id=authz_id, retry_count=10)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
            retry_count=10,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        ch_repo.find_by_id.return_value = challenge
        az_repo.find_by_id.return_value = authz
        ch_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 20
        validator.validate.side_effect = ChallengeError("network", retryable=True)
        validator.cleanup.return_value = None
        ch_registry.get_validator_or_none.return_value = validator

        ch_repo.retry_challenge.return_value = None  # returns None -> fallback to challenge

        result = ch_svc.initiate_validation(challenge.id, account_id, jwk)
        # When retry_challenge returns None, fallback is the original challenge
        assert result is challenge
        ch_repo.retry_challenge.assert_called_once_with(
            challenge.id,
            ANY,
            backoff_seconds=300,
        )

    def test_retry_returns_none_falls_back_to_original(
        self,
        ch_svc,
        ch_repo,
        az_repo,
        ch_registry,
        ch_hooks,
        ch_metrics,
        jwk,
    ):
        """When retry_challenge returns None, the original challenge is returned."""
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id, retry_count=0)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        ch_repo.find_by_id.return_value = challenge
        az_repo.find_by_id.return_value = authz
        ch_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 5
        validator.validate.side_effect = ChallengeError("retry me", retryable=True)
        validator.cleanup.return_value = None
        ch_registry.get_validator_or_none.return_value = validator

        ch_repo.retry_challenge.return_value = None

        result = ch_svc.initiate_validation(challenge.id, account_id, jwk)
        assert result is challenge

    def test_terminal_failure_complete_returns_none(
        self,
        ch_svc,
        ch_repo,
        az_repo,
        ch_registry,
        ch_hooks,
        ch_metrics,
        jwk,
    ):
        """When complete_validation returns None on terminal failure, fallback to original."""
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id, retry_count=0)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        ch_repo.find_by_id.return_value = challenge
        az_repo.find_by_id.return_value = authz
        ch_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 0
        validator.validate.side_effect = ChallengeError("bad token", retryable=False)
        validator.cleanup.return_value = None
        ch_registry.get_validator_or_none.return_value = validator

        ch_repo.complete_validation.return_value = None

        result = ch_svc.initiate_validation(challenge.id, account_id, jwk)
        assert result is challenge
        # authz should still be cascaded to invalid
        az_repo.transition_status.assert_called()

    def test_handle_challenge_error_no_settings_attributes(
        self,
        ch_repo,
        az_repo,
        ord_repo,
        ch_registry,
        ch_hooks,
        ch_metrics,
        jwk,
    ):
        """When challenge_settings lacks backoff attrs, fallback defaults are used."""
        svc = ChallengeService(
            challenge_repo=ch_repo,
            authz_repo=az_repo,
            order_repo=ord_repo,
            registry=ch_registry,
            hook_registry=ch_hooks,
            metrics=ch_metrics,
            challenge_settings=None,  # No settings object
        )

        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id, retry_count=0)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        ch_repo.find_by_id.return_value = challenge
        az_repo.find_by_id.return_value = authz
        ch_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 5
        validator.validate.side_effect = ChallengeError("transient", retryable=True)
        validator.cleanup.return_value = None
        ch_registry.get_validator_or_none.return_value = validator

        retried = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PENDING,
            retry_count=1,
        )
        ch_repo.retry_challenge.return_value = retried

        result = svc.initiate_validation(challenge.id, account_id, jwk)
        assert result is retried
        # Default backoff_base=5, so 5 * 2^0 = 5
        ch_repo.retry_challenge.assert_called_once_with(
            challenge.id,
            ANY,
            backoff_seconds=5,
        )


# ---------------------------------------------------------------------------
# _cascade_authz_valid — edge cases
# ---------------------------------------------------------------------------


class TestCascadeAuthzValidEdgeCases:
    """Cover _cascade_authz_valid branches: transition returns None,
    multiple orders, etc."""

    def test_transition_returns_none_still_checks_orders(
        self,
        ch_svc,
        az_repo,
        ord_repo,
    ):
        """When authz transition returns None (no-op), orders are still checked."""
        authz_id = uuid4()
        az_repo.transition_status.return_value = None  # no-op
        ord_repo.find_orders_by_authorization.return_value = []

        ch_svc._cascade_authz_valid(authz_id)

        az_repo.transition_status.assert_called_once()
        ord_repo.find_orders_by_authorization.assert_called_once_with(authz_id)

    def test_multiple_pending_orders_all_become_ready(
        self,
        ch_svc,
        az_repo,
        ord_repo,
    ):
        """When multiple pending orders have all authzs valid, all transition to ready."""
        authz_id = uuid4()
        o1_id = uuid4()
        o2_id = uuid4()
        o1 = _make_order(order_id=o1_id, status=OrderStatus.PENDING)
        o2 = _make_order(order_id=o2_id, status=OrderStatus.PENDING)

        az_repo.transition_status.return_value = _make_authz(
            authz_id=authz_id,
            status=AuthorizationStatus.VALID,
        )
        ord_repo.find_orders_by_authorization.return_value = [o1, o2]
        az_repo.find_by_order.return_value = [
            _make_authz(status=AuthorizationStatus.VALID),
        ]
        ord_repo.transition_status.return_value = None

        ch_svc._cascade_authz_valid(authz_id)

        # Both orders should get transitions
        assert ord_repo.transition_status.call_count == 2
        ord_repo.transition_status.assert_any_call(
            o1_id,
            OrderStatus.PENDING,
            OrderStatus.READY,
        )
        ord_repo.transition_status.assert_any_call(
            o2_id,
            OrderStatus.PENDING,
            OrderStatus.READY,
        )

    def test_order_transition_returns_none_no_error(
        self,
        ch_svc,
        az_repo,
        ord_repo,
    ):
        """When order transition returns None (already transitioned), no error."""
        authz_id = uuid4()
        order = _make_order(status=OrderStatus.PENDING)

        az_repo.transition_status.return_value = _make_authz(
            authz_id=authz_id,
            status=AuthorizationStatus.VALID,
        )
        ord_repo.find_orders_by_authorization.return_value = [order]
        az_repo.find_by_order.return_value = [
            _make_authz(status=AuthorizationStatus.VALID),
        ]
        ord_repo.transition_status.return_value = None  # no-op

        # Should not raise
        ch_svc._cascade_authz_valid(authz_id)


# ---------------------------------------------------------------------------
# _cascade_authz_invalid — edge cases
# ---------------------------------------------------------------------------


class TestCascadeAuthzInvalidEdgeCases:
    """Cover _cascade_authz_invalid: authz not found, transition returns None."""

    def test_authz_not_found_still_transitions_and_invalidates(
        self,
        ch_svc,
        az_repo,
        ord_repo,
    ):
        """When authz_repo.find_by_id returns None, we still call transition
        and _invalidate_orders_for_authz with authz=None."""
        authz_id = uuid4()
        az_repo.find_by_id.return_value = None
        az_repo.transition_status.return_value = None
        ord_repo.find_orders_by_authorization.return_value = []

        ch_svc._cascade_authz_invalid(authz_id)

        az_repo.transition_status.assert_called_once_with(
            authz_id,
            AuthorizationStatus.PENDING,
            AuthorizationStatus.INVALID,
        )
        ord_repo.find_orders_by_authorization.assert_called_once_with(authz_id)


# ---------------------------------------------------------------------------
# _invalidate_orders_for_authz — authz=None path
# ---------------------------------------------------------------------------


class TestInvalidateOrdersForAuthzNullAuthz:
    """When authz=None, error dict should not have subproblems."""

    def test_no_subproblems_when_authz_is_none(
        self,
        ch_svc,
        ord_repo,
    ):
        authz_id = uuid4()
        order_id = uuid4()
        order = _make_order(order_id=order_id, status=OrderStatus.PENDING)
        ord_repo.find_orders_by_authorization.return_value = [order]
        ord_repo.transition_status.return_value = _make_order(
            order_id=order_id,
            status=OrderStatus.INVALID,
        )

        ch_svc._invalidate_orders_for_authz(authz_id, authz=None)

        call_kwargs = ord_repo.transition_status.call_args[1]
        error = call_kwargs["error"]
        assert "subproblems" not in error
        assert "unauthorized" in error["type"]


# ---------------------------------------------------------------------------
# _check_orders_for_authz — mixed order statuses
# ---------------------------------------------------------------------------


class TestCheckOrdersForAuthzMixed:
    """Only PENDING orders are checked; others are skipped."""

    def test_mixed_order_statuses(self, ch_svc, az_repo, ord_repo):
        authz_id = uuid4()
        pending_id = uuid4()
        ready_id = uuid4()

        pending_order = _make_order(order_id=pending_id, status=OrderStatus.PENDING)
        ready_order = _make_order(order_id=ready_id, status=OrderStatus.READY)
        invalid_order = _make_order(status=OrderStatus.INVALID)

        ord_repo.find_orders_by_authorization.return_value = [
            pending_order,
            ready_order,
            invalid_order,
        ]
        az_repo.find_by_order.return_value = [
            _make_authz(status=AuthorizationStatus.VALID),
        ]
        ord_repo.transition_status.return_value = None

        ch_svc._check_orders_for_authz(authz_id)

        # Only the pending order should get a transition call
        ord_repo.transition_status.assert_called_once_with(
            pending_id,
            OrderStatus.PENDING,
            OrderStatus.READY,
        )
        # find_by_order should only be called for the pending order
        az_repo.find_by_order.assert_called_once_with(pending_id)


# ---------------------------------------------------------------------------
# initiate_validation — claim fails, find_by_id returns None
# ---------------------------------------------------------------------------


class TestInitiateClaimFailFindReturnsNone:
    """When claim fails and re-fetch also returns None, return original."""

    def test_claim_fail_refetch_none_returns_original(
        self,
        ch_svc,
        ch_repo,
        az_repo,
        jwk,
    ):
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        # First call -> challenge, second call (re-fetch) -> None
        ch_repo.find_by_id.side_effect = [challenge, None]
        az_repo.find_by_id.return_value = authz
        ch_repo.claim_for_processing.return_value = None

        result = ch_svc.initiate_validation(challenge.id, account_id, jwk)
        assert result is challenge


# ---------------------------------------------------------------------------
# process_pending — no validator, complete returns None
# ---------------------------------------------------------------------------


class TestProcessPendingNoValidatorReturnsNone:
    """When no validator and complete_validation returns None, return original."""

    def test_no_validator_complete_returns_none(
        self,
        ch_svc,
        ch_repo,
        az_repo,
        ch_registry,
        jwk,
    ):
        authz_id = uuid4()
        challenge = _make_challenge(
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id)

        ch_repo.find_by_id.return_value = challenge
        az_repo.find_by_id.return_value = authz
        ch_registry.get_validator_or_none.return_value = None
        ch_repo.complete_validation.return_value = None

        result = ch_svc.process_pending(challenge.id, "w-1", jwk)
        assert result is challenge


# ---------------------------------------------------------------------------
# _run_validation — unexpected error, complete returns None
# ---------------------------------------------------------------------------


class TestRunValidationUnexpectedErrorReturnsNone:
    """Unexpected exception with complete_validation returning None."""

    def test_unexpected_error_complete_returns_none(
        self,
        ch_svc,
        ch_repo,
        az_repo,
        ch_registry,
        ch_hooks,
        jwk,
    ):
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        ch_repo.find_by_id.return_value = challenge
        az_repo.find_by_id.return_value = authz
        ch_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.validate.side_effect = RuntimeError("kaboom")
        validator.cleanup.return_value = None
        ch_registry.get_validator_or_none.return_value = validator

        ch_repo.complete_validation.return_value = None

        result = ch_svc.initiate_validation(challenge.id, account_id, jwk)
        assert result is challenge
        ch_hooks.dispatch.assert_any_call("challenge.on_failure", ANY)


# ---------------------------------------------------------------------------
# _run_validation — success, complete returns None
# ---------------------------------------------------------------------------


class TestRunValidationSuccessReturnsNone:
    """Successful validation with complete_validation returning None."""

    def test_success_complete_returns_none(
        self,
        ch_svc,
        ch_repo,
        az_repo,
        ch_registry,
        ch_hooks,
        ch_metrics,
        jwk,
    ):
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        ch_repo.find_by_id.return_value = challenge
        az_repo.find_by_id.return_value = authz
        ch_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.validate.return_value = None
        validator.cleanup.return_value = None
        ch_registry.get_validator_or_none.return_value = validator

        ch_repo.complete_validation.return_value = None  # Returns None
        az_repo.transition_status.return_value = None
        ord_repo_mock = MagicMock()
        ord_repo_mock.find_orders_by_authorization.return_value = []

        result = ch_svc.initiate_validation(challenge.id, account_id, jwk)
        assert result is challenge  # fallback to original


# ---------------------------------------------------------------------------
# _run_validation — hooks not dispatched when hook_registry is None
# ---------------------------------------------------------------------------


class TestRunValidationNoHooksNoMetrics:
    """No hooks or metrics present -- verify no AttributeError."""

    def test_failure_without_hooks_or_metrics(
        self,
        ch_repo,
        az_repo,
        ord_repo,
        ch_registry,
        jwk,
    ):
        svc = ChallengeService(
            challenge_repo=ch_repo,
            authz_repo=az_repo,
            order_repo=ord_repo,
            registry=ch_registry,
            hook_registry=None,
            metrics=None,
            challenge_settings=None,
        )

        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id, retry_count=0)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        ch_repo.find_by_id.return_value = challenge
        az_repo.find_by_id.return_value = authz
        ch_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 0
        validator.validate.side_effect = ChallengeError("fail", retryable=False)
        validator.cleanup.return_value = None
        ch_registry.get_validator_or_none.return_value = validator

        ch_repo.complete_validation.return_value = None
        az_repo.transition_status.return_value = None
        ord_repo.find_orders_by_authorization.return_value = []

        result = svc.initiate_validation(challenge.id, account_id, jwk)
        assert result is challenge

    def test_unexpected_error_without_hooks(
        self,
        ch_repo,
        az_repo,
        ord_repo,
        ch_registry,
        jwk,
    ):
        svc = ChallengeService(
            challenge_repo=ch_repo,
            authz_repo=az_repo,
            order_repo=ord_repo,
            registry=ch_registry,
            hook_registry=None,
            metrics=None,
        )

        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        ch_repo.find_by_id.return_value = challenge
        az_repo.find_by_id.return_value = authz
        ch_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.validate.side_effect = ValueError("unexpected")
        validator.cleanup.return_value = None
        ch_registry.get_validator_or_none.return_value = validator

        ch_repo.complete_validation.return_value = None
        az_repo.transition_status.return_value = None
        ord_repo.find_orders_by_authorization.return_value = []

        result = svc.initiate_validation(challenge.id, account_id, jwk)
        assert result is challenge


# ===========================================================================
#
#  PART 2 -- CertificateService coverage gaps
#
# ===========================================================================


# ---------------------------------------------------------------------------
# Fixtures for CertificateService
# ---------------------------------------------------------------------------


@pytest.fixture()
def cert_repo():
    repo = MagicMock()
    repo.find_by_id.return_value = None
    repo.find_by_fingerprint.return_value = None
    repo.revoke.return_value = None
    repo.next_serial.return_value = 12345
    repo._entity_to_row.return_value = {"id": str(uuid4())}
    return repo


@pytest.fixture()
def cert_order_repo():
    repo = MagicMock()
    repo.find_by_id.return_value = None
    repo.transition_status.return_value = None
    return repo


@pytest.fixture()
def ca_settings():
    settings = MagicMock()
    settings.default_validity_days = 90
    settings.max_validity_days = 365
    profile = MagicMock()
    profile.validity_days = None
    profile.max_validity_days = None
    settings.profiles = {"default": profile}
    settings.internal.serial_source = "random"
    return settings


@pytest.fixture()
def ca_backend():
    backend = MagicMock()
    backend.deferred = False
    now = datetime.now(UTC)
    backend.sign.return_value = IssuedCertificate(
        pem_chain="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        not_before=now,
        not_after=now + timedelta(days=90),
        serial_number="AABB0011",
        fingerprint="deadbeefcafe",
    )
    backend.revoke.return_value = None
    return backend


@pytest.fixture()
def cert_notifier():
    return MagicMock()


@pytest.fixture()
def cert_hooks():
    return MagicMock()


@pytest.fixture()
def cert_metrics():
    return MagicMock()


@pytest.fixture()
def mock_db():
    db = MagicMock()
    # UnitOfWork mocking: __enter__ returns a MagicMock with insert/update_where
    return db


@pytest.fixture()
def cert_svc(
    cert_repo,
    cert_order_repo,
    ca_settings,
    ca_backend,
    cert_notifier,
    cert_hooks,
    cert_metrics,
    mock_db,
):
    return CertificateService(
        certificate_repo=cert_repo,
        order_repo=cert_order_repo,
        ca_settings=ca_settings,
        ca_backend=ca_backend,
        notification_service=cert_notifier,
        hook_registry=cert_hooks,
        metrics=cert_metrics,
        db=mock_db,
    )


# ---------------------------------------------------------------------------
# finalize_order — order not found / wrong account / wrong status
# ---------------------------------------------------------------------------


class TestFinalizeOrderPreChecks:
    """Precondition failures in finalize_order."""

    def test_order_not_found(self, cert_svc, cert_order_repo):
        cert_order_repo.find_by_id.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.finalize_order(uuid4(), b"fake-csr", uuid4())
        assert exc_info.value.status == 404
        assert MALFORMED in exc_info.value.error_type

    def test_wrong_account(self, cert_svc, cert_order_repo):
        account_id = uuid4()
        order = _make_order(account_id=uuid4(), status=OrderStatus.READY)
        cert_order_repo.find_by_id.return_value = order
        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.finalize_order(order.id, b"fake-csr", account_id)
        assert exc_info.value.status == 403
        assert UNAUTHORIZED in exc_info.value.error_type

    def test_order_not_ready(self, cert_svc, cert_order_repo):
        account_id = uuid4()
        order = _make_order(account_id=account_id, status=OrderStatus.PENDING)
        cert_order_repo.find_by_id.return_value = order
        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.finalize_order(order.id, b"fake-csr", account_id)
        assert ORDER_NOT_READY in exc_info.value.error_type

    def test_transition_to_processing_fails(self, cert_svc, cert_order_repo):
        """When transition READY->PROCESSING returns None, raise orderNotReady."""
        account_id = uuid4()
        order = _make_order(account_id=account_id, status=OrderStatus.READY)
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = None

        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.finalize_order(order.id, b"fake-csr", account_id)
        assert ORDER_NOT_READY in exc_info.value.error_type


# ---------------------------------------------------------------------------
# finalize_order — CSR parse failure
# ---------------------------------------------------------------------------


class TestFinalizeOrderCSRParseFailure:
    """CSR parsing fails."""

    def test_unparseable_csr(self, cert_svc, cert_order_repo):
        account_id = uuid4()
        order = _make_order(account_id=account_id, status=OrderStatus.READY)
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.finalize_order(order.id, b"not-valid-der", account_id)
        assert BAD_CSR in exc_info.value.error_type


# ---------------------------------------------------------------------------
# finalize_order — CSR signature invalid
# ---------------------------------------------------------------------------


class TestFinalizeOrderCSRSignatureInvalid:
    """CSR with invalid signature."""

    def test_invalid_csr_signature(self, cert_svc, cert_order_repo):
        account_id = uuid4()
        order = _make_order(account_id=account_id, status=OrderStatus.READY)
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        # Build a valid CSR then tamper with the DER to break the signature
        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])
        csr_der = bytearray(_csr_der(csr))
        # Flip a byte near the end (in the signature)
        if len(csr_der) > 10:
            csr_der[-5] ^= 0xFF

        # Mock csr.is_signature_valid to return False
        with patch(
            "acmeeh.services.certificate.x509.load_der_x509_csr",
        ) as mock_load:
            mock_csr = MagicMock()
            mock_csr.is_signature_valid = False
            mock_load.return_value = mock_csr

            with pytest.raises(AcmeProblem) as exc_info:
                cert_svc.finalize_order(order.id, bytes(csr_der), account_id)
            assert BAD_CSR in exc_info.value.error_type
            assert "signature" in exc_info.value.detail.lower()


# ---------------------------------------------------------------------------
# finalize_order — CSR signature algorithm not allowed
# ---------------------------------------------------------------------------


class TestFinalizeOrderCSRSigAlgNotAllowed:
    """CSR uses a disallowed signature algorithm."""

    def test_disallowed_sig_algorithm(
        self, cert_repo, cert_order_repo, ca_settings, ca_backend, mock_db
    ):
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            allowed_csr_signature_algorithms=("SHA384withECDSA",),
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        # Build a CSR signed with SHA256 (which will be "SHA256withECDSA" -- not allowed)
        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])

        with pytest.raises(AcmeProblem) as exc_info:
            svc.finalize_order(order.id, _csr_der(csr), account_id)
        assert BAD_CSR in exc_info.value.error_type
        assert "not allowed" in exc_info.value.detail


# ---------------------------------------------------------------------------
# finalize_order — RSA key too small
# ---------------------------------------------------------------------------


class TestFinalizeOrderRSAKeyTooSmall:
    """CSR with RSA key smaller than minimum."""

    def test_rsa_key_too_small(self, cert_repo, cert_order_repo, ca_settings, ca_backend, mock_db):
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            min_csr_rsa_key_size=4096,
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        key = _gen_rsa_key(2048)
        csr = _build_csr(key, ["example.com"])

        with pytest.raises(AcmeProblem) as exc_info:
            svc.finalize_order(order.id, _csr_der(csr), account_id)
        assert BAD_CSR in exc_info.value.error_type
        assert "RSA key size" in exc_info.value.detail


# ---------------------------------------------------------------------------
# finalize_order — EC key too small
# ---------------------------------------------------------------------------


class TestFinalizeOrderECKeyTooSmall:
    """CSR with EC key smaller than minimum."""

    def test_ec_key_too_small(self, cert_repo, cert_order_repo, ca_settings, ca_backend, mock_db):
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            min_csr_ec_key_size=384,  # P-256 is 256 bits
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        key = _gen_ec_key()  # P-256 = 256 bits
        csr = _build_csr(key, ["example.com"])

        with pytest.raises(AcmeProblem) as exc_info:
            svc.finalize_order(order.id, _csr_der(csr), account_id)
        assert BAD_CSR in exc_info.value.error_type
        assert "EC key size" in exc_info.value.detail


# ---------------------------------------------------------------------------
# finalize_order — CSR SANs mismatch
# ---------------------------------------------------------------------------


class TestFinalizeOrderSANsMismatch:
    """CSR SANs do not match order identifiers."""

    def test_missing_sans(self, cert_svc, cert_order_repo, cert_repo):
        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(
                Identifier(type=IdentifierType.DNS, value="example.com"),
                Identifier(type=IdentifierType.DNS, value="www.example.com"),
            ),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        # CSR only has example.com, missing www.example.com
        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])

        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.finalize_order(order.id, _csr_der(csr), account_id)
        assert BAD_CSR in exc_info.value.error_type
        assert "missing from CSR" in exc_info.value.detail

    def test_extra_sans(self, cert_svc, cert_order_repo, cert_repo):
        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        # CSR has extra SAN
        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com", "evil.com"])

        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.finalize_order(order.id, _csr_der(csr), account_id)
        assert BAD_CSR in exc_info.value.error_type
        assert "extra in CSR" in exc_info.value.detail

    def test_no_san_extension(self, cert_svc, cert_order_repo, cert_repo):
        """CSR without any SAN extension raises badCSR."""
        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        # Build CSR without SAN
        key = _gen_ec_key()
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]),
        )
        csr = builder.sign(key, hashes.SHA256())

        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.finalize_order(order.id, _csr_der(csr), account_id)
        assert BAD_CSR in exc_info.value.error_type
        assert "SubjectAlternativeName" in exc_info.value.detail

    def test_duplicate_sans(self, cert_svc, cert_order_repo, cert_repo):
        """CSR with duplicate SANs raises badCSR."""
        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        # Build CSR with duplicate SANs
        key = _gen_ec_key()
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]),
        )
        san = x509.SubjectAlternativeName(
            [
                x509.DNSName("example.com"),
                x509.DNSName("example.com"),
            ]
        )
        builder = builder.add_extension(san, critical=False)
        csr = builder.sign(key, hashes.SHA256())

        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.finalize_order(order.id, _csr_der(csr), account_id)
        assert BAD_CSR in exc_info.value.error_type
        assert "duplicate" in exc_info.value.detail.lower()


# ---------------------------------------------------------------------------
# finalize_order — CA backend signing failure
# ---------------------------------------------------------------------------


class TestFinalizeOrderCASigningFailure:
    """CA backend raises CAError during signing."""

    def test_ca_error_invalidates_order_and_notifies(
        self,
        cert_order_repo,
        cert_repo,
        ca_settings,
        ca_backend,
        cert_notifier,
        cert_hooks,
        cert_metrics,
        mock_db,
    ):
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            notification_service=cert_notifier,
            hook_registry=cert_hooks,
            metrics=cert_metrics,
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        ca_backend.sign.side_effect = CAError("HSM timeout", retryable=True)

        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])

        with pytest.raises(AcmeProblem) as exc_info:
            svc.finalize_order(order.id, _csr_der(csr), account_id)
        assert SERVER_INTERNAL in exc_info.value.error_type

        # Verify order transitioned to INVALID
        transition_calls = cert_order_repo.transition_status.call_args_list
        # Last call should be PROCESSING -> INVALID
        last_call = transition_calls[-1]
        assert last_call[0][1] == OrderStatus.PROCESSING
        assert last_call[0][2] == OrderStatus.INVALID

        # Verify metrics incremented
        cert_metrics.increment.assert_called_with("acmeeh_ca_signing_errors_total")

        # Verify notification sent
        cert_notifier.notify.assert_called_once()
        notify_args = cert_notifier.notify.call_args[0]
        assert notify_args[0] == NotificationType.DELIVERY_FAILED


# ---------------------------------------------------------------------------
# finalize_order — successful path with all integrations
# ---------------------------------------------------------------------------


class TestFinalizeOrderSuccessPath:
    """Full successful finalize path covering UoW, notifications, hooks, metrics."""

    def test_successful_finalize(
        self,
        cert_order_repo,
        cert_repo,
        ca_settings,
        ca_backend,
        cert_notifier,
        cert_hooks,
        cert_metrics,
        mock_db,
    ):
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            notification_service=cert_notifier,
            hook_registry=cert_hooks,
            metrics=cert_metrics,
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        valid_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.VALID,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.side_effect = [order, valid_order]
        cert_order_repo.transition_status.return_value = processing_order

        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])

        # Mock UnitOfWork
        uow_mock = MagicMock()
        uow_mock.__enter__ = MagicMock(return_value=uow_mock)
        uow_mock.__exit__ = MagicMock(return_value=False)
        uow_mock.insert.return_value = {"id": str(uuid4())}
        uow_mock.update_where.return_value = {"id": str(order.id)}

        with patch("acmeeh.services.certificate.UnitOfWork", return_value=uow_mock):
            result = svc.finalize_order(order.id, _csr_der(csr), account_id)

        assert result is valid_order

        # Verify CA backend was called
        ca_backend.sign.assert_called_once()

        # Verify UoW operations
        uow_mock.insert.assert_called_once()
        uow_mock.update_where.assert_called_once()

        # Verify metrics
        cert_metrics.increment.assert_called_with("acmeeh_certificates_issued_total")

        # Verify notification
        cert_notifier.notify.assert_called_once()
        notify_args = cert_notifier.notify.call_args[0]
        assert notify_args[0] == NotificationType.DELIVERY_SUCCEEDED

        # Verify hook dispatched
        cert_hooks.dispatch.assert_called_once_with(
            "certificate.issuance",
            ANY,
        )

    def test_finalize_uow_update_returns_none(
        self,
        cert_order_repo,
        cert_repo,
        ca_settings,
        ca_backend,
        mock_db,
    ):
        """When UoW update_where returns None (concurrent finalization),
        the order is still fetched and returned."""
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        valid_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.VALID,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.side_effect = [order, valid_order]
        cert_order_repo.transition_status.return_value = processing_order

        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])

        uow_mock = MagicMock()
        uow_mock.__enter__ = MagicMock(return_value=uow_mock)
        uow_mock.__exit__ = MagicMock(return_value=False)
        uow_mock.insert.return_value = {"id": str(uuid4())}
        uow_mock.update_where.return_value = None  # Concurrent finalization

        with patch("acmeeh.services.certificate.UnitOfWork", return_value=uow_mock):
            result = svc.finalize_order(order.id, _csr_der(csr), account_id)

        assert result is valid_order


# ---------------------------------------------------------------------------
# finalize_order — CAA validation
# ---------------------------------------------------------------------------


class TestFinalizeOrderCAAValidation:
    """CAA validation integration."""

    def test_caa_check_called_for_dns_identifiers(
        self,
        cert_repo,
        cert_order_repo,
        ca_settings,
        ca_backend,
        mock_db,
    ):
        caa_validator = MagicMock()
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            caa_validator=caa_validator,
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(
                Identifier(type=IdentifierType.DNS, value="example.com"),
                Identifier(type=IdentifierType.DNS, value="*.example.com"),
                Identifier(type=IdentifierType.IP, value="192.168.1.1"),
            ),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        valid_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.VALID,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.side_effect = [order, valid_order]
        cert_order_repo.transition_status.return_value = processing_order

        # Build CSR matching all identifiers
        key = _gen_ec_key()
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]),
        )
        from ipaddress import IPv4Address

        san = x509.SubjectAlternativeName(
            [
                x509.DNSName("example.com"),
                x509.DNSName("*.example.com"),
                x509.IPAddress(IPv4Address("192.168.1.1")),
            ]
        )
        builder = builder.add_extension(san, critical=False)
        csr = builder.sign(key, hashes.SHA256())

        uow_mock = MagicMock()
        uow_mock.__enter__ = MagicMock(return_value=uow_mock)
        uow_mock.__exit__ = MagicMock(return_value=False)
        uow_mock.insert.return_value = {"id": str(uuid4())}
        uow_mock.update_where.return_value = {"id": str(uuid4())}

        with patch("acmeeh.services.certificate.UnitOfWork", return_value=uow_mock):
            svc.finalize_order(order.id, _csr_der(csr), account_id)

        # CAA check should be called for DNS identifiers only
        assert caa_validator.check.call_count == 2
        caa_validator.check.assert_any_call("example.com", is_wildcard=False)
        caa_validator.check.assert_any_call("*.example.com", is_wildcard=True)

    def test_caa_check_raises_blocks_finalization(
        self,
        cert_repo,
        cert_order_repo,
        ca_settings,
        ca_backend,
        mock_db,
    ):
        """When CAA check raises AcmeProblem, finalization is blocked."""
        caa_validator = MagicMock()
        caa_validator.check.side_effect = AcmeProblem(
            "urn:ietf:params:acme:error:caa",
            "CAA record forbids issuance",
        )
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            caa_validator=caa_validator,
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])

        with pytest.raises(AcmeProblem) as exc_info:
            svc.finalize_order(order.id, _csr_der(csr), account_id)
        assert "caa" in exc_info.value.error_type


# ---------------------------------------------------------------------------
# finalize_order — CSR profile validation
# ---------------------------------------------------------------------------


class TestFinalizeOrderCSRProfile:
    """CSR profile validation integration."""

    def test_csr_profile_violation_invalidates_order(
        self,
        cert_repo,
        cert_order_repo,
        ca_settings,
        ca_backend,
        mock_db,
    ):
        csr_profile_repo = MagicMock()
        profile_mock = MagicMock()
        profile_mock.profile_data = {"allowed_key_types": ["RSA"]}
        csr_profile_repo.find_profile_for_account.return_value = profile_mock

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            csr_profile_repo=csr_profile_repo,
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])

        # Patch the function at the module where it's imported inside _validate_csr_profile
        with patch(
            "acmeeh.services.csr_validator.validate_csr_against_profile",
            side_effect=AcmeProblem(BAD_CSR, "EC keys not allowed by profile"),
        ):
            with pytest.raises(AcmeProblem) as exc_info:
                svc.finalize_order(order.id, _csr_der(csr), account_id)

        assert BAD_CSR in exc_info.value.error_type

    def test_no_csr_profile_repo_skips_validation(
        self,
        cert_svc,
        cert_order_repo,
        cert_repo,
        ca_backend,
        mock_db,
    ):
        """When csr_profile_repo is None, profile validation is skipped entirely."""
        # cert_svc has csr_profile_repo=None by default
        assert cert_svc._csr_profile_repo is None

    def test_no_profile_for_account_skips_validation(
        self,
        cert_repo,
        cert_order_repo,
        ca_settings,
        ca_backend,
        mock_db,
    ):
        """When no profile is found for account, validation is skipped."""
        csr_profile_repo = MagicMock()
        csr_profile_repo.find_profile_for_account.return_value = None

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            csr_profile_repo=csr_profile_repo,
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        valid_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.VALID,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.side_effect = [order, valid_order]
        cert_order_repo.transition_status.return_value = processing_order

        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])

        uow_mock = MagicMock()
        uow_mock.__enter__ = MagicMock(return_value=uow_mock)
        uow_mock.__exit__ = MagicMock(return_value=False)
        uow_mock.insert.return_value = {"id": str(uuid4())}
        uow_mock.update_where.return_value = {"id": str(uuid4())}

        with patch("acmeeh.services.certificate.UnitOfWork", return_value=uow_mock):
            result = svc.finalize_order(order.id, _csr_der(csr), account_id)

        assert result is valid_order


# ---------------------------------------------------------------------------
# finalize_order — CT submitter
# ---------------------------------------------------------------------------


class TestFinalizeOrderCTSubmitter:
    """CT submitter is passed to the backend.sign call."""

    def test_ct_submitter_passed_to_backend(
        self,
        cert_repo,
        cert_order_repo,
        ca_settings,
        ca_backend,
        mock_db,
    ):
        ct_submitter = MagicMock()
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            ct_submitter=ct_submitter,
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        valid_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.VALID,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.side_effect = [order, valid_order]
        cert_order_repo.transition_status.return_value = processing_order

        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])

        uow_mock = MagicMock()
        uow_mock.__enter__ = MagicMock(return_value=uow_mock)
        uow_mock.__exit__ = MagicMock(return_value=False)
        uow_mock.insert.return_value = {"id": str(uuid4())}
        uow_mock.update_where.return_value = {"id": str(uuid4())}

        with patch("acmeeh.services.certificate.UnitOfWork", return_value=uow_mock):
            svc.finalize_order(order.id, _csr_der(csr), account_id)

        # Verify CT submitter was passed
        sign_kwargs = ca_backend.sign.call_args[1]
        assert sign_kwargs["ct_submitter"] is ct_submitter


# ---------------------------------------------------------------------------
# finalize_order — serial number generation
# ---------------------------------------------------------------------------


class TestSerialNumberGeneration:
    """_generate_serial: database vs random mode."""

    def test_database_serial_source(
        self, cert_repo, cert_order_repo, ca_settings, ca_backend, mock_db
    ):
        ca_settings.internal.serial_source = "database"
        cert_repo.next_serial.return_value = 42

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            db=mock_db,
        )

        serial = svc._generate_serial()
        assert serial == 42
        cert_repo.next_serial.assert_called_once()

    def test_random_serial_source(
        self, cert_repo, cert_order_repo, ca_settings, ca_backend, mock_db
    ):
        ca_settings.internal.serial_source = "random"

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            db=mock_db,
        )

        serial = svc._generate_serial()
        assert isinstance(serial, int)
        assert serial >= 0
        # 159-bit max -> less than 2^159
        assert serial < (2**159)
        cert_repo.next_serial.assert_not_called()


# ---------------------------------------------------------------------------
# finalize_order — profile validity_days/max_validity_days
# ---------------------------------------------------------------------------


class TestFinalizeOrderValidityDays:
    """Verify validity_days are correctly computed from profile and global limits."""

    def test_profile_validity_days_override(
        self,
        cert_repo,
        cert_order_repo,
        ca_settings,
        ca_backend,
        mock_db,
    ):
        profile = ca_settings.profiles["default"]
        profile.validity_days = 30
        profile.max_validity_days = 60
        ca_settings.default_validity_days = 90
        ca_settings.max_validity_days = 365

        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        valid_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.VALID,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.side_effect = [order, valid_order]
        cert_order_repo.transition_status.return_value = processing_order

        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])

        uow_mock = MagicMock()
        uow_mock.__enter__ = MagicMock(return_value=uow_mock)
        uow_mock.__exit__ = MagicMock(return_value=False)
        uow_mock.insert.return_value = {"id": str(uuid4())}
        uow_mock.update_where.return_value = {"id": str(uuid4())}

        with patch("acmeeh.services.certificate.UnitOfWork", return_value=uow_mock):
            svc.finalize_order(order.id, _csr_der(csr), account_id)

        # validity_days = profile.validity_days=30, max=min(365,60)=60 -> min(30,60)=30
        sign_kwargs = ca_backend.sign.call_args[1]
        assert sign_kwargs["validity_days"] == 30


# ---------------------------------------------------------------------------
# download — basic paths
# ---------------------------------------------------------------------------


class TestDownload:
    """CertificateService.download tests."""

    def test_cert_not_found(self, cert_svc, cert_repo):
        cert_repo.find_by_id.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.download(uuid4(), uuid4())
        assert exc_info.value.status == 404

    def test_wrong_account(self, cert_svc, cert_repo):
        account_id = uuid4()
        cert = _make_certificate(account_id=uuid4())
        cert_repo.find_by_id.return_value = cert
        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.download(cert.id, account_id)
        assert exc_info.value.status == 403

    def test_successful_download(self, cert_svc, cert_repo, cert_hooks):
        account_id = uuid4()
        cert = _make_certificate(account_id=account_id)
        cert_repo.find_by_id.return_value = cert

        result = cert_svc.download(cert.id, account_id)
        assert result == cert.pem_chain
        cert_hooks.dispatch.assert_called_once_with(
            "certificate.delivery",
            ANY,
        )

    def test_download_without_hooks(
        self, cert_repo, cert_order_repo, ca_settings, ca_backend, mock_db
    ):
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            hook_registry=None,
            db=mock_db,
        )

        account_id = uuid4()
        cert = _make_certificate(account_id=account_id)
        cert_repo.find_by_id.return_value = cert

        result = svc.download(cert.id, account_id)
        assert result == cert.pem_chain


# ---------------------------------------------------------------------------
# revoke — various auth paths
# ---------------------------------------------------------------------------


class TestRevoke:
    """CertificateService.revoke tests."""

    def test_invalid_reason_code(self, cert_svc):
        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.revoke(b"fake-cert-der", reason=7)
        assert BAD_REVOCATION_REASON in exc_info.value.error_type

    def test_unparseable_certificate(self, cert_svc):
        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.revoke(b"not-a-cert", account_id=uuid4())
        assert MALFORMED in exc_info.value.error_type

    def test_cert_not_found_in_db(self, cert_svc, cert_repo):
        key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        cert_repo.find_by_fingerprint.return_value = None

        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.revoke(cert_der, account_id=uuid4())
        assert exc_info.value.status == 404

    def test_already_revoked(self, cert_svc, cert_repo):
        key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        fingerprint = hashlib.sha256(cert_der).hexdigest()

        cert_record = _make_certificate(
            fingerprint=fingerprint,
            revoked_at=datetime.now(UTC),
        )
        cert_repo.find_by_fingerprint.return_value = cert_record

        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.revoke(cert_der, account_id=cert_record.account_id)
        assert ALREADY_REVOKED in exc_info.value.error_type

    def test_account_key_auth_wrong_owner(self, cert_svc, cert_repo):
        key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        fingerprint = hashlib.sha256(cert_der).hexdigest()

        cert_record = _make_certificate(
            fingerprint=fingerprint,
            account_id=uuid4(),
        )
        cert_repo.find_by_fingerprint.return_value = cert_record

        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.revoke(cert_der, account_id=uuid4())
        assert UNAUTHORIZED in exc_info.value.error_type

    def test_no_auth_provided(self, cert_svc, cert_repo):
        """Neither account_id nor jwk provided."""
        key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        fingerprint = hashlib.sha256(cert_der).hexdigest()

        cert_record = _make_certificate(fingerprint=fingerprint)
        cert_repo.find_by_fingerprint.return_value = cert_record

        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.revoke(cert_der)
        assert UNAUTHORIZED in exc_info.value.error_type
        assert "account key or certificate key" in exc_info.value.detail

    def test_successful_revoke_with_account_key(
        self,
        cert_svc,
        cert_repo,
        ca_backend,
        cert_notifier,
        cert_hooks,
        cert_metrics,
    ):
        key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        account_id = uuid4()

        cert_record = _make_certificate(
            fingerprint=fingerprint,
            account_id=account_id,
        )
        cert_repo.find_by_fingerprint.return_value = cert_record
        cert_repo.revoke.return_value = cert_record

        cert_svc.revoke(
            cert_der,
            reason=RevocationReason.KEY_COMPROMISE,
            account_id=account_id,
        )

        cert_repo.revoke.assert_called_once_with(
            cert_record.id,
            RevocationReason.KEY_COMPROMISE,
        )
        cert_metrics.increment.assert_called_with("acmeeh_certificates_revoked_total")
        cert_notifier.notify.assert_called_once()
        cert_hooks.dispatch.assert_called_once_with("certificate.revocation", ANY)
        ca_backend.revoke.assert_called_once()

    def test_revoke_repo_returns_none_raises_already_revoked(
        self,
        cert_svc,
        cert_repo,
    ):
        """When cert_repo.revoke returns None, it means already revoked (race)."""
        key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        account_id = uuid4()

        cert_record = _make_certificate(
            fingerprint=fingerprint,
            account_id=account_id,
        )
        cert_repo.find_by_fingerprint.return_value = cert_record
        cert_repo.revoke.return_value = None  # Race condition

        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.revoke(cert_der, account_id=account_id)
        assert ALREADY_REVOKED in exc_info.value.error_type

    def test_revoke_ca_backend_error_does_not_propagate(
        self,
        cert_svc,
        cert_repo,
        ca_backend,
    ):
        """CA backend revocation error is logged but does not fail."""
        key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        account_id = uuid4()

        cert_record = _make_certificate(
            fingerprint=fingerprint,
            account_id=account_id,
        )
        cert_repo.find_by_fingerprint.return_value = cert_record
        cert_repo.revoke.return_value = cert_record

        ca_backend.revoke.side_effect = CAError("Backend down")

        # Should not raise
        cert_svc.revoke(cert_der, account_id=account_id)

    def test_revoke_with_unspecified_reason(
        self,
        cert_svc,
        cert_repo,
        ca_backend,
    ):
        """reason=0 maps to RevocationReason.UNSPECIFIED."""
        key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        account_id = uuid4()

        cert_record = _make_certificate(
            fingerprint=fingerprint,
            account_id=account_id,
        )
        cert_repo.find_by_fingerprint.return_value = cert_record
        cert_repo.revoke.return_value = cert_record

        cert_svc.revoke(cert_der, reason=0, account_id=account_id)

        cert_repo.revoke.assert_called_once_with(
            cert_record.id,
            RevocationReason.UNSPECIFIED,
        )

    def test_revoke_with_none_reason(
        self,
        cert_svc,
        cert_repo,
        ca_backend,
    ):
        """reason=None -> rev_reason=None."""
        key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        account_id = uuid4()

        cert_record = _make_certificate(
            fingerprint=fingerprint,
            account_id=account_id,
        )
        cert_repo.find_by_fingerprint.return_value = cert_record
        cert_repo.revoke.return_value = cert_record

        cert_svc.revoke(cert_der, reason=None, account_id=account_id)

        cert_repo.revoke.assert_called_once_with(cert_record.id, None)

    def test_revoke_without_notifier_hooks_metrics(
        self,
        cert_repo,
        cert_order_repo,
        ca_settings,
        ca_backend,
        mock_db,
    ):
        """Revoke works without optional deps."""
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            notification_service=None,
            hook_registry=None,
            metrics=None,
            db=mock_db,
        )

        key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        account_id = uuid4()

        cert_record = _make_certificate(
            fingerprint=fingerprint,
            account_id=account_id,
        )
        cert_repo.find_by_fingerprint.return_value = cert_record
        cert_repo.revoke.return_value = cert_record

        # Should not raise
        svc.revoke(cert_der, account_id=account_id)


# ---------------------------------------------------------------------------
# revoke — JWK (certificate key) auth path
# ---------------------------------------------------------------------------


class TestRevokeJWKAuth:
    """Revocation using the certificate's private key (JWK auth)."""

    def test_jwk_auth_matching_key_succeeds(
        self,
        cert_svc,
        cert_repo,
        ca_backend,
    ):
        key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        fingerprint = hashlib.sha256(cert_der).hexdigest()

        cert_record = _make_certificate(fingerprint=fingerprint)
        cert_repo.find_by_fingerprint.return_value = cert_record
        cert_repo.revoke.return_value = cert_record

        jwk_dict = _ec_key_to_jwk(key)

        cert_svc.revoke(cert_der, jwk=jwk_dict)
        cert_repo.revoke.assert_called_once()

    def test_jwk_auth_mismatched_key_raises(
        self,
        cert_svc,
        cert_repo,
    ):
        key = _gen_ec_key()
        other_key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        fingerprint = hashlib.sha256(cert_der).hexdigest()

        cert_record = _make_certificate(fingerprint=fingerprint)
        cert_repo.find_by_fingerprint.return_value = cert_record

        jwk_dict = _ec_key_to_jwk(other_key)

        with pytest.raises(AcmeProblem) as exc_info:
            cert_svc.revoke(cert_der, jwk=jwk_dict)
        assert UNAUTHORIZED in exc_info.value.error_type

    def test_jwk_auth_invalid_jwk_raises(
        self,
        cert_svc,
        cert_repo,
    ):
        """Invalid JWK dict raises an AcmeProblem."""
        key = _gen_ec_key()
        cert_der = _build_self_signed_cert(key, ["example.com"])
        fingerprint = hashlib.sha256(cert_der).hexdigest()

        cert_record = _make_certificate(fingerprint=fingerprint)
        cert_repo.find_by_fingerprint.return_value = cert_record

        # Bogus JWK that will fail to parse -- jwk_to_public_key may raise
        # AcmeProblem(BAD_PUBLIC_KEY) or another error, both caught by revoke()
        bad_jwk = {"kty": "INVALID", "x": "bad"}

        with pytest.raises(AcmeProblem):
            cert_svc.revoke(cert_der, jwk=bad_jwk)
        # Either BAD_PUBLIC_KEY or UNAUTHORIZED is acceptable -- the key is
        # that revocation is refused


# ---------------------------------------------------------------------------
# finalize_order — CA signing failure without notifier
# ---------------------------------------------------------------------------


class TestFinalizeCAErrorWithoutNotifier:
    """CA signing error when notifier is None -- should not crash."""

    def test_ca_error_without_notifier(
        self,
        cert_repo,
        cert_order_repo,
        ca_settings,
        ca_backend,
        mock_db,
    ):
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            notification_service=None,
            metrics=None,
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.return_value = order
        cert_order_repo.transition_status.return_value = processing_order

        ca_backend.sign.side_effect = CAError("timeout")

        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])

        with pytest.raises(AcmeProblem) as exc_info:
            svc.finalize_order(order.id, _csr_der(csr), account_id)
        assert SERVER_INTERNAL in exc_info.value.error_type


# ---------------------------------------------------------------------------
# finalize_order — success without optional deps
# ---------------------------------------------------------------------------


class TestFinalizeSuccessMinimalDeps:
    """Finalize with only required deps (no notifier, hooks, metrics)."""

    def test_finalize_minimal(
        self,
        cert_repo,
        cert_order_repo,
        ca_settings,
        ca_backend,
        mock_db,
    ):
        svc = CertificateService(
            certificate_repo=cert_repo,
            order_repo=cert_order_repo,
            ca_settings=ca_settings,
            ca_backend=ca_backend,
            notification_service=None,
            hook_registry=None,
            metrics=None,
            db=mock_db,
        )

        account_id = uuid4()
        order = _make_order(
            account_id=account_id,
            status=OrderStatus.READY,
            identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        )
        processing_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.PROCESSING,
            identifiers=order.identifiers,
        )
        valid_order = _make_order(
            order_id=order.id,
            account_id=account_id,
            status=OrderStatus.VALID,
            identifiers=order.identifiers,
        )
        cert_order_repo.find_by_id.side_effect = [order, valid_order]
        cert_order_repo.transition_status.return_value = processing_order

        key = _gen_ec_key()
        csr = _build_csr(key, ["example.com"])

        uow_mock = MagicMock()
        uow_mock.__enter__ = MagicMock(return_value=uow_mock)
        uow_mock.__exit__ = MagicMock(return_value=False)
        uow_mock.insert.return_value = {"id": str(uuid4())}
        uow_mock.update_where.return_value = {"id": str(uuid4())}

        with patch("acmeeh.services.certificate.UnitOfWork", return_value=uow_mock):
            result = svc.finalize_order(order.id, _csr_der(csr), account_id)

        assert result is valid_order
