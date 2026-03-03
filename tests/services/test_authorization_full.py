"""Unit tests for acmeeh.services.authorization — AuthorizationService."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from acmeeh.app.errors import MALFORMED, UNAUTHORIZED, AcmeProblem
from acmeeh.core.types import (
    AuthorizationStatus,
    ChallengeStatus,
    ChallengeType,
    IdentifierType,
)
from acmeeh.models.authorization import Authorization
from acmeeh.models.challenge import Challenge
from acmeeh.services.authorization import AuthorizationService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_authz(
    authz_id=None,
    account_id=None,
    identifier_type=IdentifierType.DNS,
    identifier_value="example.com",
    status=AuthorizationStatus.PENDING,
    wildcard=False,
):
    return Authorization(
        id=authz_id or uuid4(),
        account_id=account_id or uuid4(),
        identifier_type=identifier_type,
        identifier_value=identifier_value,
        status=status,
        expires=datetime.now(UTC) + timedelta(days=7),
        wildcard=wildcard,
    )


def _make_challenge(
    challenge_id=None,
    authorization_id=None,
    challenge_type=ChallengeType.HTTP_01,
    status=ChallengeStatus.PENDING,
):
    return Challenge(
        id=challenge_id or uuid4(),
        authorization_id=authorization_id or uuid4(),
        type=challenge_type,
        token="test-token-abc123",
        status=status,
    )


def _make_service(
    authz_repo=None,
    challenge_repo=None,
    pre_auth_days=30,
    enabled_challenge_types=("http-01", "dns-01"),
):
    return AuthorizationService(
        authz_repo=authz_repo or MagicMock(),
        challenge_repo=challenge_repo or MagicMock(),
        pre_authorization_lifetime_days=pre_auth_days,
        enabled_challenge_types=enabled_challenge_types,
    )


# ---------------------------------------------------------------------------
# get_authorization
# ---------------------------------------------------------------------------


class TestGetAuthorization:
    def test_not_found_raises_malformed_404(self):
        authz_repo = MagicMock()
        authz_repo.find_by_id.return_value = None

        svc = _make_service(authz_repo=authz_repo)

        with pytest.raises(AcmeProblem) as exc_info:
            svc.get_authorization(uuid4(), uuid4())

        assert exc_info.value.error_type == MALFORMED
        assert exc_info.value.status == 404

    def test_wrong_account_raises_unauthorized_403(self):
        authz_repo = MagicMock()
        account_id = uuid4()
        other_account = uuid4()
        authz = _make_authz(account_id=account_id)
        authz_repo.find_by_id.return_value = authz

        svc = _make_service(authz_repo=authz_repo)

        with pytest.raises(AcmeProblem) as exc_info:
            svc.get_authorization(authz.id, other_account)

        assert exc_info.value.error_type == UNAUTHORIZED
        assert exc_info.value.status == 403

    def test_success_returns_authz_and_challenges(self):
        authz_repo = MagicMock()
        challenge_repo = MagicMock()

        account_id = uuid4()
        authz = _make_authz(account_id=account_id)
        challenges = [
            _make_challenge(authorization_id=authz.id, challenge_type=ChallengeType.HTTP_01),
            _make_challenge(authorization_id=authz.id, challenge_type=ChallengeType.DNS_01),
        ]

        authz_repo.find_by_id.return_value = authz
        challenge_repo.find_by_authorization.return_value = challenges

        svc = _make_service(authz_repo=authz_repo, challenge_repo=challenge_repo)
        result_authz, result_challenges = svc.get_authorization(authz.id, account_id)

        assert result_authz == authz
        assert result_challenges == challenges
        challenge_repo.find_by_authorization.assert_called_once_with(authz.id)


# ---------------------------------------------------------------------------
# check_order_ready
# ---------------------------------------------------------------------------


class TestCheckOrderReady:
    def test_delegates_to_repo(self):
        authz_repo = MagicMock()
        order_id = uuid4()
        authz_repo.all_valid_for_order.return_value = True

        svc = _make_service(authz_repo=authz_repo)
        result = svc.check_order_ready(order_id)

        assert result is True
        authz_repo.all_valid_for_order.assert_called_once_with(order_id)

    def test_returns_false_when_not_ready(self):
        authz_repo = MagicMock()
        authz_repo.all_valid_for_order.return_value = False

        svc = _make_service(authz_repo=authz_repo)
        assert svc.check_order_ready(uuid4()) is False


# ---------------------------------------------------------------------------
# deactivate
# ---------------------------------------------------------------------------


class TestDeactivate:
    def test_not_found_raises_malformed(self):
        authz_repo = MagicMock()
        authz_repo.find_by_id.return_value = None

        svc = _make_service(authz_repo=authz_repo)

        with pytest.raises(AcmeProblem) as exc_info:
            svc.deactivate(uuid4(), uuid4())

        assert exc_info.value.error_type == MALFORMED
        assert exc_info.value.status == 404

    def test_wrong_account_raises_unauthorized(self):
        authz_repo = MagicMock()
        account_id = uuid4()
        other_account = uuid4()
        authz = _make_authz(account_id=account_id)
        authz_repo.find_by_id.return_value = authz

        svc = _make_service(authz_repo=authz_repo)

        with pytest.raises(AcmeProblem) as exc_info:
            svc.deactivate(authz.id, other_account)

        assert exc_info.value.error_type == UNAUTHORIZED
        assert exc_info.value.status == 403

    def test_deactivate_from_pending_succeeds(self):
        authz_repo = MagicMock()
        account_id = uuid4()
        authz = _make_authz(account_id=account_id, status=AuthorizationStatus.PENDING)
        deactivated = _make_authz(
            authz_id=authz.id,
            account_id=account_id,
            status=AuthorizationStatus.DEACTIVATED,
        )

        authz_repo.find_by_id.return_value = authz
        # First transition (PENDING -> DEACTIVATED) succeeds
        authz_repo.transition_status.return_value = deactivated

        svc = _make_service(authz_repo=authz_repo)
        result = svc.deactivate(authz.id, account_id)

        assert result.status == AuthorizationStatus.DEACTIVATED
        authz_repo.transition_status.assert_called_once_with(
            authz.id,
            AuthorizationStatus.PENDING,
            AuthorizationStatus.DEACTIVATED,
        )

    def test_deactivate_from_valid_succeeds(self):
        authz_repo = MagicMock()
        account_id = uuid4()
        authz = _make_authz(account_id=account_id, status=AuthorizationStatus.VALID)
        deactivated = _make_authz(
            authz_id=authz.id,
            account_id=account_id,
            status=AuthorizationStatus.DEACTIVATED,
        )

        authz_repo.find_by_id.return_value = authz
        # First transition (PENDING -> DEACTIVATED) returns None (not in PENDING)
        # Second transition (VALID -> DEACTIVATED) succeeds
        authz_repo.transition_status.side_effect = [None, deactivated]

        svc = _make_service(authz_repo=authz_repo)
        result = svc.deactivate(authz.id, account_id)

        assert result.status == AuthorizationStatus.DEACTIVATED
        assert authz_repo.transition_status.call_count == 2

    def test_deactivate_from_invalid_status_raises(self):
        authz_repo = MagicMock()
        account_id = uuid4()
        authz = _make_authz(account_id=account_id, status=AuthorizationStatus.INVALID)

        authz_repo.find_by_id.return_value = authz
        # Both transitions return None (cannot deactivate from INVALID)
        authz_repo.transition_status.return_value = None

        svc = _make_service(authz_repo=authz_repo)

        with pytest.raises(AcmeProblem) as exc_info:
            svc.deactivate(authz.id, account_id)

        assert exc_info.value.error_type == MALFORMED
        assert "cannot be deactivated" in exc_info.value.detail.lower()


# ---------------------------------------------------------------------------
# create_pre_authorization
# ---------------------------------------------------------------------------


class TestCreatePreAuthorization:
    def test_creates_new_authz_with_challenges(self):
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        account_id = uuid4()

        authz_repo.find_reusable.return_value = None

        svc = _make_service(authz_repo=authz_repo, challenge_repo=challenge_repo)
        authz, challenges = svc.create_pre_authorization(account_id, "dns", "example.com")

        assert authz.account_id == account_id
        assert authz.identifier_type == IdentifierType.DNS
        assert authz.identifier_value == "example.com"
        assert authz.status == AuthorizationStatus.PENDING
        assert authz.wildcard is False
        authz_repo.create.assert_called_once()
        # Both HTTP-01 and DNS-01 for a normal DNS identifier
        assert len(challenges) == 2
        assert challenge_repo.create.call_count == 2
        challenge_types = {c.type for c in challenges}
        assert ChallengeType.HTTP_01 in challenge_types
        assert ChallengeType.DNS_01 in challenge_types

    def test_reuses_existing_authorization(self):
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        account_id = uuid4()

        existing_authz = _make_authz(account_id=account_id, status=AuthorizationStatus.VALID)
        existing_challenges = [
            _make_challenge(
                authorization_id=existing_authz.id, challenge_type=ChallengeType.HTTP_01
            ),
        ]

        authz_repo.find_reusable.return_value = existing_authz
        challenge_repo.find_by_authorization.return_value = existing_challenges

        svc = _make_service(authz_repo=authz_repo, challenge_repo=challenge_repo)
        authz, challenges = svc.create_pre_authorization(account_id, "dns", "example.com")

        assert authz == existing_authz
        assert challenges == existing_challenges
        authz_repo.create.assert_not_called()
        challenge_repo.create.assert_not_called()

    def test_wildcard_skips_http01(self):
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        account_id = uuid4()

        authz_repo.find_reusable.return_value = None

        svc = _make_service(authz_repo=authz_repo, challenge_repo=challenge_repo)
        authz, challenges = svc.create_pre_authorization(account_id, "dns", "*.example.com")

        assert authz.wildcard is True
        # Wildcard strips "*." prefix for the identifier value
        assert authz.identifier_value == "example.com"
        # Only DNS-01 for wildcard
        assert len(challenges) == 1
        assert challenges[0].type == ChallengeType.DNS_01
        challenge_repo.create.assert_called_once()

    def test_ip_identifier_skips_http01_and_dns01(self):
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        account_id = uuid4()

        authz_repo.find_reusable.return_value = None

        svc = _make_service(authz_repo=authz_repo, challenge_repo=challenge_repo)
        authz, challenges = svc.create_pre_authorization(account_id, "ip", "192.168.1.1")

        assert authz.identifier_type == IdentifierType.IP
        assert authz.identifier_value == "192.168.1.1"
        # Neither HTTP-01 nor DNS-01 is applicable for IP identifiers;
        # TLS-ALPN-01 must be enabled for IP-based challenges.
        assert len(challenges) == 0
        challenge_repo.create.assert_not_called()

    def test_ip_identifier_gets_tls_alpn01(self):
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        account_id = uuid4()

        authz_repo.find_reusable.return_value = None

        svc = _make_service(
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            enabled_challenge_types=("http-01", "dns-01", "tls-alpn-01"),
        )
        authz, challenges = svc.create_pre_authorization(account_id, "ip", "192.168.1.1")

        assert authz.identifier_type == IdentifierType.IP
        # Only TLS-ALPN-01 for IP
        assert len(challenges) == 1
        assert challenges[0].type == ChallengeType.TLS_ALPN_01
        challenge_repo.create.assert_called_once()

    def test_pre_authorization_lifetime(self):
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        account_id = uuid4()

        authz_repo.find_reusable.return_value = None

        svc = _make_service(authz_repo=authz_repo, challenge_repo=challenge_repo, pre_auth_days=15)
        authz, _ = svc.create_pre_authorization(account_id, "dns", "example.com")

        # The expiry should be approximately 15 days from now
        expected_min = datetime.now(UTC) + timedelta(days=14, hours=23)
        expected_max = datetime.now(UTC) + timedelta(days=15, minutes=1)
        assert expected_min <= authz.expires <= expected_max

    def test_only_creates_enabled_challenge_types(self):
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        account_id = uuid4()

        authz_repo.find_reusable.return_value = None

        # Only http-01 enabled
        svc = _make_service(
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            enabled_challenge_types=("http-01",),
        )
        authz, challenges = svc.create_pre_authorization(account_id, "dns", "example.com")

        assert len(challenges) == 1
        assert challenges[0].type == ChallengeType.HTTP_01
        challenge_repo.create.assert_called_once()

    def test_reuse_filters_stale_challenge_types(self):
        authz_repo = MagicMock()
        challenge_repo = MagicMock()
        account_id = uuid4()

        existing_authz = _make_authz(account_id=account_id, status=AuthorizationStatus.VALID)
        # Existing authorization has both http-01 and dns-01 from a previous config
        existing_challenges = [
            _make_challenge(
                authorization_id=existing_authz.id, challenge_type=ChallengeType.HTTP_01
            ),
            _make_challenge(
                authorization_id=existing_authz.id, challenge_type=ChallengeType.DNS_01
            ),
        ]

        authz_repo.find_reusable.return_value = existing_authz
        challenge_repo.find_by_authorization.return_value = existing_challenges

        # Only http-01 enabled now
        svc = _make_service(
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            enabled_challenge_types=("http-01",),
        )
        authz, challenges = svc.create_pre_authorization(account_id, "dns", "example.com")

        assert authz == existing_authz
        assert len(challenges) == 1
        assert challenges[0].type == ChallengeType.HTTP_01


class TestGetAuthorizationFiltering:
    def test_filters_stale_challenge_types(self):
        authz_repo = MagicMock()
        challenge_repo = MagicMock()

        account_id = uuid4()
        authz = _make_authz(account_id=account_id)
        # DB has both types from a previous config
        challenges = [
            _make_challenge(authorization_id=authz.id, challenge_type=ChallengeType.HTTP_01),
            _make_challenge(authorization_id=authz.id, challenge_type=ChallengeType.DNS_01),
        ]

        authz_repo.find_by_id.return_value = authz
        challenge_repo.find_by_authorization.return_value = challenges

        # Only http-01 enabled now
        svc = _make_service(
            authz_repo=authz_repo,
            challenge_repo=challenge_repo,
            enabled_challenge_types=("http-01",),
        )
        result_authz, result_challenges = svc.get_authorization(authz.id, account_id)

        assert result_authz == authz
        assert len(result_challenges) == 1
        assert result_challenges[0].type == ChallengeType.HTTP_01
