"""Unit tests for acmeeh.services.account — Account service."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from acmeeh.app.errors import (
    ACCOUNT_DOES_NOT_EXIST,
    INVALID_CONTACT,
    UNAUTHORIZED,
    UNSUPPORTED_CONTACT,
    AcmeProblem,
)
from acmeeh.core.types import AccountStatus
from acmeeh.models.account import Account
from acmeeh.services.account import AccountService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _email_settings(require_contact=False, allowed_domains=()):
    return SimpleNamespace(
        require_contact=require_contact,
        allowed_domains=list(allowed_domains),
    )


def _tos_settings(require_agreement=False, url=""):
    return SimpleNamespace(
        require_agreement=require_agreement,
        url=url,
    )


def _make_account(account_id=None, status=AccountStatus.VALID, **kwargs):
    return Account(
        id=account_id or uuid4(),
        jwk_thumbprint="tp_test",
        jwk={"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
        status=status,
        **kwargs,
    )


def _account_settings(allow_contact_update=True, allow_deactivation=True):
    return SimpleNamespace(
        allow_contact_update=allow_contact_update,
        allow_deactivation=allow_deactivation,
    )


def _make_service(
    account_repo=None,
    contact_repo=None,
    email_settings=None,
    tos_settings=None,
    notification_service=None,
    hook_registry=None,
    eab_required=False,
    authz_repo=None,
    metrics=None,
    account_settings=None,
):
    return AccountService(
        account_repo=account_repo or MagicMock(),
        contact_repo=contact_repo or MagicMock(),
        email_settings=email_settings or _email_settings(),
        tos_settings=tos_settings or _tos_settings(),
        notification_service=notification_service,
        hook_registry=hook_registry,
        eab_required=eab_required,
        metrics=metrics,
        authz_repo=authz_repo,
        account_settings=account_settings or _account_settings(),
    )


# ---------------------------------------------------------------------------
# TestCreateOrFind
# ---------------------------------------------------------------------------


class TestCreateOrFind:
    JWK = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}

    @patch("acmeeh.services.account.security_events")
    @patch("acmeeh.services.account.compute_thumbprint", return_value="tp_test")
    def test_returns_existing_account(self, mock_tp, mock_se):
        existing = _make_account()
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = existing
        contact_repo = MagicMock()
        contact_repo.find_by_account.return_value = []

        svc = _make_service(account_repo=repo, contact_repo=contact_repo)
        account, contacts, created = svc.create_or_find(self.JWK)
        assert account is existing
        assert created is False

    @patch("acmeeh.services.account.security_events")
    @patch("acmeeh.services.account.compute_thumbprint", return_value="tp_new")
    def test_creates_new_account(self, mock_tp, mock_se):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None
        contact_repo = MagicMock()

        svc = _make_service(account_repo=repo, contact_repo=contact_repo)
        account, contacts, created = svc.create_or_find(self.JWK)
        assert created is True
        repo.create.assert_called_once()

    @patch("acmeeh.services.account.compute_thumbprint", return_value="tp")
    def test_enforces_tos_agreement(self, mock_tp):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None

        svc = _make_service(
            account_repo=repo,
            tos_settings=_tos_settings(require_agreement=True),
        )
        with pytest.raises(AcmeProblem, match="Terms of service"):
            svc.create_or_find(self.JWK, tos_agreed=False)

    @patch("acmeeh.services.account.compute_thumbprint", return_value="tp")
    def test_rejects_when_eab_required_but_not_provided(self, mock_tp):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None

        svc = _make_service(account_repo=repo, eab_required=True)
        with pytest.raises(AcmeProblem, match="External account binding"):
            svc.create_or_find(self.JWK)

    @patch("acmeeh.services.account.security_events")
    @patch("acmeeh.services.account.compute_thumbprint", return_value="tp")
    def test_validates_contacts_invalid_mailto(self, mock_tp, mock_se):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None

        svc = _make_service(account_repo=repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_or_find(self.JWK, contact=["tel:+1234567890"])
        assert exc_info.value.error_type == UNSUPPORTED_CONTACT

    @patch("acmeeh.services.account.security_events")
    @patch("acmeeh.services.account.compute_thumbprint", return_value="tp")
    def test_enforces_contact_requirement(self, mock_tp, mock_se):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None

        svc = _make_service(
            account_repo=repo,
            email_settings=_email_settings(require_contact=True),
        )
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_or_find(self.JWK)
        assert exc_info.value.error_type == INVALID_CONTACT

    @patch("acmeeh.services.account.security_events")
    @patch("acmeeh.services.account.compute_thumbprint", return_value="tp")
    def test_enforces_email_domain_allowlist(self, mock_tp, mock_se):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None

        svc = _make_service(
            account_repo=repo,
            email_settings=_email_settings(allowed_domains=["corp.com"]),
        )
        with pytest.raises(AcmeProblem) as exc_info:
            svc.create_or_find(self.JWK, contact=["mailto:user@other.com"])
        assert exc_info.value.error_type == INVALID_CONTACT

    @patch("acmeeh.services.account.security_events")
    @patch("acmeeh.services.account.compute_thumbprint", return_value="tp")
    def test_dispatches_hooks_and_notifications(self, mock_tp, mock_se):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None
        contact_repo = MagicMock()
        hooks = MagicMock()
        notifier = MagicMock()

        svc = _make_service(
            account_repo=repo,
            contact_repo=contact_repo,
            hook_registry=hooks,
            notification_service=notifier,
        )
        svc.create_or_find(self.JWK, contact=["mailto:a@b.com"], tos_agreed=True)
        hooks.dispatch.assert_called_once()
        notifier.notify.assert_called_once()


# ---------------------------------------------------------------------------
# TestFindByJwk
# ---------------------------------------------------------------------------


class TestFindByJwk:
    @patch("acmeeh.services.account.compute_thumbprint", return_value="tp")
    def test_returns_account(self, mock_tp):
        existing = _make_account()
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = existing

        svc = _make_service(account_repo=repo)
        assert svc.find_by_jwk({"kty": "EC"}) is existing

    @patch("acmeeh.services.account.compute_thumbprint", return_value="tp")
    def test_raises_when_not_found(self, mock_tp):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None

        svc = _make_service(account_repo=repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.find_by_jwk({"kty": "EC"})
        assert exc_info.value.error_type == ACCOUNT_DOES_NOT_EXIST


# ---------------------------------------------------------------------------
# TestFindById
# ---------------------------------------------------------------------------


class TestFindById:
    def test_returns_account(self):
        uid = uuid4()
        existing = _make_account(account_id=uid)
        repo = MagicMock()
        repo.find_by_id.return_value = existing

        svc = _make_service(account_repo=repo)
        assert svc.find_by_id(uid) is existing

    def test_raises_when_not_found(self):
        repo = MagicMock()
        repo.find_by_id.return_value = None

        svc = _make_service(account_repo=repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.find_by_id(uuid4())
        assert exc_info.value.error_type == ACCOUNT_DOES_NOT_EXIST


# ---------------------------------------------------------------------------
# TestUpdateContacts
# ---------------------------------------------------------------------------


class TestUpdateContacts:
    def test_replaces_contacts(self):
        uid = uuid4()
        account = _make_account(account_id=uid)
        repo = MagicMock()
        repo.find_by_id.return_value = account
        contact_repo = MagicMock()
        contact_repo.replace_for_account.return_value = []

        svc = _make_service(account_repo=repo, contact_repo=contact_repo)
        svc.update_contacts(uid, ["mailto:new@corp.com"])
        contact_repo.replace_for_account.assert_called_once()

    def test_rejects_non_valid_account(self):
        uid = uuid4()
        account = _make_account(account_id=uid, status=AccountStatus.DEACTIVATED)
        repo = MagicMock()
        repo.find_by_id.return_value = account

        svc = _make_service(account_repo=repo)
        with pytest.raises(AcmeProblem, match="not in valid status"):
            svc.update_contacts(uid, ["mailto:a@b.com"])


# ---------------------------------------------------------------------------
# TestDeactivate
# ---------------------------------------------------------------------------


class TestDeactivate:
    @patch("acmeeh.services.account.security_events")
    def test_deactivates_valid_account(self, mock_se):
        uid = uuid4()
        deactivated = _make_account(account_id=uid, status=AccountStatus.DEACTIVATED)
        repo = MagicMock()
        repo.deactivate.return_value = deactivated

        svc = _make_service(account_repo=repo)
        result = svc.deactivate(uid)
        assert result.status == AccountStatus.DEACTIVATED

    @patch("acmeeh.services.account.security_events")
    def test_cascades_to_authorizations(self, mock_se):
        uid = uuid4()
        deactivated = _make_account(account_id=uid, status=AccountStatus.DEACTIVATED)
        repo = MagicMock()
        repo.deactivate.return_value = deactivated
        authz_repo = MagicMock()
        authz_repo.deactivate_for_account.return_value = 3

        svc = _make_service(account_repo=repo, authz_repo=authz_repo)
        svc.deactivate(uid)
        authz_repo.deactivate_for_account.assert_called_once_with(uid)

    def test_raises_when_cannot_deactivate(self):
        repo = MagicMock()
        repo.deactivate.return_value = None

        svc = _make_service(account_repo=repo)
        with pytest.raises(AcmeProblem, match="cannot be deactivated"):
            svc.deactivate(uuid4())


# ---------------------------------------------------------------------------
# TestRevoke
# ---------------------------------------------------------------------------


class TestRevoke:
    @patch("acmeeh.services.account.security_events")
    def test_revokes_valid_account(self, mock_se):
        uid = uuid4()
        revoked = _make_account(account_id=uid, status=AccountStatus.REVOKED)
        repo = MagicMock()
        repo.revoke.return_value = revoked

        svc = _make_service(account_repo=repo)
        result = svc.revoke(uid, reason="eab_revoked:k1")
        assert result.status == AccountStatus.REVOKED
        repo.revoke.assert_called_once_with(uid)
        mock_se.account_revoked.assert_called_once_with(uid, reason="eab_revoked:k1")

    @patch("acmeeh.services.account.security_events")
    def test_cascades_to_authorizations(self, mock_se):
        uid = uuid4()
        revoked = _make_account(account_id=uid, status=AccountStatus.REVOKED)
        repo = MagicMock()
        repo.revoke.return_value = revoked
        authz_repo = MagicMock()
        authz_repo.deactivate_for_account.return_value = 2

        svc = _make_service(account_repo=repo, authz_repo=authz_repo)
        svc.revoke(uid)
        authz_repo.deactivate_for_account.assert_called_once_with(uid)

    @patch("acmeeh.services.account.security_events")
    def test_notifies_with_reason(self, mock_se):
        uid = uuid4()
        revoked = _make_account(account_id=uid, status=AccountStatus.REVOKED)
        repo = MagicMock()
        repo.revoke.return_value = revoked
        notifier = MagicMock()

        svc = _make_service(account_repo=repo, notification_service=notifier)
        svc.revoke(uid, reason="eab_revoked:k1")

        notifier.notify.assert_called_once()
        notif_type, notified_id, context = notifier.notify.call_args.args
        from acmeeh.core.types import NotificationType  # noqa: PLC0415

        assert notif_type == NotificationType.ACCOUNT_REVOKED
        assert notified_id == uid
        assert context["reason"] == "eab_revoked:k1"

    def test_returns_none_when_not_valid(self):
        """CAS miss (already deactivated/revoked) is a no-op, not an error —
        admin cascade must stay idempotent."""
        repo = MagicMock()
        repo.revoke.return_value = None
        authz_repo = MagicMock()
        notifier = MagicMock()

        svc = _make_service(
            account_repo=repo,
            authz_repo=authz_repo,
            notification_service=notifier,
        )
        assert svc.revoke(uuid4()) is None
        authz_repo.deactivate_for_account.assert_not_called()
        notifier.notify.assert_not_called()

    @patch("acmeeh.services.account.security_events")
    def test_ignores_allow_deactivation_policy(self, mock_se):
        """Revocation is admin-initiated and must bypass the client-facing
        ``allow_deactivation`` flag."""
        uid = uuid4()
        revoked = _make_account(account_id=uid, status=AccountStatus.REVOKED)
        repo = MagicMock()
        repo.revoke.return_value = revoked

        svc = _make_service(
            account_repo=repo,
            account_settings=_account_settings(allow_deactivation=False),
        )
        result = svc.revoke(uid)
        assert result.status == AccountStatus.REVOKED


# ---------------------------------------------------------------------------
# TestAccountPolicyLockdown
# ---------------------------------------------------------------------------


class TestAccountPolicyLockdown:
    def test_contact_update_blocked_by_policy(self):
        uid = uuid4()
        account = _make_account(account_id=uid)
        repo = MagicMock()
        repo.find_by_id.return_value = account

        svc = _make_service(
            account_repo=repo,
            account_settings=_account_settings(allow_contact_update=False),
        )
        with pytest.raises(AcmeProblem) as exc_info:
            svc.update_contacts(uid, ["mailto:a@b.com"])
        assert exc_info.value.error_type == UNAUTHORIZED
        assert exc_info.value.status == 403
        assert "disabled by server policy" in str(exc_info.value.detail)

    def test_deactivation_blocked_by_policy(self):
        uid = uuid4()
        svc = _make_service(
            account_settings=_account_settings(allow_deactivation=False),
        )
        with pytest.raises(AcmeProblem) as exc_info:
            svc.deactivate(uid)
        assert exc_info.value.error_type == UNAUTHORIZED
        assert exc_info.value.status == 403
        assert "disabled by server policy" in str(exc_info.value.detail)
