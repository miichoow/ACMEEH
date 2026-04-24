"""Tests for previously untested AdminUserService methods and edge cases."""

import logging
from unittest.mock import MagicMock

import pytest

from acmeeh.admin.service import AdminUserService
from acmeeh.app.errors import AcmeProblem
from acmeeh.config.settings import AdminApiSettings


@pytest.fixture
def settings():
    return AdminApiSettings(
        enabled=True,
        base_path="/api",
        token_secret="test-secret",
        token_expiry_seconds=3600,
        initial_admin_email="admin@example.com",
        password_length=20,
        default_page_size=50,
        max_page_size=1000,
    )


@pytest.fixture
def user_repo():
    return MagicMock()


@pytest.fixture
def audit_repo():
    return MagicMock()


@pytest.fixture
def notification_service():
    return MagicMock()


@pytest.fixture
def notification_repo():
    return MagicMock()


@pytest.fixture
def cert_repo():
    return MagicMock()


@pytest.fixture
def service(user_repo, audit_repo, settings):
    """Service with minimal dependencies (no optional repos)."""
    return AdminUserService(
        user_repo=user_repo,
        audit_repo=audit_repo,
        settings=settings,
    )


@pytest.fixture
def full_service(
    user_repo, audit_repo, settings, notification_service, notification_repo, cert_repo
):
    """Service with all optional dependencies wired up."""
    return AdminUserService(
        user_repo=user_repo,
        audit_repo=audit_repo,
        settings=settings,
        notification_service=notification_service,
        notification_repo=notification_repo,
        cert_repo=cert_repo,
    )


# ---------------------------------------------------------------------------
# cleanup_audit_log
# ---------------------------------------------------------------------------


class TestCleanupAuditLog:
    def test_deletes_entries_and_returns_count(self, service, audit_repo):
        audit_repo.delete_older_than.return_value = 42
        result = service.cleanup_audit_log(max_age_days=90)
        audit_repo.delete_older_than.assert_called_once_with(90)
        assert result == 42

    def test_logs_when_entries_deleted(self, service, audit_repo, caplog):
        audit_repo.delete_older_than.return_value = 5
        with caplog.at_level(logging.INFO):
            service.cleanup_audit_log(max_age_days=30)
        assert "Cleaned up 5 audit log entries older than 30 days" in caplog.text

    def test_no_log_when_zero_deleted(self, service, audit_repo, caplog):
        audit_repo.delete_older_than.return_value = 0
        with caplog.at_level(logging.INFO):
            result = service.cleanup_audit_log(max_age_days=30)
        assert result == 0
        assert "Cleaned up" not in caplog.text


# ---------------------------------------------------------------------------
# list_notifications
# ---------------------------------------------------------------------------


class TestListNotifications:
    def test_returns_empty_list_when_no_repo(self, service):
        result = service.list_notifications()
        assert result == []

    def test_returns_empty_list_when_no_repo_with_args(self, service):
        result = service.list_notifications(status="failed", limit=10, offset=5)
        assert result == []

    def test_delegates_to_repo(self, full_service, notification_repo):
        expected = [MagicMock(), MagicMock()]
        notification_repo.find_all_paginated.return_value = expected
        result = full_service.list_notifications(status="pending", limit=25, offset=10)
        notification_repo.find_all_paginated.assert_called_once_with("pending", 25, 10)
        assert result == expected

    def test_uses_default_limit_and_offset(self, full_service, notification_repo):
        notification_repo.find_all_paginated.return_value = []
        full_service.list_notifications()
        notification_repo.find_all_paginated.assert_called_once_with(None, 50, 0)


# ---------------------------------------------------------------------------
# retry_failed_notifications
# ---------------------------------------------------------------------------


class TestRetryFailedNotifications:
    def test_returns_zero_when_no_notification_service(self, service):
        result = service.retry_failed_notifications()
        assert result == 0

    def test_delegates_to_notification_service(self, full_service, notification_service):
        notification_service.retry_all_failed.return_value = 3
        result = full_service.retry_failed_notifications()
        notification_service.retry_all_failed.assert_called_once_with()
        assert result == 3


# ---------------------------------------------------------------------------
# purge_notifications
# ---------------------------------------------------------------------------


class TestPurgeNotifications:
    def test_returns_zero_when_no_repo(self, service):
        result = service.purge_notifications(days=30)
        assert result == 0

    def test_delegates_to_repo(self, full_service, notification_repo):
        notification_repo.purge_old.return_value = 7
        result = full_service.purge_notifications(days=60)
        notification_repo.purge_old.assert_called_once_with(60)
        assert result == 7


# ---------------------------------------------------------------------------
# search_certificates
# ---------------------------------------------------------------------------


class TestSearchCertificates:
    def test_returns_empty_list_when_no_repo(self, service):
        result = service.search_certificates(filters={"domain": "example.com"})
        assert result == []

    def test_returns_empty_list_when_no_repo_with_all_args(self, service):
        result = service.search_certificates(filters={"status": "valid"}, limit=10, offset=5)
        assert result == []

    def test_delegates_to_repo(self, full_service, cert_repo):
        expected = [MagicMock()]
        cert_repo.search.return_value = expected
        filters = {"domain": "example.com", "status": "valid"}
        result = full_service.search_certificates(filters, limit=20, offset=5)
        cert_repo.search.assert_called_once_with(filters, 20, 5)
        assert result == expected

    def test_uses_default_limit_and_offset(self, full_service, cert_repo):
        cert_repo.search.return_value = []
        full_service.search_certificates(filters={})
        cert_repo.search.assert_called_once_with({}, 50, 0)


# ---------------------------------------------------------------------------
# get_certificate_by_serial
# ---------------------------------------------------------------------------


class TestGetCertificateBySerial:
    def test_raises_503_when_no_repo(self, service):
        with pytest.raises(AcmeProblem) as exc_info:
            service.get_certificate_by_serial("AABB0011")
        assert exc_info.value.status == 503
        assert "not available" in str(exc_info.value.detail).lower()

    def test_raises_404_when_cert_not_found(self, full_service, cert_repo):
        cert_repo.find_by_serial.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            full_service.get_certificate_by_serial("DEADBEEF")
        assert exc_info.value.status == 404
        cert_repo.find_by_serial.assert_called_once_with("DEADBEEF")

    def test_returns_cert_when_found(self, full_service, cert_repo):
        mock_cert = MagicMock()
        cert_repo.find_by_serial.return_value = mock_cert
        result = full_service.get_certificate_by_serial("AABB0011")
        cert_repo.find_by_serial.assert_called_once_with("AABB0011")
        assert result is mock_cert


# ---------------------------------------------------------------------------
# search_audit_log
# ---------------------------------------------------------------------------


class TestSearchAuditLog:
    def test_delegates_to_audit_repo(self, service, audit_repo):
        expected = [MagicMock(), MagicMock()]
        audit_repo.search.return_value = expected
        filters = {"action": "login", "username": "admin"}
        result = service.search_audit_log(filters, limit=500)
        audit_repo.search.assert_called_once_with(filters, 500)
        assert result == expected

    def test_uses_default_limit(self, service, audit_repo):
        audit_repo.search.return_value = []
        service.search_audit_log(filters={})
        audit_repo.search.assert_called_once_with({}, 1000)


# ---------------------------------------------------------------------------
# _send_password_email
# ---------------------------------------------------------------------------


class TestSendPasswordEmail:
    @pytest.fixture
    def mock_user(self):
        user = MagicMock()
        user.username = "jdoe"
        user.email = "jdoe@example.com"
        user.role.value = "admin"
        return user

    def test_noop_when_no_notification_service(self, service, mock_user):
        # notification_service is None; should return without error
        service._send_password_email(
            notification_type=MagicMock(),
            user=mock_user,
            plain_password="s3cret!",
        )

    def test_sends_notification_on_success(self, full_service, notification_service, mock_user):
        notif_type = MagicMock()
        full_service._send_password_email(notif_type, mock_user, "p@ssw0rd")
        notification_service.notify.assert_called_once_with(
            notif_type,
            account_id=None,
            context={
                "username": "jdoe",
                "email": "jdoe@example.com",
                "password": "p@ssw0rd",
                "role": "admin",
            },
            explicit_recipients=["jdoe@example.com"],
        )

    def test_logs_exception_on_failure(self, full_service, notification_service, mock_user, caplog):
        notif_type = MagicMock()
        notif_type.value = "password_reset"
        notification_service.notify.side_effect = RuntimeError("SMTP down")
        with caplog.at_level(logging.ERROR):
            # Should NOT raise
            full_service._send_password_email(notif_type, mock_user, "p@ss")
        assert "Failed to send password_reset notification to jdoe@example.com" in caplog.text

    def test_exception_does_not_propagate(self, full_service, notification_service, mock_user):
        notif_type = MagicMock()
        notif_type.value = "welcome"
        notification_service.notify.side_effect = Exception("unexpected")
        # Must not raise
        full_service._send_password_email(notif_type, mock_user, "pwd")


# ---------------------------------------------------------------------------
# ACME account inspection (list_accounts / get_account)
# ---------------------------------------------------------------------------


class TestListAccountsService:
    def test_returns_empty_when_account_repo_missing(self, service):
        accounts, eab_kids = service.list_accounts({})
        assert accounts == []
        assert eab_kids == {}

    def test_delegates_to_repos_and_merges_eab_kids(self, user_repo, audit_repo, settings):
        from uuid import uuid4

        account_repo = MagicMock()
        acct1 = MagicMock(id=uuid4())
        acct2 = MagicMock(id=uuid4())
        account_repo.search.return_value = [acct1, acct2]
        account_repo.find_eab_kids_for_accounts.return_value = {acct1.id: "kid-1"}

        svc = AdminUserService(
            user_repo=user_repo,
            audit_repo=audit_repo,
            settings=settings,
            account_repo=account_repo,
        )

        filters = {"status": "valid"}
        accounts, eab_kids = svc.list_accounts(filters, limit=10, offset=0)

        account_repo.search.assert_called_once_with(filters, 10, 0)
        account_repo.find_eab_kids_for_accounts.assert_called_once_with(
            [acct1.id, acct2.id],
        )
        assert accounts == [acct1, acct2]
        assert eab_kids == {acct1.id: "kid-1"}


class TestGetAccountService:
    def test_raises_503_when_account_repo_missing(self, service):
        from uuid import uuid4

        with pytest.raises(AcmeProblem) as exc:
            service.get_account(uuid4())
        assert exc.value.status == 503

    def test_raises_404_when_account_not_found(self, user_repo, audit_repo, settings):
        from uuid import uuid4

        account_repo = MagicMock()
        account_repo.find_by_id.return_value = None
        svc = AdminUserService(
            user_repo=user_repo,
            audit_repo=audit_repo,
            settings=settings,
            account_repo=account_repo,
        )
        with pytest.raises(AcmeProblem) as exc:
            svc.get_account(uuid4())
        assert exc.value.status == 404

    def test_returns_account_with_contacts_eab_and_profile(
        self,
        user_repo,
        audit_repo,
        settings,
    ):
        from uuid import uuid4

        acct_id = uuid4()
        profile_id = uuid4()
        account = MagicMock(id=acct_id)
        contact = MagicMock(contact_uri="mailto:ops@example.com")
        profile = MagicMock(id=profile_id)

        account_repo = MagicMock()
        account_repo.find_by_id.return_value = account
        account_repo.find_eab_kids_for_accounts.return_value = {acct_id: "kid-abc"}
        contact_repo = MagicMock()
        contact_repo.find_by_account.return_value = [contact]
        csr_profile_repo = MagicMock()
        csr_profile_repo.find_profile_for_account.return_value = profile

        svc = AdminUserService(
            user_repo=user_repo,
            audit_repo=audit_repo,
            settings=settings,
            csr_profile_repo=csr_profile_repo,
            account_repo=account_repo,
            account_contact_repo=contact_repo,
        )

        result_account, contacts, eab_kid, profile_id_out = svc.get_account(acct_id)
        assert result_account is account
        assert contacts == [contact]
        assert eab_kid == "kid-abc"
        assert profile_id_out == profile_id

    def test_unbound_account_returns_none_for_eab_and_profile(
        self,
        user_repo,
        audit_repo,
        settings,
    ):
        from uuid import uuid4

        acct_id = uuid4()
        account = MagicMock(id=acct_id)

        account_repo = MagicMock()
        account_repo.find_by_id.return_value = account
        account_repo.find_eab_kids_for_accounts.return_value = {}
        csr_profile_repo = MagicMock()
        csr_profile_repo.find_profile_for_account.return_value = None

        svc = AdminUserService(
            user_repo=user_repo,
            audit_repo=audit_repo,
            settings=settings,
            csr_profile_repo=csr_profile_repo,
            account_repo=account_repo,
        )

        _account, contacts, eab_kid, profile_id = svc.get_account(acct_id)
        assert contacts == []
        assert eab_kid is None
        assert profile_id is None
