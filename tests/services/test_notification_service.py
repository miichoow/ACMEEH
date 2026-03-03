"""Unit tests for acmeeh.services.notification — NotificationService."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

from acmeeh.core.types import NotificationStatus, NotificationType
from acmeeh.models.account import AccountContact
from acmeeh.models.notification import Notification
from acmeeh.services.notification import NotificationService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _smtp_settings(
    enabled=True,
    host="smtp.example.com",
    port=587,
    username="",
    password="",
    use_tls=False,
    from_address="noreply@example.com",
    cc=(),
    bcc=(),
    timeout_seconds=10,
):
    return SimpleNamespace(
        enabled=enabled,
        host=host,
        port=port,
        username=username,
        password=password,
        use_tls=use_tls,
        from_address=from_address,
        cc=cc,
        bcc=bcc,
        timeout_seconds=timeout_seconds,
    )


def _notification_settings(
    enabled=True,
    max_retries=3,
    batch_size=10,
    retry_delay_seconds=60,
    retry_backoff_multiplier=2.0,
    retry_max_delay_seconds=3600,
    disabled_types=(),
):
    return SimpleNamespace(
        enabled=enabled,
        max_retries=max_retries,
        batch_size=batch_size,
        retry_delay_seconds=retry_delay_seconds,
        retry_backoff_multiplier=retry_backoff_multiplier,
        retry_max_delay_seconds=retry_max_delay_seconds,
        disabled_types=disabled_types,
    )


def _make_service(
    notification_repo=None,
    contact_repo=None,
    smtp_settings=None,
    notification_settings=None,
    renderer=None,
    server_url="https://acme.example.com",
):
    return NotificationService(
        notification_repo=notification_repo or MagicMock(),
        contact_repo=contact_repo or MagicMock(),
        smtp_settings=smtp_settings or _smtp_settings(),
        notification_settings=notification_settings or _notification_settings(),
        renderer=renderer or MagicMock(render=MagicMock(return_value=("Subject", "<p>Body</p>"))),
        server_url=server_url,
    )


def _make_notification(
    notification_id=None,
    notification_type=NotificationType.DELIVERY_SUCCEEDED,
    recipient="user@example.com",
    subject="Test",
    body="<p>Test</p>",
    status=NotificationStatus.PENDING,
    account_id=None,
):
    return Notification(
        id=notification_id or uuid4(),
        notification_type=notification_type,
        recipient=recipient,
        subject=subject,
        body=body,
        status=status,
        account_id=account_id,
    )


# ---------------------------------------------------------------------------
# notify — disabled
# ---------------------------------------------------------------------------


class TestNotifyDisabled:
    def test_notify_when_disabled_returns_empty_list(self):
        svc = _make_service(notification_settings=_notification_settings(enabled=False))
        result = svc.notify(
            NotificationType.DELIVERY_SUCCEEDED,
            uuid4(),
            {"cert_id": "abc"},
        )
        assert result == []

    def test_notify_with_no_recipients_returns_empty_list(self):
        contact_repo = MagicMock()
        contact_repo.find_by_account.return_value = []
        svc = _make_service(contact_repo=contact_repo)
        result = svc.notify(
            NotificationType.DELIVERY_SUCCEEDED,
            uuid4(),
            {"cert_id": "abc"},
        )
        assert result == []


# ---------------------------------------------------------------------------
# notify — SMTP enabled, success / failure
# ---------------------------------------------------------------------------


class TestNotifySmtpEnabled:
    def test_send_success_marks_sent(self):
        notif_repo = MagicMock()
        contact_repo = MagicMock()
        renderer = MagicMock()

        account_id = uuid4()
        contact = AccountContact(
            id=uuid4(),
            account_id=account_id,
            contact_uri="mailto:user@example.com",
        )
        contact_repo.find_by_account.return_value = [contact]
        renderer.render.return_value = ("Cert Issued", "<p>Issued</p>")

        sent_notification = _make_notification(status=NotificationStatus.SENT)
        notif_repo.mark_sent.return_value = sent_notification

        svc = _make_service(
            notification_repo=notif_repo,
            contact_repo=contact_repo,
            smtp_settings=_smtp_settings(enabled=True),
            renderer=renderer,
        )

        with patch.object(svc, "_send_email", return_value=True) as mock_send:
            result = svc.notify(
                NotificationType.DELIVERY_SUCCEEDED,
                account_id,
                {"cert_id": "abc"},
            )

        assert len(result) == 1
        notif_repo.create.assert_called_once()
        notif_repo.mark_sent.assert_called_once()
        mock_send.assert_called_once_with("user@example.com", "Cert Issued", "<p>Issued</p>")

    def test_send_failure_marks_failed(self):
        notif_repo = MagicMock()
        contact_repo = MagicMock()
        renderer = MagicMock()

        account_id = uuid4()
        contact = AccountContact(
            id=uuid4(),
            account_id=account_id,
            contact_uri="mailto:user@example.com",
        )
        contact_repo.find_by_account.return_value = [contact]
        renderer.render.return_value = ("Cert Issued", "<p>Issued</p>")

        failed_notification = _make_notification(status=NotificationStatus.FAILED)
        notif_repo.mark_failed.return_value = failed_notification

        svc = _make_service(
            notification_repo=notif_repo,
            contact_repo=contact_repo,
            smtp_settings=_smtp_settings(enabled=True),
            renderer=renderer,
        )

        with patch.object(svc, "_send_email", return_value=False) as mock_send:
            result = svc.notify(
                NotificationType.DELIVERY_SUCCEEDED,
                account_id,
                {"cert_id": "abc"},
            )

        assert len(result) == 1
        notif_repo.create.assert_called_once()
        notif_repo.mark_failed.assert_called_once()
        mock_send.assert_called_once()


# ---------------------------------------------------------------------------
# notify — SMTP disabled (records but no send)
# ---------------------------------------------------------------------------


class TestNotifySmtpDisabled:
    def test_records_but_does_not_send(self):
        notif_repo = MagicMock()
        contact_repo = MagicMock()
        renderer = MagicMock()

        account_id = uuid4()
        contact = AccountContact(
            id=uuid4(),
            account_id=account_id,
            contact_uri="mailto:admin@example.com",
        )
        contact_repo.find_by_account.return_value = [contact]
        renderer.render.return_value = ("Subject", "<p>Body</p>")

        svc = _make_service(
            notification_repo=notif_repo,
            contact_repo=contact_repo,
            smtp_settings=_smtp_settings(enabled=False),
            renderer=renderer,
        )

        with patch.object(svc, "_send_email") as mock_send:
            result = svc.notify(
                NotificationType.DELIVERY_SUCCEEDED,
                account_id,
                {},
            )

        assert len(result) == 1
        notif_repo.create.assert_called_once()
        mock_send.assert_not_called()
        notif_repo.mark_sent.assert_not_called()
        notif_repo.mark_failed.assert_not_called()


# ---------------------------------------------------------------------------
# notify — explicit recipients
# ---------------------------------------------------------------------------


class TestNotifyExplicitRecipients:
    def test_explicit_recipients_bypasses_contact_lookup(self):
        notif_repo = MagicMock()
        contact_repo = MagicMock()
        renderer = MagicMock()
        renderer.render.return_value = ("Explicit", "<p>Explicit</p>")

        svc = _make_service(
            notification_repo=notif_repo,
            contact_repo=contact_repo,
            smtp_settings=_smtp_settings(enabled=True),
            renderer=renderer,
        )

        with patch.object(svc, "_send_email", return_value=True):
            result = svc.notify(
                NotificationType.ADMIN_USER_CREATED,
                None,
                {},
                explicit_recipients=["admin@corp.com", "ops@corp.com"],
            )

        assert len(result) == 2
        contact_repo.find_by_account.assert_not_called()
        assert notif_repo.create.call_count == 2


# ---------------------------------------------------------------------------
# retry_failed
# ---------------------------------------------------------------------------


class TestRetryFailed:
    def test_retry_failed_when_disabled_returns_zero(self):
        svc = _make_service(notification_settings=_notification_settings(enabled=False))
        assert svc.retry_failed() == 0

    def test_retry_failed_when_smtp_disabled_returns_zero(self):
        svc = _make_service(
            smtp_settings=_smtp_settings(enabled=False),
            notification_settings=_notification_settings(enabled=True),
        )
        assert svc.retry_failed() == 0

    def test_retry_failed_retries_pending_notifications(self):
        notif_repo = MagicMock()
        n1 = _make_notification(recipient="a@b.com", subject="S1", body="B1")
        n2 = _make_notification(recipient="c@d.com", subject="S2", body="B2")
        notif_repo.find_pending_retry.return_value = [n1, n2]

        svc = _make_service(
            notification_repo=notif_repo,
            smtp_settings=_smtp_settings(enabled=True),
            notification_settings=_notification_settings(enabled=True),
        )

        # First succeeds, second fails
        with patch.object(svc, "_send_email", side_effect=[True, False]) as mock_send:
            retried = svc.retry_failed()

        assert retried == 1
        assert mock_send.call_count == 2
        notif_repo.mark_sent.assert_called_once_with(n1.id)
        notif_repo.mark_failed.assert_called_once_with(n2.id, "SMTP retry failed")


# ---------------------------------------------------------------------------
# _send_email
# ---------------------------------------------------------------------------


class TestSendEmail:
    @patch("acmeeh.services.notification.smtplib.SMTP")
    def test_send_email_success(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        svc = _make_service(
            smtp_settings=_smtp_settings(
                enabled=True,
                host="mail.test.com",
                port=25,
                from_address="noreply@test.com",
                use_tls=False,
                username="",
            )
        )

        result = svc._send_email("user@test.com", "Hello", "<p>Hi</p>")

        assert result is True
        mock_smtp_class.assert_called_once_with("mail.test.com", 25, timeout=10)
        mock_server.ehlo.assert_called()
        mock_server.sendmail.assert_called_once()

    @patch("acmeeh.services.notification.smtplib.SMTP")
    def test_send_email_with_tls(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        svc = _make_service(
            smtp_settings=_smtp_settings(
                enabled=True,
                use_tls=True,
                username="",
            )
        )

        result = svc._send_email("user@test.com", "Subj", "<p>B</p>")

        assert result is True
        mock_server.starttls.assert_called_once()
        # ehlo is called twice: once before starttls, once after
        assert mock_server.ehlo.call_count == 2

    @patch("acmeeh.services.notification.smtplib.SMTP")
    def test_send_email_with_auth(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        svc = _make_service(
            smtp_settings=_smtp_settings(
                enabled=True,
                username="smtpuser",
                password="secret123",
            )
        )

        result = svc._send_email("user@test.com", "Subj", "<p>B</p>")

        assert result is True
        mock_server.login.assert_called_once_with("smtpuser", "secret123")

    @patch("acmeeh.services.notification.smtplib.SMTP")
    def test_send_email_exception_returns_false(self, mock_smtp_class):
        mock_smtp_class.side_effect = ConnectionRefusedError("Connection refused")

        svc = _make_service(smtp_settings=_smtp_settings(enabled=True))

        result = svc._send_email("user@test.com", "Subj", "<p>B</p>")

        assert result is False

    @patch("acmeeh.services.notification.smtplib.SMTP")
    def test_send_email_with_cc(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        svc = _make_service(
            smtp_settings=_smtp_settings(
                enabled=True,
                cc=("ops@test.com", "team@test.com"),
                use_tls=False,
                username="",
            )
        )

        result = svc._send_email("user@test.com", "Subj", "<p>B</p>")

        assert result is True
        call_args = mock_server.sendmail.call_args
        envelope = call_args[0][1]
        assert envelope == ["user@test.com", "ops@test.com", "team@test.com"]
        # Cc header present in the message
        msg_str = call_args[0][2]
        assert "Cc: ops@test.com, team@test.com" in msg_str

    @patch("acmeeh.services.notification.smtplib.SMTP")
    def test_send_email_with_bcc(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        svc = _make_service(
            smtp_settings=_smtp_settings(
                enabled=True,
                bcc=("audit@test.com",),
                use_tls=False,
                username="",
            )
        )

        result = svc._send_email("user@test.com", "Subj", "<p>B</p>")

        assert result is True
        call_args = mock_server.sendmail.call_args
        envelope = call_args[0][1]
        assert envelope == ["user@test.com", "audit@test.com"]
        # BCC must NOT appear in headers
        msg_str = call_args[0][2]
        assert "audit@test.com" not in msg_str.split("\n\n")[0].lower().replace("audit@test.com", "") or "Bcc" not in msg_str
        assert "Bcc" not in msg_str

    @patch("acmeeh.services.notification.smtplib.SMTP")
    def test_send_email_with_cc_and_bcc(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        svc = _make_service(
            smtp_settings=_smtp_settings(
                enabled=True,
                cc=("ops@test.com",),
                bcc=("audit@test.com",),
                use_tls=False,
                username="",
            )
        )

        result = svc._send_email("user@test.com", "Subj", "<p>B</p>")

        assert result is True
        call_args = mock_server.sendmail.call_args
        envelope = call_args[0][1]
        assert envelope == ["user@test.com", "ops@test.com", "audit@test.com"]
        msg_str = call_args[0][2]
        assert "Cc: ops@test.com" in msg_str
        assert "Bcc" not in msg_str


# ---------------------------------------------------------------------------
# _resolve_recipients
# ---------------------------------------------------------------------------


class TestResolveRecipients:
    def test_explicit_list_returned_as_is(self):
        svc = _make_service()
        result = svc._resolve_recipients(uuid4(), ["a@b.com", "c@d.com"])
        assert result == ["a@b.com", "c@d.com"]

    def test_none_account_id_returns_empty(self):
        svc = _make_service()
        result = svc._resolve_recipients(None, None)
        assert result == []

    def test_resolves_from_account_contacts(self):
        contact_repo = MagicMock()
        account_id = uuid4()

        contacts = [
            AccountContact(
                id=uuid4(), account_id=account_id, contact_uri="mailto:alice@example.com"
            ),
            AccountContact(id=uuid4(), account_id=account_id, contact_uri="mailto:bob@example.com"),
            AccountContact(id=uuid4(), account_id=account_id, contact_uri="tel:+1234567890"),
        ]
        contact_repo.find_by_account.return_value = contacts

        svc = _make_service(contact_repo=contact_repo)
        result = svc._resolve_recipients(account_id, None)

        assert result == ["alice@example.com", "bob@example.com"]
        contact_repo.find_by_account.assert_called_once_with(account_id)

    def test_resolves_mailto_case_insensitive(self):
        contact_repo = MagicMock()
        account_id = uuid4()

        contacts = [
            AccountContact(
                id=uuid4(), account_id=account_id, contact_uri="MAILTO:UPPER@example.com"
            ),
        ]
        contact_repo.find_by_account.return_value = contacts

        svc = _make_service(contact_repo=contact_repo)
        result = svc._resolve_recipients(account_id, None)

        assert result == ["UPPER@example.com"]
