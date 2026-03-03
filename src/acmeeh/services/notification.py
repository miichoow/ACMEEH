"""Notification service — email dispatch, retries, and audit trail.

Graceful degradation:
- ``notifications.enabled=False`` → complete no-op
- ``smtp.enabled=False`` → records persisted but not sent (audit trail)
- SMTP failure → recorded as FAILED, eligible for background retry
"""

from __future__ import annotations

import logging
import smtplib
from datetime import UTC, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from acmeeh.core.types import NotificationStatus, NotificationType
from acmeeh.models.notification import Notification

if TYPE_CHECKING:
    from acmeeh.config.settings import NotificationSettings, SmtpSettings
    from acmeeh.notifications.renderer import TemplateRenderer
    from acmeeh.repositories.account import AccountContactRepository
    from acmeeh.repositories.notification import NotificationRepository

log = logging.getLogger(__name__)


class NotificationService:
    """Manages email notification lifecycle."""

    def __init__(
        self,
        notification_repo: NotificationRepository,
        contact_repo: AccountContactRepository,
        smtp_settings: SmtpSettings,
        notification_settings: NotificationSettings,
        renderer: TemplateRenderer,
        server_url: str,
    ) -> None:
        self._notifications = notification_repo
        self._contacts = contact_repo
        self._smtp = smtp_settings
        self._settings = notification_settings
        self._renderer = renderer
        self._server_url = server_url

    def notify(
        self,
        notification_type: NotificationType,
        account_id: UUID | None,
        context: dict[str, Any],
        *,
        explicit_recipients: list[str] | None = None,
    ) -> list[Notification]:
        """Create and attempt to send notifications.

        Parameters
        ----------
        notification_type:
            The type of notification event.
        account_id:
            The account to notify (contacts looked up from DB).
        context:
            Template variables for rendering.
        explicit_recipients:
            Override recipients instead of looking up account contacts.

        Returns
        -------
        list[Notification]
            All notification records created (regardless of send status).

        """
        if not self._settings.enabled:
            return []

        if notification_type.value in self._settings.disabled_types:
            log.debug(
                "Notification type %s is disabled — skipping",
                notification_type.value,
            )
            return []

        # Resolve recipients
        recipients = self._resolve_recipients(account_id, explicit_recipients)
        if not recipients:
            log.debug(
                "No recipients for %s notification (account=%s)",
                notification_type.value,
                account_id,
            )
            return []

        # Inject common context
        context = {
            **context,
            "server_url": self._server_url,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        # Render template
        subject, body = self._renderer.render(notification_type, context)

        # Phase 1: Create all notification records (DB operations)
        notifications: list[Notification] = []
        for recipient in recipients:
            notification = Notification(
                id=uuid4(),
                notification_type=notification_type,
                recipient=recipient,
                subject=subject,
                body=body,
                status=NotificationStatus.PENDING,
                account_id=account_id,
            )
            self._notifications.create(notification)
            notifications.append(notification)

        if not self._smtp.enabled:
            for n in notifications:
                log.debug(
                    "SMTP disabled — notification %s recorded but not sent",
                    n.id,
                )
            return notifications

        # Phase 2: Send all emails (network I/O, no DB connections held)
        send_results: list[tuple[Notification, bool]] = []
        for notification in notifications:
            success = self._send_email(notification.recipient, subject, body)
            send_results.append((notification, success))

        # Phase 3: Update all statuses (DB operations)
        results: list[Notification] = []
        for notification, success in send_results:
            if success:
                updated = self._notifications.mark_sent(notification.id)
                results.append(updated if updated else notification)
            else:
                updated = self._notifications.mark_failed(
                    notification.id,
                    "SMTP send failed",
                )
                results.append(updated if updated else notification)

        return results

    def retry_failed(self) -> int:
        """Retry failed notifications (called by background scheduler).

        Returns the number of notifications successfully retried.
        """
        if not self._settings.enabled or not self._smtp.enabled:
            return 0

        pending = self._notifications.find_pending_retry(
            max_retries=self._settings.max_retries,
            batch_size=self._settings.batch_size,
            base_delay=self._settings.retry_delay_seconds,
            backoff_multiplier=self._settings.retry_backoff_multiplier,
            max_delay=self._settings.retry_max_delay_seconds,
        )

        retried = 0
        for notification in pending:
            success = self._send_email(
                notification.recipient,
                notification.subject,
                notification.body,
            )
            if success:
                self._notifications.mark_sent(notification.id)
                retried += 1
            else:
                self._notifications.mark_failed(
                    notification.id,
                    "SMTP retry failed",
                )

        if retried:
            log.info("Retried %d/%d failed notifications", retried, len(pending))

        return retried

    def _send_email(self, recipient: str, subject: str, body: str) -> bool:
        """Send a single email via SMTP.

        Uses per-message connections (not pooled) for simplicity and
        reliability at the expected low volume.

        Never raises — catches all exceptions and returns a bool.
        """
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = self._smtp.from_address
            msg["To"] = recipient
            msg["Subject"] = subject
            if self._smtp.cc:
                msg["Cc"] = ", ".join(self._smtp.cc)
            msg.attach(MIMEText(body, "html", "utf-8"))

            envelope_recipients = (
                [recipient] + list(self._smtp.cc) + list(self._smtp.bcc)
            )

            with smtplib.SMTP(
                self._smtp.host, self._smtp.port, timeout=self._smtp.timeout_seconds
            ) as server:
                server.ehlo()
                if self._smtp.use_tls:
                    server.starttls()
                    server.ehlo()
                if self._smtp.username:
                    server.login(self._smtp.username, self._smtp.password)
                server.sendmail(
                    self._smtp.from_address,
                    envelope_recipients,
                    msg.as_string(),
                )

            return True
        except Exception:
            log.exception("Failed to send email to %s", recipient)
            return False

    def _resolve_recipients(
        self,
        account_id: UUID | None,
        explicit_recipients: list[str] | None,
    ) -> list[str]:
        """Resolve the list of email addresses to notify."""
        if explicit_recipients:
            return list(explicit_recipients)

        if account_id is None:
            return []

        contacts = self._contacts.find_by_account(account_id)
        recipients = []
        for contact in contacts:
            uri = contact.contact_uri
            if uri.lower().startswith("mailto:"):
                recipients.append(uri[7:])
        return recipients
