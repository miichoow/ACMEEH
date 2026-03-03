"""Key change service — ACME key rollover (RFC 8555 §7.3.5).

Handles the inner+outer JWS key rollover flow, ensuring the new key
is not already in use by another account.
"""

from __future__ import annotations

import hmac
import logging
from typing import TYPE_CHECKING

from acmeeh.app.errors import MALFORMED, SERVER_INTERNAL, AcmeProblem
from acmeeh.core.jws import compute_thumbprint
from acmeeh.core.types import NotificationType

if TYPE_CHECKING:
    from uuid import UUID

    from acmeeh.models.account import Account
    from acmeeh.repositories.account import AccountRepository

log = logging.getLogger(__name__)


class KeyChangeService:
    """Manages ACME account key rollover."""

    def __init__(self, account_repo: AccountRepository, notifier=None) -> None:
        self._accounts = account_repo
        self._notifier = notifier

    def rollover(
        self,
        account_id: UUID,
        old_jwk: dict,
        new_jwk: dict,
    ) -> Account:
        """Perform an account key rollover.

        Parameters
        ----------
        account_id:
            The account whose key is being changed.
        old_jwk:
            The current (old) JWK — must match the account's key.
        new_jwk:
            The new JWK to associate with the account.

        Returns
        -------
        Account
            The updated account with the new key.

        Raises
        ------
        AcmeProblem
            ``MALFORMED`` if new key is already in use or old key
            doesn't match.

        """
        # Compute new thumbprint
        new_thumbprint = compute_thumbprint(new_jwk)

        # Check no existing account uses the new key
        existing = self._accounts.find_by_thumbprint(new_thumbprint)
        if existing is not None:
            raise AcmeProblem(
                MALFORMED,
                "The new key is already associated with an existing account",
                status=409,
            )

        # Verify old key matches account
        old_thumbprint = compute_thumbprint(old_jwk)
        account = self._accounts.find_by_id(account_id)
        if account is None:
            raise AcmeProblem(MALFORMED, "Account not found", status=404)
        if not hmac.compare_digest(account.jwk_thumbprint, old_thumbprint):
            raise AcmeProblem(
                MALFORMED,
                "Old key does not match the account's current key",
            )

        # Update the key
        result = self._accounts.update_jwk(account_id, new_jwk, new_thumbprint)
        if result is None:
            raise AcmeProblem(
                SERVER_INTERNAL,
                "Key rollover failed — account may not be in valid status",
                status=500,
            )

        log.info("Key rollover completed for account %s", account_id)
        if self._notifier:
            try:
                self._notifier.notify(
                    NotificationType.KEY_ROLLOVER_SUCCEEDED,
                    account_id,
                    {
                        "account_id": str(account_id),
                        "old_thumbprint": old_thumbprint,
                        "new_thumbprint": new_thumbprint,
                    },
                )
            except Exception:  # noqa: BLE001
                log.exception("Failed to send KEY_ROLLOVER_SUCCEEDED notification")
        return result
