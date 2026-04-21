"""Repository classes for the ACMEEH persistence layer.

Each repository extends :class:`pypgkit.BaseRepository` with custom
query methods for the ACMEEH domain.
"""

from acmeeh.repositories.account import AccountContactRepository, AccountRepository
from acmeeh.repositories.authorization import AuthorizationRepository
from acmeeh.repositories.certificate import CertificateRepository
from acmeeh.repositories.challenge import ChallengeRepository
from acmeeh.repositories.nonce import NonceRepository
from acmeeh.repositories.notification import NotificationRepository
from acmeeh.repositories.order import OrderRepository
from acmeeh.repositories.server_settings import ServerSettingsRepository

__all__ = [
    "AccountContactRepository",
    "AccountRepository",
    "AuthorizationRepository",
    "CertificateRepository",
    "ChallengeRepository",
    "NonceRepository",
    "NotificationRepository",
    "OrderRepository",
    "ServerSettingsRepository",
]
