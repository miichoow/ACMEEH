"""Token management and auth decorators for the admin API."""

from __future__ import annotations

import functools
import logging
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from flask import g, request
from itsdangerous import (
    BadSignature,
    SignatureExpired,
    URLSafeTimedSerializer,
)

from acmeeh.app.errors import AcmeProblem

if TYPE_CHECKING:
    from collections.abc import Callable

    from pypgkit import Database

    from acmeeh.admin.models import AdminUser

log = logging.getLogger(__name__)

# Error type URNs for admin API (reuse pattern from ACME errors)
_ADMIN_ERR = "urn:acmeeh:admin:error:"
ADMIN_UNAUTHORIZED = _ADMIN_ERR + "unauthorized"
ADMIN_FORBIDDEN = _ADMIN_ERR + "forbidden"


class TokenBlacklist:
    """Database-backed token blacklist shared across all instances.

    Stores revoked token signatures in ``admin.token_blacklist``.
    Falls back to an in-memory dict when no database is available
    (e.g. in tests).
    """

    def __init__(self, db: Database | None = None) -> None:
        """Initialize the token blacklist.

        Args:
            db: Optional database instance for persistent storage.
        """
        self._lock = threading.Lock()
        self._revoked: dict[str, float] = {}  # in-memory fallback
        self._db = db

    def set_db(self, db: Database) -> None:
        """Attach a database connection for HA-safe operation."""
        self._db = db

    def revoke_token(
        self,
        token: str,
        max_age_seconds: int = 3600,
    ) -> None:
        """Revoke a token by storing its signature portion."""
        sig = self._extract_signature(token)
        if self._db is not None:
            expires_at = datetime.now(UTC) + timedelta(seconds=max_age_seconds)
            try:
                self._db.execute(
                    "INSERT INTO admin.token_blacklist "  # noqa: S608
                    "(token_signature, expires_at) "
                    "VALUES (%s, %s) "
                    "ON CONFLICT (token_signature) DO NOTHING",
                    (sig, expires_at),
                )
            except Exception:  # noqa: BLE001
                log.exception(
                    "Failed to write token to DB blacklist, falling back to memory",
                )
            else:
                return
        with self._lock:
            self._revoked[sig] = time.monotonic()

    def is_revoked(self, token: str) -> bool:
        """Check whether a token has been revoked."""
        sig = self._extract_signature(token)
        if self._db is not None:
            try:
                row = self._db.fetch_value(
                    "SELECT 1 FROM admin.token_blacklist "  # noqa: S608
                    "WHERE token_signature = %s "
                    "AND expires_at > now()",
                    (sig,),
                )
                if row is not None:
                    return True
            except Exception:  # noqa: BLE001
                log.exception(
                    "Failed to check DB token blacklist, checking memory",
                )
                from acmeeh.db.init import log_pool_stats  # noqa: PLC0415

                log_pool_stats(self._db, "token_blacklist")
        with self._lock:
            return sig in self._revoked

    def cleanup(self, max_age_seconds: int) -> int:
        """Remove expired entries.

        Returns:
            Count of removed entries.
        """
        removed = 0
        if self._db is not None:
            try:
                removed = self._db.execute(
                    "DELETE FROM admin.token_blacklist WHERE expires_at < now()",
                )
            except Exception:  # noqa: BLE001
                log.exception(
                    "Failed to clean up DB token blacklist",
                )
        # Also clean in-memory fallback
        cutoff = time.monotonic() - max_age_seconds
        with self._lock:
            expired = [sig for sig, ts in self._revoked.items() if ts < cutoff]
            for sig in expired:
                del self._revoked[sig]
                removed += len(expired)
        return removed

    @staticmethod
    def _extract_signature(token: str) -> str:
        """Extract the signature part of an itsdangerous token."""
        # itsdangerous tokens are payload.timestamp.signature
        parts = token.rsplit(".", 1)
        return parts[-1] if len(parts) > 1 else token


# Module-level singleton
_token_blacklist = TokenBlacklist()


def get_token_blacklist() -> TokenBlacklist:
    """Return the module-level token blacklist singleton."""
    return _token_blacklist


class LoginRateLimiter:
    """In-memory rate limiter for admin login attempts.

    Tracks failed attempts per IP/username and blocks after
    max_attempts within window_seconds.
    Lockout lasts lockout_seconds.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 900,
    ) -> None:
        """Initialize the rate limiter.

        Args:
            max_attempts: Allowed failures before lockout.
            window_seconds: Time window for counting failures.
            lockout_seconds: Duration of the lockout period.
        """
        self._max_attempts = max_attempts
        self._window = window_seconds
        self._lockout = lockout_seconds
        self._attempts: dict[str, list[float]] = {}
        self._lockouts: dict[str, float] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        """Raise ``AcmeProblem`` if the key is locked out."""
        now = time.monotonic()
        with self._lock:
            lockout_until = self._lockouts.get(key, 0)
            if now < lockout_until:
                remaining = int(lockout_until - now)
                raise AcmeProblem(
                    ADMIN_UNAUTHORIZED,
                    f"Too many failed login attempts. Try again in {remaining} seconds.",
                    status=429,
                    headers={
                        "Retry-After": str(remaining),
                    },
                )

    def record_failure(self, key: str) -> None:
        """Record a failed login attempt."""
        now = time.monotonic()
        with self._lock:
            attempts = self._attempts.setdefault(key, [])
            # Prune old attempts outside the window
            cutoff = now - self._window
            self._attempts[key] = [t for t in attempts if t > cutoff]
            self._attempts[key].append(now)
            if len(self._attempts[key]) >= self._max_attempts:
                self._lockouts[key] = now + self._lockout
                log.warning(
                    "Login lockout triggered for key: %s",
                    key,
                )

    def record_success(self, key: str) -> None:
        """Clear attempts on successful login."""
        with self._lock:
            self._attempts.pop(key, None)
            self._lockouts.pop(key, None)


_login_limiter = LoginRateLimiter()


def get_login_limiter() -> LoginRateLimiter:
    """Return the module-level login rate limiter."""
    return _login_limiter


def create_token(
    user: AdminUser,
    secret: str,
    max_age: int,
) -> str:
    """Create a signed bearer token for an admin user."""
    _ = max_age  # reserved for future per-token TTL
    serializer = URLSafeTimedSerializer(secret)
    return serializer.dumps(
        {
            "user_id": str(user.id),
            "username": user.username,
            "role": user.role.value,
        }
    )


def decode_token(
    token: str,
    secret: str,
    max_age: int,
) -> dict[str, Any] | None:
    """Decode and validate a bearer token.

    Returns the payload dict or ``None`` if invalid/expired.
    """
    serializer = URLSafeTimedSerializer(secret)
    try:
        return serializer.loads(token, max_age=max_age)  # type: ignore[return-value]
    except (BadSignature, SignatureExpired):
        return None


def require_admin_auth(
    fn: Callable[..., Any],
) -> Callable[..., Any]:
    """Enforce bearer token auth on admin endpoints.

    Load the admin user from the DB, check enabled status,
    and store the user on ``g.admin_user``.
    """

    @functools.wraps(fn)
    def wrapper(
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        from uuid import UUID  # noqa: PLC0415

        from acmeeh.app.context import get_container  # noqa: PLC0415

        container = get_container()
        settings = container.settings.admin_api

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise AcmeProblem(
                ADMIN_UNAUTHORIZED,
                "Missing or invalid Authorization header",
                status=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header[7:]

        # Check blacklist before decoding
        if _token_blacklist.is_revoked(token):
            raise AcmeProblem(
                ADMIN_UNAUTHORIZED,
                "Token has been revoked",
                status=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        payload = decode_token(
            token,
            settings.token_secret,
            settings.token_expiry_seconds,
        )
        if payload is None:
            raise AcmeProblem(
                ADMIN_UNAUTHORIZED,
                "Invalid or expired token",
                status=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        assert container.admin_user_repo is not None
        user = container.admin_user_repo.find_by_id(
            UUID(payload["user_id"]),
        )
        if user is None or not user.enabled:
            raise AcmeProblem(
                ADMIN_UNAUTHORIZED,
                "Account disabled or not found",
                status=401,
            )

        g.admin_user = user
        return fn(*args, **kwargs)

    return wrapper


def require_role(
    *roles: str,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Restrict access to specific admin roles.

    Must be applied **after** ``@require_admin_auth``.
    """

    def decorator(
        fn: Callable[..., Any],
    ) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            user = g.admin_user
            if user.role.value not in roles:
                raise AcmeProblem(
                    ADMIN_FORBIDDEN,
                    f"Role '{user.role.value}' does not have permission for this action",
                    status=403,
                )
            return fn(*args, **kwargs)

        return wrapper

    return decorator
