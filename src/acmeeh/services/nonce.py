"""Nonce service — create, consume, and garbage-collect replay nonces.

Each ACME request must carry a fresh nonce in the JWS protected
header.  The server issues nonces via ``Replay-Nonce`` headers and
consumes them exactly once.

Nonces have a configurable TTL (``expiry_seconds``) and are enforced
via the ``expires_at`` column in the database.

**Batch pre-generation** (pool pressure mitigation):
Instead of one DB INSERT per response, nonces are bulk-inserted in
batches of ``_BATCH_SIZE`` and served from an in-memory buffer.  This
reduces connection pool checkouts by ~100x for nonce creation —
critical under sustained load where pool exhaustion is possible.

Usage::

    svc = NonceService(nonce_repo, nonce_settings)
    token = svc.create()         # issue a new nonce
    ok    = svc.consume(token)   # consume (True if valid)
    n     = svc.gc()             # delete expired nonces
"""

from __future__ import annotations

import collections
import logging
import secrets
import threading
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acmeeh.config.settings import NonceSettings
    from acmeeh.repositories.nonce import NonceRepository

from acmeeh.models.nonce import Nonce

log = logging.getLogger(__name__)

# Batch pre-generation tunables
_BATCH_SIZE = 100  # nonces per bulk INSERT
_REFILL_COOLDOWN = 2.0  # seconds to wait before retrying after a batch failure


class NonceService:
    """Manages ACME replay nonces with batch pre-generation."""

    def __init__(
        self,
        nonce_repo: NonceRepository,
        settings: NonceSettings,
    ) -> None:
        self._repo = nonce_repo
        self._settings = settings
        # Pre-generated nonce buffer — serves nonces without per-response DB hits.
        # Each entry is ``(token, expires_at)`` so we can drop entries that
        # aged out while sitting in the deque (low-traffic workers otherwise
        # hand out tokens the DB GC has already removed).
        self._buffer: collections.deque[tuple[str, datetime]] = collections.deque()
        self._buffer_lock = threading.Lock()
        self._last_refill_failure: float = 0.0

    def create(self) -> str:
        """Return a nonce token for a ``Replay-Nonce`` header.

        Serves from a pre-generated buffer.  When the buffer is empty,
        a batch of nonces is bulk-inserted into the database in a
        single statement.  Falls back to single-INSERT if the batch
        fails (e.g. pool exhaustion).  When the pool is critically
        exhausted, raises immediately instead of blocking for
        ``connection_timeout`` seconds.
        """
        with self._buffer_lock:
            token = self._pop_valid_locked()
            if token is not None:
                return token
            try:
                self._refill_buffer()
            except Exception:  # noqa: BLE001
                log.debug(
                    "Batch nonce generation failed, falling back to single insert",
                )
                return self._create_single()
            token = self._pop_valid_locked()
            if token is not None:
                return token
        return self._create_single()

    def create_if_healthy(self) -> str | None:
        """Return a nonce if the pool can serve one, else ``None``.

        Unlike :meth:`create`, this never blocks waiting for a pool
        connection.  Used by the after-request hook to avoid tying up
        gunicorn workers during pool exhaustion.
        """
        # Serve from buffer first — no DB needed
        with self._buffer_lock:
            token = self._pop_valid_locked()
            if token is not None:
                return token

        # Buffer empty (or fully expired) — only refill if pool is healthy
        try:
            self._refill_buffer()
        except Exception:  # noqa: BLE001
            log.debug("Nonce generation skipped — pool likely exhausted")
            return None

        with self._buffer_lock:
            return self._pop_valid_locked()

    def _pop_valid_locked(self) -> str | None:
        """Pop the next non-expired token from the buffer (caller holds the lock).

        Discards aged-out entries: the DB's ``nonce_gc`` task deletes
        rows past ``expires_at``, so handing out such a token would
        always fail ``consume()`` and surface as ``badNonce`` to the
        client.
        """
        now = datetime.now(UTC)
        while self._buffer:
            token, expires_at = self._buffer.popleft()
            if expires_at > now:
                return token
        return None

    def _refill_buffer(self) -> None:
        """Bulk-insert a batch of nonces and load tokens into the buffer."""
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=self._settings.expiry_seconds)
        batch = [
            Nonce(
                nonce=secrets.token_urlsafe(self._settings.length),
                expires_at=expires_at,
                created_at=now,
            )
            for _ in range(_BATCH_SIZE)
        ]
        self._repo.bulk_create(batch)
        self._buffer.extend((n.nonce, n.expires_at) for n in batch)

    def _create_single(self) -> str:
        """Create and persist a single nonce (fallback when batch fails)."""
        token = secrets.token_urlsafe(self._settings.length)
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=self._settings.expiry_seconds)
        nonce = Nonce(nonce=token, expires_at=expires_at, created_at=now)
        self._repo.create(nonce)
        return token

    def consume(self, nonce_value: str) -> bool:
        """Consume a nonce (exactly-once semantics).

        The nonce must exist in the database and not be past its
        ``expires_at`` timestamp.  Both conditions are enforced
        atomically by the repository's ``DELETE … WHERE expires_at >
        now() RETURNING`` query — a single DB round-trip.

        Returns True if the nonce was valid and consumed, False otherwise.
        """
        return self._repo.consume(nonce_value)

    def gc(self, *, conn=None) -> int:
        """Garbage-collect expired nonces.

        Returns the number of deleted nonces.
        """
        return self._repo.gc_expired(conn=conn)
