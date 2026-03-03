"""Rate limiters — in-memory and database-backed.

Thread-safe, keyed by (category, client_ip).  Raises
:class:`~acmeeh.app.errors.AcmeProblem` (429) when a limit is exceeded.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from acmeeh.app.errors import RATE_LIMITED, AcmeProblem

if TYPE_CHECKING:
    from pypgkit import Database

    from acmeeh.config.settings import RateLimitSettings

log = logging.getLogger(__name__)


class InMemoryRateLimiter:
    """Sliding-window counter rate limiter (in-memory)."""

    def __init__(self, settings: RateLimitSettings) -> None:
        self._settings = settings
        self._windows: dict[str, dict[str, list[float]]] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

    def check(self, key: str, category: str) -> None:
        if not self._settings.enabled:
            return

        rule = getattr(self._settings, category, None)
        if rule is None:
            return

        now = time.monotonic()
        window_start = now - rule.window_seconds
        compound_key = f"{category}:{key}"

        with self._lock:
            self._maybe_cleanup(now)

            bucket = self._windows.setdefault(category, {})
            timestamps = bucket.get(compound_key)

            if timestamps is None:
                bucket[compound_key] = [now]
                return

            timestamps[:] = [t for t in timestamps if t > window_start]

            if len(timestamps) >= rule.requests:
                oldest = min(timestamps) if timestamps else now
                retry_after = int(oldest + rule.window_seconds - now) + 1
                from acmeeh.logging import security_events

                security_events.rate_limit_exceeded(key, category, key)
                raise AcmeProblem(
                    RATE_LIMITED,
                    f"Rate limit exceeded for {category}. Try again in {retry_after} seconds.",
                    status=429,
                    headers={"Retry-After": str(retry_after)},
                )

            timestamps.append(now)

    def _maybe_cleanup(self, now: float) -> None:
        if now - self._last_cleanup < self._settings.gc_interval_seconds:
            return
        self._last_cleanup = now
        for category in list(self._windows):
            bucket = self._windows[category]
            rule = getattr(self._settings, category, None)
            if rule is None:
                continue
            window_start = now - rule.window_seconds
            for compound_key in list(bucket):
                bucket[compound_key] = [t for t in bucket[compound_key] if t > window_start]
                if not bucket[compound_key]:
                    del bucket[compound_key]


class DatabaseRateLimiter:
    """Fixed-window counter rate limiter backed by PostgreSQL.

    Uses ``INSERT ... ON CONFLICT DO UPDATE`` for atomic upserts.
    Each window is aligned to ``floor(now / window_seconds) * window_seconds``.
    """

    def __init__(self, settings: RateLimitSettings, db: Database) -> None:
        self._settings = settings
        self._db = db

    def check(self, key: str, category: str) -> None:
        if not self._settings.enabled:
            return

        rule = getattr(self._settings, category, None)
        if rule is None:
            return

        # Fast fail-open: if the pool is under pressure, skip the DB
        # check entirely instead of blocking for connection_timeout
        # seconds and causing cascading exhaustion.
        from acmeeh.db.init import is_pool_healthy  # noqa: PLC0415

        if not is_pool_healthy(self._db):
            log.debug(
                "Rate limiter: pool under pressure — fail-open for %s:%s",
                category,
                key,
            )
            return

        now = datetime.now(UTC)
        epoch = now.timestamp()
        window_start_ts = math.floor(epoch / rule.window_seconds) * rule.window_seconds
        window_start = datetime.fromtimestamp(window_start_ts, tz=UTC)
        compound_key = f"{category}:{key}"

        # Atomic upsert + fetch in a single SQL statement to avoid
        # checking out two separate pool connections.
        try:
            total = self._db.fetch_value(
                "WITH upsert AS ("
                "  INSERT INTO rate_limit_counters (compound_key, window_start, counter) "
                "  VALUES (%s, %s, 1) "
                "  ON CONFLICT (compound_key, window_start) "
                "  DO UPDATE SET counter = rate_limit_counters.counter + 1 "
                "  RETURNING counter"
                ") SELECT counter FROM upsert",
                (compound_key, window_start),
            )
        except Exception:  # noqa: BLE001
            # Fail-open: if the pool is exhausted or the DB is unreachable,
            # allow the request through rather than blocking for 30s and
            # causing cascading pool exhaustion.
            log.warning(
                "Rate limiter DB check failed (fail-open): key=%s category=%s",
                key,
                category,
            )
            return

        if total is not None and total > rule.requests:
            retry_after = rule.window_seconds - int(epoch - window_start_ts)
            retry_after = max(retry_after, 1)
            from acmeeh.logging import security_events  # noqa: PLC0415

            security_events.rate_limit_exceeded(key, category, key)
            raise AcmeProblem(
                RATE_LIMITED,
                f"Rate limit exceeded for {category}. Try again in {retry_after} seconds.",
                status=429,
                headers={"Retry-After": str(retry_after)},
            )

    def gc(self, max_age_seconds: int | None = None, *, conn=None) -> int:
        """Delete expired rate limit counters. Returns rows deleted."""
        if max_age_seconds is None:
            max_age_seconds = self._settings.gc_max_age_seconds
        cutoff = datetime.fromtimestamp(
            time.time() - max_age_seconds,
            tz=UTC,
        )
        db = conn or self._db
        return db.execute(
            "DELETE FROM rate_limit_counters WHERE window_start < %s",
            (cutoff,),
        )


# Keep the old name as an alias for backward compatibility
RateLimiter = InMemoryRateLimiter


def create_rate_limiter(
    settings: RateLimitSettings,
    db: Database | None = None,
) -> InMemoryRateLimiter | DatabaseRateLimiter:
    """Factory: create the appropriate rate limiter based on config."""
    if settings.backend == "database" and db is not None:
        log.info("Using database-backed rate limiter")
        return DatabaseRateLimiter(settings, db)
    log.info("Using in-memory rate limiter")
    return InMemoryRateLimiter(settings)
