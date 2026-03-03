"""Database initialisation from ACMEEH configuration.

Usage::

    from acmeeh.config import get_config
    from acmeeh.db.init import init_database

    init_database(get_config().settings.database)
"""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import Generator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pypgkit import Database, DatabaseConfig

if TYPE_CHECKING:
    from acmeeh.config.settings import DatabaseSettings

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pool helpers
# ---------------------------------------------------------------------------


def _get_raw_pool(db: Any) -> Any | None:
    """Navigate the PyPGKit pool hierarchy to find the raw psycopg_pool.

    PyPGKit wraps psycopg_pool.ConnectionPool in a ConnectionPoolSingleton.
    The hierarchy is::

        Database.pool  ->  ConnectionPoolSingleton
        ConnectionPoolSingleton._pool  ->  psycopg_pool.ConnectionPool

    We try private attrs first to avoid properties that raise when the
    pool is in a closed/uninitialised state.
    """
    wrapper = getattr(db, "pool", None) or getattr(db, "_pool", None)
    if wrapper is None:
        return None
    # If the wrapper itself has close+open+get_stats, it might already
    # be the raw pool (e.g. if PyPGKit exposes it directly).
    if hasattr(wrapper, "get_stats") and hasattr(wrapper, "open"):
        return wrapper
    # Otherwise dig into the wrapper for the raw psycopg_pool
    for attr in ("_pool", "_conn_pool"):
        candidate = getattr(wrapper, attr, None)
        if candidate is not None and candidate is not wrapper:
            return candidate
    return wrapper  # return whatever we have as last resort


def log_pool_stats(db: Any, context: str = "") -> None:
    """Log connection pool statistics for debugging pool exhaustion."""
    pool = _get_raw_pool(db)
    if pool is None:
        return
    try:
        stats = pool.get_stats()
        log.warning(
            "Pool stats%s: size=%s available=%s waiting=%s",
            f" ({context})" if context else "",
            stats.get("pool_size", "?"),
            stats.get("pool_available", "?"),
            stats.get("requests_waiting", "?"),
        )
    except Exception:  # noqa: BLE001, S110
        pass


def get_pool_health(
    db: Any, pressure_threshold: int = 3,
) -> tuple[str, dict[str, int]]:
    """Return the pool health level and raw stats.

    Graduated response levels:

    * ``"healthy"`` — available connections above *pressure_threshold*
    * ``"pressure"`` — available connections at or below threshold
    * ``"critical"`` — zero available **and** requests already waiting

    Returns ``("healthy", {})`` when the pool is inaccessible.
    """
    pool = _get_raw_pool(db)
    if pool is None or not hasattr(pool, "get_stats"):
        return "healthy", {}
    try:
        stats = pool.get_stats()
        available = stats.get("pool_available", 1)
        waiting = stats.get("requests_waiting", 0)
        info = {
            "available": available,
            "waiting": waiting,
            "size": stats.get("pool_size", 0),
            "max": stats.get("pool_max", 0),
        }
        pool_size = stats.get("pool_size", 0)
        checked_out = pool_size - available
        if available == 0 and waiting > 0:
            return "critical", info
        if available <= pressure_threshold and checked_out > 0:
            return "pressure", info
        return "healthy", info
    except Exception:  # noqa: BLE001
        return "healthy", {}


def is_pool_healthy(db: Any, reserve: int = 2) -> bool:
    """Return ``True`` when the pool has more than *reserve* connections free.

    Background workers should call this before starting a work cycle
    and yield to request-handling threads when it returns ``False``.
    """
    health, _ = get_pool_health(db, pressure_threshold=reserve)
    return health == "healthy"


# ---------------------------------------------------------------------------
# Connection wrapper for advisory lock reuse
# ---------------------------------------------------------------------------


class _ConnectionWrapper:
    """Wrap a psycopg connection with a PyPGKit-compatible interface.

    Allows the advisory-lock connection to be reused for DB operations
    inside the lock context, avoiding a second pool checkout that leads
    to pool exhaustion when multiple background workers run concurrently.
    """

    __slots__ = ("_conn",)

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def execute(self, query: str, params: tuple | None = None) -> int:
        """Execute and return rowcount (matches ``Database.execute``)."""
        cur = self._conn.execute(query, params)
        return cur.rowcount

    def fetch_all(
        self, query: str, params: tuple | None = None, *, as_dict: bool = False,
    ) -> list:
        """Fetch all rows (matches ``Database.fetch_all``)."""
        if as_dict:
            from psycopg.rows import dict_row

            cur = self._conn.cursor(row_factory=dict_row)
            cur.execute(query, params)
            return cur.fetchall()
        return self._conn.execute(query, params).fetchall()

    def fetch_one(
        self, query: str, params: tuple | None = None, *, as_dict: bool = False,
    ) -> Any | None:
        """Fetch one row (matches ``Database.fetch_one``)."""
        if as_dict:
            from psycopg.rows import dict_row

            cur = self._conn.cursor(row_factory=dict_row)
            cur.execute(query, params)
            return cur.fetchone()
        return self._conn.execute(query, params).fetchone()

    def fetch_value(self, query: str, params: tuple | None = None) -> Any | None:
        """Fetch a single scalar value (matches ``Database.fetch_value``)."""
        row = self._conn.execute(query, params).fetchone()
        return row[0] if row else None


@contextlib.contextmanager
def advisory_lock(db: Any, lock_id: int) -> Generator[tuple[bool, _ConnectionWrapper | None], None, None]:
    """Hold a PostgreSQL advisory lock on a single dedicated connection.

    Ensures lock and unlock happen on the **same** connection, fixing the
    broken pattern where session-level advisory locks with a connection
    pool could acquire/release on different connections.

    Uses ``Database.connection()`` (PyPGKit's public context manager) to
    obtain a connection that is held for the duration of the ``with``
    block and returned to the pool on exit.

    Yields a ``(acquired, conn)`` tuple.  *conn* is a
    :class:`_ConnectionWrapper` around the lock's connection when
    *acquired* is True — callers should use it for DB operations inside
    the lock to avoid checking out a second pool connection.  *conn* is
    ``None`` when the lock was not acquired or when no database is
    available.

    Raises on pool exhaustion so callers can log and skip the cycle.
    """
    if db is None:
        yield True, None
        return

    if not callable(getattr(db, "connection", None)):
        yield True, None
        return

    # Pre-check: bail immediately when the pool has no connections
    # available.  Blocking on db.connection() would add this caller
    # to requests_waiting in pool stats.  The pool pressure guard
    # then sees waiting>0 and rejects ALL HTTP requests — but since
    # those requests never reach the DB layer, no connections are
    # ever freed, creating a permanent 503 deadlock.  Background
    # workers (the primary callers) retry on the next cycle.
    pool = _get_raw_pool(db)
    if pool is not None and hasattr(pool, "get_stats"):
        try:
            stats = pool.get_stats()
            if stats.get("pool_available", 1) == 0:
                yield False, None
                return
        except Exception:  # noqa: BLE001, S110
            pass

    acquired = False
    with db.connection() as conn:
        row = conn.execute(
            "SELECT pg_try_advisory_lock(%s)", (lock_id,),
        ).fetchone()
        acquired = bool(row and row[0])
        try:
            yield acquired, _ConnectionWrapper(conn) if acquired else None
        finally:
            if acquired:
                with contextlib.suppress(Exception):
                    conn.execute(
                        "SELECT pg_advisory_unlock(%s)", (lock_id,),
                    )


def reinit_pool_after_fork() -> None:
    """Reset the connection pool completely after a gunicorn fork.

    After ``fork()``, the child process inherits the master's pool state
    which is broken in four ways:

    1. **Stale connections** — idle connections in ``_pool`` share
       PostgreSQL sessions with the master via duplicated file
       descriptors.  Using them risks session corruption.
    2. **Dead threads** — psycopg_pool's worker and scheduler threads
       don't survive ``fork()``.  Any ``AddConnection`` tasks (including
       those queued by ``check()``) go to a dead task queue and are
       never processed.
    3. **Ghost connections** — ``_nconns`` includes slots checked out in
       the master.  No code in the child holds them, so they are never
       returned — creating permanent phantom "in use" slots.
    4. **Stuck growth flag** — ``_growing`` may be ``True`` from an
       in-flight grow operation in the master, permanently blocking
       ``_maybe_grow_pool()`` in the child.

    Instead of calling ``check()`` (which schedules replacement tasks to
    dead worker threads), we perform a full pool reset: close all
    inherited connections, reset internal state, and call ``open()`` to
    spawn fresh threads that fill the pool with new connections.

    Must be called in gunicorn's ``post_fork`` hook **before** any DB
    access (including background worker startup).
    """
    if not Database.is_initialized():
        return

    db = Database.get_instance()
    raw_pool = _get_raw_pool(db)
    if raw_pool is None:
        log.warning(
            "Cannot reset pool after fork: "
            "pool attribute not accessible on Database",
        )
        return

    # Verify this looks like a psycopg_pool ConnectionPool with the
    # internals we need.  If not, fall back to check() as best effort.
    if not _has_pool_internals(raw_pool):
        log.warning(
            "Pool does not expose expected psycopg_pool internals "
            "(pid=%d) — falling back to check()",
            os.getpid(),
        )
        if hasattr(raw_pool, "check"):
            try:
                raw_pool.check()
            except Exception:  # noqa: BLE001
                log.exception("check() failed after fork")
        return

    _reset_pool_after_fork(raw_pool)


def _has_pool_internals(pool: Any) -> bool:
    """Return ``True`` when *pool* exposes the internal attributes we need."""
    required = ("_pool", "_nconns", "_closed", "_opened", "_workers", "open")
    return all(hasattr(pool, attr) for attr in required)


def _close_inherited_connections(raw_pool: Any) -> int:
    """Close all idle connections inherited from the master process.

    These connections share PostgreSQL sessions with the master via
    duplicated file descriptors and are unsafe to use in the child.
    """
    pool_deque = getattr(raw_pool, "_pool", None)
    if pool_deque is None:
        return 0

    closed = 0
    while pool_deque:
        try:
            conn = pool_deque.popleft()
        except IndexError:
            break
        with contextlib.suppress(Exception):
            conn.close()
        closed += 1

    return closed


def _reset_pool_after_fork(raw_pool: Any) -> None:
    """Full pool reset after fork.

    Closes inherited connections, resets all internal counters, flags,
    and dead thread references, then reopens the pool so it fills with
    fresh connections belonging to this child process.

    Operates directly on psycopg_pool 3.x ``ConnectionPool`` internals::

        _pool          deque of idle connections
        _nconns        total connection count (idle + checked-out)
        _growing       one-at-a-time growth flag
        _nconns_min    shrink-tracking counter
        _workers       list of worker Thread objects (dead after fork)
        _sched_runner  scheduler Thread (dead after fork)
        _waiting       deque of clients waiting for a connection
        _closed        pool-is-not-serving flag
        _opened        pool-has-been-opened-at-least-once flag

    After resetting these, ``open()`` creates a fresh task queue,
    scheduler, and worker threads, then schedules ``_nconns``
    ``AddConnection`` tasks to fill the pool.
    """
    pid = os.getpid()
    min_size = getattr(raw_pool, "_min_size", 5)  # noqa: SLF001

    # --- Step 1: Close inherited connections ---
    # They share PostgreSQL sessions with the master and are unsafe.
    closed = _close_inherited_connections(raw_pool)

    # --- Step 2: Reset connection tracking ---
    # All connections are now closed; zero out the counter.  We set it
    # to min_size in step 7 before open() so _start_initial_tasks()
    # knows how many AddConnection tasks to schedule.
    raw_pool._nconns = 0               # noqa: SLF001

    if hasattr(raw_pool, "_growing"):
        raw_pool._growing = False      # noqa: SLF001
    if hasattr(raw_pool, "_nconns_min"):
        raw_pool._nconns_min = 0       # noqa: SLF001

    # --- Step 3: Clear master's client wait queue ---
    waiting = getattr(raw_pool, "_waiting", None)
    if waiting is not None:
        waiting.clear()
    if hasattr(raw_pool, "_pool_full_event"):
        raw_pool._pool_full_event = None  # noqa: SLF001

    # --- Step 4: Clear dead thread references ---
    # Threads don't survive fork().  The old Thread objects are zombies.
    # _start_workers() asserts ``not self._workers``, so we MUST clear
    # the list before calling open().
    raw_pool._workers = []             # noqa: SLF001
    if hasattr(raw_pool, "_sched_runner"):
        raw_pool._sched_runner = None  # noqa: SLF001

    # --- Step 5: Reset lock ---
    # RLock state is undefined after fork (may be held by a thread that
    # no longer exists).  Delete it so _ensure_lock() recreates fresh.
    with contextlib.suppress(AttributeError):
        delattr(raw_pool, "_lock")

    # --- Step 6: Allow _open() to run ---
    # _open() returns early if ``not _closed``.
    # _check_open() raises if ``_opened and _closed`` (pool was opened
    # then closed and cannot be reused).
    # Setting _closed=True, _opened=False bypasses both guards.
    raw_pool._closed = True            # noqa: SLF001
    raw_pool._opened = False           # noqa: SLF001

    # --- Step 7: Set _nconns for initial fill ---
    # _start_initial_tasks() schedules exactly _nconns AddConnection
    # tasks, so we set this to min_size before open().
    raw_pool._nconns = min_size        # noqa: SLF001

    # --- Step 8: Reopen the pool ---
    # open() → _open() creates fresh _tasks Queue, _sched Scheduler,
    # spawns new worker/scheduler threads, and schedules AddConnection
    # tasks to fill the pool with fresh connections.
    try:
        raw_pool.open(wait=False)
        log.info(
            "Pool fully reset after fork: closed %d inherited "
            "connection(s), restarting with min_size=%d (pid=%d)",
            closed,
            min_size,
            pid,
        )
    except Exception:  # noqa: BLE001
        log.exception(
            "Failed to reopen pool after fork (pid=%d) — "
            "pool may be non-functional",
            pid,
        )


def _settings_to_config(settings: DatabaseSettings) -> DatabaseConfig:
    """Map ACMEEH DatabaseSettings to PyPGKit DatabaseConfig."""
    return DatabaseConfig(
        host=settings.host,
        port=settings.port,
        database=settings.database,
        user=settings.user,
        password=settings.password,
        sslmode=settings.sslmode,
        min_connections=settings.min_connections,
        max_connections=settings.max_connections,
        connection_timeout=settings.connection_timeout,
        max_idle_time=settings.max_idle_seconds,
        options={"prepare_threshold": None},
    )


def init_database(settings: DatabaseSettings) -> Database:
    """Initialise the :class:`Database` singleton from config settings.

    If the singleton is already initialised, returns the existing instance.

    Parameters
    ----------
    settings:
        The ``database`` section from :class:`AcmeehSettings`.

    Returns
    -------
    Database
        The ready-to-use database instance.

    """
    if Database.is_initialized():
        log.debug("Database already initialised, returning existing instance")
        return Database.get_instance()

    config = _settings_to_config(settings)

    log.info(
        "Initialising database connection: %s@%s:%s/%s",
        settings.user,
        settings.host,
        settings.port,
        settings.database,
    )

    db = Database.init(
        config=config,
        schema_path=_SCHEMA_PATH if settings.auto_setup else None,
        auto_setup=settings.auto_setup,
        interactive=False,
    )

    log.info(
        "Database initialised successfully "
        "(pool: min=%d max=%d timeout=%.1fs)",
        settings.min_connections,
        settings.max_connections,
        settings.connection_timeout,
    )

    # Warn about risky pool configurations that lead to pool exhaustion
    # under sustained load.
    if settings.max_connections < 10:  # noqa: PLR2004
        log.warning(
            "database.max_connections=%d is very small — "
            "pool exhaustion is likely under moderate load. "
            "Consider increasing to at least 20.",
            settings.max_connections,
        )
    if settings.connection_timeout > 15:  # noqa: PLR2004
        log.warning(
            "database.connection_timeout=%.0fs is high — "
            "requests will block for up to %.0fs when the pool is "
            "exhausted, tying up gunicorn workers. "
            "Consider reducing to 5-10s.",
            settings.connection_timeout,
            settings.connection_timeout,
        )

    return db
