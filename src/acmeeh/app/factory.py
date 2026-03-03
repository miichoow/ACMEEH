"""Flask application factory for ACMEEH.

Usage::

    from acmeeh.app import create_app
    from acmeeh.config import get_config
    from acmeeh.db import init_database

    db  = init_database(get_config().settings.database)
    app = create_app(config=get_config(), database=db)
"""

from __future__ import annotations

import atexit
import logging
import sys
from typing import TYPE_CHECKING

from flask import Flask, jsonify

if TYPE_CHECKING:
    from flask.typing import ResponseReturnValue
    from pypgkit import Database

    from acmeeh.config.acmeeh_config import AcmeehConfig

log = logging.getLogger(__name__)


def create_app(  # noqa: C901, PLR0915
    config: AcmeehConfig | None = None,
    database: Database | None = None,
) -> Flask:
    """Create and configure the ACMEEH Flask application.

    Parameters
    ----------
    config:
        Loaded :class:`AcmeehConfig`.  Falls back to :func:`get_config`
        when ``None``.
    database:
        Initialised :class:`Database` singleton.  When provided, the
        dependency container with all repositories is wired up.  When
        ``None`` the app still starts (useful for ``--validate-only``
        or testing) but repository access will raise at runtime.

    Returns
    -------
    Flask
        Fully configured WSGI application.

    """
    if config is None:
        from acmeeh.config import get_config  # noqa: PLC0415

        config = get_config()

    settings = config.settings

    app = Flask("acmeeh")
    app.config["ACMEEH_SETTINGS"] = settings
    app.config["ACMEEH_CONFIG"] = config
    app.config["MAX_CONTENT_LENGTH"] = settings.security.max_request_body_bytes

    # -- Rate limiter -------------------------------------------------------
    if settings.security.rate_limits.enabled:
        from acmeeh.app.rate_limiter import create_rate_limiter  # noqa: PLC0415

        app.extensions["rate_limiter"] = create_rate_limiter(
            settings.security.rate_limits,
            database,
        )

    # -- Graceful shutdown coordinator --------------------------------------
    from acmeeh.app.shutdown import ShutdownCoordinator  # noqa: PLC0415

    shutdown_coordinator = ShutdownCoordinator(
        graceful_timeout=settings.server.graceful_timeout,
    )
    app.extensions["shutdown_coordinator"] = shutdown_coordinator
    atexit.register(shutdown_coordinator.initiate)

    # -- WSGI middleware (outermost layer) -----------------------------------
    if settings.proxy.enabled:
        from acmeeh.app.middleware import TrustedProxyMiddleware  # noqa: PLC0415

        app.wsgi_app = TrustedProxyMiddleware(  # type: ignore[method-assign]
            app.wsgi_app,
            trusted_proxies=settings.proxy.trusted_proxies,
            for_header=settings.proxy.forwarded_for_header,
            proto_header=settings.proxy.forwarded_proto_header,
        )
        log.info(
            "Proxy middleware enabled (trusted: %s)",
            list(settings.proxy.trusted_proxies) or "all",
        )

    # Server header hardening — applied outermost so it overrides headers
    # set by the WSGI server (Werkzeug dev server, gunicorn, etc.)
    from acmeeh.app.middleware import ServerHeaderMiddleware  # noqa: PLC0415

    app.wsgi_app = ServerHeaderMiddleware(app.wsgi_app)  # type: ignore[method-assign]

    # -- Error handlers (RFC 7807) ------------------------------------------
    from acmeeh.app.errors import register_error_handlers  # noqa: PLC0415

    register_error_handlers(app)

    # -- Connection pool pressure guard (must register BEFORE rate limiter) --
    # Registered early so pool-exhausted requests are rejected instantly
    # (0.2ms) rather than blocking for 30s in a DB-backed rate limiter call.
    if database is not None:
        from acmeeh.db.init import _get_raw_pool  # noqa: PLC0415

        _raw_pool = _get_raw_pool(database)

        _health_paths = frozenset({"/livez", "/healthz", "/readyz"})

        # Pool-size dependent thresholds — computed once at startup.
        #
        # critical_threshold: below this → hard reject (503, Retry-After 5s)
        # pressure_threshold: below this → soft reject when requests queue
        #
        # For small pools (≤20) we use a relative 30%/50% split so we
        # start shedding before the pool is fully pinned.  For larger
        # pools, 10%/20% keeps the thresholds reasonable.
        _pool_max = 50
        try:
            _startup_stats = _raw_pool.get_stats() if _raw_pool and hasattr(_raw_pool, "get_stats") else {}
            _pool_max = int(_startup_stats.get("pool_max", 50) or 50)
        except (TypeError, ValueError, Exception):
            _pool_max = 50
        if _pool_max <= 20:  # noqa: PLR2004
            _critical_threshold = max(1, _pool_max * 3 // 10)  # 30%
            _pressure_threshold = max(2, _pool_max * 5 // 10)  # 50%
        else:
            _critical_threshold = max(2, _pool_max // 10)       # 10%
            _pressure_threshold = max(3, _pool_max * 2 // 10)   # 20%

        # Track when the last recovery probe was allowed through
        # during pool exhaustion.  This breaks the deadlock where
        # the guard rejects all requests (preventing connection
        # recovery) while a background worker waits for a connection
        # (keeping waiting>0).
        import time as _time  # noqa: PLC0415

        _probe_state = {"last_probe": 0.0}
        _probe_interval = 2.0  # seconds between recovery probes

        @app.before_request
        def _pool_pressure_guard() -> ResponseReturnValue | None:  # noqa: PLR0911
            """Reject non-health requests early when the pool is nearly exhausted.

            Four-tier load shedding:
            * **growth headroom** (pool_size well below pool_max): allow —
              the pool will create new connections on demand.  This prevents
              ghost "checked out" connections (e.g. from pre-fork pool
              state) from blocking all traffic on a nearly-empty pool.
            * **exhausted** (available=0, waiting>0, pool at max): hard reject,
              Retry-After 5s — but allows a periodic "recovery probe" request
              through every 2s to break the deadlock where the guard's own
              rejection prevents connections from ever being freed.
            * **critical** (available ≤ critical_threshold, pool near max):
              hard reject, Retry-After 3s
            * **pressure** (available ≤ pressure_threshold, waiting>0):
              soft reject, Retry-After 2s

            Uses ``pool_size - pool_available`` (checked-out count) to
            distinguish genuine exhaustion from an idle-shrunk pool.
            Without this, psycopg_pool's ``max_idle`` timeout shrinks
            the pool to ``min_connections``, the guard sees low
            ``available`` vs ``pool_max``, and permanently rejects all
            requests — preventing the pool from ever growing back.
            """
            from flask import request  # noqa: PLC0415

            if request.path in _health_paths:
                return None
            if _raw_pool is None or not hasattr(_raw_pool, "get_stats"):
                return None
            try:
                stats = _raw_pool.get_stats()
                available = stats.get("pool_available", 1)
                waiting = stats.get("requests_waiting", 0)
                pool_size = stats.get("pool_size", _pool_max)
                checked_out = pool_size - available

                # Growth headroom: when the pool is well below its maximum,
                # new requests get a fresh connection created instantly —
                # there is no blocking risk.  Skip load shedding entirely.
                #
                # This is critical after gunicorn fork: the child inherits
                # pool accounting from the master, where min_connections
                # slots may appear "checked out" even though the master's
                # code no longer exists in this process.  These ghost
                # connections inflate checked_out without consuming real
                # capacity, causing false 503 rejections on a pool that
                # has ample room to grow (e.g. size=6/30 checked_out=5).
                if pool_size + _pressure_threshold <= _pool_max:
                    return None

                _error_body = jsonify(
                    {
                        "type": "urn:ietf:params:acme:error:serverInternal",
                        "detail": "Server is temporarily overloaded. Please retry.",
                    }
                )

                # Exhausted: nothing available AND requests already queuing
                if available == 0 and waiting > 0:
                    # If the pool can still grow (size < max), psycopg_pool
                    # is creating new connections for the waiters.  Let the
                    # request through — the wait is temporary.
                    if pool_size < _pool_max:
                        log.debug(
                            "Pool growing — letting request through "
                            "(available=%s size=%s/%s waiting=%s path=%s)",
                            available,
                            pool_size,
                            _pool_max,
                            waiting,
                            request.path,
                        )
                        return None

                    # Pool is at max capacity.  Reject most requests to
                    # fail fast, but allow a periodic "recovery probe"
                    # through to break the deadlock where the guard's own
                    # rejection prevents connections from being freed.
                    now = _time.monotonic()
                    if now - _probe_state["last_probe"] >= _probe_interval:
                        _probe_state["last_probe"] = now
                        log.info(
                            "Pool exhaustion recovery probe — allowing "
                            "request through (size=%s/%s waiting=%s path=%s)",
                            pool_size,
                            _pool_max,
                            waiting,
                            request.path,
                        )
                        return None

                    log.warning(
                        "Pool exhausted — rejecting request "
                        "(available=%s size=%s/%s waiting=%s path=%s)",
                        available,
                        pool_size,
                        _pool_max,
                        waiting,
                        request.path,
                    )
                    return (_error_body, 503, {"Retry-After": "5"})

                # Critical: very few connections left AND a significant
                # number are actually checked out.  The checked_out guard
                # prevents false rejection when the pool has shrunk due
                # to idle timeout (pool_size ≈ available ≈ min_connections).
                if (
                    available <= _critical_threshold
                    and checked_out > _critical_threshold
                ):
                    log.warning(
                        "Pool critically low — rejecting request "
                        "(available=%s size=%s/%s checked_out=%s waiting=%s path=%s)",
                        available,
                        pool_size,
                        _pool_max,
                        checked_out,
                        waiting,
                        request.path,
                    )
                    return (_error_body, 503, {"Retry-After": "3"})

                # Pressure: pool is stressed AND requests are already queuing
                if available <= _pressure_threshold and waiting > 0:
                    log.warning(
                        "Pool under pressure — shedding load "
                        "(available=%s size=%s/%s checked_out=%s waiting=%s path=%s)",
                        available,
                        pool_size,
                        _pool_max,
                        checked_out,
                        waiting,
                        request.path,
                    )
                    return (_error_body, 503, {"Retry-After": "2"})
            except Exception:  # noqa: BLE001, S110
                pass
            return None

        @app.teardown_appcontext
        def _monitor_pool_health(exc: BaseException | None) -> None:
            """Log a warning when the pool is under pressure at request end."""
            try:
                if _raw_pool is None or not hasattr(_raw_pool, "get_stats"):
                    return
                stats = _raw_pool.get_stats()
                available = stats.get("pool_available", 0)
                waiting = stats.get("requests_waiting", 0)
                # Always log when connections are queued, regardless of
                # whether this request itself had an exception.
                if waiting > 0:
                    log.warning(
                        "Pool pressure at request teardown: "
                        "size=%s/%s available=%s waiting=%s%s",
                        stats.get("pool_size", "?"),
                        stats.get("pool_max", "?"),
                        available,
                        waiting,
                        f" (exc={type(exc).__name__})" if exc else "",
                    )
            except Exception:  # noqa: BLE001, S110
                pass

    # -- Request lifecycle hooks --------------------------------------------
    from acmeeh.app.middleware import register_request_hooks  # noqa: PLC0415

    register_request_hooks(app)

    # -- Infrastructure endpoints -------------------------------------------
    _register_health(app)

    # -- Dependency container -----------------------------------------------
    if database is not None:
        from acmeeh.app.context import Container  # noqa: PLC0415

        container = Container(
            database,
            settings,
            shutdown_coordinator=shutdown_coordinator,
            rate_limiter=app.extensions.get("rate_limiter"),
        )
        app.extensions["container"] = container

        # -- CA backend startup check ---------------------------------------
        try:
            container.ca_backend.startup_check()
        except Exception:
            log.exception("CA backend startup check failed")
            raise

        # -- Hook registry shutdown (process exit, not per-request) ---------
        atexit.register(container.hook_registry.shutdown)

        # -- Cleanup worker: register rate-limit GC task (no thread yet) -----
        from acmeeh.app.rate_limiter import DatabaseRateLimiter  # noqa: PLC0415
        from acmeeh.services.cleanup_worker import _CleanupTask  # noqa: PLC0415

        rate_limiter = app.extensions.get("rate_limiter")
        if isinstance(rate_limiter, DatabaseRateLimiter):
            gc_interval = settings.security.rate_limits.gc_interval_seconds
            container.cleanup_worker._tasks.append(  # noqa: SLF001
                _CleanupTask(
                    name="rate_limit_gc",
                    interval_seconds=gc_interval,
                    func=lambda conn, _rl=rate_limiter: _rl.gc(conn=conn),
                ),
            )

        # -- ACME API routes ------------------------------------------------
        from acmeeh.api import register_blueprints  # noqa: PLC0415

        register_blueprints(app)

        # -- CRL endpoint (optional) ----------------------------------------
        # (registered inside register_blueprints if enabled)

        # -- Metrics endpoint (optional) ------------------------------------
        if settings.metrics.enabled:
            from acmeeh.api.metrics import metrics_bp  # noqa: PLC0415

            app.register_blueprint(
                metrics_bp,
                url_prefix=settings.metrics.path,
            )
            log.info("Metrics endpoint registered at %s", settings.metrics.path)

        # -- Admin API (optional) -------------------------------------------
        if settings.admin_api.enabled and container.admin_service is not None:
            from acmeeh.admin.routes import admin_bp  # noqa: PLC0415

            app.register_blueprint(
                admin_bp,
                url_prefix=settings.admin_api.base_path.rstrip("/"),
            )
            log.info(
                "Admin API registered at %s",
                settings.admin_api.base_path,
            )

            # Bootstrap initial admin user
            pw = container.admin_service.bootstrap_admin(
                settings.admin_api.initial_admin_email,
            )
            if pw is not None:
                log.warning(
                    "Initial admin user created — password printed to stderr",
                )
                sys.stderr.write(
                    "\n"
                    "╔══════════════════════════════════════════════╗\n"
                    "║       INITIAL ADMIN USER CREATED             ║\n"
                    "║                                              ║\n"
                    f"║  Username: admin                             ║\n"
                    f"║  Password: {pw:<33s} ║\n"
                    "║                                              ║\n"
                    "║  Change this password immediately!           ║\n"
                    "╚══════════════════════════════════════════════╝\n"
                    "\n",
                )
                sys.stderr.flush()

    # -- Config hot-reload (SIGHUP) -----------------------------------------
    shutdown_coordinator.register_reload_signal()

    @app.before_request
    def _check_config_reload() -> None:
        """Reload safe config sections when SIGHUP is received."""
        sc = app.extensions.get("shutdown_coordinator")
        if sc is None or not sc.reload_requested:
            return

        try:
            cfg = app.config.get("ACMEEH_CONFIG")
            if cfg is None:
                sc.consume_reload()
                return

            new_settings = cfg.reload_settings()
            current = app.config["ACMEEH_SETTINGS"]
            reloaded = []

            # Only reload safe sections: logging level, rate_limits,
            # notifications, metrics toggle
            if new_settings.logging.level != current.logging.level:
                import logging as _logging  # noqa: PLC0415

                _logging.getLogger().setLevel(new_settings.logging.level)
                reloaded.append(f"logging.level={new_settings.logging.level}")

            if new_settings.security.rate_limits != current.security.rate_limits:
                reloaded.append("security.rate_limits")

            if new_settings.notifications != current.notifications:
                reloaded.append("notifications")

            if new_settings.metrics.enabled != current.metrics.enabled:
                reloaded.append(
                    f"metrics.enabled={new_settings.metrics.enabled}",
                )

            if reloaded:
                app.config["ACMEEH_SETTINGS"] = new_settings
                log.info(
                    "Config hot-reloaded sections: %s",
                    ", ".join(reloaded),
                )
            else:
                log.info(
                    "Config reload requested but no safe-to-reload changes detected",
                )
        except Exception:
            log.exception("Config hot-reload failed")
        finally:
            sc.consume_reload()

    log.info("Flask application created")
    return app


# ---------------------------------------------------------------------------
# Worker lifecycle
# ---------------------------------------------------------------------------


def start_workers(app: Flask) -> None:
    """Start background worker threads.

    Must be called **after fork** when running under gunicorn (i.e. in
    the ``post_fork`` hook) because threads created before ``fork()``
    are silently killed in child processes.

    For the Flask development server (``--dev``), call this once after
    :func:`create_app` returns.
    """
    container = app.extensions.get("container")
    if container is None:
        return

    shutdown_coordinator = app.extensions.get("shutdown_coordinator")

    if container.challenge_worker is not None:
        container.challenge_worker.start()
        atexit.register(container.challenge_worker.stop)

    container.cleanup_worker.start()
    atexit.register(container.cleanup_worker.stop)

    if shutdown_coordinator is not None:
        def _drain_on_shutdown() -> None:
            try:
                shutdown_coordinator.drain_processing_challenges(
                    container.challenges,
                )
            except Exception:  # noqa: BLE001
                log.debug("drain_processing_challenges failed during shutdown")

        atexit.register(_drain_on_shutdown)

    container.expiration_worker.start()
    atexit.register(container.expiration_worker.stop)


# ---------------------------------------------------------------------------
# Infrastructure endpoints
# ---------------------------------------------------------------------------


def _register_health(app: Flask) -> None:  # noqa: C901, PLR0915
    """Register ``/livez``, ``/healthz``, and ``/readyz`` probes."""

    @app.route("/livez")
    def livez() -> ResponseReturnValue:
        """Return minimal liveness probe."""
        resp = jsonify({"alive": True})
        resp.headers["Cache-Control"] = "no-store"
        return resp, 200

    @app.route("/healthz")
    def healthz() -> ResponseReturnValue:  # noqa: C901, PLR0912, PLR0915
        """Return health status.

        Only exposes high-level pass/fail per subsystem — no internal
        metrics (pool sizes, worker thread names, CRL details, version)
        that would aid reconnaissance.
        """
        result: dict = {"status": "ok"}
        checks: dict = {}

        container = app.extensions.get("container")
        if container is not None:
            settings = container.settings

            # Connection pool stats — checked BEFORE the DB ping so we
            # can skip the ping (which blocks for connection_timeout)
            # when the pool is already exhausted.
            pool_exhausted = False
            try:
                from acmeeh.db.init import _get_raw_pool  # noqa: PLC0415

                pool = _get_raw_pool(container.db)
                if pool is not None and hasattr(pool, "get_stats"):
                    stats = pool.get_stats()
                    avail = stats.get("pool_available", 0)
                    waiting = stats.get("requests_waiting", 0)
                    if avail == 0 and waiting > 0:
                        pool_exhausted = True
                        result["status"] = "degraded"
            except Exception:  # noqa: BLE001
                log.debug("Failed to retrieve connection pool stats")

            # DB ping — skip when pool is exhausted to avoid blocking
            # the health probe for connection_timeout seconds.
            if pool_exhausted:
                checks["database"] = "degraded"
                result["status"] = "degraded"
            else:
                try:
                    container.db.fetch_value("SELECT 1")
                    checks["database"] = "ok"
                except Exception:  # noqa: BLE001
                    checks["database"] = "error"
                    result["status"] = "degraded"

            # Shutdown coordinator status
            shutdown_coord = app.extensions.get("shutdown_coordinator")
            if shutdown_coord is not None and shutdown_coord.is_shutting_down:
                result["status"] = "degraded"

            if container.crl_manager is not None:
                crl_health = container.crl_manager.health_status()
                checks["crl"] = "ok" if not crl_health.get("stale") else "stale"
                if crl_health.get("stale"):
                    result["status"] = "degraded"

            # Worker liveness — only report aggregate ok/degraded
            _any_worker_dead = False
            for attr in ("challenge_worker", "cleanup_worker", "expiration_worker"):
                worker = getattr(container, attr, None)
                if worker is not None:
                    t = getattr(worker, "_thread", None)
                    if t is not None and not t.is_alive():
                        _any_worker_dead = True
            if _any_worker_dead:
                checks["workers"] = "degraded"
                result["status"] = "degraded"
            elif any(
                getattr(container, a, None) is not None
                for a in ("challenge_worker", "cleanup_worker", "expiration_worker")
            ):
                checks["workers"] = "ok"

            # CA backend status
            try:
                container.ca_backend.startup_check()
                checks["ca_backend"] = "ok"
            except Exception:  # noqa: BLE001
                checks["ca_backend"] = "error"
                result["status"] = "degraded"

            # SMTP connectivity (non-critical)
            if settings.smtp.enabled:
                try:
                    import smtplib  # noqa: PLC0415

                    with smtplib.SMTP(
                        settings.smtp.host,
                        settings.smtp.port,
                        timeout=5,
                    ) as s:
                        s.ehlo()
                    checks["smtp"] = "ok"
                except Exception:  # noqa: BLE001
                    checks["smtp"] = "unreachable"

            # DNS resolver reachability (non-critical)
            resolvers = settings.dns.resolvers or settings.challenges.dns01.resolvers
            if resolvers:
                try:
                    import socket  # noqa: PLC0415

                    socket.create_connection(
                        (resolvers[0], 53),
                        timeout=3,
                    ).close()
                    checks["dns_resolver"] = "ok"
                except Exception:  # noqa: BLE001
                    checks["dns_resolver"] = "unreachable"

        if checks:
            result["checks"] = checks

        code = 200 if result["status"] == "ok" else 503
        resp = jsonify(result)
        resp.headers["Cache-Control"] = "no-store"
        return resp, code

    @app.route("/readyz")
    def readyz() -> ResponseReturnValue:
        """Return Kubernetes readiness probe."""

        def _ready_err(reason: str, code: int = 503) -> ResponseReturnValue:
            resp = jsonify({"ready": False, "reason": reason})
            resp.headers["Cache-Control"] = "no-store"
            return resp, code

        container = app.extensions.get("container")
        if container is None:
            return _ready_err("Container not initialized")

        # Check DB connectivity — use pool stats first to avoid
        # blocking for connection_timeout when pool is exhausted.
        from acmeeh.db.init import get_pool_health  # noqa: PLC0415

        _health, _pstats = get_pool_health(container.db)
        if _health == "critical":
            return _ready_err("Connection pool exhausted")
        try:
            container.db.fetch_value("SELECT 1")
        except Exception:  # noqa: BLE001
            return _ready_err("Database not connected")

        # Check CA backend
        try:
            container.ca_backend.startup_check()
        except Exception:  # noqa: BLE001
            return _ready_err("CA backend not ready")

        # Check CRL freshness if enabled
        if container.crl_manager is not None:
            crl_health = container.crl_manager.health_status()
            if crl_health.get("stale"):
                return _ready_err("CRL is stale")

        resp = jsonify({"ready": True})
        resp.headers["Cache-Control"] = "no-store"
        return resp, 200
