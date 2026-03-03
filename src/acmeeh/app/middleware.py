"""Middleware stack for ACMEEH.

WSGI-level:
    :class:`TrustedProxyMiddleware` — resolves real client IP and
    protocol from configurable forwarded headers, validates the
    connecting address against a trusted-proxy allowlist, and handles
    ``X-Forwarded-Prefix`` for root-path / reverse-proxy mounting.

Flask-level (registered via :func:`register_request_hooks`):
    * Request ID generation / passthrough (``X-Request-ID``)
    * Request timing
    * Structured access logging
"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import TYPE_CHECKING
from uuid import uuid4

from flask import Flask, g, request

if TYPE_CHECKING:
    from collections.abc import Sequence

log = logging.getLogger(__name__)
access_log = logging.getLogger("acmeeh.access")


# ═══════════════════════════════════════════════════════════════════════════
# WSGI middleware
# ═══════════════════════════════════════════════════════════════════════════


class TrustedProxyMiddleware:
    """WSGI middleware that processes forwarded headers from trusted proxies.

    If the connecting address (``REMOTE_ADDR``) is in the trusted set,
    the middleware overwrites environ values with the content of the
    configured forwarded headers.  Untrusted connections pass through
    unchanged.

    Handles:
    * ``X-Forwarded-For``  (or custom)  → ``REMOTE_ADDR``
    * ``X-Forwarded-Proto`` (or custom) → ``wsgi.url_scheme``
    * ``X-Forwarded-Prefix``            → ``SCRIPT_NAME``
    """

    def __init__(
        self,
        app,
        *,
        trusted_proxies: Sequence[str] = (),
        for_header: str = "X-Forwarded-For",
        proto_header: str = "X-Forwarded-Proto",
    ) -> None:
        self.app = app
        self._networks = self._parse_networks(trusted_proxies)
        self._for_key = self._wsgi_header_key(for_header)
        self._proto_key = self._wsgi_header_key(proto_header)

    # -- internal helpers ---------------------------------------------------

    @staticmethod
    def _wsgi_header_key(header: str) -> str:
        """``X-Forwarded-For`` → ``HTTP_X_FORWARDED_FOR``."""
        return "HTTP_" + header.upper().replace("-", "_")

    @staticmethod
    def _parse_networks(
        proxies: Sequence[str],
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        networks = []
        for entry in proxies:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                log.warning("Ignoring unparseable trusted proxy: %s", entry)
        return networks

    def _is_trusted(self, addr: str) -> bool:
        if not self._networks:
            # Empty allowlist with proxy enabled = trust everything
            # (config already warns about this)
            return True
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return any(ip in net for net in self._networks)

    def _extract_client_ip(self, forwarded_for: str) -> str:
        """Walk ``X-Forwarded-For`` right-to-left, return first untrusted."""
        parts = [p.strip() for p in forwarded_for.split(",")]
        for addr in reversed(parts):
            if not self._is_trusted(addr):
                return addr
        return parts[0]

    # -- WSGI __call__ ------------------------------------------------------

    def __call__(self, environ, start_response):
        remote = environ.get("REMOTE_ADDR", "")

        if self._is_trusted(remote):
            # Real client IP
            forwarded_for = environ.get(self._for_key, "")
            if forwarded_for:
                environ["REMOTE_ADDR"] = self._extract_client_ip(forwarded_for)

            # Protocol
            proto = environ.get(self._proto_key, "")
            if proto:
                environ["wsgi.url_scheme"] = proto.strip().lower()

            # Root path (reverse-proxy prefix)
            prefix = environ.get("HTTP_X_FORWARDED_PREFIX", "")
            if prefix:
                environ["SCRIPT_NAME"] = prefix.rstrip("/")

        return self.app(environ, start_response)


class ServerHeaderMiddleware:
    """WSGI middleware that replaces the ``Server`` response header.

    Applied as the outermost WSGI layer so it overrides any header set
    by the WSGI server itself (e.g. Werkzeug's ``Server: Werkzeug/x.y``
    or gunicorn's default).
    """

    def __init__(self, app, *, server_name: str = "ACMEEH") -> None:
        self.app = app
        self._server_name = server_name

    def __call__(self, environ, start_response):
        def _start_response(status, headers, exc_info=None):
            # Remove any existing Server header(s) and inject ours
            filtered = [(k, v) for k, v in headers if k.lower() != "server"]
            filtered.append(("Server", self._server_name))
            return start_response(status, filtered, exc_info)

        return self.app(environ, _start_response)


# ═══════════════════════════════════════════════════════════════════════════
# Flask request lifecycle hooks
# ═══════════════════════════════════════════════════════════════════════════


def register_request_hooks(app: Flask) -> None:
    """Register before/after request hooks for ID tracking, timing, and
    access logging.
    """

    @app.before_request
    def _before_request() -> None:
        g.request_id = request.headers.get("X-Request-ID") or uuid4().hex
        g.start_time = time.monotonic()

        # Rate limiting
        rate_limiter = app.extensions.get("rate_limiter")
        if rate_limiter is not None:
            settings = app.config.get("ACMEEH_SETTINGS")
            if settings is not None:
                client_ip = request.remote_addr or "unknown"
                paths = settings.acme.paths
                path = request.path
                category = None
                if path.endswith(paths.new_nonce):
                    category = "new_nonce"
                elif path.endswith(paths.new_account):
                    category = "new_account"
                elif path.endswith(paths.new_order):
                    category = "new_order"
                elif "/chall/" in path:
                    category = "challenge"
                if category:
                    rate_limiter.check(client_ip, category)

    @app.after_request
    def _after_request(response):
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        _settings = app.config.get("ACMEEH_SETTINGS")
        if _settings is not None:
            ext_url = _settings.server.external_url
            hsts_max_age = _settings.security.hsts_max_age_seconds
            if ext_url.startswith("https://") and hsts_max_age > 0:
                response.headers["Strict-Transport-Security"] = (
                    f"max-age={hsts_max_age}; includeSubDomains"
                )

        # Attach request ID to response
        request_id = getattr(g, "request_id", None)
        if request_id:
            response.headers["X-Request-ID"] = request_id

        # Metrics
        status = response.status_code
        _container = app.extensions.get("container")
        if _container is not None:
            _collector = getattr(_container, "metrics_collector", None)
            if _collector is not None:
                _collector.increment(
                    "acmeeh_http_requests_total",
                    labels={"method": request.method, "status": str(status)},
                )

        # Access log
        duration_ms = _elapsed_ms()
        level = (
            logging.WARNING
            if 400 <= status < 500
            else logging.ERROR
            if status >= 500
            else logging.INFO
        )
        access_log.log(
            level,
            "%s %s %s %.1fms",
            request.method,
            request.path,
            status,
            duration_ms,
            extra={
                "method": request.method,
                "path": request.path,
                "status": status,
                "duration_ms": round(duration_ms, 1),
                "content_length": response.content_length,
            },
        )

        return response


def _elapsed_ms() -> float:
    start = getattr(g, "start_time", None)
    if start is None:
        return 0.0
    return (time.monotonic() - start) * 1000
