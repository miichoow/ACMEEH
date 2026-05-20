"""Structured logging configuration for ACMEEH.

Provides JSON and text formatters, a request-context filter that
injects Flask ``g`` attributes into every log record, and a
one-call ``configure_logging`` function driven by config settings.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acmeeh.config.settings import LoggingSettings

# Attributes that are part of the standard LogRecord — everything
# else is considered "extra" and gets included in structured output.
_STANDARD_ATTRS = frozenset(
    {
        "args",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
        # Our own well-known context attributes (handled explicitly):
        "request_id",
        "client_ip",
        "account_id",
        "method",
        "path",
    }
)


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


class StructuredFormatter(logging.Formatter):
    """JSON-lines formatter for production logging.

    Every record becomes a single JSON object on one line containing
    the standard fields plus any *extra* attributes passed by the
    caller or injected by filters.
    """

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()

        data: dict = {
            "timestamp": datetime.fromtimestamp(
                record.created,
                tz=UTC,
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.message,
        }

        # Request context (set by RequestContextFilter)
        request_id = getattr(record, "request_id", None)
        if request_id is not None:
            data["request_id"] = request_id

        client_ip = getattr(record, "client_ip", None)
        if client_ip is not None:
            data["client_ip"] = client_ip

        account_id = getattr(record, "account_id", None)
        if account_id is not None:
            data["account_id"] = account_id

        method = getattr(record, "method", None)
        if method is not None:
            data["method"] = method

        path = getattr(record, "path", None)
        if path is not None:
            data["path"] = path

        # Caller-supplied extra fields
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                data.setdefault(key, value)

        if record.exc_info and record.exc_info[0] is not None:
            data["exception"] = self.formatException(record.exc_info)

        if record.stack_info:
            data["stack_info"] = self.formatStack(record.stack_info)

        return json.dumps(data, default=str)


class TextFormatter(logging.Formatter):
    """Human-readable formatter for development / console use."""

    _FMT = "%(asctime)s %(levelname)-8s [%(request_id)s] %(client_ip)s %(name)s — %(message)s"

    def __init__(self) -> None:
        super().__init__(fmt=self._FMT, datefmt="%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Filter
# ---------------------------------------------------------------------------


class RequestContextFilter(logging.Filter):
    """Inject Flask request context into every log record.

    Adds ``request_id``, ``client_ip``, ``account_id``, ``method``,
    and ``path`` from ``flask.g`` / ``flask.request`` when a request
    context is active, otherwise falls back to ``"-"``.
    """

    # Attributes injected by this filter (used by StructuredFormatter
    # to distinguish context from arbitrary extra fields).
    CONTEXT_ATTRS = frozenset(
        {
            "request_id",
            "client_ip",
            "account_id",
            "method",
            "path",
        }
    )

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        # Set defaults so formatters always have the attributes
        if not hasattr(record, "request_id"):
            record.request_id = "-"  # type: ignore[attr-defined]
        if not hasattr(record, "client_ip"):
            record.client_ip = "-"  # type: ignore[attr-defined]
        if not hasattr(record, "account_id"):
            record.account_id = None  # type: ignore[attr-defined]
        if not hasattr(record, "method"):
            record.method = None  # type: ignore[attr-defined]
        if not hasattr(record, "path"):
            record.path = None  # type: ignore[attr-defined]

        try:
            from flask import g, has_request_context, request

            if has_request_context():
                record.request_id = getattr(g, "request_id", record.request_id)  # type: ignore[attr-defined]
                record.client_ip = request.remote_addr or record.client_ip  # type: ignore[attr-defined]
                record.method = request.method  # type: ignore[attr-defined]
                record.path = request.path  # type: ignore[attr-defined]

                # Account ID from JWS authentication
                acct = getattr(g, "account", None)
                if acct is not None:
                    record.account_id = str(acct.id)  # type: ignore[attr-defined]
        except ImportError:
            pass

        return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def configure_logging(settings: LoggingSettings) -> logging.Logger:
    """Configure the ``acmeeh`` logger hierarchy from settings.

    Replaces any bootstrap handlers with properly formatted output.
    Sets up an optional audit logger if ``settings.audit.enabled``.

    Returns the root ``acmeeh`` logger.
    """
    level = getattr(logging, settings.level.upper(), logging.INFO)

    # ── Root acmeeh logger ──────────────────────────────────────────
    root = logging.getLogger("acmeeh")
    root.setLevel(level)
    root.handlers.clear()
    root.propagate = False

    formatter: logging.Formatter
    formatter = StructuredFormatter() if settings.format == "json" else TextFormatter()

    ctx_filter = RequestContextFilter()

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    console.addFilter(ctx_filter)
    root.addHandler(console)

    # ── Access logger (inherits from root, no extra handlers) ───────
    access = logging.getLogger("acmeeh.access")
    access.setLevel(logging.INFO)

    # ── Audit logger ────────────────────────────────────────────────
    if settings.audit.enabled:
        audit = logging.getLogger("acmeeh.audit")
        audit.setLevel(logging.INFO)

        if settings.audit.file:
            try:
                from logging.handlers import RotatingFileHandler

                fh = RotatingFileHandler(
                    settings.audit.file,
                    maxBytes=settings.audit.max_file_size_bytes,
                    backupCount=settings.audit.backup_count,
                )
                # Audit logs are always structured JSON
                fh.setFormatter(StructuredFormatter())
                fh.addFilter(ctx_filter)
                audit.addHandler(fh)
            except OSError as exc:
                root.warning(
                    "Could not open audit log file %s: %s",
                    settings.audit.file,
                    exc,
                )

    # ── Quieten noisy third-party loggers ───────────────────────────
    for lib in ("werkzeug", "gunicorn", "gunicorn.access", "gunicorn.error", "acmeow"):
        logging.getLogger(lib).setLevel(logging.WARNING)

    return root
