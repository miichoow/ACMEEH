"""Server settings repository — key/value store shared across workers.

Used for small pieces of HA-safe runtime state that must be visible to
every gunicorn worker (e.g. maintenance mode), where neither config
files nor per-process flags are appropriate.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pypgkit import Database

log = logging.getLogger(__name__)


class ServerSettingsRepository:
    """Tiny JSONB-backed kv store for cross-worker runtime settings."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def get(self, key: str) -> Any | None:
        """Return the decoded JSON value for ``key``, or ``None`` when absent."""
        row = self._db.fetch_value(
            "SELECT value FROM server_settings WHERE key = %s",
            (key,),
        )
        if row is None:
            return None
        # psycopg3 decodes JSONB automatically; guard against drivers
        # that return raw text.
        if isinstance(row, (str, bytes, bytearray)):
            return json.loads(row)
        return row

    def set(self, key: str, value: Any) -> None:
        """Upsert ``value`` under ``key``."""
        self._db.execute(
            "INSERT INTO server_settings (key, value, updated_at) "
            "VALUES (%s, %s::jsonb, now()) "
            "ON CONFLICT (key) DO UPDATE "
            "SET value = EXCLUDED.value, updated_at = now()",
            (key, json.dumps(value)),
        )
