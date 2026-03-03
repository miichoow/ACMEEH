"""Nonce repository."""

from __future__ import annotations

import logging

from pypgkit import BaseRepository, Database

from acmeeh.models.nonce import Nonce

log = logging.getLogger(__name__)


class NonceRepository(BaseRepository[Nonce]):
    table_name = "nonces"
    primary_key = "nonce"

    def __init__(self, db, audit_consumed: bool = False) -> None:
        super().__init__(db)
        self._audit_consumed = audit_consumed

    def _row_to_entity(self, row: dict) -> Nonce:
        return Nonce(
            nonce=row["nonce"],
            expires_at=row["expires_at"],
            created_at=row.get("created_at"),
        )

    def _entity_to_row(self, entity: Nonce) -> dict:
        return {
            "nonce": entity.nonce,
            "expires_at": entity.expires_at,
        }

    def consume(self, nonce_value: str, client_ip: str | None = None) -> bool:
        """Atomically consume a nonce (exactly-once semantics).

        Deletes the nonce only if it exists and has not expired.
        Optionally records the consumption in the nonce_audit table.

        Returns True if the nonce was valid and consumed, False otherwise.
        """
        db = Database.get_instance()
        row = db.fetch_one(
            "DELETE FROM nonces WHERE nonce = %s AND expires_at > now() RETURNING nonce",
            (nonce_value,),
            as_dict=True,
        )
        consumed = row is not None

        if consumed and self._audit_consumed:
            db.execute(
                "INSERT INTO nonce_audit (nonce, client_ip) VALUES (%s, %s)",
                (nonce_value, client_ip),
            )

        return consumed

    def bulk_create(self, nonces: list[Nonce]) -> int:
        """Bulk-insert nonces in a single multi-row INSERT.

        Uses one connection checkout for the entire batch instead of one
        per nonce — critical for reducing pool pressure under load.

        Returns the number of rows inserted.
        """
        if not nonces:
            return 0
        db = Database.get_instance()
        placeholders = ", ".join(["(%s, %s)"] * len(nonces))
        params: list = []
        for n in nonces:
            params.extend([n.nonce, n.expires_at])
        return db.execute(
            f"INSERT INTO nonces (nonce, expires_at) VALUES {placeholders}",
            tuple(params),
        )

    def gc_expired(self, *, conn=None) -> int:
        """Delete expired nonces. Returns the count of deleted rows."""
        db = conn or Database.get_instance()
        return db.execute(
            "DELETE FROM nonces WHERE expires_at <= now()",
        )
