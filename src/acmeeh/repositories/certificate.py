"""Certificate repository."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pypgkit import BaseRepository, Database

from acmeeh.core.types import RevocationReason
from acmeeh.models.certificate import Certificate

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

log = logging.getLogger(__name__)


class CertificateRepository(BaseRepository[Certificate]):
    table_name = "certificates"
    primary_key = "id"

    def _row_to_entity(self, row: dict) -> Certificate:
        reason = row.get("revocation_reason")
        return Certificate(
            id=row["id"],
            account_id=row["account_id"],
            order_id=row["order_id"],
            serial_number=row["serial_number"],
            fingerprint=row["fingerprint"],
            pem_chain=row["pem_chain"],
            not_before_cert=row["not_before_cert"],
            not_after_cert=row["not_after_cert"],
            revoked_at=row.get("revoked_at"),
            revocation_reason=RevocationReason(reason) if reason is not None else None,
            public_key_fingerprint=row.get("public_key_fingerprint"),
            san_values=row.get("san_values"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _entity_to_row(self, entity: Certificate) -> dict:
        from psycopg.types.json import Jsonb

        row = {
            "id": entity.id,
            "account_id": entity.account_id,
            "order_id": entity.order_id,
            "serial_number": entity.serial_number,
            "fingerprint": entity.fingerprint,
            "pem_chain": entity.pem_chain,
            "not_before_cert": entity.not_before_cert,
            "not_after_cert": entity.not_after_cert,
            "revoked_at": entity.revoked_at,
            "revocation_reason": (
                entity.revocation_reason.value if entity.revocation_reason is not None else None
            ),
        }
        if entity.public_key_fingerprint is not None:
            row["public_key_fingerprint"] = entity.public_key_fingerprint
        if entity.san_values is not None:
            row["san_values"] = Jsonb(entity.san_values)
        return row

    def find_by_serial(self, serial_number: str) -> Certificate | None:
        """Find a certificate by its serial number."""
        return self.find_one_by({"serial_number": serial_number})

    def find_by_fingerprint(self, fingerprint: str) -> Certificate | None:
        """Find a certificate by its fingerprint."""
        return self.find_one_by({"fingerprint": fingerprint})

    def find_by_account(self, account_id: UUID) -> list[Certificate]:
        """Return all certificates for a given account."""
        return self.find_by({"account_id": account_id})

    def revoke(
        self,
        certificate_id: UUID,
        reason: RevocationReason | None = None,
    ) -> Certificate | None:
        """Atomically revoke a certificate (only if not already revoked).

        Returns the updated certificate, or None if it was already
        revoked.
        """
        db = Database.get_instance()
        reason_value = reason.value if reason is not None else RevocationReason.UNSPECIFIED.value
        row = db.fetch_one(
            "UPDATE certificates "
            "SET revoked_at = now(), revocation_reason = %s "
            "WHERE id = %s AND revoked_at IS NULL "
            "RETURNING *",
            (reason_value, certificate_id),
            as_dict=True,
        )
        if row is None:
            log.debug(
                "CAS guard failed: certificate %s already revoked",
                certificate_id,
            )
        return self._row_to_entity(row) if row else None

    def next_serial(self) -> int:
        """Get the next certificate serial number from the database sequence."""
        db = Database.get_instance()
        return db.fetch_value(
            "SELECT nextval('certificate_serial_seq')",
        )

    def find_expiring(self, before: datetime, *, conn=None) -> list[Certificate]:
        """Find non-revoked certificates expiring before the given time."""
        db = conn or Database.get_instance()
        rows = db.fetch_all(
            "SELECT * FROM certificates "
            "WHERE not_after_cert < %s "
            "  AND revoked_at IS NULL "
            "ORDER BY not_after_cert",
            (before,),
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def find_revoked(self) -> list[Certificate]:
        """Return all revoked certificates (for CRL generation)."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT * FROM certificates WHERE revoked_at IS NOT NULL ORDER BY revoked_at",
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def count_revoked_since(self, since: datetime) -> int:
        """Count certificates revoked since a given timestamp."""
        db = Database.get_instance()
        count = db.fetch_value(
            "SELECT COUNT(*) FROM certificates WHERE revoked_at IS NOT NULL AND revoked_at > %s",
            (since,),
        )
        return count or 0

    def find_by_public_key_fingerprint(self, fingerprint: str) -> list[Certificate]:
        """Find certificates matching a SHA-256 hash of the public key DER."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT * FROM certificates WHERE public_key_fingerprint = %s",
            (fingerprint,),
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def find_valid_certs_for_hosts(
        self,
        hosts: list[str],
        not_after_cutoff: datetime,
    ) -> list[Certificate]:
        """Find active certs whose SANs overlap with hosts and expire after cutoff."""
        db = Database.get_instance()
        rows = db.fetch_all(
            "SELECT * FROM certificates "
            "WHERE san_values ?| %s "
            "  AND revoked_at IS NULL "
            "  AND not_after_cert > %s",
            (hosts, not_after_cutoff),
            as_dict=True,
        )
        return [self._row_to_entity(r) for r in rows]

    def search(
        self,
        filters: dict,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Certificate]:
        """Search certificates with dynamic filters.

        Supported filter keys: account_id, serial, fingerprint, status,
        domain (SAN match), expiring_before.
        """
        db = Database.get_instance()
        conditions = []
        params = []

        if "account_id" in filters:
            conditions.append("account_id = %s")
            params.append(filters["account_id"])
        if "serial" in filters:
            conditions.append("serial_number = %s")
            params.append(filters["serial"])
        if "fingerprint" in filters:
            conditions.append("fingerprint = %s")
            params.append(filters["fingerprint"])
        if "status" in filters:
            status = filters["status"]
            if status == "revoked":
                conditions.append("revoked_at IS NOT NULL")
            elif status in ("active", "valid"):
                conditions.append("revoked_at IS NULL AND not_after_cert > now()")
            elif status == "expired":
                conditions.append("not_after_cert <= now()")
        if "serial_numbers" in filters:
            serial_list = filters["serial_numbers"]
            if serial_list:
                placeholders = ", ".join(["%s"] * len(serial_list))
                conditions.append(f"serial_number IN ({placeholders})")
                params.extend(serial_list)
        if "domain" in filters:
            conditions.append("san_values @> %s::jsonb")
            import json

            params.append(json.dumps([filters["domain"]]))
        if "expiring_before" in filters:
            conditions.append("not_after_cert < %s")
            params.append(filters["expiring_before"])

        where = " AND ".join(conditions) if conditions else "TRUE"
        query = (
            f"SELECT * FROM certificates WHERE {where} ORDER BY created_at DESC LIMIT %s OFFSET %s"
        )
        params.extend([limit, offset])

        rows = db.fetch_all(query, tuple(params), as_dict=True)
        return [self._row_to_entity(r) for r in rows]
