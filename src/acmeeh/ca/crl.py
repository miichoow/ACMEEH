"""CRL generation and caching.

Builds X.509 Certificate Revocation Lists signed by the internal CA
root key, and serves them from an in-memory cache.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (
    CertificateRevocationListBuilder,
    RevokedCertificateBuilder,
)

if TYPE_CHECKING:
    from cryptography import x509

    from acmeeh.config.settings import CrlSettings
    from acmeeh.repositories.certificate import CertificateRepository

log = logging.getLogger(__name__)

_HEX_BASE = 16
_STALE_MULTIPLIER = 2

_HASH_MAP: dict[str, hashes.HashAlgorithm] = {
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}


class CRLManager:
    """Build and cache DER-encoded CRLs.

    In HA mode (when ``db`` is provided), the built CRL is stored in the
    ``crl_cache`` table so all instances serve the same CRL.  Only one
    instance rebuilds at a time using a PostgreSQL advisory lock.
    """

    # Advisory lock ID -- arbitrary but stable
    _ADVISORY_LOCK_ID = 712_948

    def __init__(  # noqa: PLR0913
        self,
        root_cert: x509.Certificate,
        root_key: Any,
        cert_repo: CertificateRepository,
        settings: CrlSettings,
        shutdown_coordinator: Any = None,
        db: Any = None,
    ) -> None:
        """Initialize CRL manager with CA key material and settings."""
        self._root_cert = root_cert
        self._root_key = root_key
        self._cert_repo = cert_repo
        self._settings = settings
        self._cached_crl: bytes | None = None
        self._cached_at: float = 0.0
        self._lock = threading.Lock()
        self._last_rebuild_error: str | None = None
        self._last_revoked_count: int = 0
        self._last_revocation_check: float = 0.0
        self._shutdown = shutdown_coordinator
        self._db = db
        self._created_at: float = time.monotonic()

    def get_crl(self) -> bytes:  # noqa: PLR0912
        """Return the cached CRL, rebuilding if stale."""
        now = time.monotonic()
        interval = self._settings.rebuild_interval_seconds
        if self._cached_crl is not None and (now - self._cached_at) < interval:
            return self._cached_crl

        with self._lock:
            # Double-check after acquiring lock
            if self._cached_crl is not None and (time.monotonic() - self._cached_at) < interval:
                return self._cached_crl

            try:
                return self._get_crl_locked()
            except Exception:
                log.exception("CRL rebuild failed")
                # Return stale CRL if available
                if self._cached_crl is not None:
                    log.warning("Serving stale CRL after rebuild failure")
                    return self._cached_crl
                raise

    def _get_crl_locked(self) -> bytes:
        """Perform the actual CRL build or cache refresh while locked."""
        # If we have a cached CRL and the pool is under pressure,
        # serve the stale CRL instead of blocking on DB operations.
        if self._cached_crl is not None and self._db is not None:
            from acmeeh.db.init import is_pool_healthy  # noqa: PLC0415

            if not is_pool_healthy(self._db):
                log.debug("CRL: pool under pressure — serving stale CRL")
                self._cached_at = time.monotonic()
                return self._cached_crl

        # In HA mode, try to read from shared DB cache first
        if self._db is not None:
            db_crl = self._read_db_cache()
            if db_crl is not None:
                self._cached_crl = db_crl
                self._cached_at = time.monotonic()
                self._last_rebuild_error = None
                return db_crl

        # Incremental check: skip rebuild if no new revocations
        if self._cached_crl is not None:
            check_since = (
                datetime.fromtimestamp(
                    self._last_revocation_check,
                    tz=UTC,
                )
                if self._last_revocation_check > 0
                else datetime.min.replace(tzinfo=UTC)
            )
            new_revocations = self._cert_repo.count_revoked_since(
                check_since,
            )
            if new_revocations == 0:
                # No new revocations -- extend cache lifetime
                self._cached_at = time.monotonic()
                self._last_revocation_check = time.monotonic()
                return self._cached_crl

        crl_bytes = self._build_with_shutdown_tracking()

        # Store in DB for other instances
        if self._db is not None:
            self._write_db_cache(crl_bytes)

        self._cached_crl = crl_bytes
        self._cached_at = time.monotonic()
        self._last_revocation_check = time.monotonic()
        self._last_rebuild_error = None
        return crl_bytes

    def _build_with_shutdown_tracking(self) -> bytes:
        """Build CRL, wrapping with shutdown coordinator if available."""
        if self._shutdown is not None:
            ctx = self._shutdown.track("crl_rebuild")
            ctx.__enter__()  # noqa: PLC2801
        else:
            ctx = None
        try:
            return self._build()
        finally:
            if ctx is not None:
                ctx.__exit__(None, None, None)  # noqa: PLC2801

    def force_rebuild(self) -> bytes:
        """Force an immediate CRL rebuild, resetting error state."""
        with self._lock:
            crl_bytes = self._build()
            if self._db is not None:
                self._write_db_cache(crl_bytes)
            self._cached_crl = crl_bytes
            self._cached_at = time.monotonic()
            self._last_rebuild_error = None
            return crl_bytes

    def health_status(self) -> dict[str, Any]:
        """Return CRL health status information."""
        now = time.monotonic()
        cache_age = now - self._cached_at if self._cached_at > 0 else None
        return {
            "last_rebuild": cache_age,
            "stale": self._is_stale(),
            "error": self._last_rebuild_error,
            "revoked_count": self._last_revoked_count,
        }

    def _is_stale(self) -> bool:
        """Return True when cache age exceeds 2x the rebuild interval.

        During the startup grace period (one full rebuild interval after
        creation), a missing CRL is not considered stale — the first
        rebuild cycle simply hasn't had time to run yet.
        """
        if self._cached_crl is None:
            age_since_creation = time.monotonic() - self._created_at
            return age_since_creation > self._settings.rebuild_interval_seconds
        age = time.monotonic() - self._cached_at
        return age > (_STALE_MULTIPLIER * self._settings.rebuild_interval_seconds)

    def _read_db_cache(self) -> bytes | None:
        """Read CRL from shared DB cache if fresh enough."""
        try:
            row = self._db.fetch_one(
                "SELECT crl_der, built_at, revoked_count FROM crl_cache WHERE id = 1",
                as_dict=True,  # noqa: FBT003
            )
            if row is None:
                return None
            built_at = row["built_at"]
            age = (datetime.now(UTC) - built_at).total_seconds()
            if age < self._settings.rebuild_interval_seconds:
                self._last_revoked_count = row["revoked_count"]
                return bytes(row["crl_der"])
            return None
        except Exception:  # noqa: BLE001
            log.debug(
                "Could not read CRL from DB cache",
                exc_info=True,
            )
            return None

    def _write_db_cache(self, crl_bytes: bytes) -> None:
        """Write CRL to shared DB cache using advisory lock.

        All operations run on a **single** connection so the session-level
        advisory lock is acquired and released on the same backend session.
        Using separate ``self._db`` calls would check out different pool
        connections, leaking the lock on the acquiring connection.
        """
        import contextlib  # noqa: PLC0415

        try:
            with self._db.connection() as conn:
                row = conn.execute(
                    "SELECT pg_try_advisory_lock(%s)",
                    (self._ADVISORY_LOCK_ID,),
                ).fetchone()
                got_lock = bool(row and row[0])
                if not got_lock:
                    return
                try:
                    conn.execute(
                        "INSERT INTO crl_cache "
                        "(id, crl_der, built_at, revoked_count) "
                        "VALUES (1, %s, now(), %s) "
                        "ON CONFLICT (id) DO UPDATE SET "
                        "  crl_der = EXCLUDED.crl_der, "
                        "  built_at = EXCLUDED.built_at, "
                        "  revoked_count = EXCLUDED.revoked_count",
                        (crl_bytes, self._last_revoked_count),
                    )
                finally:
                    with contextlib.suppress(Exception):
                        conn.execute(
                            "SELECT pg_advisory_unlock(%s)",
                            (self._ADVISORY_LOCK_ID,),
                        )
        except Exception:  # noqa: BLE001
            log.warning(
                "Failed to write CRL to DB cache",
                exc_info=True,
            )

    def _build(self) -> bytes:
        """Build a fresh DER-encoded CRL."""
        now = datetime.now(UTC)
        next_update = now + timedelta(
            seconds=self._settings.next_update_seconds,
        )
        hash_alg = _HASH_MAP.get(
            self._settings.hash_algorithm,
            hashes.SHA256(),
        )

        builder = (
            CertificateRevocationListBuilder()
            .issuer_name(self._root_cert.subject)
            .last_update(now)
            .next_update(next_update)
        )

        # Add revoked certificates
        revoked = self._cert_repo.find_revoked()
        self._last_revoked_count = len(revoked)
        for cert in revoked:
            serial = int(cert.serial_number, _HEX_BASE)
            rev_builder = (
                RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(cert.revoked_at or now)
            )
            builder = builder.add_revoked_certificate(
                rev_builder.build(),
            )

        crl = builder.sign(self._root_key, hash_alg)  # type: ignore[arg-type]
        der_bytes = crl.public_bytes(serialization.Encoding.DER)

        log.info(
            "CRL rebuilt: %d revoked certificates, next update %s",
            len(revoked),
            next_update.isoformat(),
        )
        return der_bytes
