"""ACME Renewal Information service (draft-ietf-acme-ari).

Computes suggested renewal windows based on certificate validity
and revocation status.
"""

from __future__ import annotations

import base64
import logging
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acmeeh.config.settings import AriSettings
    from acmeeh.repositories.certificate import CertificateRepository

log = logging.getLogger(__name__)

_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")


def _serial_from_rfc9773_cert_id(cert_id: str) -> str | None:
    """Extract the serial number (lowercase hex, no leading zeros) from an ARI certID.

    RFC 9773 s4.1: ``base64url(AKI keyIdentifier) "." base64url(serial)`` where the serial
    is the DER INTEGER *value* octets (big endian; a leading 0x00 octet when the high bit
    is set).  The two parts are encoded separately, so the string as a whole is not valid
    base64url.  Serials are stored as ``format(serial, "x")``, hence the normalisation.

    Returns ``None`` when *cert_id* is not of that form.  The AKI part is not checked
    against the issuing CA: the serial is unique within this server's CA.
    """
    if cert_id.count(".") != 1:
        return None
    _aki, _, serial_part = cert_id.partition(".")
    if not _BASE64URL.fullmatch(serial_part):
        return None
    try:
        octets = base64.urlsafe_b64decode(serial_part + "=" * (-len(serial_part) % 4))
    except ValueError:
        return None
    return format(int.from_bytes(octets, "big"), "x") if octets else None


class RenewalInfoService:
    """Computes ARI renewal windows for certificates."""

    def __init__(
        self,
        cert_repo: CertificateRepository,
        settings: AriSettings,
    ) -> None:
        self._certs = cert_repo
        self._settings = settings

    def get_renewal_info(self, cert_id: str) -> dict | None:
        """Compute renewal info for a certID.

        Parameters
        ----------
        cert_id:
            Base64url-encoded ``AKI.keyIdentifier || '.' || serialNumber``
            as defined in draft-ietf-acme-ari.

        Returns
        -------
        dict or None
            Renewal info with suggestedWindow, or None if cert not found.

        """
        serial_hex = _serial_from_rfc9773_cert_id(cert_id)
        if serial_hex is None and "." in cert_id:
            return None  # looks like an RFC 9773 certID but is malformed
        if serial_hex is None:
            # Not RFC 9773: the pre-RFC form (the whole "AKI.serial" string base64url
            # encoded), or the serial itself.  Kept for existing callers.
            try:
                decoded = base64.urlsafe_b64decode(cert_id + "==").decode("ascii")
                parts = decoded.split(".")
                if len(parts) != 2:
                    return None
                serial_hex = parts[1]
            except Exception:  # noqa: BLE001
                serial_hex = cert_id

        cert = self._certs.find_by_serial(serial_hex)
        if cert is None:
            return None

        now = datetime.now(UTC)

        # Compute suggested window
        validity_duration = (cert.not_after_cert - cert.not_before_cert).total_seconds()
        renewal_offset = validity_duration * self._settings.renewal_percentage

        window_start = cert.not_after_cert.timestamp() - renewal_offset
        window_start_dt = datetime.fromtimestamp(window_start, tz=UTC)
        window_end_dt = cert.not_after_cert

        # If cert is revoked, window starts now
        if cert.revoked_at is not None:
            window_start_dt = now

        # Compute retry-after (seconds until window start, min 1 hour)
        retry_after = max(int((window_start_dt - now).total_seconds()), 3600)

        return {
            "suggestedWindow": {
                "start": window_start_dt.isoformat(),
                "end": window_end_dt.isoformat(),
            },
            "retryAfter": retry_after,
        }

    def should_renew(self, cert_id: str) -> bool:
        """Check if a certificate should be renewed now.

        Parameters
        ----------
        cert_id:
            The certID string (serial number or ARI-encoded ID).

        Returns
        -------
        bool
            True if the certificate is within its suggested renewal window.

        """
        info = self.get_renewal_info(cert_id)
        if info is None:
            return False

        now = datetime.now(UTC)
        window_start = datetime.fromisoformat(info["suggestedWindow"]["start"])
        return now >= window_start
