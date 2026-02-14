"""Abstract base class for CA backends.

All CA backends (built-in and custom) must inherit from
:class:`CABackend` and implement :meth:`sign` and :meth:`revoke`.

The ``sign`` method receives a parsed CSR, a certificate profile,
validity parameters, and an optional serial number, and returns an
:class:`IssuedCertificate` containing the PEM chain and metadata.

The ``revoke`` method notifies the backend of a revocation — this is
called *after* the database record has been updated, allowing backends
to propagate the event (e.g. to an external CA or CRL publisher).
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from cryptography import x509

    from acmeeh.config.settings import CAProfileSettings, CASettings
    from acmeeh.core.types import RevocationReason

log = logging.getLogger(__name__)


class CAError(Exception):
    """Raised by CA backends on signing or revocation failure.

    Parameters
    ----------
    detail:
        Human-readable description of the failure.
    retryable:
        Whether the failure is transient and the operation may be retried.

    """

    def __init__(self, detail: str, *, retryable: bool = False) -> None:
        self.detail = detail
        self.retryable = retryable
        super().__init__(detail)


@dataclass(frozen=True)
class IssuedCertificate:
    """Result of a successful certificate signing operation.

    Attributes
    ----------
    pem_chain:
        Full PEM certificate chain (leaf + intermediates + optionally root).
    not_before:
        Certificate validity start time.
    not_after:
        Certificate validity end time.
    serial_number:
        Hex-encoded serial number as stored in the database.
    fingerprint:
        SHA-256 hex digest of the leaf certificate's DER encoding.

    """

    pem_chain: str
    not_before: datetime
    not_after: datetime
    serial_number: str
    fingerprint: str


class CABackend(abc.ABC):
    """Base class for all CA backend implementations.

    Subclasses must implement :meth:`sign` and :meth:`revoke`.

    Parameters
    ----------
    ca_settings:
        The full ``ca`` configuration section.

    """

    def __init__(self, ca_settings: CASettings) -> None:
        self._settings = ca_settings

    @abc.abstractmethod
    def sign(
        self,
        csr: x509.CertificateSigningRequest,
        *,
        profile: CAProfileSettings,
        validity_days: int,
        serial_number: int | None = None,
        ct_submitter=None,
    ) -> IssuedCertificate:
        """Sign a CSR and return the issued certificate.

        Parameters
        ----------
        csr:
            Parsed PKCS#10 certificate signing request.
        profile:
            Certificate profile defining key usages and EKUs.
        validity_days:
            Requested certificate lifetime in days.
        serial_number:
            Serial number to embed in the certificate.  Provided when the
            caller manages serial allocation (e.g. database sequence).
            Backends that manage their own serials (e.g. external CAs) may
            ignore this and return the actual serial in the result.
        ct_submitter:
            Optional :class:`CTPreCertSubmitter` for pre-certificate CT
            submission (RFC 6962).  When provided, the backend should
            build a pre-certificate with the CT poison extension, submit
            it to CT logs, collect SCTs, and embed them in the final
            certificate.  Backends that do not support pre-cert CT may
            ignore this parameter.

        Returns
        -------
        IssuedCertificate
            The signed certificate with full chain and metadata.

        Raises
        ------
        CAError
            On any signing failure.

        """

    @abc.abstractmethod
    def revoke(
        self,
        *,
        serial_number: str,
        certificate_pem: str,
        reason: RevocationReason | None = None,
    ) -> None:
        """Notify the backend that a certificate has been revoked.

        Called *after* the revocation has been recorded in the database.
        For internal backends this is typically a no-op; external backends
        forward the event to the upstream CA.

        Parameters
        ----------
        serial_number:
            Hex-encoded serial number of the revoked certificate.
        certificate_pem:
            PEM-encoded leaf certificate.
        reason:
            RFC 5280 revocation reason code, or ``None`` for unspecified.

        Raises
        ------
        CAError
            On any revocation notification failure.

        """

    @property
    def deferred(self) -> bool:
        """Whether ``sign()`` may block for an unbounded amount of time.

        Backends that return ``True`` signal that finalization should run
        in a background thread so the HTTP request can return immediately
        with order status ``processing`` (RFC 8555 §7.4).
        """
        return False

    def startup_check(self) -> None:
        """Optional startup health check.

        Called during application initialisation to verify the backend
        is correctly configured (e.g. root cert exists, external CA is
        reachable).  Default implementation is a no-op.

        Raises
        ------
        CAError
            If the backend is misconfigured.

        """
