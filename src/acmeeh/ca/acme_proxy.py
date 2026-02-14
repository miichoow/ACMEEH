"""ACME Proxy CA backend.

Forward CSRs to an upstream ACME server via ACMEOW.  Downstream
clients talk to ACMEEH normally -- challenges are auto-accepted and
the CSR is validated then forwarded upstream.

Requires ACMEOW >= 1.1.0 for external CSR support via
``finalize_order(csr=<bytes>)``.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from acmeeh.ca.base import CABackend, CAError, IssuedCertificate
from acmeeh.ca.upstream_handlers import load_upstream_handler

if TYPE_CHECKING:
    from cryptography import x509

    from acmeeh.config.settings import CAProfileSettings, CASettings
    from acmeeh.core.types import RevocationReason

log = logging.getLogger(__name__)


class AcmeProxyBackend(CABackend):
    """CA backend that proxies certificate requests to an upstream ACME CA.

    Uses ACMEOW to manage the upstream ACME protocol flow.  The ACMEOW
    client is stateful, so all operations are serialised with a lock.

    Parameters
    ----------
    ca_settings:
        The full ``ca`` configuration section.

    """

    def __init__(self, ca_settings: CASettings) -> None:
        """Initialise the proxy backend with its configuration."""
        super().__init__(ca_settings)
        self._proxy = ca_settings.acme_proxy
        self._client: Any = None
        self._handler: Any = None
        self._identifier_cls: Any = None
        self._lock = threading.Lock()

    @property
    def deferred(self) -> bool:
        """The upstream ACME flow may block indefinitely."""
        return True

    def startup_check(self) -> None:  # noqa: PLR0912
        """Validate configuration and initialise the ACMEOW client.

        Create the storage directory, load the upstream challenge
        handler, and register an account with the upstream CA.

        Raises
        ------
        CAError
            If required fields are missing, ACMEOW is not installed,
            or account registration fails.

        """
        if not self._proxy.directory_url:
            msg = "ca.acme_proxy.directory_url is required"
            raise CAError(msg)
        if not self._proxy.email:
            msg = "ca.acme_proxy.email is required"
            raise CAError(msg)
        if not self._proxy.challenge_handler:
            msg = "ca.acme_proxy.challenge_handler is required"
            raise CAError(msg)

        # Create storage directory
        storage = Path(self._proxy.storage_path)
        try:
            storage.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            msg = f"Failed to create storage directory '{storage}': {exc}"
            raise CAError(msg) from exc

        # Load the upstream challenge handler
        try:
            self._handler = load_upstream_handler(
                self._proxy.challenge_handler,
                self._proxy.challenge_handler_config,
            )
        except CAError:
            raise
        except Exception as exc:  # noqa: BLE001
            msg = (
                f"Failed to load upstream challenge handler "
                f"'{self._proxy.challenge_handler}': {exc}"
            )
            raise CAError(msg) from exc

        # Initialise ACMEOW client
        try:
            from acmeow import AcmeClient, ChallengeType, Identifier  # noqa: PLC0415
        except ImportError as exc:
            msg = "ACMEOW is not installed. Install with: pip install acmeow"
            raise CAError(msg) from exc

        self._identifier_cls = Identifier
        self._challenge_type = ChallengeType(self._proxy.challenge_type)

        try:
            self._init_acme_client(AcmeClient, storage)
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to initialise ACMEOW client: {exc}"
            raise CAError(msg, retryable=True) from exc

    def _init_acme_client(
        self,
        acme_client_cls: type,
        storage: Path,
    ) -> None:
        """Create the ACMEOW client and register an account.

        Parameters
        ----------
        acme_client_cls:
            The ``AcmeClient`` class from ACMEOW.
        storage:
            Path to the local storage directory.

        """
        client_kwargs: dict[str, Any] = {
            "server_url": self._proxy.directory_url,
            "email": self._proxy.email,
            "storage_path": str(storage),
        }
        if self._proxy.proxy_url:
            client_kwargs["proxy_url"] = self._proxy.proxy_url
        if not self._proxy.verify_ssl:
            client_kwargs["verify_ssl"] = False  # noqa: FBT003

        self._client = acme_client_cls(**client_kwargs)

        # Configure EAB if provided
        if self._proxy.eab_kid and self._proxy.eab_hmac_key:
            self._client.set_external_account_binding(
                kid=self._proxy.eab_kid,
                hmac_key=self._proxy.eab_hmac_key,
            )

        # Register account
        self._client.create_account()
        log.info(
            "ACME proxy: registered account with %s",
            self._proxy.directory_url,
        )

    def sign(  # noqa: PLR0913
        self,
        csr: x509.CertificateSigningRequest,
        *,
        profile: CAProfileSettings,  # noqa: ARG002
        validity_days: int,  # noqa: ARG002
        serial_number: int | None = None,  # noqa: ARG002
        ct_submitter: Any = None,  # noqa: ARG002
    ) -> IssuedCertificate:
        """Forward a CSR to the upstream ACME CA.

        Extract identifiers from the CSR SAN extension, create an
        upstream order, complete challenges via the configured handler,
        and finalise with the original CSR.

        Parameters
        ----------
        csr:
            Parsed PKCS#10 certificate signing request.
        profile:
            Certificate profile (not used -- upstream CA decides).
        validity_days:
            Requested lifetime (not used -- upstream CA decides).
        serial_number:
            Ignored -- the upstream CA assigns its own serial.
        ct_submitter:
            Accepted for interface compatibility but ignored -- CT
            submission is managed by the upstream ACME CA.

        Returns
        -------
        IssuedCertificate
            The certificate issued by the upstream CA.

        Raises
        ------
        CAError
            On any upstream ACME failure.

        """
        if self._client is None:
            msg = "ACME proxy client not initialised; call startup_check() first"
            raise CAError(msg)

        # Extract identifiers from CSR SAN
        identifiers = self._extract_identifiers(csr)
        if not identifiers:
            msg = "CSR contains no Subject Alternative Names"
            raise CAError(msg)

        # Get CSR in DER format for ACMEOW
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            Encoding,
        )

        csr_der = csr.public_bytes(Encoding.DER)

        with self._lock:
            try:
                cert_pem = self._execute_upstream_flow(
                    identifiers,
                    csr_der,
                )
            except CAError:
                raise
            except Exception as exc:  # noqa: BLE001
                exc_type = type(exc).__name__
                retryable = _is_retryable(exc)
                msg = f"Upstream ACME error ({exc_type}): {exc}"
                raise CAError(
                    msg,
                    retryable=retryable,
                ) from exc

        # Parse the leaf certificate to extract metadata
        return self._parse_issued_cert(cert_pem)

    def _execute_upstream_flow(
        self,
        identifiers: list[tuple[str, str]],
        csr_der: bytes,
    ) -> str:
        """Run the full upstream ACME order-challenge-finalize flow.

        Parameters
        ----------
        identifiers:
            List of ``(type, value)`` tuples (``"dns"`` or ``"ip"``).
        csr_der:
            DER-encoded certificate signing request.

        Returns
        -------
        str
            PEM-encoded certificate chain from the upstream CA.

        """
        acme_ids = [
            self._identifier_cls.dns(value) if id_type == "dns" else self._identifier_cls.ip(value)
            for id_type, value in identifiers
        ]

        # 1. Create order with the upstream CA
        log.info(
            "ACME proxy: creating order for %d identifier(s)",
            len(acme_ids),
        )
        self._client.create_order(acme_ids)

        # 2. Complete challenges via the configured handler
        log.info(
            "ACME proxy: completing %s challenges",
            self._proxy.challenge_type,
        )
        self._client.complete_challenges(
            self._handler,
            challenge_type=self._challenge_type,
        )

        # 3. Finalise with the external CSR (ACMEOW v1.1.0)
        log.info("ACME proxy: finalising order with external CSR")
        self._client.finalize_order(csr=csr_der)

        # 4. Retrieve the certificate
        cert_pem, _ = self._client.get_certificate()
        log.info("ACME proxy: certificate issued successfully")
        return cert_pem  # type: ignore[return-value]

    def revoke(
        self,
        *,
        serial_number: str,
        certificate_pem: str,
        reason: RevocationReason | None = None,
    ) -> None:
        """Attempt best-effort revocation via the upstream ACME CA.

        Called after the revocation has been recorded in the local
        database.  Errors are logged but not raised -- the local
        revocation is authoritative.

        Parameters
        ----------
        serial_number:
            Hex-encoded serial number.
        certificate_pem:
            PEM-encoded leaf certificate.
        reason:
            RFC 5280 revocation reason code.

        """
        if self._client is None:
            log.warning(
                "ACME proxy client not initialised; skipping upstream revocation for serial %s",
                serial_number,
            )
            return

        try:
            self._revoke_upstream(
                serial_number,
                certificate_pem,
                reason,
            )
        except Exception:  # noqa: BLE001
            log.warning(
                "ACME proxy: upstream revocation failed for serial %s",
                serial_number,
                exc_info=True,
            )

    def _revoke_upstream(
        self,
        serial_number: str,
        certificate_pem: str,
        reason: RevocationReason | None,
    ) -> None:
        """Send the revocation request to the upstream CA.

        Parameters
        ----------
        serial_number:
            Hex-encoded serial number.
        certificate_pem:
            PEM-encoded leaf certificate.
        reason:
            RFC 5280 revocation reason code.

        """
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            Encoding,
        )
        from cryptography.x509 import (  # noqa: PLC0415
            load_pem_x509_certificate,
        )

        cert = load_pem_x509_certificate(certificate_pem.encode())
        cert_der = cert.public_bytes(Encoding.DER)

        reason_code = reason.value if reason is not None else 0
        self._client.revoke_certificate(cert_der, reason=reason_code)
        log.info(
            "ACME proxy: revoked certificate %s upstream",
            serial_number,
        )

    @staticmethod
    def _extract_identifiers(
        csr: x509.CertificateSigningRequest,
    ) -> list[tuple[str, str]]:
        """Extract domain names and IPs from the CSR SAN extension.

        Returns a list of ``(type, value)`` tuples where *type* is
        ``"dns"`` or ``"ip"``.
        """
        from cryptography.x509 import (  # noqa: PLC0415
            DNSName,
            ExtensionNotFound,
            IPAddress,
        )
        from cryptography.x509.oid import ExtensionOID  # noqa: PLC0415

        identifiers: list[tuple[str, str]] = []
        try:
            san = csr.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            )
        except ExtensionNotFound:
            return identifiers

        for name in san.value:  # type: ignore[attr-defined]
            if isinstance(name, DNSName):
                identifiers.append(("dns", name.value))
            elif isinstance(name, IPAddress):
                identifiers.append(("ip", str(name.value)))

        return identifiers

    @staticmethod
    def _parse_issued_cert(cert_pem: str) -> IssuedCertificate:
        """Parse a PEM certificate chain and extract metadata."""
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            Encoding,
        )
        from cryptography.x509 import (  # noqa: PLC0415
            load_pem_x509_certificate,
        )

        leaf_cert = load_pem_x509_certificate(cert_pem.encode())
        serial_hex = format(leaf_cert.serial_number, "x")

        fingerprint = hashlib.sha256(
            leaf_cert.public_bytes(Encoding.DER),
        ).hexdigest()

        not_before = leaf_cert.not_valid_before_utc
        not_after = leaf_cert.not_valid_after_utc

        return IssuedCertificate(
            pem_chain=cert_pem,
            not_before=not_before,
            not_after=not_after,
            serial_number=serial_hex,
            fingerprint=fingerprint,
        )


def _is_retryable(exc: Exception) -> bool:
    """Determine whether an upstream error is retryable via heuristics."""
    exc_name = type(exc).__name__.lower()
    retryable_patterns = (
        "timeout",
        "connection",
        "network",
        "server",
        "503",
        "429",
    )
    msg = str(exc).lower()
    return any(p in exc_name or p in msg for p in retryable_patterns)
