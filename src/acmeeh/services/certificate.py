"""Certificate service -- finalize, download, revoke (RFC 8555 S7.4 / S7.6).

Handles CSR validation, CA backend delegation, certificate download,
and revocation with dual-auth support.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import logging
import secrets
import threading
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from acmeeh.app.errors import (
    ALREADY_REVOKED,
    BAD_CSR,
    BAD_REVOCATION_REASON,
    MALFORMED,
    ORDER_NOT_READY,
    SERVER_INTERNAL,
    UNAUTHORIZED,
    AcmeProblem,
)
from acmeeh.ca.base import CAError
from acmeeh.core.state import log_transition
from acmeeh.core.types import (
    NotificationType,
    OrderStatus,
    RevocationReason,
)
from acmeeh.db.unit_of_work import UnitOfWork
from acmeeh.logging import security_events

if TYPE_CHECKING:
    from pypgkit import Database

    from acmeeh.admin.repository import CsrProfileRepository
    from acmeeh.ca.base import CABackend
    from acmeeh.ca.caa import CAAValidator
    from acmeeh.ca.ct import CTPreCertSubmitter
    from acmeeh.config.settings import CASettings
    from acmeeh.hooks.registry import HookRegistry
    from acmeeh.metrics.collector import MetricsCollector
    from acmeeh.models.order import Order
    from acmeeh.repositories.certificate import CertificateRepository
    from acmeeh.repositories.order import OrderRepository
    from acmeeh.services.notification import NotificationService

log = logging.getLogger(__name__)


class CertificateService:
    """Manage certificate issuance, download, and revocation."""

    def __init__(  # noqa: PLR0913
        self,
        certificate_repo: CertificateRepository,
        order_repo: OrderRepository,
        ca_settings: CASettings,
        ca_backend: CABackend,
        notification_service: NotificationService | None = None,
        hook_registry: HookRegistry | None = None,
        caa_validator: CAAValidator | None = None,
        csr_profile_repo: CsrProfileRepository | None = None,
        ct_submitter: CTPreCertSubmitter | None = None,
        allowed_csr_signature_algorithms: tuple[str, ...] | None = None,
        metrics: MetricsCollector | None = None,
        db: Database | None = None,
        min_csr_rsa_key_size: int = 2048,
        min_csr_ec_key_size: int = 256,
    ) -> None:
        """Initialize the certificate service.

        Parameters
        ----------
        certificate_repo:
            Repository for certificate persistence.
        order_repo:
            Repository for order persistence.
        ca_settings:
            CA configuration settings.
        ca_backend:
            The CA backend used for signing and revocation.
        notification_service:
            Optional notification service for delivery events.
        hook_registry:
            Optional hook registry for lifecycle events.
        caa_validator:
            Optional CAA record validator.
        csr_profile_repo:
            Optional CSR profile repository for policy checks.
        ct_submitter:
            Optional Certificate Transparency log submitter.
        allowed_csr_signature_algorithms:
            Tuple of allowed CSR signature algorithm names.
        metrics:
            Optional metrics collector for counters.
        db:
            Optional database instance for unit-of-work transactions.
        min_csr_rsa_key_size:
            Minimum acceptable RSA key size in bits.
        min_csr_ec_key_size:
            Minimum acceptable EC key size in bits.

        """
        self._certs = certificate_repo
        self._orders = order_repo
        self._ca = ca_settings
        self._backend = ca_backend
        self._notifier = notification_service
        self._hooks = hook_registry
        self._caa = caa_validator
        self._csr_profile_repo = csr_profile_repo
        self._ct_submitter = ct_submitter
        self._allowed_csr_sig_algs = allowed_csr_signature_algorithms
        self._metrics = metrics
        self._db = db
        self._min_csr_rsa_key_size = min_csr_rsa_key_size
        self._min_csr_ec_key_size = min_csr_ec_key_size

    def finalize_order(  # noqa: C901, PLR0912, PLR0915
        self,
        order_id: UUID,
        csr_der: bytes,
        account_id: UUID,
    ) -> Order | None:
        """Finalize an order by submitting a CSR.

        Parameters
        ----------
        order_id:
            The order to finalize.
        csr_der:
            DER-encoded PKCS#10 CSR.
        account_id:
            The requesting account's ID.

        Returns
        -------
        Order
            The updated order (status will be ``valid``).

        """
        # Verify order ownership and status
        order = self._orders.find_by_id(order_id)
        if order is None:
            raise AcmeProblem(
                MALFORMED,
                "Order not found",
                status=404,
            )
        if order.account_id != account_id:
            raise AcmeProblem(
                UNAUTHORIZED,
                "Order does not belong to this account",
                status=403,
            )
        if order.status != OrderStatus.READY:
            raise AcmeProblem(
                ORDER_NOT_READY,
                f"Order is not ready for finalization (status: {order.status.value})",
                status=403,
            )

        # Transition to processing
        order = self._orders.transition_status(
            order_id,
            OrderStatus.READY,
            OrderStatus.PROCESSING,
        )
        if order is not None:
            log_transition(
                "order",
                order_id,
                OrderStatus.READY,
                OrderStatus.PROCESSING,
                reason="finalization started",
            )
        if order is None:
            raise AcmeProblem(
                ORDER_NOT_READY,
                "Order could not be transitioned to processing",
            )

        # Parse and validate CSR
        try:
            csr = x509.load_der_x509_csr(csr_der)
        except Exception as exc:  # noqa: BLE001
            self._orders.transition_status(
                order_id,
                OrderStatus.PROCESSING,
                OrderStatus.INVALID,
                error={
                    "type": "urn:ietf:params:acme:error:badCSR",
                    "detail": str(exc),
                },
            )
            security_events.csr_rejected(
                account_id,
                f"Cannot parse CSR: {exc}",
            )
            raise AcmeProblem(
                BAD_CSR,
                f"Cannot parse CSR: {exc}",
            ) from exc

        # Validate CSR signature
        if not csr.is_signature_valid:
            self._orders.transition_status(
                order_id,
                OrderStatus.PROCESSING,
                OrderStatus.INVALID,
                error={
                    "type": "urn:ietf:params:acme:error:badCSR",
                    "detail": "Invalid CSR signature",
                },
            )
            security_events.csr_rejected(
                account_id,
                "CSR signature verification failed",
            )
            raise AcmeProblem(
                BAD_CSR,
                "CSR signature verification failed",
            )

        # Validate CSR signature algorithm against policy
        if self._allowed_csr_sig_algs:
            from acmeeh.services.csr_validator import _SIG_ALG_NAMES  # noqa: PLC0415

            sig_oid = csr.signature_algorithm_oid.dotted_string
            sig_name = _SIG_ALG_NAMES.get(sig_oid, sig_oid)
            if sig_name not in self._allowed_csr_sig_algs:
                detail = f"CSR signature algorithm '{sig_name}' is not allowed"
                self._orders.transition_status(
                    order_id,
                    OrderStatus.PROCESSING,
                    OrderStatus.INVALID,
                    error={
                        "type": ("urn:ietf:params:acme:error:badCSR"),
                        "detail": detail,
                    },
                )
                security_events.csr_rejected(
                    account_id,
                    detail,
                )
                raise AcmeProblem(BAD_CSR, detail)

        # Validate CSR key strength against global minimums
        self._validate_csr_key_strength(csr, order_id, account_id)

        # Validate CSR SANs match order identifiers
        self._validate_csr_identifiers(csr, order)

        # CSR profile validation
        self._validate_csr_profile(csr, account_id, order_id)

        # CAA validation
        if self._caa is not None:
            for ident in order.identifiers:
                if ident.type.value == "dns":
                    is_wild = ident.value.startswith("*.")
                    self._caa.check(
                        ident.value,
                        is_wildcard=is_wild,
                    )

        # Determine certificate profile
        profile = self._ca.profiles.get(
            "default",
            next(iter(self._ca.profiles.values())),
        )

        # Determine validity days -- respect profile and global limits
        validity_days = self._ca.default_validity_days
        if profile.validity_days is not None:
            validity_days = profile.validity_days
        max_days = self._ca.max_validity_days
        if profile.max_validity_days is not None:
            max_days = min(max_days, profile.max_validity_days)
        validity_days = min(validity_days, max_days)

        # Generate serial number for backends that need it
        serial_number = self._generate_serial()

        # Pre-compute values needed by _complete_signing
        pub_key_der = csr.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pk_fingerprint = hashlib.sha256(pub_key_der).hexdigest()
        san_vals = _extract_san_values(csr)

        if self._backend.deferred:
            # Deferred signing: run in a background thread so the HTTP
            # request returns immediately with order status PROCESSING.
            # The client will poll (RFC 8555 §7.4 Retry-After).
            t = threading.Thread(
                target=self._complete_signing,
                args=(
                    order,
                    csr,
                    profile,
                    validity_days,
                    serial_number,
                    pk_fingerprint,
                    san_vals,
                ),
                daemon=True,
            )
            t.start()
            return order

        # Synchronous signing (normal path)
        return self._complete_signing(
            order,
            csr,
            profile,
            validity_days,
            serial_number,
            pk_fingerprint,
            san_vals,
        )

    def _complete_signing(  # noqa: PLR0913
        self,
        order: Order,
        csr: x509.CertificateSigningRequest,
        profile: Any,
        validity_days: int,
        serial_number: int,
        pk_fingerprint: str,
        san_vals: list[str] | None,
    ) -> Order:
        """Sign the CSR and store the certificate.

        Called synchronously for normal backends or in a daemon thread
        for deferred backends.  Handles its own errors — on ``CAError``
        the order is transitioned to INVALID.
        """
        order_id = order.id
        account_id = order.account_id

        # Call CA backend to sign
        try:
            result = self._backend.sign(
                csr,
                profile=profile,
                validity_days=validity_days,
                serial_number=serial_number,
                ct_submitter=self._ct_submitter,
            )
        except CAError as exc:
            log.exception(
                "CA backend signing failed: %s",
                exc.detail,
            )
            if self._metrics:
                self._metrics.increment(
                    "acmeeh_ca_signing_errors_total",
                )
            self._orders.transition_status(
                order_id,
                OrderStatus.PROCESSING,
                OrderStatus.INVALID,
                error={
                    "type": ("urn:ietf:params:acme:error:serverInternal"),
                    "detail": "Certificate signing failed",
                },
            )
            if self._notifier:
                domains = [ident.value for ident in order.identifiers]
                self._notifier.notify(
                    NotificationType.DELIVERY_FAILED,
                    account_id,
                    {
                        "domains": domains,
                        "order_id": str(order_id),
                        "error_detail": exc.detail,
                    },
                )
            if self._backend.deferred:
                # Running in background thread — cannot raise HTTP error
                return order  # type: ignore[return-value]
            raise AcmeProblem(
                SERVER_INTERNAL,
                "Certificate signing failed",
                500,
            ) from exc

        # Store certificate and transition order atomically
        from acmeeh.models.certificate import Certificate  # noqa: PLC0415

        cert_id = uuid4()
        cert_entity = Certificate(
            id=cert_id,
            account_id=account_id,
            order_id=order_id,
            serial_number=result.serial_number,
            fingerprint=result.fingerprint,
            pem_chain=result.pem_chain,
            not_before_cert=result.not_before,
            not_after_cert=result.not_after,
            public_key_fingerprint=pk_fingerprint,
            san_values=san_vals,
        )

        # Atomic: cert INSERT + order PROCESSING->VALID
        cert_row = self._certs._entity_to_row(cert_entity)  # noqa: SLF001
        with UnitOfWork(self._db) as uow:
            uow.insert("certificates", cert_row)
            order_row = uow.update_where(
                "orders",
                set_values={
                    "status": OrderStatus.VALID.value,
                    "certificate_id": cert_id,
                },
                where={
                    "id": order_id,
                    "status": OrderStatus.PROCESSING.value,
                },
            )
        if order_row is None:
            # Another instance already transitioned this order
            log.warning(
                "Order %s was no longer PROCESSING after "
                "cert INSERT -- possible concurrent finalization",
                order_id,
            )
        else:
            log_transition(
                "order",
                order_id,
                OrderStatus.PROCESSING,
                OrderStatus.VALID,
                reason="certificate issued",
            )
        order = self._orders.find_by_id(order_id)

        log.info(
            "Order %s finalized: certificate %s (serial=%s)",
            order_id,
            cert_id,
            result.serial_number,
        )
        security_events.certificate_issued(
            account_id,
            result.serial_number,
            [i.value for i in order.identifiers],
        )

        if self._metrics:
            self._metrics.increment(
                "acmeeh_certificates_issued_total",
            )

        if self._notifier:
            domains = [ident.value for ident in order.identifiers]
            self._notifier.notify(
                NotificationType.DELIVERY_SUCCEEDED,
                account_id,
                {
                    "domains": domains,
                    "serial_number": result.serial_number,
                    "not_after": str(result.not_after),
                    "order_id": str(order_id),
                    "certificate_id": str(cert_id),
                },
            )

        if self._hooks:
            self._hooks.dispatch(
                "certificate.issuance",
                {
                    "certificate_id": str(cert_id),
                    "order_id": str(order_id),
                    "account_id": str(account_id),
                    "serial_number": result.serial_number,
                    "domains": [i.value for i in order.identifiers],
                    "not_after": str(result.not_after),
                    "pem_chain": result.pem_chain,
                },
            )

        return order

    def download(self, cert_id: UUID, account_id: UUID) -> str:
        """Download a certificate's PEM chain.

        Parameters
        ----------
        cert_id:
            The certificate ID.
        account_id:
            The requesting account's ID.

        Returns
        -------
        str
            The PEM certificate chain.

        """
        cert = self._certs.find_by_id(cert_id)
        if cert is None:
            raise AcmeProblem(
                MALFORMED,
                "Certificate not found",
                status=404,
            )
        if cert.account_id != account_id:
            raise AcmeProblem(
                UNAUTHORIZED,
                "Certificate does not belong to this account",
                status=403,
            )

        security_events.certificate_downloaded(
            account_id,
            cert.serial_number,
        )

        if self._hooks:
            self._hooks.dispatch(
                "certificate.delivery",
                {
                    "certificate_id": str(cert_id),
                    "account_id": str(account_id),
                    "serial_number": cert.serial_number,
                },
            )

        return cert.pem_chain

    def revoke(  # noqa: C901
        self,
        cert_der: bytes,
        reason: int | None = None,
        account_id: UUID | None = None,
        jwk: dict[str, Any] | None = None,
    ) -> None:
        """Revoke a certificate.

        Supports dual authentication:
        - Account key (kid): account_id must match cert owner
        - Certificate key (jwk): jwk must match cert's public key

        Parameters
        ----------
        cert_der:
            DER-encoded certificate to revoke.
        reason:
            RFC 5280 revocation reason code (0-10).
        account_id:
            Account ID if authenticating via account key.
        jwk:
            JWK if authenticating via certificate key.

        """
        # Validate reason code
        rev_reason = None
        if reason is not None:
            try:  # noqa: SIM105
                rev_reason = RevocationReason(reason)
            except ValueError:
                raise AcmeProblem(
                    BAD_REVOCATION_REASON,
                    f"Invalid revocation reason code: {reason}. Must be 0-6, 8-10.",
                ) from None

        # Parse the certificate
        try:
            cert_obj = x509.load_der_x509_certificate(cert_der)
        except Exception as exc:  # noqa: BLE001
            raise AcmeProblem(
                MALFORMED,
                f"Cannot parse certificate: {exc}",
            ) from exc

        # Compute fingerprint to find in database
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        cert_record = self._certs.find_by_fingerprint(fingerprint)
        if cert_record is None:
            raise AcmeProblem(
                MALFORMED,
                "Certificate not found in the server's database",
                status=404,
            )

        # Check if already revoked
        if cert_record.revoked_at is not None:
            raise AcmeProblem(
                ALREADY_REVOKED,
                "Certificate has already been revoked",
            )

        # Authorization check
        if account_id is not None:
            # Account key auth: must own the certificate
            if cert_record.account_id != account_id:
                raise AcmeProblem(
                    UNAUTHORIZED,
                    "Account does not own this certificate",
                    status=403,
                )
        elif jwk is not None:
            # Certificate key auth: JWK must match cert's
            # public key
            from acmeeh.core.jws import jwk_to_public_key  # noqa: PLC0415

            try:
                request_key = jwk_to_public_key(jwk)
                cert_key = cert_obj.public_key()
                # Compare serialized public key bytes
                req_bytes = request_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                cert_bytes = cert_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                if not _hmac.compare_digest(
                    req_bytes,
                    cert_bytes,
                ):
                    raise AcmeProblem(  # noqa: TRY301
                        UNAUTHORIZED,
                        "JWK does not match the certificate's public key",
                        status=403,
                    )
            except AcmeProblem:
                raise
            except Exception as exc:  # noqa: BLE001
                raise AcmeProblem(
                    UNAUTHORIZED,
                    f"Cannot verify certificate key: {exc}",
                    status=403,
                ) from exc
        else:
            raise AcmeProblem(
                UNAUTHORIZED,
                "Revocation requires either account key or certificate key",
                status=403,
            )

        # Perform database revocation
        result = self._certs.revoke(cert_record.id, rev_reason)
        if result is None:
            raise AcmeProblem(
                ALREADY_REVOKED,
                "Certificate has already been revoked",
            )

        reason_str = rev_reason.name if rev_reason else "unspecified"
        log.info(
            "Revoked certificate %s (serial=%s, reason=%s)",
            cert_record.id,
            cert_record.serial_number,
            reason_str,
        )
        security_events.certificate_revoked(
            cert_record.account_id,
            cert_record.serial_number,
            reason_str,
        )

        if self._metrics:
            self._metrics.increment(
                "acmeeh_certificates_revoked_total",
            )

        if self._notifier:
            self._notifier.notify(
                NotificationType.REVOCATION_SUCCEEDED,
                cert_record.account_id,
                {
                    "serial_number": cert_record.serial_number,
                    "domains": [],
                    "reason": reason_str,
                },
            )

        if self._hooks:
            self._hooks.dispatch(
                "certificate.revocation",
                {
                    "certificate_id": str(cert_record.id),
                    "account_id": str(
                        cert_record.account_id,
                    ),
                    "serial_number": cert_record.serial_number,
                    "reason": reason_str,
                },
            )

        # Notify CA backend of revocation (best-effort)
        try:
            # Extract leaf PEM from chain
            leaf_pem = cert_record.pem_chain.split(
                "-----END CERTIFICATE-----",
            )[0]
            leaf_pem += "-----END CERTIFICATE-----\n"

            self._backend.revoke(
                serial_number=cert_record.serial_number,
                certificate_pem=leaf_pem,
                reason=rev_reason,
            )
        except CAError as exc:
            # Log but don't fail -- DB revocation already succeeded
            log.warning(
                "CA backend revocation notification failed for serial=%s: %s",
                cert_record.serial_number,
                exc.detail,
            )

    def _generate_serial(self) -> int:
        """Generate a certificate serial number per configuration.

        Use database sequence when ``serial_source`` is
        ``"database"``, or a 160-bit random value otherwise.
        """
        if self._ca.internal.serial_source == "database":
            return self._certs.next_serial()
        # RFC 5280 S4.1.2.2: serial must be positive, max 20 octets
        # (159 bits -- high bit must be 0)
        return int.from_bytes(secrets.token_bytes(20), "big") >> 1

    def _validate_csr_profile(
        self,
        csr: x509.CertificateSigningRequest,
        account_id: UUID,
        order_id: UUID,
    ) -> None:
        """Validate the CSR against the account's CSR profile."""
        if self._csr_profile_repo is None:
            return

        profile = self._csr_profile_repo.find_profile_for_account(
            account_id,
        )
        if profile is None:
            return

        from acmeeh.services.csr_validator import validate_csr_against_profile  # noqa: PLC0415

        try:  # noqa: SIM105
            validate_csr_against_profile(
                csr,
                profile.profile_data,
                certificate_repo=self._certs,
            )
        except AcmeProblem:
            self._orders.transition_status(
                order_id,
                OrderStatus.PROCESSING,
                OrderStatus.INVALID,
                error={
                    "type": ("urn:ietf:params:acme:error:badCSR"),
                    "detail": ("CSR does not conform to the assigned profile"),
                },
            )
            raise

    def _validate_csr_key_strength(
        self,
        csr: x509.CertificateSigningRequest,
        order_id: UUID,
        account_id: UUID,
    ) -> None:
        """Validate CSR public key meets minimum strength requirements."""
        from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: PLC0415

        pub_key = csr.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_bits = pub_key.key_size
            if key_bits < self._min_csr_rsa_key_size:
                reason_msg = (
                    f"RSA key size {key_bits} bits is below minimum {self._min_csr_rsa_key_size}"
                )
                self._orders.transition_status(
                    order_id,
                    OrderStatus.PROCESSING,
                    OrderStatus.INVALID,
                    error={
                        "type": ("urn:ietf:params:acme:error:badCSR"),
                        "detail": reason_msg,
                    },
                )
                security_events.csr_rejected(
                    account_id,
                    reason_msg,
                )
                raise AcmeProblem(BAD_CSR, reason_msg)
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_bits = pub_key.curve.key_size
            if key_bits < self._min_csr_ec_key_size:
                reason_msg = (
                    f"EC key size {key_bits} bits is below minimum {self._min_csr_ec_key_size}"
                )
                self._orders.transition_status(
                    order_id,
                    OrderStatus.PROCESSING,
                    OrderStatus.INVALID,
                    error={
                        "type": ("urn:ietf:params:acme:error:badCSR"),
                        "detail": reason_msg,
                    },
                )
                security_events.csr_rejected(
                    account_id,
                    reason_msg,
                )
                raise AcmeProblem(BAD_CSR, reason_msg)

    def _validate_csr_identifiers(  # noqa: C901
        self,
        csr: x509.CertificateSigningRequest,
        order: Order,
    ) -> None:
        """Validate that CSR SANs exactly match order identifiers."""
        try:
            san_ext = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName,
            )
        except x509.ExtensionNotFound:
            raise AcmeProblem(
                BAD_CSR,
                "CSR must contain a SubjectAlternativeName extension",
            ) from None

        # Extract SANs from CSR and check for duplicates
        csr_identifiers: set[tuple[str, str]] = set()
        duplicates: list[str] = []
        for name in san_ext.value.get_values_for_type(
            x509.DNSName,
        ):
            key = ("dns", name.lower())
            if key in csr_identifiers:
                duplicates.append(f"dns:{name}")
            csr_identifiers.add(key)
        for ip in san_ext.value.get_values_for_type(
            x509.IPAddress,
        ):
            key = ("ip", str(ip))
            if key in csr_identifiers:
                duplicates.append(f"ip:{ip}")
            csr_identifiers.add(key)

        if duplicates:
            raise AcmeProblem(
                BAD_CSR,
                f"CSR contains duplicate SANs: {', '.join(duplicates)}",
            )

        # Extract identifiers from order
        order_identifiers = {(ident.type.value, ident.value.lower()) for ident in order.identifiers}

        if csr_identifiers != order_identifiers:
            missing = order_identifiers - csr_identifiers
            extra = csr_identifiers - order_identifiers
            details: list[str] = []
            subproblems: list[dict[str, Any]] = []
            if missing:
                details.append(
                    f"missing from CSR: {sorted(missing)}",
                )
                subproblems.extend(
                    {
                        "type": BAD_CSR,
                        "detail": "Identifier missing from CSR",
                        "identifier": {
                            "type": id_type,
                            "value": id_value,
                        },
                    }
                    for id_type, id_value in sorted(missing)
                )
            if extra:
                details.append(
                    f"extra in CSR: {sorted(extra)}",
                )
                subproblems.extend(
                    {
                        "type": BAD_CSR,
                        "detail": ("Identifier in CSR not present in order"),
                        "identifier": {
                            "type": id_type,
                            "value": id_value,
                        },
                    }
                    for id_type, id_value in sorted(extra)
                )
            raise AcmeProblem(
                BAD_CSR,
                f"CSR identifiers do not match order: {'; '.join(details)}",
                subproblems=subproblems or None,
            )


def _extract_san_values(
    csr: x509.CertificateSigningRequest,
) -> list[str] | None:
    """Extract SAN values from a CSR for storage.

    Parameters
    ----------
    csr:
        The parsed certificate signing request.

    Returns
    -------
    list[str] | None
        Lowercase DNS names and IP addresses, or ``None``.

    """
    try:
        san_ext = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        )
        san_list = [
            name.lower()
            for name in san_ext.value.get_values_for_type(
                x509.DNSName,
            )
        ]
        san_list.extend(
            str(ip)
            for ip in san_ext.value.get_values_for_type(
                x509.IPAddress,
            )
        )
        return san_list if san_list else None
    except x509.ExtensionNotFound:
        return None
