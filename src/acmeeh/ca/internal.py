"""Internal CA backend -- sign certificates with a local root key.

Loads a PEM-encoded root certificate and private key from disk,
builds X.509 certificates from CSRs with proper extensions
(SAN, key usage, EKU, AKI, SKI, basic constraints), and returns
a PEM certificate chain.

Supports database-backed or random serial number assignment, and
``file`` key provider (PKCS#11 and encrypted file are extension
points for future implementation).
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from acmeeh.ca.base import CABackend, CAError, IssuedCertificate
from acmeeh.ca.cert_utils import build_eku, build_key_usage
from acmeeh.ca.ct import encode_sct_list

_HASH_ALGORITHMS = {
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}

_CT_POISON_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")
_SCT_LIST_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import (
        PrivateKeyTypes,
    )
    from cryptography.x509 import Extension

    from acmeeh.ca.ct import CTPreCertSubmitter
    from acmeeh.config.settings import CAProfileSettings, CASettings
    from acmeeh.core.types import RevocationReason

log = logging.getLogger(__name__)


class InternalCABackend(CABackend):
    """Sign certificates using a local root CA certificate and key.

    The root certificate and key are loaded lazily on first ``sign()``
    call to allow the application to start even if paths are not yet
    configured (e.g. during config validation).
    """

    def __init__(self, ca_settings: CASettings) -> None:
        """Initialise the internal CA backend.

        Parameters
        ----------
        ca_settings:
            The full ``ca`` configuration section.

        """
        super().__init__(ca_settings)
        self._root_cert: x509.Certificate | None = None
        self._root_key: PrivateKeyTypes | None = None
        self._chain_pem: str | None = None
        self._hash_algorithm = _HASH_ALGORITHMS.get(
            ca_settings.internal.hash_algorithm,
            hashes.SHA256(),
        )

    def startup_check(self) -> None:
        """Verify root cert and key are loadable."""
        self._ensure_loaded()

    def _ensure_loaded(self) -> None:  # noqa: C901, PLR0912, PLR0915
        """Lazily load root certificate, key, and optional chain."""
        if self._root_cert is not None:
            return

        internal = self._settings.internal  # noqa: SLF001

        # Load root certificate
        self._load_root_cert(internal.root_cert_path)

        # Load root private key
        self._load_root_key(internal.root_key_path)

        # Check file permissions on private key
        self._check_key_permissions(internal.root_key_path)

        # Load optional intermediate chain
        if internal.chain_path:
            self._load_chain(internal.chain_path)

        log.info(
            "Internal CA backend loaded (cert=%s, key=%s, chain=%s)",
            internal.root_cert_path,
            internal.root_key_path,
            internal.chain_path or "none",
        )

    def _load_root_cert(self, cert_path: str | None) -> None:
        """Load the root CA certificate from disk.

        Parameters
        ----------
        cert_path:
            Filesystem path to the PEM-encoded root certificate.

        Raises
        ------
        CAError
            If the path is missing or the certificate cannot be loaded.

        """
        if not cert_path:
            msg = "ca.internal.root_cert_path is required for the internal CA backend"
            raise CAError(msg)
        try:
            self._root_cert = x509.load_pem_x509_certificate(
                Path(cert_path).read_bytes(),
            )
        except FileNotFoundError:
            msg = f"Root certificate not found: {cert_path}"
            raise CAError(msg) from None
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to load root certificate from {cert_path}: {exc}"
            raise CAError(msg) from exc

    def _load_root_key(self, key_path: str | None) -> None:
        """Load the root CA private key from disk.

        Parameters
        ----------
        key_path:
            Filesystem path to the PEM-encoded private key.

        Raises
        ------
        CAError
            If the path is missing or the key cannot be loaded.

        """
        if not key_path:
            msg = "ca.internal.root_key_path is required for the internal CA backend"
            raise CAError(msg)
        try:
            self._root_key = serialization.load_pem_private_key(
                Path(key_path).read_bytes(),
                password=None,
            )
        except FileNotFoundError:
            msg = f"Root private key not found: {key_path}"
            raise CAError(msg) from None
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to load root private key from {key_path}: {exc}"
            raise CAError(msg) from exc

    @staticmethod
    def _check_key_permissions(key_path: str | None) -> None:
        """Warn if private key file has overly permissive permissions.

        Parameters
        ----------
        key_path:
            Filesystem path to the private key file.

        """
        if not key_path:
            return
        try:
            key_stat = os.stat(key_path)
            mode = key_stat.st_mode
            # Warn if group or others can read the key
            if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
                log.warning(
                    "Private key file '%s' has overly permissive "
                    "permissions (mode=%o). Recommend chmod 600.",
                    key_path,
                    stat.S_IMODE(mode),
                )
        except OSError:
            pass  # Permission check is best-effort

    def _load_chain(self, chain_path: str) -> None:
        """Load the optional intermediate chain from disk.

        Parameters
        ----------
        chain_path:
            Filesystem path to the PEM-encoded chain file.

        Raises
        ------
        CAError
            If the chain file cannot be loaded.

        """
        try:
            self._chain_pem = Path(chain_path).read_text().strip()
        except FileNotFoundError:
            msg = f"Chain file not found: {chain_path}"
            raise CAError(msg) from None
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to load chain from {chain_path}: {exc}"
            raise CAError(msg) from exc

    @property
    def root_cert(self) -> x509.Certificate | None:
        """Return the loaded root certificate, or None if not yet loaded."""
        return self._root_cert

    @property
    def root_key(self) -> PrivateKeyTypes | None:
        """Return the loaded root private key, or None if not yet loaded."""
        return self._root_key

    def sign(  # noqa: PLR0913
        self,
        csr: x509.CertificateSigningRequest,
        *,
        profile: CAProfileSettings,
        validity_days: int,
        serial_number: int | None = None,
        ct_submitter: CTPreCertSubmitter | None = None,
    ) -> IssuedCertificate:
        """Sign a CSR with the internal root CA.

        Build a certificate with:
        - Subject CN from the first SAN in the CSR
        - Issuer from root certificate's subject
        - SAN extension copied from CSR
        - Key usage and EKU from the profile
        - Basic constraints (CA=false)
        - Authority key identifier from root cert
        - Subject key identifier from CSR public key

        When *ct_submitter* is provided, a pre-certificate with the CT
        poison extension (OID 1.3.6.1.4.1.11129.2.4.3) is built first,
        submitted to CT logs for SCT collection, and the final certificate
        is issued with an embedded SCT list extension instead of the poison.

        Parameters
        ----------
        csr:
            Parsed PKCS#10 certificate signing request.
        profile:
            Certificate profile defining key usages and EKUs.
        validity_days:
            Requested certificate lifetime in days.
        serial_number:
            Serial number to embed in the certificate.
        ct_submitter:
            Optional CT pre-certificate submitter.

        Returns
        -------
        IssuedCertificate
            The signed certificate with full chain and metadata.

        Raises
        ------
        CAError
            On any signing failure.

        """
        self._ensure_loaded()
        if self._root_cert is None:
            msg = "Root certificate not loaded"
            raise CAError(msg)
        if self._root_key is None:
            msg = "Root private key not loaded"
            raise CAError(msg)

        # Determine serial -- RFC 5280 sec 4.1.2.2 limits to 20 octets
        # positive, so max 159 bits (high bit must be 0)
        if serial_number is None:
            serial_number = int.from_bytes(secrets.token_bytes(20), "big") >> 1

        # Determine validity
        now = datetime.now(UTC)
        not_before = now
        not_after = now + timedelta(days=validity_days)

        # Extract SANs from CSR for subject CN
        try:
            san_ext = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName,
            )
        except x509.ExtensionNotFound:
            msg = "CSR does not contain a SubjectAlternativeName extension"
            raise CAError(msg) from None

        # Use first DNS name as CN, fall back to first IP
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        ip_addrs = san_ext.value.get_values_for_type(x509.IPAddress)
        if dns_names:
            cn = dns_names[0]
        elif ip_addrs:
            cn = str(ip_addrs[0])
        else:
            msg = "CSR SAN contains no DNS names or IP addresses"
            raise CAError(msg)

        # Build certificate
        try:
            builder = self._build_cert_base(
                csr,
                san_ext,
                cn,
                serial_number,
                not_before,
                not_after,
                profile,
            )

            if ct_submitter is not None:
                cert = self._sign_with_ct(
                    builder,
                    ct_submitter,
                    serial_number,
                    cn,
                    validity_days,
                )
            else:
                # Sign with root key (standard flow)
                cert = builder.sign(
                    self._root_key,
                    self._hash_algorithm,  # type: ignore[arg-type]
                )

        except CAError:
            raise
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to build/sign certificate: {exc}"
            raise CAError(
                msg,
                retryable=False,
            ) from exc

        return self._build_issued_certificate(
            cert,
            serial_number,
            cn,
            validity_days,
        )

    def _build_issued_certificate(
        self,
        cert: x509.Certificate,
        serial_number: int,
        cn: str,
        validity_days: int,
    ) -> IssuedCertificate:
        """Encode a signed certificate and build the issued result.

        Parameters
        ----------
        cert:
            The signed X.509 certificate.
        serial_number:
            The certificate serial number.
        cn:
            Common name of the certificate subject.
        validity_days:
            Certificate validity in days.

        Returns
        -------
        IssuedCertificate
            The issued certificate with PEM chain and metadata.

        """
        if self._root_cert is None:
            msg = "Root certificate not loaded"
            raise CAError(msg)

        # Encode to PEM
        leaf_pem = cert.public_bytes(
            serialization.Encoding.PEM,
        ).decode("ascii")
        leaf_der = cert.public_bytes(serialization.Encoding.DER)

        # Build full chain: leaf + intermediates + root
        chain_parts = [leaf_pem.strip()]
        if self._chain_pem:
            chain_parts.append(self._chain_pem)
        # Append root cert
        root_pem = self._root_cert.public_bytes(
            serialization.Encoding.PEM,
        ).decode("ascii")
        chain_parts.append(root_pem.strip())

        pem_chain = "\n".join(chain_parts) + "\n"

        # Compute metadata
        fingerprint = hashlib.sha256(leaf_der).hexdigest()
        serial_str = format(serial_number, "x")

        log.info(
            "Internal CA signed certificate: serial=%s, cn=%s, validity=%d days",
            serial_str,
            cn,
            validity_days,
        )

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        return IssuedCertificate(
            pem_chain=pem_chain,
            not_before=not_before,
            not_after=not_after,
            serial_number=serial_str,
            fingerprint=fingerprint,
        )

    def _build_cert_base(  # noqa: PLR0913
        self,
        csr: x509.CertificateSigningRequest,
        san_ext: Extension[Any],
        cn: str,
        serial_number: int,
        not_before: datetime,
        not_after: datetime,
        profile: CAProfileSettings,
    ) -> x509.CertificateBuilder:
        """Build a CertificateBuilder with all standard extensions.

        Return the builder ready for signing (or for adding the CT
        poison / SCT list extension before signing).

        Parameters
        ----------
        csr:
            Parsed PKCS#10 certificate signing request.
        san_ext:
            The SAN extension extracted from the CSR.
        cn:
            Common name for the certificate subject.
        serial_number:
            Serial number to embed in the certificate.
        not_before:
            Certificate validity start time.
        not_after:
            Certificate validity end time.
        profile:
            Certificate profile defining key usages and EKUs.

        Returns
        -------
        x509.CertificateBuilder
            The builder with all extensions added.

        """
        if self._root_cert is None:
            msg = "Root certificate not loaded"
            raise CAError(msg)

        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, cn)],
                ),
            )
            .issuer_name(self._root_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial_number)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )

        # SAN from CSR
        builder = builder.add_extension(
            san_ext.value,
            critical=False,
        )

        # Basic constraints -- not a CA
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        # Key usage from profile
        if profile.key_usages:
            builder = builder.add_extension(
                build_key_usage(profile.key_usages),
                critical=True,
            )

        # Extended key usage from profile
        if profile.extended_key_usages:
            builder = builder.add_extension(
                build_eku(profile.extended_key_usages),
                critical=False,
            )

        # Authority key identifier from root cert
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self._root_cert.public_key(),  # type: ignore[arg-type]
            ),
            critical=False,
        )

        # Subject key identifier from CSR public key
        return builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )

    def _sign_with_ct(
        self,
        builder: x509.CertificateBuilder,
        ct_submitter: CTPreCertSubmitter,
        serial_number: int,
        cn: str,
        validity_days: int,
    ) -> x509.Certificate:
        """Perform the CT pre-certificate flow and return the final cert.

        1. Add CT poison extension to builder, sign pre-certificate
        2. Submit pre-cert DER to CT logs via *ct_submitter*
        3. Collect SCTs
        4. Build final cert with SCT list extension (no poison)
        5. Sign and return

        Parameters
        ----------
        builder:
            Certificate builder ready for signing.
        ct_submitter:
            CT pre-certificate submitter.
        serial_number:
            Certificate serial number.
        cn:
            Common name of the certificate subject.
        validity_days:
            Certificate validity in days.

        Returns
        -------
        x509.Certificate
            The final signed certificate with embedded SCTs.

        Raises
        ------
        CAError
            If the pre-certificate signing or final signing fails.

        """
        if self._root_key is None:
            msg = "Root private key not loaded"
            raise CAError(msg)

        # Step 1: Add CT poison extension and sign pre-certificate
        precert_builder = builder.add_extension(
            x509.UnrecognizedExtension(
                _CT_POISON_OID,
                b"\x05\x00",  # ASN.1 NULL
            ),
            critical=True,
        )
        precert = precert_builder.sign(
            self._root_key,
            self._hash_algorithm,  # type: ignore[arg-type]
        )
        precert_der = precert.public_bytes(serialization.Encoding.DER)

        log.info(
            "Internal CA built pre-certificate: serial=%s, cn=%s",
            format(serial_number, "x"),
            cn,
        )

        # Step 2: Submit pre-cert to CT logs
        scts = ct_submitter.submit_precert(precert_der)

        if not scts:
            log.warning(
                "No SCTs received from CT logs for serial=%s; "
                "issuing certificate without embedded SCTs",
                format(serial_number, "x"),
            )
            # Fall back to standard signing (no poison, no SCTs)
            return builder.sign(
                self._root_key,
                self._hash_algorithm,  # type: ignore[arg-type]
            )

        log.info(
            "Received %d SCT(s) from CT logs for serial=%s",
            len(scts),
            format(serial_number, "x"),
        )

        # Step 3: Encode SCT list into TLS wire format
        sct_list_bytes = encode_sct_list(scts)

        # Step 4: Build final cert with SCT list extension (no poison)
        final_builder = builder.add_extension(
            x509.UnrecognizedExtension(
                _SCT_LIST_OID,
                sct_list_bytes,
            ),
            critical=False,
        )

        # Step 5: Sign final certificate
        final_cert = final_builder.sign(
            self._root_key,
            self._hash_algorithm,  # type: ignore[arg-type]
        )

        log.info(
            "Internal CA signed final certificate with %d embedded "
            "SCT(s): serial=%s, cn=%s, validity=%d days",
            len(scts),
            format(serial_number, "x"),
            cn,
            validity_days,
        )

        return final_cert

    def revoke(
        self,
        *,
        serial_number: str,
        certificate_pem: str,  # noqa: ARG002
        reason: RevocationReason | None = None,
    ) -> None:
        """Record revocation for internal CA (no-op).

        CRL generation is a separate concern and not handled here.

        Parameters
        ----------
        serial_number:
            Hex-encoded serial number of the revoked certificate.
        certificate_pem:
            PEM-encoded leaf certificate (unused by this backend).
        reason:
            RFC 5280 revocation reason code, or ``None`` for unspecified.

        """
        log.debug(
            "Internal CA backend: revocation recorded for serial=%s "
            "(reason=%s) -- database-only, no CRL action",
            serial_number,
            reason.name if reason else "unspecified",
        )
