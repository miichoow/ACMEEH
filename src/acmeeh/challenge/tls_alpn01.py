"""TLS-ALPN-01 challenge validator (RFC 8737).

Production implementation of the ``tls-alpn-01`` challenge type.
Connects to the identifier on the configured port with ALPN
``acme-tls/1``, validates the self-signed certificate's SAN and
``acmeIdentifier`` extension against the expected key authorization
digest.

Security hardening:
- TLS 1.2+ minimum version
- Structured errors with retryable classification
- Strict DER ASN.1 OCTET STRING parsing (no fallback guessing)
- IPv6 support with correct SNI handling
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import socket
import ssl
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

from acmeeh.challenge.base import ChallengeError, ChallengeValidator
from acmeeh.core.jws import key_authorization
from acmeeh.core.types import ChallengeType

if TYPE_CHECKING:
    from acmeeh.config.settings import TlsAlpn01Settings

log = logging.getLogger(__name__)

# OID for the acmeIdentifier extension (RFC 8737 §3)
_ACME_IDENTIFIER_OID = ObjectIdentifier("1.3.6.1.5.5.7.1.31")

# ALPN protocol identifier
_ACME_TLS_ALPN = "acme-tls/1"


class TlsAlpn01Validator(ChallengeValidator):
    """TLS-ALPN-01 challenge validator (RFC 8737).

    Performs a full TLS handshake to the identifier with the
    ``acme-tls/1`` ALPN protocol and validates the peer certificate.
    """

    challenge_type = ChallengeType.TLS_ALPN_01
    supported_identifier_types = frozenset({"dns", "ip"})

    def __init__(self, settings: TlsAlpn01Settings | None = None) -> None:
        super().__init__(settings=settings)

    def validate(
        self,
        *,
        token: str,
        jwk: dict,
        identifier_type: str,
        identifier_value: str,
    ) -> None:
        """Validate a TLS-ALPN-01 challenge.

        Algorithm:
        1. Compute key_authorization and its SHA-256 digest
        2. TLS connect with ALPN ["acme-tls/1"], minimum TLS 1.2
        3. Verify negotiated ALPN
        4. Extract and parse peer certificate
        5. Verify SAN contains the identifier
        6. Verify acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31)
           is present, critical, and contains the expected digest
        """
        port = getattr(self.settings, "port", 443)
        timeout = getattr(self.settings, "timeout_seconds", 10)

        # Step 1: compute expected digest
        key_authz = key_authorization(token, jwk)
        expected_digest = hashlib.sha256(key_authz.encode("ascii")).digest()

        log.debug(
            "TLS-ALPN-01 validation: connecting to %s:%s",
            identifier_value,
            port,
        )

        # Step 2: TLS connect with ALPN and minimum version
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Self-signed cert expected
        ctx.set_alpn_protocols([_ACME_TLS_ALPN])

        # Determine SNI server_hostname — None for IP addresses
        server_hostname: str | None = identifier_value
        try:
            ipaddress.ip_address(identifier_value)
            server_hostname = None
        except ValueError:
            pass

        try:
            with (
                socket.create_connection(
                    (identifier_value, port),
                    timeout=timeout,
                ) as sock,
                ctx.wrap_socket(
                    sock,
                    server_hostname=server_hostname,
                ) as tls_sock,
            ):
                # Step 3: verify negotiated ALPN
                negotiated = tls_sock.selected_alpn_protocol()
                if negotiated != _ACME_TLS_ALPN:
                    msg = (
                        f"ALPN negotiation failed: expected '{_ACME_TLS_ALPN}', got '{negotiated}'"
                    )
                    log.warning(msg)
                    raise ChallengeError(
                        msg,
                        retryable=False,
                    )

                # Step 4: extract peer certificate (DER)
                der_cert = tls_sock.getpeercert(binary_form=True)
                if der_cert is None:
                    msg = "No peer certificate presented"
                    raise ChallengeError(
                        msg,
                        retryable=False,
                    )

        except ChallengeError:
            raise
        except (ssl.SSLError, OSError) as exc:
            msg = f"TLS connection to {identifier_value}:{port} failed: {exc}"
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=True,
            ) from exc

        # Parse the certificate with cryptography
        try:
            cert = x509.load_der_x509_certificate(der_cert)
        except Exception as exc:
            msg = f"Failed to parse peer certificate DER: {exc}"
            raise ChallengeError(
                msg,
                retryable=False,
            ) from exc

        # Step 5: verify SAN contains the identifier
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName,
            )
        except x509.ExtensionNotFound:
            msg = "Certificate does not contain a SubjectAlternativeName extension"
            raise ChallengeError(
                msg,
                retryable=False,
            )

        san_matched = False
        if identifier_type == "dns":
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            san_matched = identifier_value.lower() in (n.lower() for n in dns_names)
        elif identifier_type == "ip":
            try:
                target_ip = ipaddress.ip_address(identifier_value)
                ip_addrs = san_ext.value.get_values_for_type(x509.IPAddress)
                san_matched = target_ip in ip_addrs
            except ValueError:
                pass

        if not san_matched:
            msg = (
                f"Certificate SAN does not contain identifier "
                f"({identifier_type}: {identifier_value})"
            )
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=False,
            )

        # Step 6: verify acmeIdentifier extension
        try:
            acme_ext = cert.extensions.get_extension_for_oid(
                _ACME_IDENTIFIER_OID,
            )
        except x509.ExtensionNotFound:
            msg = (
                "Certificate does not contain the acmeIdentifier extension "
                f"(OID {_ACME_IDENTIFIER_OID.dotted_string})"
            )
            raise ChallengeError(
                msg,
                retryable=False,
            )

        # Must be marked critical (RFC 8737 §3)
        if not acme_ext.critical:
            msg = "acmeIdentifier extension must be marked critical"
            raise ChallengeError(
                msg,
                retryable=False,
            )

        # The extension value is an ASN.1 OCTET STRING containing the
        # SHA-256 digest.  cryptography gives us the raw DER value.
        ext_der = acme_ext.value.value  # type: ignore[attr-defined]
        actual_digest = _parse_acme_identifier_extension(ext_der)

        if actual_digest != expected_digest:
            msg = "acmeIdentifier extension digest does not match expected value"
            log.warning(msg)
            raise ChallengeError(
                msg,
                retryable=False,
            )

        log.info(
            "TLS-ALPN-01 validation succeeded for %s:%s (port %s)",
            identifier_type,
            identifier_value,
            port,
        )


def _parse_acme_identifier_extension(ext_der: bytes) -> bytes:
    """Parse the DER-encoded acmeIdentifier extension value.

    Expects a DER OCTET STRING (tag ``0x04``) wrapping exactly 32 bytes
    (SHA-256 digest).  Rejects anything that doesn't match this format.

    Parameters
    ----------
    ext_der:
        Raw DER bytes from the extension value.

    Returns
    -------
    bytes
        The 32-byte SHA-256 digest.

    Raises
    ------
    ChallengeError
        If the DER structure is invalid or the digest length is wrong.

    """
    if len(ext_der) < 2:
        msg = f"acmeIdentifier extension DER too short ({len(ext_der)} bytes)"
        raise ChallengeError(
            msg,
            retryable=False,
        )

    if ext_der[0] != 0x04:
        msg = f"acmeIdentifier extension: expected OCTET STRING tag (0x04), got 0x{ext_der[0]:02x}"
        raise ChallengeError(
            msg,
            retryable=False,
        )

    # Parse DER length (supports both short and long form)
    offset = 1
    first_len_byte = ext_der[offset]
    offset += 1

    if first_len_byte < 0x80:
        # Short form: length is the byte itself
        length = first_len_byte
    elif first_len_byte == 0x80:
        msg = "acmeIdentifier extension: indefinite-length encoding not allowed in DER"
        raise ChallengeError(
            msg,
            retryable=False,
        )
    else:
        # Long form: first byte indicates number of length bytes
        num_len_bytes = first_len_byte & 0x7F
        if offset + num_len_bytes > len(ext_der):
            msg = "acmeIdentifier extension: truncated DER length field"
            raise ChallengeError(
                msg,
                retryable=False,
            )
        length = 0
        for _i in range(num_len_bytes):
            length = (length << 8) | ext_der[offset]
            offset += 1

    # Verify we have exactly the right number of bytes remaining
    if offset + length != len(ext_der):
        msg = (
            f"acmeIdentifier extension: DER length mismatch — "
            f"declared {length} content bytes at offset {offset}, "
            f"but {len(ext_der) - offset} bytes remain"
        )
        raise ChallengeError(
            msg,
            retryable=False,
        )

    digest = ext_der[offset:]
    if len(digest) != 32:
        msg = f"acmeIdentifier extension: expected 32-byte SHA-256 digest, got {len(digest)} bytes"
        raise ChallengeError(
            msg,
            retryable=False,
        )

    return digest
