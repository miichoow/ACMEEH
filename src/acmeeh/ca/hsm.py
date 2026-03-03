"""HSM CA backend -- signs certificates via PKCS#11.

The private key never leaves the Hardware Security Module.  Uses
``python-pkcs11`` for PKCS#11 access and the ``cryptography`` library
to build X.509 certificate structures.

The signing workflow:
1. Build the certificate with all extensions using CertificateBuilder
2. Sign with an ephemeral in-memory key to produce TBS bytes
3. Sign the TBS bytes via PKCS#11
4. Assemble the final DER certificate manually
5. Parse back with x509.load_der_x509_certificate()
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import queue
import secrets
import threading
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID

from acmeeh.ca.base import CABackend, CAError, IssuedCertificate
from acmeeh.ca.cert_utils import build_eku, build_key_usage

if TYPE_CHECKING:
    from types import TracebackType

    from acmeeh.config.settings import (
        CAProfileSettings,
        CASettings,
        HsmSettings,
    )
    from acmeeh.core.types import RevocationReason

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ASN.1 DER constants
# ---------------------------------------------------------------------------
# Threshold at which DER length encoding switches to long form.
_DER_LONG_FORM_THRESHOLD = 0x80
# High-bit mask for DER integer sign detection.
_DER_SIGN_BIT_MASK = 0x80

# ---------------------------------------------------------------------------
# Signature algorithm DER encodings (AlgorithmIdentifier SEQUENCE)
# ---------------------------------------------------------------------------
# These are pre-encoded ASN.1 SEQUENCE { OID, parameters } values.

_SIG_ALGORITHM_DER = {
    # RSA PKCS#1 v1.5
    ("rsa", "sha256"): (
        b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00"
    ),  # sha256WithRSAEncryption
    ("rsa", "sha384"): (
        b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c\x05\x00"
    ),  # sha384WithRSAEncryption
    ("rsa", "sha512"): (
        b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d\x05\x00"
    ),  # sha512WithRSAEncryption
    # ECDSA
    ("ec", "sha256"): (b"\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02"),  # ecdsa-with-SHA256
    ("ec", "sha384"): (b"\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03"),  # ecdsa-with-SHA384
    ("ec", "sha512"): (b"\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x04"),  # ecdsa-with-SHA512
}

# PKCS#11 mechanism constants (CKM_*)
_CKM_SHA256_RSA_PKCS = 0x00000040
_CKM_SHA384_RSA_PKCS = 0x00000041
_CKM_SHA512_RSA_PKCS = 0x00000042
_CKM_ECDSA = 0x00001041

_RSA_MECHANISMS = {
    "sha256": _CKM_SHA256_RSA_PKCS,
    "sha384": _CKM_SHA384_RSA_PKCS,
    "sha512": _CKM_SHA512_RSA_PKCS,
}

_HASH_ALGORITHMS = {
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}


# ---------------------------------------------------------------------------
# DER assembly helpers
# ---------------------------------------------------------------------------


def _encode_der_length(length: int) -> bytes:
    """Encode an ASN.1 DER length field."""
    if length < _DER_LONG_FORM_THRESHOLD:
        return bytes([length])
    # Determine how many bytes needed
    length_bytes = length.to_bytes(
        (length.bit_length() + 7) // 8,
        "big",
    )
    return bytes([_DER_LONG_FORM_THRESHOLD | len(length_bytes)]) + length_bytes


def _int_to_der_integer(value: int) -> bytes:
    """Encode an integer as ASN.1 DER INTEGER (tag 0x02)."""
    if value == 0:
        content = b"\x00"
    else:
        byte_len = (value.bit_length() + 7) // 8
        content = value.to_bytes(byte_len, "big")
        # Ensure positive encoding -- prepend 0x00 if high bit set
        if content[0] & _DER_SIGN_BIT_MASK:
            content = b"\x00" + content
    return b"\x02" + _encode_der_length(len(content)) + content


def _ecdsa_raw_to_der(raw_sig: bytes) -> bytes:
    """Convert PKCS#11 ECDSA raw ``(r || s)`` signature to DER format.

    PKCS#11 returns a flat concatenation of ``r`` and ``s`` as
    fixed-width unsigned big-endian integers.  X.509 expects
    DER-encoded ``SEQUENCE { INTEGER r, INTEGER s }``.
    """
    if len(raw_sig) % 2 != 0:
        msg = f"ECDSA raw signature has odd length ({len(raw_sig)}); expected even (r||s)"
        raise CAError(
            msg,
        )
    half = len(raw_sig) // 2
    r_val = int.from_bytes(raw_sig[:half], "big")
    s_val = int.from_bytes(raw_sig[half:], "big")

    r_der = _int_to_der_integer(r_val)
    s_der = _int_to_der_integer(s_val)

    inner = r_der + s_der
    return b"\x30" + _encode_der_length(len(inner)) + inner


def _assemble_certificate_der(
    tbs_der: bytes,
    sig_algorithm_der: bytes,
    signature: bytes,
) -> bytes:
    """Assemble a complete X.509 certificate from components.

    Returns DER encoding of::

        SEQUENCE {
            TBSCertificate      (already DER-encoded),
            AlgorithmIdentifier (already DER-encoded),
            BIT STRING          (signature)
        }
    """
    # BIT STRING: tag 0x03, length, 0x00 (no unused bits), sig bytes
    bit_string_content = b"\x00" + signature
    bit_string = b"\x03" + _encode_der_length(len(bit_string_content)) + bit_string_content

    inner = tbs_der + sig_algorithm_der + bit_string
    return b"\x30" + _encode_der_length(len(inner)) + inner


# ---------------------------------------------------------------------------
# Session pool
# ---------------------------------------------------------------------------


class _Pkcs11SessionPool:
    """Thread-safe pool of PKCS#11 sessions.

    Sessions are lazily created up to ``max_size``.  Use as a context
    manager via :meth:`acquire`::

        with pool.acquire() as session:
            session.sign(key, data, mechanism)
    """

    def __init__(  # noqa: PLR0913
        self,
        token: Any,
        pin: str,
        *,
        login_required: bool,
        max_size: int,
        pool_timeout: int = 30,
    ) -> None:
        """Initialise the session pool."""
        self._token = token
        self._pin = pin
        self._login_required = login_required
        self._max_size = max_size
        self._pool_timeout = pool_timeout
        self._pool: queue.Queue[Any] = queue.Queue(maxsize=max_size)
        self._created = 0
        self._lock = threading.Lock()

    def _create_session(self) -> Any:
        """Open a new PKCS#11 session."""
        if self._login_required:
            return self._token.open(
                rw=False,
                user_pin=self._pin,
            )
        return self._token.open(rw=False)

    class _SessionContext:
        """Context manager that acquires and releases a session."""

        def __init__(self, pool: _Pkcs11SessionPool) -> None:
            """Store a reference to the owning pool."""
            self._pool = pool
            self._session: Any = None

        def __enter__(self) -> Any:
            """Acquire a PKCS#11 session from the pool."""
            try:
                self._session = self._pool._pool.get_nowait()  # noqa: SLF001
            except queue.Empty:
                with self._pool._lock:  # noqa: SLF001
                    if (
                        self._pool._created  # noqa: SLF001
                        < self._pool._max_size  # noqa: SLF001
                    ):
                        self._session = (
                            self._pool._create_session()  # noqa: SLF001
                        )
                        self._pool._created += 1  # noqa: SLF001
                    else:
                        # All sessions created; wait for return
                        self._session = self._pool._pool.get(  # noqa: SLF001
                            timeout=self._pool._pool_timeout,  # noqa: SLF001
                        )
            return self._session

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            _exc_val: BaseException | None,
            _exc_tb: TracebackType | None,
        ) -> None:
            """Return or discard the session on context exit."""
            if self._session is not None:
                if exc_type is not None:
                    # On error, discard and create fresh on next
                    with contextlib.suppress(Exception):
                        self._session.close()
                    with self._pool._lock:  # noqa: SLF001
                        self._pool._created -= 1  # noqa: SLF001
                else:
                    self._pool._pool.put(self._session)  # noqa: SLF001

    def acquire(self) -> _SessionContext:
        """Return a context manager that yields a PKCS#11 session."""
        return self._SessionContext(self)

    def close_all(self) -> None:
        """Close all pooled sessions."""
        while True:
            try:
                session = self._pool.get_nowait()
                session.close()
            except queue.Empty:
                break
        with self._lock:
            self._created = 0


# ---------------------------------------------------------------------------
# HSM CA Backend
# ---------------------------------------------------------------------------


class HsmCABackend(CABackend):
    """Sign certificates using a Hardware Security Module via PKCS#11.

    The private key never leaves the HSM.  Certificate structures are
    built with the ``cryptography`` library, but the actual TBS
    signature is performed by the HSM.
    """

    def __init__(self, ca_settings: CASettings) -> None:
        """Initialise the HSM backend (lazy connection on first use)."""
        super().__init__(ca_settings)
        self._issuer_cert: x509.Certificate | None = None
        self._chain_pem: str | None = None
        self._session_pool: _Pkcs11SessionPool | None = None
        self._pkcs11_lib: Any = None
        self._key_handle: Any = None
        self._loaded = False

    def startup_check(self) -> None:
        """Verify PKCS#11 lib, token, and key are accessible."""
        self._ensure_loaded()

    def _ensure_loaded(self) -> None:  # noqa: C901, PLR0912, PLR0915
        """Lazily initialise PKCS#11 connection and load issuer cert."""
        if self._loaded:
            return

        hsm = self._settings.hsm

        # Import python-pkcs11 lazily
        try:
            import pkcs11  # noqa: PLC0415
            import pkcs11.util.ec  # noqa: PLC0415
            import pkcs11.util.rsa  # noqa: PLC0415
        except ImportError as exc:
            msg = (
                "python-pkcs11 package is required for the HSM "
                "backend. Install it with: pip install python-pkcs11"
            )
            raise CAError(
                msg,
            ) from exc

        self._load_pkcs11_library(hsm, pkcs11)
        token = self._find_token(hsm)

        # Create session pool
        self._session_pool = _Pkcs11SessionPool(
            token=token,
            pin=hsm.pin,
            login_required=hsm.login_required,
            max_size=hsm.session_pool_size,
            pool_timeout=hsm.session_pool_timeout_seconds,
        )

        # Verify key exists
        try:
            with self._session_pool.acquire() as session:
                self._key_handle = self._find_key(session, hsm)
        except CAError:
            raise
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to find signing key in HSM: {exc}"
            raise CAError(
                msg,
            ) from exc

        self._load_issuer_cert(hsm)
        self._load_chain(hsm)

        self._loaded = True
        log.info(
            "HSM CA backend loaded (lib=%s, token=%s, key=%s, cert=%s, chain=%s)",
            hsm.pkcs11_library,
            hsm.token_label or f"slot:{hsm.slot_id}",
            hsm.key_label or f"id:{hsm.key_id}",
            hsm.issuer_cert_path,
            hsm.chain_path or "none",
        )

    def _load_pkcs11_library(
        self,
        hsm: HsmSettings,
        pkcs11_module: Any,
    ) -> None:
        """Load the PKCS#11 shared library."""
        if not hsm.pkcs11_library:
            msg = "ca.hsm.pkcs11_library is required for the HSM backend"
            raise CAError(msg)
        try:
            self._pkcs11_lib = pkcs11_module.lib(
                hsm.pkcs11_library,
            )
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to load PKCS#11 library '{hsm.pkcs11_library}': {exc}"
            raise CAError(msg) from exc

    def _find_token(self, hsm: HsmSettings) -> Any:
        """Locate the PKCS#11 token by label or slot ID."""
        token = None
        try:
            if hsm.token_label:
                token = self._pkcs11_lib.get_token(
                    token_label=hsm.token_label,
                )
            elif hsm.slot_id is not None:
                for t in self._pkcs11_lib.get_tokens():
                    if t.slot.slot_id == hsm.slot_id:
                        token = t
                        break
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to find PKCS#11 token: {exc}"
            raise CAError(msg) from exc

        if token is None:
            label_info = (
                f"token_label='{hsm.token_label}'" if hsm.token_label else f"slot_id={hsm.slot_id}"
            )
            msg = f"PKCS#11 token not found ({label_info})"
            raise CAError(msg)

        return token

    def _load_issuer_cert(self, hsm: HsmSettings) -> None:
        """Load the issuer certificate from disk."""
        if not hsm.issuer_cert_path:
            msg = "ca.hsm.issuer_cert_path is required for the HSM backend"
            raise CAError(msg)
        try:
            with open(hsm.issuer_cert_path, "rb") as f:  # noqa: PTH123
                self._issuer_cert = x509.load_pem_x509_certificate(f.read())
        except FileNotFoundError:
            msg = f"Issuer certificate not found: {hsm.issuer_cert_path}"
            raise CAError(msg) from None
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to load issuer certificate from {hsm.issuer_cert_path}: {exc}"
            raise CAError(msg) from exc

    def _load_chain(self, hsm: HsmSettings) -> None:
        """Load the optional chain file from disk."""
        if not hsm.chain_path:
            return
        try:
            with open(hsm.chain_path) as f:  # noqa: PTH123
                self._chain_pem = f.read().strip()
        except FileNotFoundError:
            msg = f"Chain file not found: {hsm.chain_path}"
            raise CAError(msg) from None
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to load chain from {hsm.chain_path}: {exc}"
            raise CAError(msg) from exc

    @staticmethod
    def _find_key(
        session: Any,
        hsm: HsmSettings,
    ) -> Any:
        """Locate the signing key in the HSM session."""
        import pkcs11 as p11  # noqa: PLC0415

        key_class = p11.ObjectClass.PRIVATE_KEY
        attrs: dict[Any, Any] = {
            p11.Attribute.CLASS: key_class,
        }
        if hsm.key_label:
            attrs[p11.Attribute.LABEL] = hsm.key_label
        if hsm.key_id:
            attrs[p11.Attribute.ID] = bytes.fromhex(hsm.key_id)

        keys = list(session.get_objects(attrs))
        if not keys:
            label_info = []
            if hsm.key_label:
                label_info.append(f"label='{hsm.key_label}'")
            if hsm.key_id:
                label_info.append(f"id='{hsm.key_id}'")
            msg = f"Signing key not found in HSM ({', '.join(label_info)})"
            raise CAError(msg)
        return keys[0]

    def sign(  # noqa: PLR0915
        self,
        csr: x509.CertificateSigningRequest,
        *,
        profile: CAProfileSettings,
        validity_days: int,
        serial_number: int | None = None,
        ct_submitter: Any = None,  # noqa: ARG002
    ) -> IssuedCertificate:
        """Sign a CSR using the HSM.

        Build the certificate with cryptography, then sign the TBS
        bytes via PKCS#11.

        The ``ct_submitter`` parameter is accepted for interface
        compatibility but ignored -- CT pre-cert submission is not
        currently supported for the HSM backend.
        """
        self._ensure_loaded()
        assert self._issuer_cert is not None  # noqa: S101
        assert self._session_pool is not None  # noqa: S101

        hsm = self._settings.hsm

        # Determine serial
        if serial_number is None:
            serial_number = int.from_bytes(secrets.token_bytes(20), "big") >> 1

        # Determine validity
        now = datetime.now(UTC)
        not_before = now
        not_after = now + timedelta(days=validity_days)

        # Extract SANs from CSR
        try:
            san_ext = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName,
            )
        except x509.ExtensionNotFound as exc:
            msg = "CSR does not contain a SubjectAlternativeName extension"
            raise CAError(msg) from exc

        cn = self._extract_common_name(san_ext)

        # Build certificate
        try:
            cert_der = self._build_and_sign_cert(
                csr,
                san_ext,
                cn,
                serial_number,
                not_before,
                not_after,
                profile,
                hsm,
            )
            cert = x509.load_der_x509_certificate(cert_der)
        except CAError:
            raise
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to build/sign certificate via HSM: {exc}"
            raise CAError(
                msg,
                retryable=False,
            ) from exc

        return self._build_result(
            cert,
            cert_der,
            serial_number,
            not_before,
            not_after,
            cn,
            validity_days,
        )

    @staticmethod
    def _extract_common_name(
        san_ext: x509.Extension[x509.SubjectAlternativeName],
    ) -> str:
        """Extract the common name from a SAN extension."""
        dns_names = san_ext.value.get_values_for_type(
            x509.DNSName,
        )
        ip_addrs = san_ext.value.get_values_for_type(
            x509.IPAddress,
        )
        if dns_names:
            return dns_names[0]
        if ip_addrs:
            return str(ip_addrs[0])
        msg = "CSR SAN contains no DNS names or IP addresses"
        raise CAError(msg)

    def _build_and_sign_cert(  # noqa: PLR0913
        self,
        csr: x509.CertificateSigningRequest,
        san_ext: x509.Extension[x509.SubjectAlternativeName],
        cn: str,
        serial_number: int,
        not_before: datetime,
        not_after: datetime,
        profile: CAProfileSettings,
        hsm: HsmSettings,
    ) -> bytes:
        """Build the X.509 structure and sign via HSM."""
        assert self._issuer_cert is not None  # noqa: S101

        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, cn)],
                ),
            )
            .issuer_name(self._issuer_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial_number)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )

        builder = builder.add_extension(
            san_ext.value,
            critical=False,
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        if profile.key_usages:
            builder = builder.add_extension(
                build_key_usage(profile.key_usages),
                critical=True,
            )

        if profile.extended_key_usages:
            builder = builder.add_extension(
                build_eku(profile.extended_key_usages),
                critical=False,
            )

        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self._issuer_cert.public_key(),  # type: ignore[arg-type]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                csr.public_key(),
            ),
            critical=False,
        )

        # Step 1: Sign with ephemeral key to get TBS bytes
        ephemeral_key = self._make_ephemeral_key(hsm.key_type)
        hash_algo = _HASH_ALGORITHMS.get(
            hsm.hash_algorithm,
            hashes.SHA256(),
        )
        temp_cert = builder.sign(ephemeral_key, hash_algo)  # type: ignore[arg-type]
        tbs_der = temp_cert.tbs_certificate_bytes

        # Step 2: Sign TBS via PKCS#11
        sig_algorithm_der = _SIG_ALGORITHM_DER[(hsm.key_type, hsm.hash_algorithm)]
        signature = self._pkcs11_sign(tbs_der, hsm)

        # Step 3: Assemble final DER
        return _assemble_certificate_der(
            tbs_der,
            sig_algorithm_der,
            signature,
        )

    def _build_result(  # noqa: PLR0913
        self,
        cert: x509.Certificate,
        cert_der: bytes,
        serial_number: int,
        not_before: datetime,
        not_after: datetime,
        cn: str,
        validity_days: int,
    ) -> IssuedCertificate:
        """Encode the signed certificate and build the result."""
        assert self._issuer_cert is not None  # noqa: S101

        leaf_pem = cert.public_bytes(
            serialization.Encoding.PEM,
        ).decode("ascii")

        # Build full chain
        chain_parts = [leaf_pem.strip()]
        if self._chain_pem:
            chain_parts.append(self._chain_pem)
        issuer_pem = self._issuer_cert.public_bytes(
            serialization.Encoding.PEM,
        ).decode("ascii")
        chain_parts.append(issuer_pem.strip())

        pem_chain = "\n".join(chain_parts) + "\n"

        fingerprint = hashlib.sha256(cert_der).hexdigest()
        serial_str = format(serial_number, "x")

        log.info(
            "HSM CA signed certificate: serial=%s, cn=%s, validity=%d days",
            serial_str,
            cn,
            validity_days,
        )

        return IssuedCertificate(
            pem_chain=pem_chain,
            not_before=not_before,
            not_after=not_after,
            serial_number=serial_str,
            fingerprint=fingerprint,
        )

    def _pkcs11_sign(
        self,
        tbs_der: bytes,
        hsm: HsmSettings,
    ) -> bytes:
        """Sign TBS bytes using the HSM key via PKCS#11."""
        import pkcs11  # noqa: PLC0415

        with self._session_pool.acquire() as session:  # type: ignore[union-attr]
            key = self._find_key(session, hsm)

            if hsm.key_type == "rsa":
                mechanism = pkcs11.Mechanism(
                    _RSA_MECHANISMS[hsm.hash_algorithm],
                )
                raw_sig = key.sign(
                    tbs_der,
                    mechanism=mechanism,
                )
                return bytes(raw_sig)
            # EC: pre-hash, then sign with CKM_ECDSA
            hash_algo = _HASH_ALGORITHMS[hsm.hash_algorithm]
            digest = hashes.Hash(hash_algo)
            digest.update(tbs_der)
            hash_bytes = digest.finalize()

            mechanism = pkcs11.Mechanism(_CKM_ECDSA)
            raw_sig = key.sign(
                hash_bytes,
                mechanism=mechanism,
            )
            return _ecdsa_raw_to_der(bytes(raw_sig))

    @staticmethod
    def _make_ephemeral_key(
        key_type: str,
    ) -> PrivateKeyTypes:
        """Create an ephemeral key matching the HSM key type."""
        if key_type == "rsa":
            return rsa.generate_private_key(
                public_exponent=65537,  # noqa: PLR2004
                key_size=2048,  # noqa: PLR2004
            )
        return ec.generate_private_key(ec.SECP256R1())

    def revoke(
        self,
        *,
        serial_number: str,
        certificate_pem: str,  # noqa: ARG002
        reason: RevocationReason | None = None,
    ) -> None:
        """Record revocation -- database-only, no CRL action."""
        log.debug(
            "HSM CA backend: revocation recorded for serial=%s "
            "(reason=%s) -- database-only, no CRL action",
            serial_number,
            reason.name if reason else "unspecified",
        )
