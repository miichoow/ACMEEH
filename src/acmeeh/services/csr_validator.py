"""CSR profile validator.

Validate a ``cryptography.x509.CertificateSigningRequest`` against an
admin-managed CSR profile (``profile_data`` dict).  All violations are
collected and reported together for better client UX.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, SignatureAlgorithmOID

from acmeeh.app.errors import BAD_CSR, AcmeProblem

log = logging.getLogger(__name__)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

    from acmeeh.repositories.certificate import CertificateRepository

# ---------------------------------------------------------------------------
# OID -> human-readable signature algorithm name
# ---------------------------------------------------------------------------
_SIG_ALG_NAMES: dict[str, str] = {
    SignatureAlgorithmOID.RSA_WITH_SHA256.dotted_string: "SHA256withRSA",
    SignatureAlgorithmOID.RSA_WITH_SHA384.dotted_string: "SHA384withRSA",
    SignatureAlgorithmOID.RSA_WITH_SHA512.dotted_string: "SHA512withRSA",
    SignatureAlgorithmOID.ECDSA_WITH_SHA256.dotted_string: "SHA256withECDSA",
    SignatureAlgorithmOID.ECDSA_WITH_SHA384.dotted_string: "SHA384withECDSA",
    SignatureAlgorithmOID.ECDSA_WITH_SHA512.dotted_string: "SHA512withECDSA",
    SignatureAlgorithmOID.ED25519.dotted_string: "Ed25519",
    SignatureAlgorithmOID.ED448.dotted_string: "Ed448",
}

# ---------------------------------------------------------------------------
# Extended Key Usage OID -> human-readable name
# ---------------------------------------------------------------------------
_EKU_NAMES: dict[str, str] = {
    ExtendedKeyUsageOID.SERVER_AUTH.dotted_string: "serverAuth",
    ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string: "clientAuth",
    ExtendedKeyUsageOID.CODE_SIGNING.dotted_string: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string: "emailProtection",
    ExtendedKeyUsageOID.TIME_STAMPING.dotted_string: "timeStamping",
    ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string: "OCSPSigning",
}

# Key Usage bit names (matching cryptography's KeyUsage attribute names)
_KEY_USAGE_ATTRS: list[str] = [
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
]


# Sentinel value meaning "no limit" for CN/SAN count constraints.
# Profile data uses -1 (or omission) to indicate unlimited.
UNLIMITED = -1

# Minimum printable character ordinal (control characters below this).
_MIN_PRINTABLE_ORD = 0x20


def _get_key_type_label(pub_key: PublicKeyTypes) -> str:
    """Return a human-readable key type string.

    Example results: ``'RSA'``, ``'EC.secp256r1'``.
    """
    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return f"EC.{pub_key.curve.name}"
    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub_key, ed448.Ed448PublicKey):
        return "Ed448"
    return type(pub_key).__name__


def _get_key_size(pub_key: PublicKeyTypes) -> int | None:
    """Return the key size in bits, or None for fixed-size algorithms."""
    if isinstance(pub_key, rsa.RSAPublicKey):
        return pub_key.key_size
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return pub_key.curve.key_size
    return None


def _compute_public_key_fingerprint(pub_key: PublicKeyTypes) -> str:
    """Compute SHA-256 hex digest of the public key DER bytes."""
    der = pub_key.public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _check_subdomain_depth(
    name: str,
    base_domains: list[str],
    max_depth: int,
) -> str | None:
    """Check that *name* does not exceed *max_depth* labels beyond a base domain.

    Return a violation string or ``None``.
    """
    lower_name = name.lower()

    # Strip wildcard prefix for base-domain matching, but the wildcard
    # label still counts toward depth.
    match_name = lower_name.removeprefix("*.")

    # Find the longest matching base domain.
    best_base: str | None = None
    for bd in base_domains:
        bd_lower = bd.lower()
        if match_name == bd_lower or match_name.endswith(
            "." + bd_lower,
        ):
            if best_base is None or len(bd_lower) > len(best_base):
                best_base = bd_lower

    if best_base is None:
        return f"DNS name '{name}' does not match any configured base domain"

    # Count depth = total labels in original name minus base labels.
    total_labels = len(lower_name.split("."))
    base_labels = len(best_base.split("."))
    depth = total_labels - base_labels

    if depth > max_depth:
        return (
            f"DNS name '{name}' has subdomain depth {depth} "
            f"which exceeds maximum allowed depth {max_depth} "
            f"(base domain: '{best_base}')"
        )

    return None


def _extract_cn_values(
    csr: x509.CertificateSigningRequest,
) -> list[str]:
    """Extract all Common Name values from the CSR subject."""
    return [
        str(attr.value)
        for attr in csr.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME,
        )
    ]


def _extract_san_values(
    csr: x509.CertificateSigningRequest,
) -> list[tuple[str, str]]:
    """Extract SAN (type, value) tuples from the CSR."""
    try:
        san_ext = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        )
    except x509.ExtensionNotFound:
        return []

    result: list[tuple[str, str]] = [
        *[("DNS_NAME", name) for name in san_ext.value.get_values_for_type(x509.DNSName)],
        *[("IP_ADDRESS", str(ip)) for ip in san_ext.value.get_values_for_type(x509.IPAddress)],
        *[
            ("RFC822_NAME", email)
            for email in san_ext.value.get_values_for_type(
                x509.RFC822Name,
            )
        ],
        *[
            ("URI", uri)
            for uri in san_ext.value.get_values_for_type(
                x509.UniformResourceIdentifier,
            )
        ],
    ]
    return result


def validate_csr_against_profile(  # noqa: C901, PLR0912, PLR0915
    csr: x509.CertificateSigningRequest,
    profile_data: dict[str, Any],
    certificate_repo: CertificateRepository | None = None,
) -> None:
    """Validate a CSR against a profile policy.

    Raise :class:`AcmeProblem` with type ``badCSR`` if any violations
    are found.  All violations are collected and reported together.
    """
    violations: list[str] = []
    pub_key = csr.public_key()
    key_type = _get_key_type_label(pub_key)

    _check_key_constraints(profile_data, key_type, pub_key, violations)
    _check_signature_algorithm(profile_data, csr, violations)
    _check_key_usages(profile_data, csr, violations)
    _check_extended_key_usages(profile_data, csr, violations)

    cn_values = _extract_cn_values(csr)
    san_pairs = _extract_san_values(csr)

    _check_cn_constraints(profile_data, cn_values, violations)
    _check_san_constraints(profile_data, csr, san_pairs, violations)
    _check_wildcard_constraints(
        profile_data,
        cn_values,
        san_pairs,
        violations,
    )
    _check_subdomain_depth_constraints(
        profile_data,
        cn_values,
        san_pairs,
        violations,
    )
    _check_key_reuse(
        profile_data,
        pub_key,
        certificate_repo,
        violations,
    )
    _check_renewal_window(
        profile_data,
        san_pairs,
        certificate_repo,
        violations,
    )

    if violations:
        log.warning("CSR rejected by profile: %s", "; ".join(violations))
        subproblems = [{"type": BAD_CSR, "detail": v} for v in violations]
        raise AcmeProblem(
            BAD_CSR,
            f"CSR profile violations: {'; '.join(violations)}",
            subproblems=subproblems,
        )


def _check_key_constraints(
    profile_data: dict[str, Any],
    key_type: str,
    pub_key: PublicKeyTypes,
    violations: list[str],
) -> None:
    """Check key type and minimum key size constraints."""
    authorized_keys = profile_data.get("authorized_keys")
    if authorized_keys is None:
        return
    if key_type not in authorized_keys:
        violations.append(
            f"Key type '{key_type}' is not authorized. Allowed: {sorted(authorized_keys.keys())}",
        )
        return
    min_size = authorized_keys[key_type]
    if min_size and min_size > 0:
        actual_size = _get_key_size(pub_key)
        if actual_size is not None and actual_size < min_size:
            violations.append(
                f"Key size {actual_size} bits is below minimum {min_size} for {key_type}",
            )


def _check_signature_algorithm(
    profile_data: dict[str, Any],
    csr: x509.CertificateSigningRequest,
    violations: list[str],
) -> None:
    """Check that the CSR signature algorithm is authorized."""
    authorized_sig_algs = profile_data.get(
        "authorized_signature_algorithms",
    )
    if authorized_sig_algs is None:
        return
    sig_oid = csr.signature_algorithm_oid.dotted_string
    sig_name = _SIG_ALG_NAMES.get(sig_oid, sig_oid)
    if sig_name not in authorized_sig_algs:
        violations.append(
            f"Signature algorithm '{sig_name}' is not authorized. Allowed: {authorized_sig_algs}",
        )


def _check_key_usages(
    profile_data: dict[str, Any],
    csr: x509.CertificateSigningRequest,
    violations: list[str],
) -> None:
    """Check that CSR key usages are authorized."""
    authorized_ku = profile_data.get("authorized_key_usages")
    if authorized_ku is None:
        return
    try:
        ku_ext = csr.extensions.get_extension_for_class(x509.KeyUsage)
        csr_usages: list[str] = []
        for attr in _KEY_USAGE_ATTRS:
            try:
                if getattr(ku_ext.value, attr):
                    csr_usages.append(attr)
            except ValueError:
                pass
        unauthorized = [u for u in csr_usages if u not in authorized_ku]
        if unauthorized:
            violations.append(
                f"Key usages not authorized: {unauthorized}. Allowed: {authorized_ku}",
            )
    except x509.ExtensionNotFound:
        pass


def _check_extended_key_usages(
    profile_data: dict[str, Any],
    csr: x509.CertificateSigningRequest,
    violations: list[str],
) -> None:
    """Check that CSR extended key usages are authorized."""
    authorized_eku = profile_data.get("authorized_extended_key_usages")
    if authorized_eku is None:
        return
    try:
        eku_ext = csr.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage,
        )
        csr_ekus = [_EKU_NAMES.get(oid.dotted_string, oid.dotted_string) for oid in eku_ext.value]
        unauthorized = [e for e in csr_ekus if e not in authorized_eku]
        if unauthorized:
            violations.append(
                f"Extended key usages not authorized: {unauthorized}. Allowed: {authorized_eku}",
            )
    except x509.ExtensionNotFound:
        pass


def _check_cn_constraints(
    profile_data: dict[str, Any],
    cn_values: list[str],
    violations: list[str],
) -> None:
    """Check common name count and regex constraints."""
    cn_min = profile_data.get("common_name_minimum", UNLIMITED)
    cn_max = profile_data.get("common_name_maximum", UNLIMITED)
    if cn_min != UNLIMITED and len(cn_values) < cn_min:
        violations.append(
            f"CSR has {len(cn_values)} CN(s), minimum required is {cn_min}",
        )
    if cn_max != UNLIMITED and len(cn_values) > cn_max:
        violations.append(
            f"CSR has {len(cn_values)} CN(s), maximum allowed is {cn_max}",
        )

    cn_regex = profile_data.get("common_name_regex")
    if cn_regex is not None:
        pat = re.compile(cn_regex)
        for cn in cn_values:
            if not pat.fullmatch(cn):
                violations.append(
                    f"CN '{cn}' does not match required pattern '{cn_regex}'",
                )


def _check_san_constraints(
    profile_data: dict[str, Any],
    csr: x509.CertificateSigningRequest,
    san_pairs: list[tuple[str, str]],
    violations: list[str],
) -> None:
    """Check SAN-related constraints including count, regex, types, and content."""
    # Control characters and null bytes
    for san_type, san_val in san_pairs:
        if "\x00" in san_val:
            violations.append(
                f"SAN '{san_type}:{san_val!r}' contains null byte -- possible injection attack",
            )
        elif any(ord(c) < _MIN_PRINTABLE_ORD for c in san_val):
            violations.append(
                f"SAN '{san_type}:{san_val!r}' contains control characters",
            )

    # Duplicate SANs
    seen_sans: set[tuple[str, str]] = set()
    for san_type, san_val in san_pairs:
        key = (
            san_type,
            san_val.lower() if san_type == "DNS_NAME" else san_val,
        )
        if key in seen_sans:
            violations.append(
                f"Duplicate SAN '{san_val}' ({san_type}) in CSR",
            )
        seen_sans.add(key)

    # SAN count
    san_min = profile_data.get("san_minimum", UNLIMITED)
    san_max = profile_data.get("san_maximum", UNLIMITED)
    if san_min != UNLIMITED and len(san_pairs) < san_min:
        violations.append(
            f"CSR has {len(san_pairs)} SAN(s), minimum required is {san_min}",
        )
    if san_max != UNLIMITED and len(san_pairs) > san_max:
        violations.append(
            f"CSR has {len(san_pairs)} SAN(s), maximum allowed is {san_max}",
        )

    # SAN value regex
    san_regex = profile_data.get("san_regex")
    if san_regex is not None:
        pat = re.compile(san_regex)
        for san_type, san_val in san_pairs:
            if not pat.fullmatch(san_val):
                violations.append(
                    f"SAN '{san_val}' ({san_type}) does not match required pattern '{san_regex}'",
                )

    # SAN types
    allowed_san_types = profile_data.get("san_types")
    if allowed_san_types is not None:
        for san_type, _san_val in san_pairs:
            if san_type not in allowed_san_types:
                violations.append(
                    f"SAN type '{san_type}' is not allowed. Allowed: {allowed_san_types}",
                )

    # Subject regex
    subject_regex = profile_data.get("subject_regex")
    if subject_regex is not None:
        subject_str = csr.subject.rfc4514_string()
        pat = re.compile(subject_regex)
        if not pat.fullmatch(subject_str):
            violations.append(
                f"Subject '{subject_str}' does not match required pattern '{subject_regex}'",
            )


def _check_wildcard_constraints(
    profile_data: dict[str, Any],
    cn_values: list[str],
    san_pairs: list[tuple[str, str]],
    violations: list[str],
) -> None:
    """Check wildcard restrictions in CN and SAN values."""
    if profile_data.get("wildcard_in_common_name") is False:  # noqa: FBT003
        for cn in cn_values:
            if cn.startswith("*."):
                violations.append(
                    f"Wildcard CN '{cn}' is not permitted",
                )

    if profile_data.get("wildcard_in_san") is False:  # noqa: FBT003
        for san_type, san_val in san_pairs:
            if san_type == "DNS_NAME" and san_val.startswith("*."):
                violations.append(
                    f"Wildcard SAN '{san_val}' is not permitted",
                )


def _check_subdomain_depth_constraints(
    profile_data: dict[str, Any],
    cn_values: list[str],
    san_pairs: list[tuple[str, str]],
    violations: list[str],
) -> None:
    """Check subdomain depth restrictions against base domains."""
    max_depth = profile_data.get("max_subdomain_depth")
    base_domains = profile_data.get("depth_base_domains")
    if max_depth is None or base_domains is None:
        return
    for san_type, san_val in san_pairs:
        if san_type == "DNS_NAME":
            violation = _check_subdomain_depth(
                san_val,
                base_domains,
                max_depth,
            )
            if violation:
                violations.append(violation)
    for cn in cn_values:
        violation = _check_subdomain_depth(
            cn,
            base_domains,
            max_depth,
        )
        if violation:
            violations.append(violation)


def _check_key_reuse(
    profile_data: dict[str, Any],
    pub_key: PublicKeyTypes,
    certificate_repo: CertificateRepository | None,
    violations: list[str],
) -> None:
    """Check that the public key has not been used before."""
    if (
        profile_data.get("reuse_key") is not False  # noqa: FBT003
        or certificate_repo is None
    ):
        return
    fp = _compute_public_key_fingerprint(pub_key)
    existing = certificate_repo.find_by_public_key_fingerprint(fp)
    if existing:
        violations.append(
            f"Key reuse is not permitted -- {len(existing)} existing "
            f"certificate(s) use the same public key",
        )


def _check_renewal_window(
    profile_data: dict[str, Any],
    san_pairs: list[tuple[str, str]],
    certificate_repo: CertificateRepository | None,
    violations: list[str],
) -> None:
    """Check that renewal is permitted based on active certificate expiry."""
    renewal_days = profile_data.get("renewal_window_days", 0)
    if renewal_days <= 0 or certificate_repo is None:
        return
    hosts = [v for t, v in san_pairs if t == "DNS_NAME"]
    if not hosts:
        return
    cutoff = datetime.now(UTC) + timedelta(days=renewal_days)
    active = certificate_repo.find_valid_certs_for_hosts(
        hosts,
        cutoff,
    )
    if active:
        violations.append(
            f"Renewal not yet permitted -- {len(active)} active "
            f"certificate(s) for these hosts expire after "
            f"{cutoff.date().isoformat()} (renewal window: "
            f"{renewal_days} days)",
        )
