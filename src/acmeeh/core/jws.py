"""JWS parsing, verification, and JWK utilities (RFC 7515 / 7517 / 7638).

Uses the ``cryptography`` library directly -- no josepy dependency.
All functions raise :class:`~acmeeh.app.errors.AcmeProblem` on failure
so they integrate cleanly with the Flask error-handling pipeline.

Security note:
    This module handles raw cryptographic operations.  Changes should
    be reviewed carefully for timing-safe comparisons, algorithm
    confusion attacks, and key-policy enforcement.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from acmeeh.app.errors import (
    BAD_NONCE,
    BAD_PUBLIC_KEY,
    BAD_SIGNATURE_ALGORITHM,
    MALFORMED,
    UNAUTHORIZED,
    AcmeProblem,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

log = logging.getLogger(__name__)

# --- Constants -----------------------------------------------------------

_MIN_RSA_EXPONENT = 65537
"""Minimum acceptable RSA public exponent (RFC 8555)."""

_EC_SIG_COMPONENT_MULTIPLIER = 2
"""EC signatures consist of two equal-length components (r || s)."""


# --- Base64url helpers (RFC 7515 S2) -------------------------------------


def _b64url_decode(s: str) -> bytes:
    """Decode a base64url string (no padding required).

    Parameters
    ----------
    s:
        Base64url-encoded string.

    Returns
    -------
    bytes
        Decoded bytes.

    """
    s = s.replace("-", "+").replace("_", "/")
    remainder = len(s) % 4  # noqa: PLR2004
    if remainder:
        s += "=" * (4 - remainder)  # noqa: PLR2004
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    """Encode bytes to base64url without padding.

    Parameters
    ----------
    b:
        Raw bytes to encode.

    Returns
    -------
    str
        Base64url-encoded string.

    """
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# --- Algorithm dispatch --------------------------------------------------

# Maps JWA algorithm name to (hash, key_type)
_RSA_ALGORITHMS: dict[str, hashes.HashAlgorithm] = {
    "RS256": hashes.SHA256(),
    "RS384": hashes.SHA384(),
    "RS512": hashes.SHA512(),
}

_EC_ALGORITHMS: dict[str, tuple[hashes.HashAlgorithm, str, int]] = {
    "ES256": (hashes.SHA256(), "P-256", 32),
    "ES384": (hashes.SHA384(), "P-384", 48),
    "ES512": (hashes.SHA512(), "P-521", 66),
}

# Canonical JWK curve names to cryptography curve classes
_EC_CURVES: dict[str, type[ec.EllipticCurve]] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}


# --- JWSObject dataclass ------------------------------------------------


@dataclass(frozen=True)
class JWSObject:
    """Parsed JWS Flattened JSON Serialization.

    Attributes
    ----------
    protected_header:
        Decoded protected header dictionary.
    protected_b64:
        Base64url-encoded protected header string.
    payload:
        Decoded JSON payload (``None`` for POST-as-GET).
    payload_b64:
        Base64url-encoded payload string.
    signature:
        Raw signature bytes.
    signature_b64:
        Base64url-encoded signature string.

    """

    protected_header: dict[str, Any]
    protected_b64: str
    payload: Any  # noqa: ANN401
    payload_b64: str
    signature: bytes
    signature_b64: str

    @property
    def algorithm(self) -> str:
        """Return the ``alg`` value from the protected header."""
        return self.protected_header.get("alg", "")

    @property
    def nonce(self) -> str | None:
        """Return the ``nonce`` value from the protected header."""
        return self.protected_header.get("nonce")

    @property
    def url(self) -> str | None:
        """Return the ``url`` value from the protected header."""
        return self.protected_header.get("url")

    @property
    def kid(self) -> str | None:
        """Return the ``kid`` value from the protected header."""
        return self.protected_header.get("kid")

    @property
    def jwk(self) -> dict[str, Any] | None:
        """Return the ``jwk`` value from the protected header."""
        return self.protected_header.get("jwk")

    @property
    def is_post_as_get(self) -> bool:
        """Return ``True`` when the payload is empty (POST-as-GET per RFC 8555 S6.3)."""
        return self.payload_b64 == ""


# --- JWS parsing ---------------------------------------------------------


def parse_jws(body: bytes) -> JWSObject:
    """Parse a JWS Flattened JSON Serialization from a request body.

    Parameters
    ----------
    body:
        Raw bytes of the HTTP request body.

    Returns
    -------
    JWSObject
        The parsed JWS components.

    Raises
    ------
    AcmeProblem
        ``MALFORMED`` if the body is not valid JWS JSON.

    """
    try:
        outer = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        msg = f"Request body is not valid JSON: {exc}"
        raise AcmeProblem(MALFORMED, msg) from exc

    if not isinstance(outer, dict):
        raise AcmeProblem(MALFORMED, "JWS must be a JSON object")

    for field in ("protected", "payload", "signature"):
        if field not in outer:
            msg = f"JWS missing required field '{field}'"
            raise AcmeProblem(MALFORMED, msg)

    # RFC 8555 §6.2: JWS Flattened Serialization must contain exactly
    # "protected", "payload", and "signature" — reject unexpected fields.
    _allowed_fields = {"protected", "payload", "signature"}
    extra = set(outer) - _allowed_fields
    if extra:
        msg = f"JWS contains unexpected fields: {', '.join(sorted(extra))}"
        raise AcmeProblem(MALFORMED, msg)

    protected_b64: str = outer["protected"]
    payload_b64: str = outer["payload"]
    signature_b64: str = outer["signature"]

    # Decode protected header
    try:
        protected_bytes = _b64url_decode(protected_b64)
        protected_header: dict[str, Any] = json.loads(protected_bytes)
    except AcmeProblem:
        raise
    except Exception as exc:  # noqa: BLE001
        msg = f"Cannot decode JWS protected header: {exc}"
        raise AcmeProblem(MALFORMED, msg) from exc

    if not isinstance(protected_header, dict):
        raise AcmeProblem(
            MALFORMED,
            "JWS protected header must be a JSON object",
        )

    # Decode payload (may be empty for POST-as-GET)
    payload: Any = None  # noqa: ANN401
    if payload_b64:
        try:
            payload_bytes = _b64url_decode(payload_b64)
            payload = json.loads(payload_bytes)
        except AcmeProblem:
            raise
        except Exception as exc:  # noqa: BLE001
            msg = f"Cannot decode JWS payload: {exc}"
            raise AcmeProblem(MALFORMED, msg) from exc

    # Decode signature
    try:
        signature = _b64url_decode(signature_b64)
    except AcmeProblem:
        raise
    except Exception as exc:  # noqa: BLE001
        msg = f"Cannot decode JWS signature: {exc}"
        raise AcmeProblem(MALFORMED, msg) from exc

    return JWSObject(
        protected_header=protected_header,
        protected_b64=protected_b64,
        payload=payload,
        payload_b64=payload_b64,
        signature=signature,
        signature_b64=signature_b64,
    )


# --- Protected header validation -----------------------------------------


def validate_protected_header(  # noqa: PLR0913
    header: dict[str, Any],
    *,
    require_nonce: bool = True,  # noqa: FBT001, FBT002
    require_kid: bool = False,  # noqa: FBT001, FBT002
    require_jwk: bool = False,  # noqa: FBT001, FBT002
    request_url: str | None = None,
    allowed_algorithms: Sequence[str] | None = None,
) -> None:
    """Enforce RFC 8555 S6.2 constraints on the protected header.

    Parameters
    ----------
    header:
        The decoded protected header dictionary.
    require_nonce:
        Whether to require a ``nonce`` field.
    require_kid:
        Whether to require a ``kid`` field.
    require_jwk:
        Whether to require a ``jwk`` field.
    request_url:
        If given, verify the ``url`` field matches.
    allowed_algorithms:
        If given, restrict ``alg`` to this set.

    Raises
    ------
    AcmeProblem
        With appropriate error type on any violation.

    """
    _check_algorithm(header, allowed_algorithms)
    _check_nonce(header, require_nonce=require_nonce)
    _check_url(header, request_url)
    _check_kid_jwk(
        header,
        require_kid=require_kid,
        require_jwk=require_jwk,
    )


def _check_algorithm(
    header: dict[str, Any],
    allowed_algorithms: Sequence[str] | None,
) -> None:
    """Validate the ``alg`` field in the protected header.

    Parameters
    ----------
    header:
        Decoded protected header.
    allowed_algorithms:
        Permitted algorithm names, or ``None`` for any known algorithm.

    Raises
    ------
    AcmeProblem
        On missing or unsupported algorithm.

    """
    alg = header.get("alg")
    if not alg:
        raise AcmeProblem(
            MALFORMED,
            "JWS protected header missing 'alg'",
        )

    all_known = set(_RSA_ALGORITHMS) | set(_EC_ALGORITHMS)
    if alg not in all_known:
        msg = f"Unsupported algorithm '{alg}'; supported: {sorted(all_known)}"
        raise AcmeProblem(BAD_SIGNATURE_ALGORITHM, msg)

    if allowed_algorithms and alg not in allowed_algorithms:
        msg = (
            f"Algorithm '{alg}' not allowed by server policy; allowed: {sorted(allowed_algorithms)}"
        )
        raise AcmeProblem(BAD_SIGNATURE_ALGORITHM, msg)


def _check_nonce(
    header: dict[str, Any],
    *,
    require_nonce: bool,  # noqa: FBT001
) -> None:
    """Validate the ``nonce`` field in the protected header.

    Parameters
    ----------
    header:
        Decoded protected header.
    require_nonce:
        Whether a ``nonce`` field is required.

    Raises
    ------
    AcmeProblem
        If nonce is required but missing.

    """
    if require_nonce and "nonce" not in header:
        raise AcmeProblem(
            BAD_NONCE,
            "JWS protected header missing 'nonce'",
        )


def _check_url(
    header: dict[str, Any],
    request_url: str | None,
) -> None:
    """Validate the ``url`` field in the protected header.

    Parameters
    ----------
    header:
        Decoded protected header.
    request_url:
        Expected URL to match, or ``None`` to skip matching.

    Raises
    ------
    AcmeProblem
        If URL is missing or does not match.

    """
    if "url" not in header:
        raise AcmeProblem(
            MALFORMED,
            "JWS protected header missing 'url'",
        )

    if request_url is not None and header["url"] != request_url:
        msg = f"JWS 'url' mismatch: header has '{header['url']}', expected '{request_url}'"
        raise AcmeProblem(MALFORMED, msg)


def _check_kid_jwk(
    header: dict[str, Any],
    *,
    require_kid: bool,  # noqa: FBT001
    require_jwk: bool,  # noqa: FBT001
) -> None:
    """Validate ``kid``/``jwk`` mutual exclusion per RFC 8555 S6.2.

    Parameters
    ----------
    header:
        Decoded protected header.
    require_kid:
        Whether ``kid`` is required.
    require_jwk:
        Whether ``jwk`` is required.

    Raises
    ------
    AcmeProblem
        On mutual exclusion violation or missing field.

    """
    has_kid = "kid" in header
    has_jwk = "jwk" in header

    if has_kid and has_jwk:
        raise AcmeProblem(
            MALFORMED,
            "JWS protected header must not contain both 'kid' and 'jwk'",
        )

    if require_kid and not has_kid:
        raise AcmeProblem(
            MALFORMED,
            "JWS protected header missing 'kid'",
        )

    if require_jwk and not has_jwk:
        raise AcmeProblem(
            MALFORMED,
            "JWS protected header missing 'jwk'",
        )

    if not has_kid and not has_jwk:
        raise AcmeProblem(
            MALFORMED,
            "JWS protected header must contain either 'kid' or 'jwk'",
        )


# --- JWK to public key conversion ----------------------------------------


def jwk_to_public_key(
    jwk_dict: dict[str, Any],
) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
    """Convert a JWK dictionary to a ``cryptography`` public key.

    Support RSA and EC key types.

    Parameters
    ----------
    jwk_dict:
        The JWK dictionary with ``kty`` and key-type-specific fields.

    Raises
    ------
    AcmeProblem
        ``BAD_PUBLIC_KEY`` if the JWK is malformed or unsupported.

    Returns
    -------
    rsa.RSAPublicKey | ec.EllipticCurvePublicKey
        The deserialized public key object.

    """
    kty = jwk_dict.get("kty")

    if kty == "RSA":
        return _jwk_to_rsa(jwk_dict)

    if kty == "EC":
        return _jwk_to_ec(jwk_dict)

    msg = f"Unsupported key type '{kty}'"
    raise AcmeProblem(BAD_PUBLIC_KEY, msg)


def _jwk_to_rsa(jwk_dict: dict[str, Any]) -> rsa.RSAPublicKey:
    """Decode an RSA JWK to a public key.

    Parameters
    ----------
    jwk_dict:
        JWK dictionary with ``n`` and ``e`` fields.

    Returns
    -------
    rsa.RSAPublicKey
        The RSA public key.

    Raises
    ------
    AcmeProblem
        On invalid RSA parameters.

    """
    try:
        n = int.from_bytes(_b64url_decode(jwk_dict["n"]), "big")  # noqa: N806
        e = int.from_bytes(_b64url_decode(jwk_dict["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    except AcmeProblem:
        raise
    except Exception as exc:  # noqa: BLE001
        msg = f"Invalid RSA JWK: {exc}"
        raise AcmeProblem(BAD_PUBLIC_KEY, msg) from exc


def _jwk_to_ec(
    jwk_dict: dict[str, Any],
) -> ec.EllipticCurvePublicKey:
    """Decode an EC JWK to a public key.

    Parameters
    ----------
    jwk_dict:
        JWK dictionary with ``crv``, ``x``, and ``y`` fields.

    Returns
    -------
    ec.EllipticCurvePublicKey
        The EC public key.

    Raises
    ------
    AcmeProblem
        On invalid EC parameters or unsupported curve.

    """
    crv = jwk_dict.get("crv")
    curve_cls = _EC_CURVES.get(crv)  # type: ignore[arg-type]
    if curve_cls is None:
        msg = f"Unsupported EC curve '{crv}'; supported: {sorted(_EC_CURVES)}"
        raise AcmeProblem(BAD_PUBLIC_KEY, msg)
    try:
        x = int.from_bytes(_b64url_decode(jwk_dict["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk_dict["y"]), "big")
        return ec.EllipticCurvePublicNumbers(
            x,
            y,
            curve_cls(),
        ).public_key()
    except AcmeProblem:
        raise
    except Exception as exc:  # noqa: BLE001
        msg = f"Invalid EC JWK: {exc}"
        raise AcmeProblem(BAD_PUBLIC_KEY, msg) from exc


# --- Key policy validation ------------------------------------------------


def validate_key_policy(
    jwk_dict: dict[str, Any],
    security_settings: Any,  # noqa: ANN401
) -> None:
    """Enforce server key-policy constraints (RSA size, EC curves).

    Parameters
    ----------
    jwk_dict:
        The JWK dictionary from the request.
    security_settings:
        :class:`~acmeeh.config.settings.SecuritySettings` instance.

    Raises
    ------
    AcmeProblem
        ``BAD_PUBLIC_KEY`` on policy violation.

    """
    kty = jwk_dict.get("kty")

    if kty == "RSA":
        _validate_rsa_policy(jwk_dict, security_settings)
    elif kty == "EC":
        _validate_ec_policy(jwk_dict, security_settings)


def _validate_rsa_policy(
    jwk_dict: dict[str, Any],
    security_settings: Any,  # noqa: ANN401
) -> None:
    """Enforce RSA key size and exponent constraints.

    Parameters
    ----------
    jwk_dict:
        JWK dictionary with ``n`` and ``e`` fields.
    security_settings:
        Server security configuration.

    Raises
    ------
    AcmeProblem
        On policy violation.

    """
    n_bytes = _b64url_decode(jwk_dict.get("n", ""))
    key_bits = len(n_bytes) * 8
    min_bits: int = security_settings.min_rsa_key_size
    if key_bits < min_bits:
        msg = f"RSA key size {key_bits} bits is below minimum {min_bits}"
        raise AcmeProblem(BAD_PUBLIC_KEY, msg)
    max_bits: int = security_settings.max_rsa_key_size
    if key_bits > max_bits:
        msg = f"RSA key size {key_bits} bits exceeds maximum {max_bits}"
        raise AcmeProblem(BAD_PUBLIC_KEY, msg)
    # Validate RSA public exponent (must be odd and >= 65537)
    e_bytes = _b64url_decode(jwk_dict.get("e", ""))
    e_val = int.from_bytes(e_bytes, "big") if e_bytes else 0
    if e_val < _MIN_RSA_EXPONENT or e_val % 2 == 0:  # noqa: PLR2004
        msg = (
            f"RSA public exponent {e_val} is not acceptable; must be odd and >= {_MIN_RSA_EXPONENT}"
        )
        raise AcmeProblem(BAD_PUBLIC_KEY, msg)


def _validate_ec_policy(
    jwk_dict: dict[str, Any],
    security_settings: Any,  # noqa: ANN401
) -> None:
    """Enforce EC curve restrictions.

    Parameters
    ----------
    jwk_dict:
        JWK dictionary with ``crv`` field.
    security_settings:
        Server security configuration.

    Raises
    ------
    AcmeProblem
        On policy violation.

    """
    crv = jwk_dict.get("crv", "")
    if crv not in security_settings.allowed_ec_curves:
        msg = f"EC curve '{crv}' not allowed; allowed: {list(security_settings.allowed_ec_curves)}"
        raise AcmeProblem(BAD_PUBLIC_KEY, msg)


# --- Signature verification -----------------------------------------------


def verify_signature(
    jws: JWSObject,
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
) -> None:
    """Verify the JWS signature against the given public key.

    Verify ``ASCII(protected) || '.' || ASCII(payload)`` against
    the decoded signature using the algorithm from the protected header.

    Parameters
    ----------
    jws:
        The parsed JWS object.
    public_key:
        The public key to verify against.

    Raises
    ------
    AcmeProblem
        ``UNAUTHORIZED`` if the signature is invalid.
        ``BAD_SIGNATURE_ALGORITHM`` on algorithm mismatch.

    """
    alg = jws.algorithm
    signing_input = f"{jws.protected_b64}.{jws.payload_b64}".encode("ascii")

    try:
        if alg in _RSA_ALGORITHMS:
            _verify_rsa(alg, public_key, jws.signature, signing_input)
        elif alg in _EC_ALGORITHMS:
            _verify_ec(alg, public_key, jws.signature, signing_input)
        else:
            msg = f"Unsupported algorithm '{alg}'"
            raise AcmeProblem(BAD_SIGNATURE_ALGORITHM, msg)
    except InvalidSignature:
        from acmeeh.logging import security_events  # noqa: PLC0415

        security_events.jws_signature_failed(
            "",
            "",
            "JWS signature verification failed",
        )
        msg = "JWS signature verification failed"
        raise AcmeProblem(UNAUTHORIZED, msg) from None


def _verify_rsa(
    alg: str,
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
    signature: bytes,
    signing_input: bytes,
) -> None:
    """Verify an RSA JWS signature.

    Parameters
    ----------
    alg:
        The JWA algorithm name (e.g. ``RS256``).
    public_key:
        The public key to verify against.
    signature:
        Raw signature bytes.
    signing_input:
        The signing input (``protected.payload``).

    Raises
    ------
    AcmeProblem
        If the key is not RSA.

    """
    if not isinstance(public_key, rsa.RSAPublicKey):
        msg = f"Algorithm '{alg}' requires an RSA key"
        raise AcmeProblem(BAD_SIGNATURE_ALGORITHM, msg)
    hash_alg = _RSA_ALGORITHMS[alg]
    public_key.verify(
        signature,
        signing_input,
        padding.PKCS1v15(),
        hash_alg,
    )


def _verify_ec(  # noqa: PLR0913
    alg: str,
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
    signature: bytes,
    signing_input: bytes,
) -> None:
    """Verify an EC JWS signature.

    Parameters
    ----------
    alg:
        The JWA algorithm name (e.g. ``ES256``).
    public_key:
        The public key to verify against.
    signature:
        Raw signature bytes (r || s concatenation).
    signing_input:
        The signing input (``protected.payload``).

    Raises
    ------
    AcmeProblem
        If the key is not EC or the curve does not match.

    """
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        msg = f"Algorithm '{alg}' requires an EC key"
        raise AcmeProblem(BAD_SIGNATURE_ALGORITHM, msg)
    hash_alg, expected_curve, component_len = _EC_ALGORITHMS[alg]

    # Verify curve matches algorithm
    actual_curve = public_key.curve.name
    expected_curve_cls = _EC_CURVES[expected_curve]
    if not isinstance(public_key.curve, expected_curve_cls):
        msg = f"Algorithm '{alg}' requires curve {expected_curve}, but key uses {actual_curve}"
        raise AcmeProblem(BAD_SIGNATURE_ALGORITHM, msg)

    # JWS EC signatures are raw r||s (not DER), convert to DER
    if len(signature) != _EC_SIG_COMPONENT_MULTIPLIER * component_len:
        raise AcmeProblem(
            UNAUTHORIZED,
            "EC signature has incorrect length",
        )
    r = int.from_bytes(signature[:component_len], "big")
    s = int.from_bytes(signature[component_len:], "big")
    der_sig = utils.encode_dss_signature(r, s)

    public_key.verify(
        der_sig,
        signing_input,
        ec.ECDSA(hash_alg),
    )


# --- JWK thumbprint (RFC 7638) -------------------------------------------


def compute_thumbprint(jwk_dict: dict[str, Any]) -> str:
    """Compute the RFC 7638 JWK Thumbprint using SHA-256.

    Construct the canonical JSON representation with required members
    in lexicographic order, then return the base64url-encoded SHA-256
    hash.

    Parameters
    ----------
    jwk_dict:
        The JWK dictionary.

    Returns
    -------
    str
        Base64url-encoded thumbprint.

    """
    kty = jwk_dict.get("kty")

    if kty == "RSA":
        canonical = {
            "e": jwk_dict["e"],
            "kty": "RSA",
            "n": jwk_dict["n"],
        }
    elif kty == "EC":
        canonical = {
            "crv": jwk_dict["crv"],
            "kty": "EC",
            "x": jwk_dict["x"],
            "y": jwk_dict["y"],
        }
    else:
        msg = f"Cannot compute thumbprint for kty '{kty}'"
        raise AcmeProblem(BAD_PUBLIC_KEY, msg)

    # RFC 7638 requires members in lexicographic order, no whitespace
    canonical_json = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(  # noqa: S324
        canonical_json.encode("ascii"),
    ).digest()
    return _b64url_encode(digest)


# --- EAB inner JWS validation (RFC 8555 S7.3.4) --------------------------


def validate_eab_jws(
    eab_jws: dict[str, Any],
    outer_jwk: dict[str, Any],
    hmac_key_b64: str,
) -> str:
    """Validate an externalAccountBinding inner JWS.

    The inner JWS must:
    - Use ``alg=HS256`` in the protected header
    - Include ``kid`` (the EAB key identifier)
    - Include ``url`` matching the newAccount URL
    - Have the outer account JWK as its payload
    - Have a valid HMAC-SHA256 signature

    Parameters
    ----------
    eab_jws:
        The parsed inner JWS dict (protected, payload, signature).
    outer_jwk:
        The outer JWS's account JWK -- must match the inner payload.
    hmac_key_b64:
        Base64url-encoded HMAC key from the EAB credential.

    Returns
    -------
    str
        The EAB ``kid`` from the inner protected header.

    Raises
    ------
    AcmeProblem
        On any validation failure.

    """
    inner_protected_b64 = eab_jws.get("protected", "")
    inner_payload_b64 = eab_jws.get("payload", "")
    inner_sig_b64 = eab_jws.get("signature", "")

    if not inner_protected_b64 or not inner_sig_b64:
        raise AcmeProblem(
            MALFORMED,
            "EAB inner JWS missing required fields",
        )

    try:
        inner_header: dict[str, Any] = json.loads(
            _b64url_decode(inner_protected_b64),
        )
    except AcmeProblem:
        raise
    except Exception as exc:  # noqa: BLE001
        msg = f"Cannot decode EAB inner protected header: {exc}"
        raise AcmeProblem(MALFORMED, msg) from exc

    # Verify algorithm is HS256
    if inner_header.get("alg") != "HS256":
        msg = f"EAB inner JWS must use HS256, got '{inner_header.get('alg')}'"
        raise AcmeProblem(MALFORMED, msg)

    # Extract kid
    eab_kid: str | None = inner_header.get("kid")
    if not eab_kid:
        raise AcmeProblem(
            MALFORMED,
            "EAB inner JWS missing 'kid'",
        )

    # Verify payload is the outer JWK (constant-time comparison)
    if inner_payload_b64:
        try:
            inner_payload = json.loads(
                _b64url_decode(inner_payload_b64),
            )
        except AcmeProblem:
            raise
        except Exception as exc:  # noqa: BLE001
            msg = f"Cannot decode EAB payload: {exc}"
            raise AcmeProblem(MALFORMED, msg) from exc

        outer_canonical = json.dumps(
            outer_jwk,
            sort_keys=True,
            separators=(",", ":"),
        )
        inner_canonical = json.dumps(
            inner_payload,
            sort_keys=True,
            separators=(",", ":"),
        )
        if not _hmac.compare_digest(
            outer_canonical.encode(),
            inner_canonical.encode(),
        ):
            raise AcmeProblem(
                MALFORMED,
                "EAB inner JWS payload does not match the outer account JWK",
            )

    # Verify HMAC-SHA256 signature (constant-time comparison)
    hmac_key = _b64url_decode(hmac_key_b64)
    signing_input = f"{inner_protected_b64}.{inner_payload_b64}".encode("ascii")
    expected_sig = _hmac.new(
        hmac_key,
        signing_input,
        "sha256",
    ).digest()

    try:
        actual_sig = _b64url_decode(inner_sig_b64)
    except AcmeProblem:
        raise
    except Exception as exc:  # noqa: BLE001
        msg = f"Cannot decode EAB signature: {exc}"
        raise AcmeProblem(MALFORMED, msg) from exc

    if not _hmac.compare_digest(expected_sig, actual_sig):
        from acmeeh.logging import security_events  # noqa: PLC0415

        security_events.jws_signature_failed(
            "",
            "",
            f"EAB HMAC verification failed for kid={eab_kid}",
        )
        msg = "EAB HMAC signature verification failed"
        raise AcmeProblem(UNAUTHORIZED, msg)

    return eab_kid


# --- Key authorization (RFC 8555 S8.1) ------------------------------------


def key_authorization(token: str, jwk_dict: dict[str, Any]) -> str:
    """Compute the key authorization string: ``token.thumbprint``.

    Use by all ACME challenge types.

    Parameters
    ----------
    token:
        The challenge token.
    jwk_dict:
        The account's JWK dictionary.

    Returns
    -------
    str
        The key authorization string.

    """
    thumbprint = compute_thumbprint(jwk_dict)
    return f"{token}.{thumbprint}"
