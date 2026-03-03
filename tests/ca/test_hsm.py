"""Tests for the HSM CA backend (PKCS#11).

All PKCS#11 interactions are mocked — no real HSM or SoftHSM required.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from acmeeh.ca.base import CAError, IssuedCertificate
from acmeeh.ca.hsm import (
    HsmCABackend,
    _assemble_certificate_der,
    _ecdsa_raw_to_der,
    _encode_der_length,
    _int_to_der_integer,
    _Pkcs11SessionPool,
)
from acmeeh.config.settings import (
    AcmeProxySettings,
    CAInternalSettings,
    CAProfileSettings,
    CASettings,
    ExternalCASettings,
    HsmSettings,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_hsm_settings(**overrides) -> HsmSettings:
    defaults = {
        "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
        "token_label": "ACMEEH-CA",
        "slot_id": None,
        "pin": "1234",
        "key_label": "ca-signing-key",
        "key_id": None,
        "key_type": "ec",
        "hash_algorithm": "sha256",
        "issuer_cert_path": "/etc/acmeeh/ca-cert.pem",
        "chain_path": None,
        "serial_source": "database",
        "login_required": True,
        "session_pool_size": 4,
        "session_pool_timeout_seconds": 30,
    }
    defaults.update(overrides)
    return HsmSettings(**defaults)


def _make_ca_settings(hsm: HsmSettings | None = None) -> CASettings:
    return CASettings(
        backend="hsm",
        default_validity_days=90,
        max_validity_days=397,
        profiles={
            "default": CAProfileSettings(
                key_usages=("digital_signature", "key_encipherment"),
                extended_key_usages=("server_auth",),
                validity_days=None,
                max_validity_days=None,
            )
        },
        internal=CAInternalSettings(
            root_cert_path="",
            root_key_path="",
            chain_path=None,
            serial_source="database",
            hash_algorithm="sha256",
        ),
        external=ExternalCASettings(
            sign_url="",
            revoke_url="",
            auth_header="Authorization",
            auth_value="",
            ca_cert_path=None,
            client_cert_path=None,
            client_key_path=None,
            timeout_seconds=30,
            max_retries=0,
            retry_delay_seconds=1.0,
        ),
        acme_proxy=AcmeProxySettings(
            directory_url="",
            email="",
            storage_path="./acme_proxy_storage",
            challenge_type="dns-01",
            challenge_handler="",
            challenge_handler_config={},
            eab_kid=None,
            eab_hmac_key=None,
            proxy_url=None,
            verify_ssl=True,
            timeout_seconds=300,
        ),
        hsm=hsm or _make_hsm_settings(),
        circuit_breaker_failure_threshold=5,
        circuit_breaker_recovery_timeout=30.0,
        deferred_signing_timeout=600,
    )


def _make_test_csr(domains=None):
    """Create a real CSR with SAN for testing."""
    if domains is None:
        domains = ["example.com", "www.example.com"]
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
            ]
        )
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
        critical=False,
    )
    return builder.sign(key, hashes.SHA256())


def _make_issuer_cert() -> x509.Certificate:
    """Create a self-signed issuer certificate for testing."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now.replace(year=now.year + 10))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert


def _write_issuer_cert(tmp_path, cert: x509.Certificate | None = None) -> str:
    """Write issuer cert PEM to tmp_path and return path string."""
    if cert is None:
        cert = _make_issuer_cert()
    cert_path = tmp_path / "ca-cert.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(cert_path)


@pytest.fixture()
def profile():
    return CAProfileSettings(
        key_usages=("digital_signature", "key_encipherment"),
        extended_key_usages=("server_auth",),
        validity_days=None,
        max_validity_days=None,
    )


@pytest.fixture()
def issuer_cert():
    return _make_issuer_cert()


# ---------------------------------------------------------------------------
# DER assembly unit tests
# ---------------------------------------------------------------------------


class TestDerHelpers:
    def test_encode_der_length_short(self):
        assert _encode_der_length(0) == b"\x00"
        assert _encode_der_length(127) == b"\x7f"

    def test_encode_der_length_long(self):
        result = _encode_der_length(128)
        assert result == b"\x81\x80"
        result = _encode_der_length(256)
        assert result == b"\x82\x01\x00"

    def test_int_to_der_integer_zero(self):
        result = _int_to_der_integer(0)
        assert result == b"\x02\x01\x00"

    def test_int_to_der_integer_positive(self):
        result = _int_to_der_integer(127)
        assert result == b"\x02\x01\x7f"

    def test_int_to_der_integer_needs_padding(self):
        # 128 = 0x80, needs 0x00 prefix for positive encoding
        result = _int_to_der_integer(128)
        assert result == b"\x02\x02\x00\x80"

    def test_ecdsa_raw_to_der_roundtrip(self):
        # Create a known raw signature (r || s), each 32 bytes
        r = (42).to_bytes(32, "big")
        s = (99).to_bytes(32, "big")
        raw = r + s

        der = _ecdsa_raw_to_der(raw)

        # Verify it's a valid SEQUENCE
        assert der[0:1] == b"\x30"

        # Parse manually: should contain two INTEGERs
        # Skip SEQUENCE tag and length
        idx = 1
        seq_len_bytes = der[idx : idx + 1]
        if seq_len_bytes[0] < 0x80:
            idx += 1
        else:
            num_len_bytes = seq_len_bytes[0] & 0x7F
            idx += 1 + num_len_bytes

        # First INTEGER (r)
        assert der[idx] == 0x02
        idx += 1
        r_len = der[idx]
        idx += 1
        r_bytes = der[idx : idx + r_len]
        r_val = int.from_bytes(r_bytes, "big")
        assert r_val == 42
        idx += r_len

        # Second INTEGER (s)
        assert der[idx] == 0x02
        idx += 1
        s_len = der[idx]
        idx += 1
        s_bytes = der[idx : idx + s_len]
        s_val = int.from_bytes(s_bytes, "big")
        assert s_val == 99

    def test_ecdsa_raw_to_der_odd_length_raises(self):
        with pytest.raises(CAError, match="odd length"):
            _ecdsa_raw_to_der(b"\x01\x02\x03")

    def test_ecdsa_raw_to_der_p384(self):
        # P-384 produces 96-byte raw signatures (48 + 48)
        r = (2**300).to_bytes(48, "big")
        s = (2**200).to_bytes(48, "big")
        raw = r + s
        der = _ecdsa_raw_to_der(raw)
        assert der[0:1] == b"\x30"  # valid SEQUENCE

    def test_assemble_certificate_der_structure(self):
        # Use fake data to verify structure
        tbs = b"\x30\x03\x02\x01\x00"  # minimal SEQUENCE
        sig_alg = b"\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02"
        signature = b"\x01\x02\x03\x04"

        result = _assemble_certificate_der(tbs, sig_alg, signature)

        # Should be a SEQUENCE
        assert result[0] == 0x30
        # Should contain TBS + sig_alg + BIT STRING
        assert tbs in result
        assert sig_alg in result
        # BIT STRING tag
        assert b"\x03" in result


# ---------------------------------------------------------------------------
# Startup / _ensure_loaded tests
# ---------------------------------------------------------------------------


class TestStartupCheck:
    def test_missing_pkcs11_package_raises(self):
        settings = _make_ca_settings()
        backend = HsmCABackend(settings)

        with patch.dict(
            "sys.modules", {"pkcs11": None, "pkcs11.util.ec": None, "pkcs11.util.rsa": None}
        ):
            with patch("builtins.__import__", side_effect=ImportError("No module named 'pkcs11'")):
                with pytest.raises(CAError, match="python-pkcs11"):
                    backend.startup_check()

    def test_missing_pkcs11_library_path_raises(self):
        settings = _make_ca_settings(_make_hsm_settings(pkcs11_library=""))
        backend = HsmCABackend(settings)

        mock_pkcs11 = MagicMock()
        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            with pytest.raises(CAError, match="pkcs11_library"):
                backend.startup_check()

    def test_token_not_found_raises(self, tmp_path):
        cert_path = _write_issuer_cert(tmp_path)
        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
                token_label="NONEXISTENT",
            )
        )
        backend = HsmCABackend(settings)

        mock_pkcs11 = MagicMock()
        mock_pkcs11.lib.return_value.get_token.side_effect = Exception("Token not found")
        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            with pytest.raises(CAError, match="token"):
                backend.startup_check()

    def test_key_not_found_raises(self, tmp_path):
        cert_path = _write_issuer_cert(tmp_path)
        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
            )
        )
        backend = HsmCABackend(settings)

        mock_session = MagicMock()
        mock_session.get_objects.return_value = []  # No keys found

        mock_token = MagicMock()
        mock_token.open.return_value = mock_session

        mock_pkcs11 = MagicMock()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            with pytest.raises(CAError, match="Signing key not found"):
                backend.startup_check()

    def test_issuer_cert_not_found_raises(self, tmp_path):
        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path="/nonexistent/ca.pem",
            )
        )
        backend = HsmCABackend(settings)

        mock_key = MagicMock()
        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]

        mock_token = MagicMock()
        mock_token.open.return_value = mock_session

        mock_pkcs11 = MagicMock()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            with pytest.raises(CAError, match="Issuer certificate not found"):
                backend.startup_check()

    def test_successful_startup(self, tmp_path):
        cert_path = _write_issuer_cert(tmp_path)
        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
            )
        )
        backend = HsmCABackend(settings)

        mock_key = MagicMock()
        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]

        mock_token = MagicMock()
        mock_token.open.return_value = mock_session

        mock_pkcs11 = MagicMock()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            backend.startup_check()

        assert backend._loaded is True
        assert backend._issuer_cert is not None

    def test_startup_with_chain(self, tmp_path):
        cert_path = _write_issuer_cert(tmp_path)
        chain_path = tmp_path / "chain.pem"
        chain_path.write_text("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")

        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
                chain_path=str(chain_path),
            )
        )
        backend = HsmCABackend(settings)

        mock_key = MagicMock()
        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]

        mock_token = MagicMock()
        mock_token.open.return_value = mock_session

        mock_pkcs11 = MagicMock()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            backend.startup_check()

        assert backend._chain_pem is not None
        assert "BEGIN CERTIFICATE" in backend._chain_pem

    def test_chain_file_not_found_raises(self, tmp_path):
        cert_path = _write_issuer_cert(tmp_path)
        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
                chain_path="/nonexistent/chain.pem",
            )
        )
        backend = HsmCABackend(settings)

        mock_key = MagicMock()
        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]

        mock_token = MagicMock()
        mock_token.open.return_value = mock_session

        mock_pkcs11 = MagicMock()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            with pytest.raises(CAError, match="Chain file not found"):
                backend.startup_check()

    def test_slot_id_lookup(self, tmp_path):
        cert_path = _write_issuer_cert(tmp_path)
        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
                token_label=None,
                slot_id=3,
            )
        )
        backend = HsmCABackend(settings)

        mock_key = MagicMock()
        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]

        mock_token = MagicMock()
        mock_token.open.return_value = mock_session
        mock_token.slot.slot_id = 3

        mock_pkcs11 = MagicMock()
        mock_pkcs11.lib.return_value.get_tokens.return_value = [mock_token]

        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            backend.startup_check()

        assert backend._loaded is True

    def test_slot_id_not_found_raises(self, tmp_path):
        cert_path = _write_issuer_cert(tmp_path)
        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
                token_label=None,
                slot_id=99,
            )
        )
        backend = HsmCABackend(settings)

        mock_token = MagicMock()
        mock_token.slot.slot_id = 0  # different from requested 99

        mock_pkcs11 = MagicMock()
        mock_pkcs11.lib.return_value.get_tokens.return_value = [mock_token]

        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            with pytest.raises(CAError, match="token not found"):
                backend.startup_check()


# ---------------------------------------------------------------------------
# Sign tests
# ---------------------------------------------------------------------------


def _setup_loaded_backend(tmp_path, key_type="ec", hash_algorithm="sha256"):
    """Create a fully-loaded HsmCABackend with mocked PKCS#11."""
    issuer_cert = _make_issuer_cert()
    cert_path = _write_issuer_cert(tmp_path, issuer_cert)

    settings = _make_ca_settings(
        _make_hsm_settings(
            issuer_cert_path=cert_path,
            key_type=key_type,
            hash_algorithm=hash_algorithm,
        )
    )
    backend = HsmCABackend(settings)

    # Manually set loaded state
    backend._issuer_cert = issuer_cert
    backend._loaded = True
    backend._session_pool = MagicMock()

    return backend


class TestSign:
    def test_sign_ec_success(self, tmp_path, profile):
        backend = _setup_loaded_backend(tmp_path, key_type="ec")

        # Mock PKCS#11 signing: return a valid raw ECDSA signature (r||s)
        # Each component is 32 bytes for P-256
        mock_key = MagicMock()
        r_bytes = (12345678).to_bytes(32, "big")
        s_bytes = (87654321).to_bytes(32, "big")
        mock_key.sign.return_value = r_bytes + s_bytes

        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)

        backend._session_pool.acquire.return_value = mock_session

        mock_pkcs11 = MagicMock()
        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            csr = _make_test_csr(["example.com"])
            result = backend.sign(csr, profile=profile, validity_days=90, serial_number=12345)

        assert isinstance(result, IssuedCertificate)
        assert "BEGIN CERTIFICATE" in result.pem_chain
        assert result.serial_number == format(12345, "x")
        assert len(result.fingerprint) == 64
        assert result.not_before < result.not_after

    def test_sign_rsa_success(self, tmp_path, profile):
        backend = _setup_loaded_backend(tmp_path, key_type="rsa")

        # RSA signature: just raw bytes, no conversion needed
        mock_key = MagicMock()
        mock_key.sign.return_value = b"\x00" * 256  # fake 2048-bit RSA sig

        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)

        backend._session_pool.acquire.return_value = mock_session

        mock_pkcs11 = MagicMock()
        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            csr = _make_test_csr(["example.com"])
            result = backend.sign(csr, profile=profile, validity_days=90, serial_number=99999)

        assert isinstance(result, IssuedCertificate)
        assert result.serial_number == format(99999, "x")

    def test_sign_without_serial_generates_random(self, tmp_path, profile):
        backend = _setup_loaded_backend(tmp_path)

        mock_key = MagicMock()
        r_bytes = (1).to_bytes(32, "big")
        s_bytes = (2).to_bytes(32, "big")
        mock_key.sign.return_value = r_bytes + s_bytes

        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)

        backend._session_pool.acquire.return_value = mock_session

        mock_pkcs11 = MagicMock()
        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            csr = _make_test_csr(["example.com"])
            result = backend.sign(csr, profile=profile, validity_days=90)

        assert isinstance(result, IssuedCertificate)
        assert len(result.serial_number) > 0

    def test_sign_csr_without_san_raises(self, tmp_path, profile):
        backend = _setup_loaded_backend(tmp_path)

        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                    ]
                )
            )
            .sign(key, hashes.SHA256())
        )

        with pytest.raises(CAError, match="SubjectAlternativeName"):
            backend.sign(csr, profile=profile, validity_days=90)

    def test_sign_includes_chain(self, tmp_path, profile):
        backend = _setup_loaded_backend(tmp_path)
        backend._chain_pem = "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----"

        mock_key = MagicMock()
        r_bytes = (1).to_bytes(32, "big")
        s_bytes = (2).to_bytes(32, "big")
        mock_key.sign.return_value = r_bytes + s_bytes

        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)

        backend._session_pool.acquire.return_value = mock_session

        mock_pkcs11 = MagicMock()
        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            csr = _make_test_csr(["example.com"])
            result = backend.sign(csr, profile=profile, validity_days=90, serial_number=1)

        # Chain should include leaf + chain + issuer
        assert result.pem_chain.count("BEGIN CERTIFICATE") >= 2

    def test_sign_pkcs11_error_wrapped(self, tmp_path, profile):
        backend = _setup_loaded_backend(tmp_path)

        mock_session = MagicMock()
        mock_session.get_objects.side_effect = RuntimeError("HSM error")
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)

        backend._session_pool.acquire.return_value = mock_session

        mock_pkcs11 = MagicMock()
        with patch.dict(
            "sys.modules",
            {
                "pkcs11": mock_pkcs11,
                "pkcs11.util.ec": MagicMock(),
                "pkcs11.util.rsa": MagicMock(),
            },
        ):
            csr = _make_test_csr(["example.com"])
            with pytest.raises(CAError, match="Failed to build/sign"):
                backend.sign(csr, profile=profile, validity_days=90, serial_number=1)


# ---------------------------------------------------------------------------
# Revoke tests
# ---------------------------------------------------------------------------


class TestRevoke:
    def test_revoke_is_noop(self, tmp_path):
        backend = _setup_loaded_backend(tmp_path)
        # Should not raise
        backend.revoke(
            serial_number="abc123",
            certificate_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        )

    def test_revoke_with_reason(self, tmp_path):
        backend = _setup_loaded_backend(tmp_path)
        mock_reason = MagicMock()
        mock_reason.name = "keyCompromise"
        backend.revoke(
            serial_number="abc123",
            certificate_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
            reason=mock_reason,
        )


# ---------------------------------------------------------------------------
# Session pool tests
# ---------------------------------------------------------------------------


class TestSessionPool:
    def test_acquire_creates_session(self):
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_token.open.return_value = mock_session

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=2,
        )

        with pool.acquire() as session:
            assert session is mock_session
        mock_token.open.assert_called_once_with(rw=False, user_pin="1234")

    def test_acquire_reuses_returned_session(self):
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_token.open.return_value = mock_session

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=2,
        )

        # First acquire
        with pool.acquire() as session1:
            assert session1 is mock_session

        # Second acquire should reuse returned session
        with pool.acquire() as session2:
            assert session2 is mock_session

        # Only one session should have been created
        assert mock_token.open.call_count == 1

    def test_acquire_without_login(self):
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_token.open.return_value = mock_session

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="",
            login_required=False,
            max_size=2,
        )

        with pool.acquire() as session:
            assert session is mock_session
        mock_token.open.assert_called_once_with(rw=False)

    def test_close_all(self):
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_token.open.return_value = mock_session

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=2,
        )

        # Create and return a session
        with pool.acquire():
            pass

        pool.close_all()
        mock_session.close.assert_called_once()

    def test_error_discards_session(self):
        mock_token = MagicMock()
        mock_session1 = MagicMock()
        mock_session2 = MagicMock()
        mock_token.open.side_effect = [mock_session1, mock_session2]

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=2,
        )

        # Use and error on first session
        try:
            with pool.acquire() as session:
                raise RuntimeError("simulated error")
        except RuntimeError:
            pass

        # Session should have been discarded, new one created
        with pool.acquire() as session:
            assert session is mock_session2

        assert mock_token.open.call_count == 2
        mock_session1.close.assert_called_once()


# ---------------------------------------------------------------------------
# Ephemeral key tests
# ---------------------------------------------------------------------------


class TestMakeEphemeralKey:
    def test_ec_key(self):
        key = HsmCABackend._make_ephemeral_key("ec")
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_rsa_key(self):
        key = HsmCABackend._make_ephemeral_key("rsa")
        assert isinstance(key, rsa.RSAPrivateKey)
