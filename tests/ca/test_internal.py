"""Comprehensive unit tests for acmeeh.ca.internal.InternalCABackend."""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acmeeh.ca.base import CAError, IssuedCertificate
from acmeeh.ca.internal import InternalCABackend
from acmeeh.config.settings import (
    AcmeProxySettings,
    CAInternalSettings,
    CAProfileSettings,
    CASettings,
    ExternalCASettings,
    HsmSettings,
)

# ---------------------------------------------------------------------------
# Helpers — generate real crypto material for testing
# ---------------------------------------------------------------------------


def _generate_root_key() -> rsa.RSAPrivateKey:
    """Generate a 2048-bit RSA private key for the root CA."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _generate_root_cert(
    key: rsa.RSAPrivateKey,
    cn: str = "Test Root CA",
) -> x509.Certificate:
    """Self-sign a root CA certificate."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    )
    return builder.sign(key, hashes.SHA256())


def _write_pem_cert(cert: x509.Certificate, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_pem_key(key: rsa.RSAPrivateKey, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _make_internal_settings(**overrides) -> CAInternalSettings:
    defaults = {
        "root_cert_path": "/tmp/root.pem",
        "root_key_path": "/tmp/root.key",
        "chain_path": None,
        "serial_source": "random",
        "hash_algorithm": "sha256",
    }
    defaults.update(overrides)
    return CAInternalSettings(**defaults)


def _make_ca_settings(
    internal: CAInternalSettings | None = None,
    **overrides,
) -> CASettings:
    return CASettings(
        backend=overrides.get("backend", "internal"),
        default_validity_days=overrides.get("default_validity_days", 90),
        max_validity_days=overrides.get("max_validity_days", 397),
        profiles={
            "default": CAProfileSettings(
                key_usages=("digital_signature", "key_encipherment"),
                extended_key_usages=("server_auth",),
                validity_days=None,
                max_validity_days=None,
            ),
        },
        internal=internal or _make_internal_settings(),
        external=ExternalCASettings(
            sign_url="",
            revoke_url="",
            auth_header="",
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
            storage_path="",
            challenge_type="dns-01",
            challenge_handler="callback_dns",
            challenge_handler_config={},
            eab_kid=None,
            eab_hmac_key=None,
            proxy_url=None,
            verify_ssl=True,
            timeout_seconds=300,
        ),
        hsm=HsmSettings(
            pkcs11_library="",
            token_label=None,
            slot_id=None,
            pin="",
            key_label=None,
            key_id=None,
            key_type="ec",
            hash_algorithm="sha256",
            issuer_cert_path="",
            chain_path=None,
            serial_source="database",
            login_required=True,
            session_pool_size=4,
            session_pool_timeout_seconds=30,
        ),
        circuit_breaker_failure_threshold=5,
        circuit_breaker_recovery_timeout=30.0,
        deferred_signing_timeout=600,
    )


def _make_csr_dns(
    domain: str = "test.example.com",
) -> x509.CertificateSigningRequest:
    """Generate a CSR with a DNS SAN."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )
    )
    return builder.sign(key, hashes.SHA256())


def _make_csr_ip(
    ip_str: str = "192.168.1.1",
) -> x509.CertificateSigningRequest:
    """Generate a CSR with an IP address SAN (no DNS)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ip_addr = ipaddress.ip_address(ip_str)
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ip_str)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ip_addr)]),
            critical=False,
        )
    )
    return builder.sign(key, hashes.SHA256())


def _make_csr_no_san() -> x509.CertificateSigningRequest:
    """Generate a CSR with no SAN extension at all."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-san.example.com")])
    )
    return builder.sign(key, hashes.SHA256())


def _default_profile() -> CAProfileSettings:
    return CAProfileSettings(
        key_usages=("digital_signature", "key_encipherment"),
        extended_key_usages=("server_auth",),
        validity_days=None,
        max_validity_days=None,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def root_key() -> rsa.RSAPrivateKey:
    return _generate_root_key()


@pytest.fixture()
def root_cert(root_key: rsa.RSAPrivateKey) -> x509.Certificate:
    return _generate_root_cert(root_key)


@pytest.fixture()
def tmp_cert_file(tmp_path: Path, root_cert: x509.Certificate) -> Path:
    p = tmp_path / "root.pem"
    _write_pem_cert(root_cert, p)
    return p


@pytest.fixture()
def tmp_key_file(tmp_path: Path, root_key: rsa.RSAPrivateKey) -> Path:
    p = tmp_path / "root.key"
    _write_pem_key(root_key, p)
    return p


@pytest.fixture()
def loaded_backend(
    tmp_cert_file: Path,
    tmp_key_file: Path,
) -> InternalCABackend:
    """Return an InternalCABackend with root cert+key already loaded."""
    internal = _make_internal_settings(
        root_cert_path=str(tmp_cert_file),
        root_key_path=str(tmp_key_file),
    )
    ca_settings = _make_ca_settings(internal=internal)
    backend = InternalCABackend(ca_settings)
    backend._ensure_loaded()
    return backend


# ---------------------------------------------------------------------------
# Tests: __init__
# ---------------------------------------------------------------------------


class TestInternalCABackendInit:
    """Tests for InternalCABackend constructor."""

    def test_init_sets_sha256_default(self) -> None:
        internal = _make_internal_settings(hash_algorithm="sha256")
        ca_settings = _make_ca_settings(internal=internal)
        backend = InternalCABackend(ca_settings)
        assert isinstance(backend._hash_algorithm, hashes.SHA256)

    def test_init_sets_sha384(self) -> None:
        internal = _make_internal_settings(hash_algorithm="sha384")
        ca_settings = _make_ca_settings(internal=internal)
        backend = InternalCABackend(ca_settings)
        assert isinstance(backend._hash_algorithm, hashes.SHA384)

    def test_init_sets_sha512(self) -> None:
        internal = _make_internal_settings(hash_algorithm="sha512")
        ca_settings = _make_ca_settings(internal=internal)
        backend = InternalCABackend(ca_settings)
        assert isinstance(backend._hash_algorithm, hashes.SHA512)

    def test_init_unknown_hash_falls_back_to_sha256(self) -> None:
        internal = _make_internal_settings(hash_algorithm="md5")
        ca_settings = _make_ca_settings(internal=internal)
        backend = InternalCABackend(ca_settings)
        assert isinstance(backend._hash_algorithm, hashes.SHA256)

    def test_init_lazy_no_cert_loaded(self) -> None:
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        assert backend._root_cert is None
        assert backend._root_key is None
        assert backend._chain_pem is None


# ---------------------------------------------------------------------------
# Tests: _ensure_loaded
# ---------------------------------------------------------------------------


class TestEnsureLoaded:
    """Tests for lazy-loading via _ensure_loaded."""

    def test_ensure_loaded_file_provider(
        self,
        tmp_cert_file: Path,
        tmp_key_file: Path,
    ) -> None:
        internal = _make_internal_settings(
            root_cert_path=str(tmp_cert_file),
            root_key_path=str(tmp_key_file),
        )
        ca_settings = _make_ca_settings(internal=internal)
        backend = InternalCABackend(ca_settings)
        backend._ensure_loaded()
        assert backend._root_cert is not None
        assert backend._root_key is not None

    def test_ensure_loaded_skips_if_already_loaded(
        self,
        tmp_cert_file: Path,
        tmp_key_file: Path,
    ) -> None:
        internal = _make_internal_settings(
            root_cert_path=str(tmp_cert_file),
            root_key_path=str(tmp_key_file),
        )
        ca_settings = _make_ca_settings(internal=internal)
        backend = InternalCABackend(ca_settings)
        backend._ensure_loaded()
        # Mutate path to something invalid to prove we don't reload
        cert_ref = backend._root_cert
        backend._ensure_loaded()
        assert backend._root_cert is cert_ref

    def test_ensure_loaded_loads_chain(
        self,
        tmp_path: Path,
        tmp_cert_file: Path,
        tmp_key_file: Path,
        root_cert: x509.Certificate,
    ) -> None:
        chain_file = tmp_path / "chain.pem"
        chain_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode()
        chain_file.write_text(chain_pem)

        internal = _make_internal_settings(
            root_cert_path=str(tmp_cert_file),
            root_key_path=str(tmp_key_file),
            chain_path=str(chain_file),
        )
        ca_settings = _make_ca_settings(internal=internal)
        backend = InternalCABackend(ca_settings)
        backend._ensure_loaded()
        assert backend._chain_pem is not None
        assert "BEGIN CERTIFICATE" in backend._chain_pem


# ---------------------------------------------------------------------------
# Tests: _load_root_cert
# ---------------------------------------------------------------------------


class TestLoadRootCert:
    """Tests for _load_root_cert."""

    def test_missing_cert_path_raises(self) -> None:
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        with pytest.raises(CAError, match="root_cert_path is required"):
            backend._load_root_cert(None)

    def test_empty_cert_path_raises(self) -> None:
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        with pytest.raises(CAError, match="root_cert_path is required"):
            backend._load_root_cert("")

    def test_file_not_found_raises(self) -> None:
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        with pytest.raises(CAError, match="Root certificate not found"):
            backend._load_root_cert("/nonexistent/path/cert.pem")

    def test_invalid_cert_data_raises(self, tmp_path: Path) -> None:
        bad_cert = tmp_path / "bad.pem"
        bad_cert.write_text("not a certificate")
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        with pytest.raises(CAError, match="Failed to load root certificate"):
            backend._load_root_cert(str(bad_cert))

    def test_valid_cert_loads(self, tmp_cert_file: Path) -> None:
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        backend._load_root_cert(str(tmp_cert_file))
        assert backend._root_cert is not None
        assert isinstance(backend._root_cert, x509.Certificate)


# ---------------------------------------------------------------------------
# Tests: _load_root_key
# ---------------------------------------------------------------------------


class TestLoadRootKey:
    """Tests for _load_root_key."""

    def test_missing_key_path_raises(self) -> None:
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        with pytest.raises(CAError, match="root_key_path is required"):
            backend._load_root_key(None)

    def test_empty_key_path_raises(self) -> None:
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        with pytest.raises(CAError, match="root_key_path is required"):
            backend._load_root_key("")

    def test_file_not_found_raises(self) -> None:
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        with pytest.raises(CAError, match="Root private key not found"):
            backend._load_root_key("/nonexistent/path/key.pem")

    def test_invalid_key_data_raises(self, tmp_path: Path) -> None:
        bad_key = tmp_path / "bad.key"
        bad_key.write_text("not a private key")
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        with pytest.raises(CAError, match="Failed to load root private key"):
            backend._load_root_key(str(bad_key))

    def test_valid_key_loads(self, tmp_key_file: Path) -> None:
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        backend._load_root_key(str(tmp_key_file))
        assert backend._root_key is not None


# ---------------------------------------------------------------------------
# Tests: _check_key_permissions
# ---------------------------------------------------------------------------


class TestCheckKeyPermissions:
    """Tests for _check_key_permissions (static method)."""

    def test_none_path_does_nothing(self) -> None:
        # Should return without error
        InternalCABackend._check_key_permissions(None)

    def test_permissive_permissions_logs_warning(
        self,
        tmp_key_file: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # Make file world-readable
        tmp_key_file.chmod(0o644)
        with caplog.at_level(logging.WARNING, logger="acmeeh.ca.internal"):
            InternalCABackend._check_key_permissions(str(tmp_key_file))
        assert "overly permissive" in caplog.text

    def test_strict_permissions_no_warning(
        self,
        tmp_key_file: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # On Windows, chmod 0o600 does not actually restrict group/other
        # bits the way POSIX does — the mode may still show 0o666.
        # Mock os.stat to simulate POSIX 0o600 behaviour.
        import stat as stat_module

        mock_result = MagicMock()
        mock_result.st_mode = stat_module.S_IFREG | 0o600
        with patch("os.stat", return_value=mock_result):
            with caplog.at_level(logging.WARNING, logger="acmeeh.ca.internal"):
                InternalCABackend._check_key_permissions(str(tmp_key_file))
        assert "overly permissive" not in caplog.text

    def test_os_error_is_silenced(self) -> None:
        with patch("os.stat", side_effect=OSError("permission denied")):
            # Should not raise -- best-effort check
            InternalCABackend._check_key_permissions("/fake/key.pem")


# ---------------------------------------------------------------------------
# Tests: _load_chain
# ---------------------------------------------------------------------------


class TestLoadChain:
    """Tests for _load_chain."""

    def test_chain_file_not_found_raises(self) -> None:
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        with pytest.raises(CAError, match="Chain file not found"):
            backend._load_chain("/nonexistent/chain.pem")

    def test_generic_error_raises(self, tmp_path: Path) -> None:
        chain_file = tmp_path / "chain.pem"
        chain_file.write_text("chain content")
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            with pytest.raises(CAError, match="Failed to load chain"):
                backend._load_chain(str(chain_file))

    def test_valid_chain_loads(
        self,
        tmp_path: Path,
        root_cert: x509.Certificate,
    ) -> None:
        chain_file = tmp_path / "chain.pem"
        chain_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode()
        chain_file.write_text(chain_pem)
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        backend._load_chain(str(chain_file))
        assert backend._chain_pem is not None
        assert "BEGIN CERTIFICATE" in backend._chain_pem


# ---------------------------------------------------------------------------
# Tests: sign
# ---------------------------------------------------------------------------


class TestSign:
    """Tests for the sign method."""

    def test_sign_dns_san(self, loaded_backend: InternalCABackend) -> None:
        csr = _make_csr_dns("example.com")
        profile = _default_profile()
        result = loaded_backend.sign(
            csr,
            profile=profile,
            validity_days=90,
            serial_number=12345,
        )
        assert isinstance(result, IssuedCertificate)
        assert "BEGIN CERTIFICATE" in result.pem_chain
        assert result.serial_number == format(12345, "x")
        assert result.fingerprint  # non-empty hex
        assert result.not_before is not None
        assert result.not_after is not None
        # Verify not_after is roughly 90 days from now
        delta = result.not_after - result.not_before
        assert 89 <= delta.days <= 91

    def test_sign_ip_san_fallback(self, loaded_backend: InternalCABackend) -> None:
        csr = _make_csr_ip("10.0.0.1")
        profile = _default_profile()
        result = loaded_backend.sign(
            csr,
            profile=profile,
            validity_days=30,
            serial_number=99999,
        )
        assert isinstance(result, IssuedCertificate)
        assert result.serial_number == format(99999, "x")

    def test_sign_no_san_raises(self, loaded_backend: InternalCABackend) -> None:
        csr = _make_csr_no_san()
        profile = _default_profile()
        with pytest.raises(CAError, match="SubjectAlternativeName"):
            loaded_backend.sign(
                csr,
                profile=profile,
                validity_days=90,
            )

    def test_sign_auto_serial_when_none(self, loaded_backend: InternalCABackend) -> None:
        csr = _make_csr_dns("auto-serial.example.com")
        profile = _default_profile()
        result = loaded_backend.sign(
            csr,
            profile=profile,
            validity_days=90,
            serial_number=None,
        )
        assert isinstance(result, IssuedCertificate)
        # Serial should be a hex string
        int(result.serial_number, 16)  # should not raise

    def test_sign_with_chain(
        self,
        tmp_path: Path,
        tmp_cert_file: Path,
        tmp_key_file: Path,
        root_cert: x509.Certificate,
    ) -> None:
        chain_file = tmp_path / "chain.pem"
        chain_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode()
        chain_file.write_text(chain_pem)
        internal = _make_internal_settings(
            root_cert_path=str(tmp_cert_file),
            root_key_path=str(tmp_key_file),
            chain_path=str(chain_file),
        )
        ca_settings = _make_ca_settings(internal=internal)
        backend = InternalCABackend(ca_settings)
        csr = _make_csr_dns("chain.example.com")
        result = backend.sign(
            csr,
            profile=_default_profile(),
            validity_days=90,
        )
        # Chain should contain leaf + intermediate + root = 3 certs
        cert_count = result.pem_chain.count("BEGIN CERTIFICATE")
        assert cert_count == 3

    def test_sign_ct_submitter_with_scts(
        self,
        loaded_backend: InternalCABackend,
    ) -> None:
        """Test CT flow: pre-cert built, SCTs collected, final cert signed."""
        import base64

        mock_submitter = MagicMock()
        mock_submitter.submit_precert.return_value = [
            {
                "sct_version": 0,
                "id": base64.b64encode(b"\x01" * 32).decode(),
                "timestamp": 1700000000000,
                "extensions": "",
                "signature": base64.b64encode(b"\x04\x03\x00\x04test").decode(),
            },
        ]

        csr = _make_csr_dns("ct.example.com")
        result = loaded_backend.sign(
            csr,
            profile=_default_profile(),
            validity_days=90,
            serial_number=54321,
            ct_submitter=mock_submitter,
        )
        assert isinstance(result, IssuedCertificate)
        mock_submitter.submit_precert.assert_called_once()
        # The pre-cert DER should have been passed
        precert_der = mock_submitter.submit_precert.call_args[0][0]
        assert isinstance(precert_der, bytes)

    def test_sign_ct_submitter_no_scts_fallback(
        self,
        loaded_backend: InternalCABackend,
    ) -> None:
        """When CT returns no SCTs, fall back to standard signing."""
        mock_submitter = MagicMock()
        mock_submitter.submit_precert.return_value = []

        csr = _make_csr_dns("no-sct.example.com")
        result = loaded_backend.sign(
            csr,
            profile=_default_profile(),
            validity_days=90,
            serial_number=11111,
            ct_submitter=mock_submitter,
        )
        assert isinstance(result, IssuedCertificate)
        mock_submitter.submit_precert.assert_called_once()

    def test_sign_triggers_ensure_loaded(
        self,
        tmp_cert_file: Path,
        tmp_key_file: Path,
    ) -> None:
        """sign() should call _ensure_loaded lazily."""
        internal = _make_internal_settings(
            root_cert_path=str(tmp_cert_file),
            root_key_path=str(tmp_key_file),
        )
        ca_settings = _make_ca_settings(internal=internal)
        backend = InternalCABackend(ca_settings)
        assert backend._root_cert is None
        csr = _make_csr_dns("lazy.example.com")
        result = backend.sign(
            csr,
            profile=_default_profile(),
            validity_days=30,
        )
        assert isinstance(result, IssuedCertificate)
        assert backend._root_cert is not None


# ---------------------------------------------------------------------------
# Tests: startup_check
# ---------------------------------------------------------------------------


class TestStartupCheck:
    """Tests for startup_check."""

    def test_startup_check_loads(
        self,
        tmp_cert_file: Path,
        tmp_key_file: Path,
    ) -> None:
        internal = _make_internal_settings(
            root_cert_path=str(tmp_cert_file),
            root_key_path=str(tmp_key_file),
        )
        ca_settings = _make_ca_settings(internal=internal)
        backend = InternalCABackend(ca_settings)
        backend.startup_check()
        assert backend._root_cert is not None


# ---------------------------------------------------------------------------
# Tests: revoke
# ---------------------------------------------------------------------------


class TestRevoke:
    """Tests for the revoke method."""

    def test_revoke_logs_debug(
        self,
        loaded_backend: InternalCABackend,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.DEBUG, logger="acmeeh.ca.internal"):
            loaded_backend.revoke(
                serial_number="abc123",
                certificate_pem="-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----",
                reason=None,
            )
        assert "revocation recorded" in caplog.text
        assert "abc123" in caplog.text
        assert "unspecified" in caplog.text

    def test_revoke_with_reason(
        self,
        loaded_backend: InternalCABackend,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from acmeeh.core.types import RevocationReason

        with caplog.at_level(logging.DEBUG, logger="acmeeh.ca.internal"):
            loaded_backend.revoke(
                serial_number="def456",
                certificate_pem="-----BEGIN CERTIFICATE-----\nbar\n-----END CERTIFICATE-----",
                reason=RevocationReason.KEY_COMPROMISE,
            )
        assert "KEY_COMPROMISE" in caplog.text


# ---------------------------------------------------------------------------
# Tests: properties
# ---------------------------------------------------------------------------


class TestProperties:
    """Tests for root_cert and root_key properties."""

    def test_root_cert_none_before_load(self) -> None:
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        assert backend.root_cert is None

    def test_root_key_none_before_load(self) -> None:
        ca_settings = _make_ca_settings()
        backend = InternalCABackend(ca_settings)
        assert backend.root_key is None

    def test_root_cert_after_load(self, loaded_backend: InternalCABackend) -> None:
        assert loaded_backend.root_cert is not None
        assert isinstance(loaded_backend.root_cert, x509.Certificate)

    def test_root_key_after_load(self, loaded_backend: InternalCABackend) -> None:
        assert loaded_backend.root_key is not None
