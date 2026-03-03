"""Tests for the ACME Proxy CA backend."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acmeeh.ca.acme_proxy import AcmeProxyBackend, _is_retryable
from acmeeh.ca.base import CAError, IssuedCertificate
from acmeeh.config.settings import (
    AcmeProxySettings,
    CAInternalSettings,
    CAProfileSettings,
    CASettings,
    ExternalCASettings,
    HsmSettings,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_proxy_settings(**overrides) -> AcmeProxySettings:
    defaults = {
        "directory_url": "https://acme.upstream.example/directory",
        "email": "admin@example.com",
        "storage_path": "./test_storage",
        "challenge_type": "dns-01",
        "challenge_handler": "callback_dns",
        "challenge_handler_config": {
            "create_script": "/bin/true",
            "delete_script": "/bin/true",
        },
        "eab_kid": None,
        "eab_hmac_key": None,
        "proxy_url": None,
        "verify_ssl": True,
        "timeout_seconds": 300,
    }
    defaults.update(overrides)
    return AcmeProxySettings(**defaults)


def _make_ca_settings(proxy: AcmeProxySettings | None = None) -> CASettings:
    return CASettings(
        backend="acme_proxy",
        default_validity_days=90,
        max_validity_days=397,
        profiles={
            "default": CAProfileSettings(
                key_usages=("digital_signature",),
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
        acme_proxy=proxy or _make_proxy_settings(),
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


def _make_self_signed_cert_pem(domains=None) -> str:
    """Create a self-signed cert PEM for testing parse logic."""
    if domains is None:
        domains = ["example.com"]
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
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
        .not_valid_after(now.replace(year=now.year + 1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture()
def ca_settings():
    return _make_ca_settings()


@pytest.fixture()
def profile():
    return CAProfileSettings(
        key_usages=("digital_signature",),
        extended_key_usages=("server_auth",),
        validity_days=None,
        max_validity_days=None,
    )


# ---------------------------------------------------------------------------
# Startup check tests
# ---------------------------------------------------------------------------


class TestStartupCheck:
    def test_missing_directory_url_raises(self):
        settings = _make_ca_settings(_make_proxy_settings(directory_url=""))
        backend = AcmeProxyBackend(settings)
        with pytest.raises(CAError, match="directory_url"):
            backend.startup_check()

    def test_missing_email_raises(self):
        settings = _make_ca_settings(_make_proxy_settings(email=""))
        backend = AcmeProxyBackend(settings)
        with pytest.raises(CAError, match="email"):
            backend.startup_check()

    def test_missing_challenge_handler_raises(self):
        settings = _make_ca_settings(_make_proxy_settings(challenge_handler=""))
        backend = AcmeProxyBackend(settings)
        with pytest.raises(CAError, match="challenge_handler"):
            backend.startup_check()

    @patch("acmeeh.ca.acme_proxy.load_upstream_handler")
    @patch("acmeeh.ca.acme_proxy.Path.mkdir")
    def test_acmeow_not_installed_raises(self, mock_mkdir, mock_handler):
        mock_handler.return_value = MagicMock()
        settings = _make_ca_settings()
        backend = AcmeProxyBackend(settings)

        with patch.dict("sys.modules", {"acmeow": None}):
            with patch("builtins.__import__", side_effect=ImportError("No module named 'acmeow'")):
                with pytest.raises(CAError, match="ACMEOW"):
                    backend.startup_check()

    @patch("acmeeh.ca.acme_proxy.load_upstream_handler")
    @patch("acmeeh.ca.acme_proxy.Path.mkdir")
    def test_successful_startup(self, mock_mkdir, mock_handler):
        mock_handler.return_value = MagicMock()
        mock_client = MagicMock()
        mock_acmeow = MagicMock()
        mock_acmeow.AcmeClient.return_value = mock_client

        settings = _make_ca_settings()
        backend = AcmeProxyBackend(settings)

        mock_acmeow_enums = MagicMock()
        with patch.dict("sys.modules", {"acmeow": mock_acmeow, "acmeow.enums": mock_acmeow_enums}):
            backend.startup_check()

        call_kwargs = mock_acmeow.AcmeClient.call_args[1]
        assert call_kwargs["server_url"] == "https://acme.upstream.example/directory"
        assert call_kwargs["email"] == "admin@example.com"
        mock_client.create_account.assert_called_once_with()
        assert backend._client is mock_client

    @patch("acmeeh.ca.acme_proxy.load_upstream_handler")
    @patch("acmeeh.ca.acme_proxy.Path.mkdir")
    def test_startup_with_eab(self, mock_mkdir, mock_handler):
        mock_handler.return_value = MagicMock()
        mock_client = MagicMock()
        mock_acmeow = MagicMock()
        mock_acmeow.AcmeClient.return_value = mock_client

        proxy = _make_proxy_settings(eab_kid="kid123", eab_hmac_key="hmackey")
        settings = _make_ca_settings(proxy)
        backend = AcmeProxyBackend(settings)

        mock_acmeow_enums = MagicMock()
        with patch.dict("sys.modules", {"acmeow": mock_acmeow, "acmeow.enums": mock_acmeow_enums}):
            backend.startup_check()

        mock_client.set_external_account_binding.assert_called_once_with(
            kid="kid123",
            hmac_key="hmackey",
        )
        mock_client.create_account.assert_called_once_with()


# ---------------------------------------------------------------------------
# Sign tests
# ---------------------------------------------------------------------------


class TestSign:
    def test_sign_without_init_raises(self, ca_settings, profile):
        backend = AcmeProxyBackend(ca_settings)
        csr = _make_test_csr()
        with pytest.raises(CAError, match="not initialised"):
            backend.sign(csr, profile=profile, validity_days=90)

    def test_sign_csr_without_san_raises(self, ca_settings, profile):
        backend = AcmeProxyBackend(ca_settings)
        backend._client = MagicMock()

        # Create CSR without SAN
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

        with pytest.raises(CAError, match="no Subject Alternative Names"):
            backend.sign(csr, profile=profile, validity_days=90)

    def test_sign_success_flow(self, ca_settings, profile):
        cert_pem = _make_self_signed_cert_pem(["example.com", "www.example.com"])

        mock_client = MagicMock()
        mock_client.get_certificate.return_value = (cert_pem, None)

        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client
        backend._handler = MagicMock()
        backend._identifier_cls = MagicMock()
        backend._challenge_type = "dns-01"

        csr = _make_test_csr(["example.com", "www.example.com"])
        result = backend.sign(csr, profile=profile, validity_days=90)

        assert isinstance(result, IssuedCertificate)
        assert result.pem_chain == cert_pem
        assert result.serial_number  # non-empty hex string
        assert result.fingerprint  # non-empty hex string
        assert result.not_before is not None
        assert result.not_after is not None

        mock_client.create_order.assert_called_once()
        mock_client.complete_challenges.assert_called_once()
        mock_client.finalize_order.assert_called_once()
        mock_client.get_certificate.assert_called_once()

    def test_sign_upstream_error_wrapped(self, ca_settings, profile):
        mock_client = MagicMock()
        mock_client.create_order.side_effect = RuntimeError("upstream broke")

        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client
        backend._handler = MagicMock()
        backend._identifier_cls = MagicMock()
        backend._challenge_type = "dns-01"

        csr = _make_test_csr()
        with pytest.raises(CAError, match="Upstream ACME error"):
            backend.sign(csr, profile=profile, validity_days=90)

    def test_sign_passes_csr_der(self, ca_settings, profile):
        cert_pem = _make_self_signed_cert_pem()

        mock_client = MagicMock()
        mock_client.get_certificate.return_value = (cert_pem, None)

        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client
        backend._handler = MagicMock()
        backend._identifier_cls = MagicMock()
        backend._challenge_type = "dns-01"

        csr = _make_test_csr(["example.com"])
        backend.sign(csr, profile=profile, validity_days=90)

        # Verify finalize_order was called with csr= keyword arg (DER bytes)
        call_kwargs = mock_client.finalize_order.call_args[1]
        assert "csr" in call_kwargs
        assert isinstance(call_kwargs["csr"], bytes)


# ---------------------------------------------------------------------------
# Revoke tests
# ---------------------------------------------------------------------------


class TestRevoke:
    def test_revoke_without_client_logs_warning(self, ca_settings):
        backend = AcmeProxyBackend(ca_settings)
        # Should not raise — just logs a warning
        backend.revoke(
            serial_number="abc123",
            certificate_pem=_make_self_signed_cert_pem(),
        )

    def test_revoke_success(self, ca_settings):
        mock_client = MagicMock()
        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client

        cert_pem = _make_self_signed_cert_pem()
        backend.revoke(
            serial_number="abc123",
            certificate_pem=cert_pem,
        )

        mock_client.revoke_certificate.assert_called_once()

    def test_revoke_upstream_error_logged_not_raised(self, ca_settings):
        mock_client = MagicMock()
        mock_client.revoke_certificate.side_effect = RuntimeError("upstream error")

        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client

        cert_pem = _make_self_signed_cert_pem()
        # Should not raise
        backend.revoke(
            serial_number="abc123",
            certificate_pem=cert_pem,
        )


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------


class TestExtractIdentifiers:
    def test_extracts_dns_names(self):
        csr = _make_test_csr(["foo.com", "bar.com"])
        ids = AcmeProxyBackend._extract_identifiers(csr)
        assert ids == [("dns", "foo.com"), ("dns", "bar.com")]

    def test_empty_for_no_san(self):
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
        ids = AcmeProxyBackend._extract_identifiers(csr)
        assert ids == []


class TestParseIssuedCert:
    def test_parses_cert_pem(self):
        cert_pem = _make_self_signed_cert_pem(["example.com"])
        result = AcmeProxyBackend._parse_issued_cert(cert_pem)

        assert isinstance(result, IssuedCertificate)
        assert result.pem_chain == cert_pem
        assert len(result.serial_number) > 0
        assert len(result.fingerprint) == 64  # SHA-256 hex
        assert result.not_before < result.not_after


class TestIsRetryable:
    def test_timeout_is_retryable(self):
        assert _is_retryable(TimeoutError("timed out")) is True

    def test_connection_error_is_retryable(self):
        assert _is_retryable(ConnectionError("refused")) is True

    def test_value_error_not_retryable(self):
        assert _is_retryable(ValueError("bad value")) is False

    def test_message_based_detection(self):
        assert _is_retryable(RuntimeError("server returned 503")) is True
        assert _is_retryable(RuntimeError("rate limited 429")) is True
