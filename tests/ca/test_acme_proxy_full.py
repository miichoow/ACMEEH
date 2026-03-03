"""Extended tests for AcmeProxyBackend and upstream handler callbacks.

Covers missing coverage in acme_proxy.py (~12%) and upstream_handlers.py
(inner callback closures at lines 90-96, 108-114, 191-197, 206-212).
"""

from __future__ import annotations

import ipaddress
import sys
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acmeeh.ca.acme_proxy import AcmeProxyBackend, _is_retryable
from acmeeh.ca.base import CAError, IssuedCertificate
from acmeeh.ca.upstream_handlers import (
    CallbackDnsFactory,
    CallbackHttpFactory,
    FileHttpFactory,
    UpstreamHandlerFactory,
    _load_external_handler,
    load_upstream_handler,
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


def _make_test_csr(domains=None, ips=None):
    """Create a real CSR with SAN (DNS and/or IP) for testing."""
    if domains is None and ips is None:
        domains = ["example.com", "www.example.com"]
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    cn = (domains[0] if domains else str(ips[0])) if (domains or ips) else "test"
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ]
        )
    )

    san_entries = []
    if domains:
        san_entries.extend(x509.DNSName(d) for d in domains)
    if ips:
        san_entries.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips)

    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256())


def _make_test_csr_no_san():
    """Create a CSR with no SAN extension."""
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
            ]
        )
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


# ===========================================================================
# AcmeProxyBackend — startup_check
# ===========================================================================


class TestStartupCheckFull:
    """Tests for startup_check covering missing branches."""

    def test_missing_directory_url(self):
        settings = _make_ca_settings(_make_proxy_settings(directory_url=""))
        backend = AcmeProxyBackend(settings)
        with pytest.raises(CAError, match="directory_url is required"):
            backend.startup_check()

    def test_missing_email(self):
        settings = _make_ca_settings(_make_proxy_settings(email=""))
        backend = AcmeProxyBackend(settings)
        with pytest.raises(CAError, match="email is required"):
            backend.startup_check()

    def test_missing_challenge_handler(self):
        settings = _make_ca_settings(_make_proxy_settings(challenge_handler=""))
        backend = AcmeProxyBackend(settings)
        with pytest.raises(CAError, match="challenge_handler is required"):
            backend.startup_check()

    def test_storage_dir_creation_failure(self):
        settings = _make_ca_settings()
        backend = AcmeProxyBackend(settings)
        with patch("acmeeh.ca.acme_proxy.Path.mkdir", side_effect=OSError("permission denied")):
            with pytest.raises(CAError, match="Failed to create storage directory"):
                backend.startup_check()

    @patch("acmeeh.ca.acme_proxy.Path.mkdir")
    def test_handler_load_ca_error_reraise(self, mock_mkdir):
        """CAError from load_upstream_handler is re-raised as-is."""
        settings = _make_ca_settings()
        backend = AcmeProxyBackend(settings)
        with patch(
            "acmeeh.ca.acme_proxy.load_upstream_handler",
            side_effect=CAError("handler config bad"),
        ):
            with pytest.raises(CAError, match="handler config bad"):
                backend.startup_check()

    @patch("acmeeh.ca.acme_proxy.Path.mkdir")
    def test_handler_load_generic_exception(self, mock_mkdir):
        """Generic exception from load_upstream_handler is wrapped in CAError."""
        settings = _make_ca_settings()
        backend = AcmeProxyBackend(settings)
        with patch(
            "acmeeh.ca.acme_proxy.load_upstream_handler",
            side_effect=RuntimeError("unexpected"),
        ):
            with pytest.raises(CAError, match="Failed to load upstream challenge handler"):
                backend.startup_check()

    @patch("acmeeh.ca.acme_proxy.load_upstream_handler")
    @patch("acmeeh.ca.acme_proxy.Path.mkdir")
    def test_acmeow_import_missing(self, mock_mkdir, mock_handler):
        """ImportError when acmeow is not installed."""
        mock_handler.return_value = MagicMock()
        settings = _make_ca_settings()
        backend = AcmeProxyBackend(settings)

        with patch.dict("sys.modules", {"acmeow": None}):
            with patch(
                "builtins.__import__",
                side_effect=ImportError("No module named 'acmeow'"),
            ):
                with pytest.raises(CAError, match="ACMEOW is not installed"):
                    backend.startup_check()

    @patch("acmeeh.ca.acme_proxy.load_upstream_handler")
    @patch("acmeeh.ca.acme_proxy.Path.mkdir")
    def test_client_init_failure_retryable(self, mock_mkdir, mock_handler):
        """Client init failure wraps as retryable CAError."""
        mock_handler.return_value = MagicMock()
        mock_acmeow = MagicMock()
        mock_acmeow.AcmeClient.side_effect = ConnectionError("refused")
        mock_acmeow_enums = MagicMock()

        settings = _make_ca_settings()
        backend = AcmeProxyBackend(settings)

        with patch.dict("sys.modules", {"acmeow": mock_acmeow, "acmeow.enums": mock_acmeow_enums}):
            with pytest.raises(CAError, match="Failed to initialise ACMEOW client") as exc_info:
                backend.startup_check()
            assert exc_info.value.retryable is True

    @patch("acmeeh.ca.acme_proxy.load_upstream_handler")
    @patch("acmeeh.ca.acme_proxy.Path.mkdir")
    def test_successful_init(self, mock_mkdir, mock_handler):
        """Successful startup initialises client and handler."""
        mock_handler.return_value = MagicMock()
        mock_client = MagicMock()
        mock_acmeow = MagicMock()
        mock_acmeow.AcmeClient.return_value = mock_client
        mock_acmeow_enums = MagicMock()

        settings = _make_ca_settings()
        backend = AcmeProxyBackend(settings)

        with patch.dict("sys.modules", {"acmeow": mock_acmeow, "acmeow.enums": mock_acmeow_enums}):
            backend.startup_check()

        assert backend._client is mock_client
        assert backend._handler is mock_handler.return_value
        call_kwargs = mock_acmeow.AcmeClient.call_args[1]
        assert call_kwargs["server_url"] == "https://acme.upstream.example/directory"
        assert call_kwargs["email"] == "admin@example.com"
        mock_client.create_account.assert_called_once_with()


# ===========================================================================
# AcmeProxyBackend — _init_acme_client
# ===========================================================================


class TestInitAcmeClient:
    """Tests for _init_acme_client covering proxy_url, verify_ssl, EAB."""

    def test_with_proxy_url(self):
        proxy = _make_proxy_settings(proxy_url="http://proxy.local:8080")
        settings = _make_ca_settings(proxy)
        backend = AcmeProxyBackend(settings)

        mock_cls = MagicMock()
        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        from pathlib import Path

        backend._init_acme_client(mock_cls, Path("./storage"))

        call_kwargs = mock_cls.call_args[1]
        assert call_kwargs["proxy_url"] == "http://proxy.local:8080"

    def test_without_verify_ssl(self):
        proxy = _make_proxy_settings(verify_ssl=False)
        settings = _make_ca_settings(proxy)
        backend = AcmeProxyBackend(settings)

        mock_cls = MagicMock()
        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        from pathlib import Path

        backend._init_acme_client(mock_cls, Path("./storage"))

        call_kwargs = mock_cls.call_args[1]
        assert call_kwargs["verify_ssl"] is False

    def test_constructor_receives_server_url_and_email(self):
        settings = _make_ca_settings()
        backend = AcmeProxyBackend(settings)

        mock_cls = MagicMock()
        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        from pathlib import Path

        backend._init_acme_client(mock_cls, Path("./storage"))

        call_kwargs = mock_cls.call_args[1]
        assert call_kwargs["server_url"] == "https://acme.upstream.example/directory"
        assert call_kwargs["email"] == "admin@example.com"

    def test_create_account_called_without_args(self):
        settings = _make_ca_settings()
        backend = AcmeProxyBackend(settings)

        mock_cls = MagicMock()
        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        from pathlib import Path

        backend._init_acme_client(mock_cls, Path("./storage"))

        mock_client.create_account.assert_called_once_with()

    def test_with_eab(self):
        proxy = _make_proxy_settings(eab_kid="kid-123", eab_hmac_key="hmac-secret")
        settings = _make_ca_settings(proxy)
        backend = AcmeProxyBackend(settings)

        mock_cls = MagicMock()
        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        from pathlib import Path

        backend._init_acme_client(mock_cls, Path("./storage"))

        mock_client.set_external_account_binding.assert_called_once_with(
            kid="kid-123",
            hmac_key="hmac-secret",
        )
        mock_client.create_account.assert_called_once_with()

    def test_without_eab(self):
        proxy = _make_proxy_settings(eab_kid=None, eab_hmac_key=None)
        settings = _make_ca_settings(proxy)
        backend = AcmeProxyBackend(settings)

        mock_cls = MagicMock()
        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        from pathlib import Path

        backend._init_acme_client(mock_cls, Path("./storage"))

        mock_client.set_external_account_binding.assert_not_called()
        mock_client.create_account.assert_called_once_with()


# ===========================================================================
# AcmeProxyBackend — sign
# ===========================================================================


class TestSignFull:
    """Tests for sign covering missing branches."""

    def test_client_not_initialized(self, ca_settings, profile):
        backend = AcmeProxyBackend(ca_settings)
        csr = _make_test_csr()
        with pytest.raises(CAError, match="not initialised"):
            backend.sign(csr, profile=profile, validity_days=90)

    def test_no_sans_in_csr(self, ca_settings, profile):
        backend = AcmeProxyBackend(ca_settings)
        backend._client = MagicMock()
        csr = _make_test_csr_no_san()
        with pytest.raises(CAError, match="no Subject Alternative Names"):
            backend.sign(csr, profile=profile, validity_days=90)

    def test_successful_flow(self, ca_settings, profile):
        cert_pem = _make_self_signed_cert_pem(["test.example.com"])
        mock_client = MagicMock()
        mock_client.get_certificate.return_value = (cert_pem, None)

        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client
        backend._handler = MagicMock()
        backend._identifier_cls = MagicMock()
        backend._challenge_type = "dns-01"

        csr = _make_test_csr(["test.example.com"])
        result = backend.sign(csr, profile=profile, validity_days=90)

        assert isinstance(result, IssuedCertificate)
        assert result.pem_chain == cert_pem
        mock_client.create_order.assert_called_once()
        mock_client.complete_challenges.assert_called_once()
        mock_client.finalize_order.assert_called_once()
        mock_client.get_certificate.assert_called_once()

    def test_upstream_ca_error_reraise(self, ca_settings, profile):
        """CAError from upstream flow is re-raised directly."""
        mock_client = MagicMock()
        mock_client.create_order.side_effect = CAError("upstream CA problem")

        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client
        backend._handler = MagicMock()
        backend._identifier_cls = MagicMock()
        backend._challenge_type = "dns-01"

        csr = _make_test_csr()
        with pytest.raises(CAError, match="upstream CA problem"):
            backend.sign(csr, profile=profile, validity_days=90)

    def test_upstream_generic_retryable_exception(self, ca_settings, profile):
        """Generic retryable exception is wrapped with retryable=True."""
        mock_client = MagicMock()
        mock_client.create_order.side_effect = TimeoutError("upstream timeout")

        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client
        backend._handler = MagicMock()
        backend._identifier_cls = MagicMock()
        backend._challenge_type = "dns-01"

        csr = _make_test_csr()
        with pytest.raises(CAError) as exc_info:
            backend.sign(csr, profile=profile, validity_days=90)
        assert exc_info.value.retryable is True
        assert "Upstream ACME error" in exc_info.value.detail

    def test_upstream_generic_non_retryable_exception(self, ca_settings, profile):
        """Generic non-retryable exception is wrapped with retryable=False."""
        mock_client = MagicMock()
        mock_client.create_order.side_effect = ValueError("bad input")

        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client
        backend._handler = MagicMock()
        backend._identifier_cls = MagicMock()
        backend._challenge_type = "dns-01"

        csr = _make_test_csr()
        with pytest.raises(CAError) as exc_info:
            backend.sign(csr, profile=profile, validity_days=90)
        assert exc_info.value.retryable is False
        assert "Upstream ACME error" in exc_info.value.detail


# ===========================================================================
# AcmeProxyBackend — _execute_upstream_flow
# ===========================================================================


class TestExecuteUpstreamFlow:
    """Test the full upstream ACME flow."""

    def test_full_flow(self, ca_settings):
        cert_pem = _make_self_signed_cert_pem()
        mock_client = MagicMock()
        mock_client.get_certificate.return_value = (cert_pem, None)
        mock_handler = MagicMock()

        # Make Identifier.dns / Identifier.ip return distinguishable mocks
        mock_identifier_cls = MagicMock()
        mock_id1 = MagicMock(name="id-example")
        mock_id2 = MagicMock(name="id-www")
        mock_identifier_cls.dns.side_effect = [mock_id1, mock_id2]

        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client
        backend._handler = mock_handler
        backend._identifier_cls = mock_identifier_cls
        backend._challenge_type = "dns-01"

        identifiers = [("dns", "example.com"), ("dns", "www.example.com")]
        csr_der = b"\x30\x00"  # dummy DER

        result = backend._execute_upstream_flow(identifiers, csr_der)

        assert result == cert_pem
        mock_identifier_cls.dns.assert_any_call("example.com")
        mock_identifier_cls.dns.assert_any_call("www.example.com")
        mock_client.create_order.assert_called_once_with([mock_id1, mock_id2])
        mock_client.complete_challenges.assert_called_once_with(
            mock_handler,
            challenge_type="dns-01",
        )
        mock_client.finalize_order.assert_called_once_with(csr=csr_der)
        mock_client.get_certificate.assert_called_once()


# ===========================================================================
# AcmeProxyBackend — revoke
# ===========================================================================


class TestRevokeFull:
    """Tests for revoke covering missing branches."""

    def test_client_not_initialized_logs_warning(self, ca_settings):
        """When client is None, logs warning and returns without error."""
        backend = AcmeProxyBackend(ca_settings)
        assert backend._client is None

        # Should not raise
        backend.revoke(
            serial_number="abc123",
            certificate_pem=_make_self_signed_cert_pem(),
        )

    def test_successful_upstream_revocation(self, ca_settings):
        mock_client = MagicMock()
        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client

        cert_pem = _make_self_signed_cert_pem()
        backend.revoke(
            serial_number="abc123",
            certificate_pem=cert_pem,
        )

        mock_client.revoke_certificate.assert_called_once()

    def test_revoke_with_reason(self, ca_settings):
        """Revoke converts reason to acmeow RevocationReason enum."""
        mock_client = MagicMock()
        mock_acmeow_reason_cls = MagicMock()
        mock_acmeow_reason_instance = MagicMock()
        mock_acmeow_reason_cls.return_value = mock_acmeow_reason_instance

        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client
        backend._acmeow_revocation_reason = mock_acmeow_reason_cls

        cert_pem = _make_self_signed_cert_pem()

        mock_reason = MagicMock()
        mock_reason.value = 4  # superseded

        backend.revoke(
            serial_number="abc123",
            certificate_pem=cert_pem,
            reason=mock_reason,
        )

        mock_acmeow_reason_cls.assert_called_once_with(4)
        call_kwargs = mock_client.revoke_certificate.call_args
        assert call_kwargs[1]["reason"] is mock_acmeow_reason_instance

    def test_upstream_exception_logged_not_raised(self, ca_settings):
        """Upstream errors are caught and logged, not raised."""
        mock_client = MagicMock()
        mock_client.revoke_certificate.side_effect = RuntimeError("upstream down")

        backend = AcmeProxyBackend(ca_settings)
        backend._client = mock_client

        cert_pem = _make_self_signed_cert_pem()
        # Should not raise
        backend.revoke(
            serial_number="abc123",
            certificate_pem=cert_pem,
        )


# ===========================================================================
# AcmeProxyBackend — _extract_identifiers
# ===========================================================================


class TestExtractIdentifiersFull:
    """Tests for _extract_identifiers including IP addresses."""

    def test_dns_names(self):
        csr = _make_test_csr(domains=["foo.com", "bar.com"])
        ids = AcmeProxyBackend._extract_identifiers(csr)
        assert ids == [("dns", "foo.com"), ("dns", "bar.com")]

    def test_ip_addresses(self):
        csr = _make_test_csr(domains=None, ips=["192.168.1.1", "10.0.0.1"])
        ids = AcmeProxyBackend._extract_identifiers(csr)
        assert ("ip", "192.168.1.1") in ids
        assert ("ip", "10.0.0.1") in ids

    def test_mixed_dns_and_ip(self):
        csr = _make_test_csr(
            domains=["test.example.com"],
            ips=["192.168.1.1"],
        )
        ids = AcmeProxyBackend._extract_identifiers(csr)
        assert ("dns", "test.example.com") in ids
        assert ("ip", "192.168.1.1") in ids

    def test_no_san_returns_empty(self):
        csr = _make_test_csr_no_san()
        ids = AcmeProxyBackend._extract_identifiers(csr)
        assert ids == []


# ===========================================================================
# AcmeProxyBackend — _parse_issued_cert
# ===========================================================================


class TestParseIssuedCertFull:
    def test_valid_pem(self):
        cert_pem = _make_self_signed_cert_pem(["example.com"])
        result = AcmeProxyBackend._parse_issued_cert(cert_pem)

        assert isinstance(result, IssuedCertificate)
        assert result.pem_chain == cert_pem
        assert len(result.serial_number) > 0
        assert len(result.fingerprint) == 64  # SHA-256 hex
        assert result.not_before < result.not_after


# ===========================================================================
# _is_retryable
# ===========================================================================


class TestIsRetryableFull:
    def test_timeout_retryable(self):
        assert _is_retryable(TimeoutError("timed out")) is True

    def test_connection_retryable(self):
        assert _is_retryable(ConnectionError("refused")) is True

    def test_normal_error_not_retryable(self):
        assert _is_retryable(ValueError("bad")) is False

    def test_503_in_message_retryable(self):
        assert _is_retryable(RuntimeError("server returned 503")) is True

    def test_429_in_message_retryable(self):
        assert _is_retryable(RuntimeError("429 rate limited")) is True

    def test_network_in_name_retryable(self):
        """Custom exception with 'network' in name is retryable."""

        class NetworkFailure(Exception):
            pass

        assert _is_retryable(NetworkFailure("something")) is True


# ===========================================================================
# Upstream handlers — inner callback tests
# ===========================================================================


@pytest.fixture()
def mock_acmeow_handlers():
    """Temporarily inject a mock acmeow.handlers module into sys.modules."""
    mock_handlers = MagicMock()
    mock_acmeow = MagicMock()
    mock_acmeow.handlers = mock_handlers

    saved = {}
    for key in ("acmeow", "acmeow.handlers"):
        if key in sys.modules:
            saved[key] = sys.modules[key]

    sys.modules["acmeow"] = mock_acmeow
    sys.modules["acmeow.handlers"] = mock_handlers
    yield mock_handlers

    for key in ("acmeow", "acmeow.handlers"):
        if key in saved:
            sys.modules[key] = saved[key]
        else:
            sys.modules.pop(key, None)


class TestCallbackDnsFactoryFull:
    """Tests for CallbackDnsFactory including inner closure callbacks."""

    def test_missing_create_script(self):
        factory = CallbackDnsFactory()
        with pytest.raises(CAError, match="create_script"):
            factory.create({"delete_script": "/bin/delete.sh"})

    def test_missing_delete_script(self):
        factory = CallbackDnsFactory()
        with pytest.raises(CAError, match="delete_script"):
            factory.create({"create_script": "/bin/create.sh"})

    def test_success_creates_handler(self, mock_acmeow_handlers):
        mock_handler_cls = MagicMock()
        mock_acmeow_handlers.CallbackDnsHandler = mock_handler_cls

        factory = CallbackDnsFactory()
        factory.create(
            {
                "create_script": "/usr/bin/dns-create.sh",
                "delete_script": "/usr/bin/dns-delete.sh",
                "propagation_delay": 15,
                "script_timeout": 120,
            }
        )

        mock_handler_cls.assert_called_once()
        kwargs = mock_handler_cls.call_args[1]
        assert kwargs["propagation_delay"] == 15
        assert callable(kwargs["create_record"])
        assert callable(kwargs["delete_record"])

    def test_create_record_callback_calls_subprocess(self, mock_acmeow_handlers):
        """The inner create_record closure calls subprocess.run correctly."""
        mock_handler_cls = MagicMock()
        mock_acmeow_handlers.CallbackDnsHandler = mock_handler_cls

        factory = CallbackDnsFactory()
        factory.create(
            {
                "create_script": "/usr/bin/dns-create.sh",
                "delete_script": "/usr/bin/dns-delete.sh",
                "propagation_delay": 10,
                "script_timeout": 45,
            }
        )

        # Extract the create_record callback
        create_fn = mock_handler_cls.call_args[1]["create_record"]

        with patch("acmeeh.ca.upstream_handlers.subprocess.run") as mock_run:
            create_fn("example.com", "_acme-challenge.example.com", "token-value")
            mock_run.assert_called_once_with(
                [
                    "/usr/bin/dns-create.sh",
                    "example.com",
                    "_acme-challenge.example.com",
                    "token-value",
                ],
                check=True,
                timeout=45,
                capture_output=True,
                text=True,
            )

    def test_delete_record_callback_calls_subprocess(self, mock_acmeow_handlers):
        """The inner delete_record closure calls subprocess.run correctly."""
        mock_handler_cls = MagicMock()
        mock_acmeow_handlers.CallbackDnsHandler = mock_handler_cls

        factory = CallbackDnsFactory()
        factory.create(
            {
                "create_script": "/usr/bin/dns-create.sh",
                "delete_script": "/usr/bin/dns-delete.sh",
                "script_timeout": 30,
            }
        )

        # Extract the delete_record callback
        delete_fn = mock_handler_cls.call_args[1]["delete_record"]

        with patch("acmeeh.ca.upstream_handlers.subprocess.run") as mock_run:
            delete_fn("example.com", "_acme-challenge.example.com")
            mock_run.assert_called_once_with(
                ["/usr/bin/dns-delete.sh", "example.com", "_acme-challenge.example.com"],
                check=True,
                timeout=30,
                capture_output=True,
                text=True,
            )

    def test_default_propagation_delay_and_timeout(self, mock_acmeow_handlers):
        """Defaults to propagation_delay=10 and script_timeout=60."""
        mock_handler_cls = MagicMock()
        mock_acmeow_handlers.CallbackDnsHandler = mock_handler_cls

        factory = CallbackDnsFactory()
        factory.create(
            {
                "create_script": "/bin/create.sh",
                "delete_script": "/bin/delete.sh",
            }
        )

        kwargs = mock_handler_cls.call_args[1]
        assert kwargs["propagation_delay"] == 10

        # Verify the default timeout by calling the create callback
        create_fn = kwargs["create_record"]
        with patch("acmeeh.ca.upstream_handlers.subprocess.run") as mock_run:
            create_fn("d", "r", "v")
            assert mock_run.call_args[1]["timeout"] == 60


class TestFileHttpFactoryFull:
    def test_missing_webroot(self):
        factory = FileHttpFactory()
        with pytest.raises(CAError, match="webroot"):
            factory.create({})

    def test_success(self, mock_acmeow_handlers):
        mock_handler_cls = MagicMock()
        mock_acmeow_handlers.FileHttpHandler = mock_handler_cls

        factory = FileHttpFactory()
        factory.create({"webroot": "/var/www/html"})
        mock_handler_cls.assert_called_once_with(webroot="/var/www/html")


class TestCallbackHttpFactoryFull:
    """Tests for CallbackHttpFactory including inner closure callbacks."""

    def test_missing_deploy_script(self):
        factory = CallbackHttpFactory()
        with pytest.raises(CAError, match="deploy_script"):
            factory.create({"cleanup_script": "/bin/cleanup.sh"})

    def test_missing_cleanup_script(self):
        factory = CallbackHttpFactory()
        with pytest.raises(CAError, match="cleanup_script"):
            factory.create({"deploy_script": "/bin/deploy.sh"})

    def test_success_creates_handler(self, mock_acmeow_handlers):
        mock_handler_cls = MagicMock()
        mock_acmeow_handlers.CallbackHttpHandler = mock_handler_cls

        factory = CallbackHttpFactory()
        factory.create(
            {
                "deploy_script": "/usr/bin/deploy.sh",
                "cleanup_script": "/usr/bin/cleanup.sh",
                "script_timeout": 90,
            }
        )

        mock_handler_cls.assert_called_once()
        kwargs = mock_handler_cls.call_args[1]
        assert callable(kwargs["deploy"])
        assert callable(kwargs["cleanup"])

    def test_deploy_callback_calls_subprocess(self, mock_acmeow_handlers):
        """The inner deploy closure calls subprocess.run correctly."""
        mock_handler_cls = MagicMock()
        mock_acmeow_handlers.CallbackHttpHandler = mock_handler_cls

        factory = CallbackHttpFactory()
        factory.create(
            {
                "deploy_script": "/usr/bin/deploy.sh",
                "cleanup_script": "/usr/bin/cleanup.sh",
                "script_timeout": 45,
            }
        )

        deploy_fn = mock_handler_cls.call_args[1]["deploy"]

        with patch("acmeeh.ca.upstream_handlers.subprocess.run") as mock_run:
            deploy_fn("example.com", "my-token", "my-key-authz")
            mock_run.assert_called_once_with(
                ["/usr/bin/deploy.sh", "example.com", "my-token", "my-key-authz"],
                check=True,
                timeout=45,
                capture_output=True,
                text=True,
            )

    def test_cleanup_callback_calls_subprocess(self, mock_acmeow_handlers):
        """The inner cleanup closure calls subprocess.run correctly."""
        mock_handler_cls = MagicMock()
        mock_acmeow_handlers.CallbackHttpHandler = mock_handler_cls

        factory = CallbackHttpFactory()
        factory.create(
            {
                "deploy_script": "/usr/bin/deploy.sh",
                "cleanup_script": "/usr/bin/cleanup.sh",
                "script_timeout": 30,
            }
        )

        cleanup_fn = mock_handler_cls.call_args[1]["cleanup"]

        with patch("acmeeh.ca.upstream_handlers.subprocess.run") as mock_run:
            cleanup_fn("example.com", "my-token")
            mock_run.assert_called_once_with(
                ["/usr/bin/cleanup.sh", "example.com", "my-token"],
                check=True,
                timeout=30,
                capture_output=True,
                text=True,
            )

    def test_default_script_timeout(self, mock_acmeow_handlers):
        """Default script_timeout is 60."""
        mock_handler_cls = MagicMock()
        mock_acmeow_handlers.CallbackHttpHandler = mock_handler_cls

        factory = CallbackHttpFactory()
        factory.create(
            {
                "deploy_script": "/bin/deploy.sh",
                "cleanup_script": "/bin/cleanup.sh",
            }
        )

        deploy_fn = mock_handler_cls.call_args[1]["deploy"]
        with patch("acmeeh.ca.upstream_handlers.subprocess.run") as mock_run:
            deploy_fn("d", "t", "k")
            assert mock_run.call_args[1]["timeout"] == 60


# ===========================================================================
# load_upstream_handler and _load_external_handler
# ===========================================================================


class TestLoadUpstreamHandlerFull:
    def test_builtin_name(self):
        """Built-in names dispatch to factory.create."""
        with patch(
            "acmeeh.ca.upstream_handlers.CallbackDnsFactory.create",
            return_value="handler-obj",
        ) as mock_create:
            result = load_upstream_handler("callback_dns", {"key": "val"})
            assert result == "handler-obj"
            mock_create.assert_called_once_with({"key": "val"})

    def test_ext_prefix(self):
        """ext: prefix delegates to _load_external_handler."""
        with patch(
            "acmeeh.ca.upstream_handlers._load_external_handler",
            return_value="ext-handler",
        ) as mock_ext:
            result = load_upstream_handler("ext:my.module.Factory", {"k": "v"})
            assert result == "ext-handler"
            mock_ext.assert_called_once_with("my.module.Factory", {"k": "v"})

    def test_unknown_name(self):
        with pytest.raises(CAError, match="Unknown upstream challenge handler"):
            load_upstream_handler("nonexistent_handler", {})


class TestLoadExternalHandlerFull:
    def test_invalid_fqn_no_dots(self):
        with pytest.raises(CAError, match="must be fully qualified"):
            _load_external_handler("BadName", {})

    def test_import_error(self):
        with patch(
            "acmeeh.ca.upstream_handlers.importlib.import_module",
            side_effect=ImportError("no such module"),
        ):
            with pytest.raises(CAError, match="Failed to load"):
                _load_external_handler("nonexistent.module.Factory", {})

    def test_attribute_error(self):
        with patch(
            "acmeeh.ca.upstream_handlers.importlib.import_module",
        ) as mock_import:
            mock_module = MagicMock(spec=[])  # no attributes
            mock_import.return_value = mock_module
            with pytest.raises(CAError, match="Failed to load"):
                _load_external_handler("mypackage.module.Missing", {})

    def test_not_a_subclass(self):
        with patch(
            "acmeeh.ca.upstream_handlers.importlib.import_module",
        ) as mock_import:
            mock_module = MagicMock()
            mock_module.NotFactory = str  # str is not an UpstreamHandlerFactory
            mock_import.return_value = mock_module
            with pytest.raises(CAError, match="must be a subclass"):
                _load_external_handler("mypackage.module.NotFactory", {})

    def test_success(self):
        class GoodFactory(UpstreamHandlerFactory):
            def create(self, config):
                return f"handler-for-{config.get('x')}"

        with patch(
            "acmeeh.ca.upstream_handlers.importlib.import_module",
        ) as mock_import:
            mock_module = MagicMock()
            mock_module.GoodFactory = GoodFactory
            mock_import.return_value = mock_module
            result = _load_external_handler("mypkg.mod.GoodFactory", {"x": "test"})
            assert result == "handler-for-test"
