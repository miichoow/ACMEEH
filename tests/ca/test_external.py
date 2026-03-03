"""Comprehensive error scenario tests for ExternalCABackend."""

from __future__ import annotations

import json
import ssl
import urllib.error
from datetime import UTC
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acmeeh.ca.base import CAError
from acmeeh.ca.external import ExternalCABackend
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


def _make_external_settings(**overrides) -> ExternalCASettings:
    """Build an ExternalCASettings with sensible defaults."""
    defaults = {
        "sign_url": "https://ca.example.com/sign",
        "revoke_url": "https://ca.example.com/revoke",
        "auth_header": "Authorization",
        "auth_value": "Bearer test-token",
        "ca_cert_path": None,
        "client_cert_path": None,
        "client_key_path": None,
        "timeout_seconds": 30,
        "max_retries": 0,
        "retry_delay_seconds": 1.0,
    }
    defaults.update(overrides)
    return ExternalCASettings(**defaults)


def _make_ca_settings(ext: ExternalCASettings | None = None) -> CASettings:
    """Build a full CASettings with the given external section."""
    return CASettings(
        backend="external",
        default_validity_days=90,
        max_validity_days=397,
        profiles={
            "default": CAProfileSettings(
                key_usages=("digital_signature",),
                extended_key_usages=("server_auth",),
                validity_days=None,
                max_validity_days=None,
            ),
        },
        internal=CAInternalSettings(
            root_cert_path="",
            root_key_path="",
            chain_path=None,
            serial_source="database",
            hash_algorithm="sha256",
        ),
        external=ext or _make_external_settings(),
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


def _make_csr() -> x509.CertificateSigningRequest:
    """Generate a minimal CSR for testing."""
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    )
    return builder.sign(key, hashes.SHA256())


def _default_profile() -> CAProfileSettings:
    return CAProfileSettings(
        key_usages=("digital_signature",),
        extended_key_usages=("server_auth",),
        validity_days=None,
        max_validity_days=None,
    )


def _make_self_signed_pem() -> str:
    """Generate a self-signed certificate PEM for response mocking."""
    key = ec.generate_private_key(ec.SECP256R1())
    from datetime import datetime, timedelta

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _mock_http_error(code: int, body: str = "") -> urllib.error.HTTPError:
    """Create an HTTPError with a readable body."""
    err = urllib.error.HTTPError(
        url="https://ca.example.com/sign",
        code=code,
        msg=f"HTTP {code}",
        hdrs=None,
        fp=BytesIO(body.encode("utf-8")),
    )
    return err


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSignHTTPErrors:
    """Tests for HTTP error code handling during sign requests."""

    def test_sign_http_500_retryable(self):
        """HTTP 500 from the external CA raises a retryable CAError."""
        ext = _make_external_settings(max_retries=0)
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)
        csr = _make_csr()

        with patch("urllib.request.build_opener") as mock_opener_fn:
            opener = MagicMock()
            mock_opener_fn.return_value = opener
            opener.open.side_effect = _mock_http_error(500, "Internal Server Error")

            with pytest.raises(CAError) as exc_info:
                backend.sign(
                    csr,
                    profile=_default_profile(),
                    validity_days=90,
                )

            assert exc_info.value.retryable is True
            assert "500" in exc_info.value.detail

    def test_sign_http_400_not_retryable(self):
        """HTTP 400 from the external CA raises a non-retryable CAError."""
        ext = _make_external_settings(max_retries=0)
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)
        csr = _make_csr()

        with patch("urllib.request.build_opener") as mock_opener_fn:
            opener = MagicMock()
            mock_opener_fn.return_value = opener
            opener.open.side_effect = _mock_http_error(400, "Bad Request")

            with pytest.raises(CAError) as exc_info:
                backend.sign(
                    csr,
                    profile=_default_profile(),
                    validity_days=90,
                )

            assert exc_info.value.retryable is False
            assert "400" in exc_info.value.detail


class TestSignNetworkErrors:
    """Tests for network-level failures during sign requests."""

    def test_sign_connection_timeout(self):
        """URLError (e.g. timeout or DNS failure) raises retryable CAError."""
        ext = _make_external_settings(max_retries=0)
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)
        csr = _make_csr()

        with patch("urllib.request.build_opener") as mock_opener_fn:
            opener = MagicMock()
            mock_opener_fn.return_value = opener
            opener.open.side_effect = urllib.error.URLError(reason="timed out")

            with pytest.raises(CAError) as exc_info:
                backend.sign(
                    csr,
                    profile=_default_profile(),
                    validity_days=90,
                )

            assert exc_info.value.retryable is True
            assert "timed out" in exc_info.value.detail


class TestSignResponseParsing:
    """Tests for invalid or malformed responses from the external CA."""

    def test_sign_invalid_json_response(self):
        """Non-JSON response body raises a non-retryable CAError."""
        ext = _make_external_settings(max_retries=0)
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)
        csr = _make_csr()

        with patch("urllib.request.build_opener") as mock_opener_fn:
            opener = MagicMock()
            mock_opener_fn.return_value = opener

            # Return a mock response with invalid JSON
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read.return_value = b"<html>not json</html>"
            opener.open.return_value = mock_resp

            with pytest.raises(CAError) as exc_info:
                backend.sign(
                    csr,
                    profile=_default_profile(),
                    validity_days=90,
                )

            assert exc_info.value.retryable is False
            assert "invalid JSON" in exc_info.value.detail

    def test_sign_missing_certificate_chain(self):
        """Response with empty certificate_chain raises a CAError."""
        ext = _make_external_settings(max_retries=0)
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)
        csr = _make_csr()

        with patch("urllib.request.build_opener") as mock_opener_fn:
            opener = MagicMock()
            mock_opener_fn.return_value = opener

            # Return valid JSON but with empty certificate_chain
            resp_body = json.dumps({"certificate_chain": ""}).encode("utf-8")
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read.return_value = resp_body
            opener.open.return_value = mock_resp

            with pytest.raises(CAError) as exc_info:
                backend.sign(
                    csr,
                    profile=_default_profile(),
                    validity_days=90,
                )

            assert exc_info.value.retryable is False
            assert "certificate_chain" in exc_info.value.detail


class TestRetryLogic:
    """Tests for the retry-with-backoff mechanism."""

    def test_sign_retry_with_backoff(self):
        """Retryable errors trigger retries with exponential backoff.

        With max_retries=2 and retry_delay_seconds=0.5:
        - Attempt 0: fails (sleep 0.5 * 2^0 = 0.5)
        - Attempt 1: fails (sleep 0.5 * 2^1 = 1.0)
        - Attempt 2: succeeds
        """
        ext = _make_external_settings(max_retries=2, retry_delay_seconds=0.5)
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)
        csr = _make_csr()

        cert_pem = _make_self_signed_pem()
        success_body = json.dumps({"certificate_chain": cert_pem}).encode("utf-8")

        with (
            patch("urllib.request.build_opener") as mock_opener_fn,
            patch("time.sleep") as mock_sleep,
        ):
            opener = MagicMock()
            mock_opener_fn.return_value = opener

            # First two calls fail with 500, third succeeds
            err_500 = _mock_http_error(500, "Server Error")
            err_500_2 = _mock_http_error(500, "Server Error")
            mock_success = MagicMock()
            mock_success.status = 200
            mock_success.read.return_value = success_body

            opener.open.side_effect = [err_500, err_500_2, mock_success]

            result = backend.sign(
                csr,
                profile=_default_profile(),
                validity_days=90,
            )

            # Verify we got a successful result
            assert result.pem_chain == cert_pem
            assert result.serial_number  # non-empty hex serial

            # Verify retry attempts
            assert opener.open.call_count == 3

            # Verify exponential backoff sleep calls
            assert mock_sleep.call_count == 2
            mock_sleep.assert_any_call(0.5)  # 0.5 * 2^0
            mock_sleep.assert_any_call(1.0)  # 0.5 * 2^1

    def test_sign_retries_exhausted_raises(self):
        """When all retries are exhausted, the final CAError is raised."""
        ext = _make_external_settings(max_retries=1, retry_delay_seconds=0.1)
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)
        csr = _make_csr()

        with (
            patch("urllib.request.build_opener") as mock_opener_fn,
            patch("time.sleep"),
        ):
            opener = MagicMock()
            mock_opener_fn.return_value = opener

            err_500_1 = _mock_http_error(500, "Server Error attempt 1")
            err_500_2 = _mock_http_error(500, "Server Error attempt 2")
            opener.open.side_effect = [err_500_1, err_500_2]

            with pytest.raises(CAError) as exc_info:
                backend.sign(
                    csr,
                    profile=_default_profile(),
                    validity_days=90,
                )

            assert exc_info.value.retryable is True
            assert "500" in exc_info.value.detail
            # Both attempts should have been made (initial + 1 retry)
            assert opener.open.call_count == 2


class TestStartupCheck:
    """Tests for startup_check validation."""

    def test_startup_check_missing_sign_url(self):
        """startup_check raises CAError when sign_url is empty."""
        ext = _make_external_settings(sign_url="")
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)

        with pytest.raises(CAError) as exc_info:
            backend.startup_check()

        assert "sign_url" in exc_info.value.detail

    def test_startup_check_valid_config(self):
        """startup_check succeeds when sign_url is configured."""
        ext = _make_external_settings(sign_url="https://ca.example.com/sign")
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)

        # Should not raise
        backend.startup_check()


class TestRevoke:
    """Tests for revoke error handling."""

    def test_revoke_without_revoke_url(self):
        """Revoke with no revoke_url configured logs a warning but does not error."""
        ext = _make_external_settings(revoke_url="")
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)

        with patch("acmeeh.ca.external.log") as mock_log:
            # Should not raise
            backend.revoke(
                serial_number="0a1b2c3d",
                certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
                reason=None,
            )

            # Verify warning was logged
            mock_log.warning.assert_called_once()
            warning_msg = mock_log.warning.call_args[0][0]
            assert "revoke_url" in warning_msg.lower() or "revoke_url" in str(
                mock_log.warning.call_args
            )

    def test_revoke_http_error(self):
        """Revoke raises CAError when the external CA returns an HTTP error."""
        ext = _make_external_settings(max_retries=0)
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)

        with patch("urllib.request.build_opener") as mock_opener_fn:
            opener = MagicMock()
            mock_opener_fn.return_value = opener
            opener.open.side_effect = _mock_http_error(403, "Forbidden")

            with pytest.raises(CAError) as exc_info:
                backend.revoke(
                    serial_number="0a1b2c3d",
                    certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
                    reason=None,
                )

            assert "403" in exc_info.value.detail
            # 403 is < 500 so should not be retryable
            assert exc_info.value.retryable is False

    def test_revoke_with_reason(self):
        """Revoke includes the reason code in the request payload."""
        from acmeeh.core.types import RevocationReason

        ext = _make_external_settings(max_retries=0)
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)

        with patch("urllib.request.build_opener") as mock_opener_fn:
            opener = MagicMock()
            mock_opener_fn.return_value = opener

            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read.return_value = b"{}"
            opener.open.return_value = mock_resp

            backend.revoke(
                serial_number="deadbeef",
                certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
                reason=RevocationReason.KEY_COMPROMISE,
            )

            # Verify the request was made with the correct payload
            req_obj = opener.open.call_args[0][0]
            sent_payload = json.loads(req_obj.data.decode("utf-8"))
            assert sent_payload["serial_number"] == "deadbeef"
            assert sent_payload["reason"] == 1  # KEY_COMPROMISE


class TestMTLSConfig:
    """Tests for mTLS / SSL context configuration."""

    def test_mtls_config(self):
        """SSL context loads client cert and key when mTLS is configured."""
        ext = _make_external_settings(
            client_cert_path="/path/to/client.pem",
            client_key_path="/path/to/client.key",
            ca_cert_path="/path/to/ca-bundle.pem",
        )
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)

        with (
            patch("ssl.create_default_context") as mock_ctx_factory,
        ):
            mock_ctx = MagicMock(spec=ssl.SSLContext)
            mock_ctx_factory.return_value = mock_ctx

            ctx = backend._get_ssl_context()

            # Verify the CA trust anchor was loaded
            mock_ctx.load_verify_locations.assert_called_once_with("/path/to/ca-bundle.pem")

            # Verify the client certificate chain was loaded for mTLS
            mock_ctx.load_cert_chain.assert_called_once_with(
                "/path/to/client.pem",
                "/path/to/client.key",
            )

            assert ctx is mock_ctx

    def test_ssl_context_cached(self):
        """SSL context is built once and reused on subsequent calls."""
        ext = _make_external_settings()
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)

        with patch("ssl.create_default_context") as mock_ctx_factory:
            mock_ctx = MagicMock(spec=ssl.SSLContext)
            mock_ctx_factory.return_value = mock_ctx

            ctx1 = backend._get_ssl_context()
            ctx2 = backend._get_ssl_context()

            assert ctx1 is ctx2
            # create_default_context should only be called once
            mock_ctx_factory.assert_called_once()

    def test_ssl_context_no_mtls(self):
        """SSL context is created without mTLS when no client cert is configured."""
        ext = _make_external_settings(
            client_cert_path=None,
            client_key_path=None,
            ca_cert_path=None,
        )
        ca_settings = _make_ca_settings(ext)
        backend = ExternalCABackend(ca_settings)

        with patch("ssl.create_default_context") as mock_ctx_factory:
            mock_ctx = MagicMock(spec=ssl.SSLContext)
            mock_ctx_factory.return_value = mock_ctx

            backend._get_ssl_context()

            mock_ctx.load_verify_locations.assert_not_called()
            mock_ctx.load_cert_chain.assert_not_called()
