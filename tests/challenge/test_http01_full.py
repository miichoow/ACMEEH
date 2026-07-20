"""Additional HTTP-01 challenge validator tests for improved coverage."""

from __future__ import annotations

import io
import socket
import urllib.error
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from acmeeh.challenge.base import ChallengeError
from acmeeh.challenge.http01 import Http01Validator
from acmeeh.core.types import ChallengeType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEY_AUTHZ = "test-token.mock-thumbprint"
TOKEN = "test-token"
JWK = {"kty": "EC", "crv": "P-256"}
DOMAIN = "example.com"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(body: bytes, status: int = 200) -> MagicMock:
    """Create a mock HTTP response object."""
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = body
    return resp


def _opener_open(mock_build_opener: MagicMock) -> MagicMock:
    """Return the mock for ``opener.open(...)`` given a mocked build_opener."""
    return mock_build_opener.return_value.open


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHttp01Validator:
    """Tests for Http01Validator.validate."""

    @pytest.fixture(autouse=True)
    def _patch_key_authorization(self):
        with patch(
            "acmeeh.challenge.http01.key_authorization",
            return_value=KEY_AUTHZ,
        ):
            yield

    def test_wrong_identifier_type(self):
        """HTTP-01 only supports 'dns' identifiers."""
        validator = Http01Validator(settings=None)
        with pytest.raises(ChallengeError, match="only supports 'dns'") as exc_info:
            validator.validate(
                token=TOKEN,
                jwk=JWK,
                identifier_type="ip",
                identifier_value="192.0.2.1",
            )
        assert exc_info.value.retryable is False

    @patch("acmeeh.challenge.http01.urllib.request.build_opener")
    def test_successful_validation(self, mock_build_opener):
        """Matching response body -> success."""
        _opener_open(mock_build_opener).return_value = _make_response(
            KEY_AUTHZ.encode("utf-8"),
        )

        validator = Http01Validator(settings=None)
        # Should not raise
        validator.validate(
            token=TOKEN,
            jwk=JWK,
            identifier_type="dns",
            identifier_value=DOMAIN,
        )

        # Verify the URL was constructed correctly (port 80 omitted)
        call_args = _opener_open(mock_build_opener).call_args
        req = call_args[0][0]
        assert "/.well-known/acme-challenge/test-token" in req.full_url
        assert ":80" not in req.full_url

    @patch("acmeeh.challenge.http01.urllib.request.build_opener")
    def test_custom_port_in_url(self, mock_build_opener):
        """Custom port is included in the URL."""
        _opener_open(mock_build_opener).return_value = _make_response(
            KEY_AUTHZ.encode("utf-8"),
        )

        settings = SimpleNamespace(
            port=8080,
            timeout_seconds=10,
            blocked_networks=(),
            max_response_bytes=1048576,
        )
        validator = Http01Validator(settings=settings)
        validator.validate(
            token=TOKEN,
            jwk=JWK,
            identifier_type="dns",
            identifier_value=DOMAIN,
        )

        call_args = _opener_open(mock_build_opener).call_args
        req = call_args[0][0]
        assert ":8080/" in req.full_url

    @patch("acmeeh.challenge.http01.urllib.request.build_opener")
    def test_http_error_is_retryable(self, mock_build_opener):
        """HTTPError -> ChallengeError(retryable=True)."""
        _opener_open(mock_build_opener).side_effect = urllib.error.HTTPError(
            url="http://example.com",
            code=503,
            msg="Service Unavailable",
            hdrs=MagicMock(),
            fp=io.BytesIO(b""),
        )

        validator = Http01Validator(settings=None)
        with pytest.raises(ChallengeError, match="HTTP 503") as exc_info:
            validator.validate(
                token=TOKEN,
                jwk=JWK,
                identifier_type="dns",
                identifier_value=DOMAIN,
            )
        assert exc_info.value.retryable is True

    @patch("acmeeh.challenge.http01.urllib.request.build_opener")
    def test_url_error_is_retryable(self, mock_build_opener):
        """URLError -> ChallengeError(retryable=True)."""
        _opener_open(mock_build_opener).side_effect = urllib.error.URLError("Connection refused")

        validator = Http01Validator(settings=None)
        with pytest.raises(ChallengeError, match="could not connect") as exc_info:
            validator.validate(
                token=TOKEN,
                jwk=JWK,
                identifier_type="dns",
                identifier_value=DOMAIN,
            )
        assert exc_info.value.retryable is True

    @patch("acmeeh.challenge.http01.urllib.request.build_opener")
    def test_body_mismatch_not_retryable(self, mock_build_opener):
        """Response body doesn't match -> ChallengeError(retryable=False)."""
        _opener_open(mock_build_opener).return_value = _make_response(
            b"wrong-key-authorization",
        )

        validator = Http01Validator(settings=None)
        with pytest.raises(ChallengeError, match="does not match") as exc_info:
            validator.validate(
                token=TOKEN,
                jwk=JWK,
                identifier_type="dns",
                identifier_value=DOMAIN,
            )
        assert exc_info.value.retryable is False

    @patch("acmeeh.challenge.http01.urllib.request.build_opener")
    def test_non_utf8_body_not_retryable(self, mock_build_opener):
        """Non-UTF-8 response body -> ChallengeError(retryable=False)."""
        _opener_open(mock_build_opener).return_value = _make_response(
            b"\xff\xfe\x00\x01\x80\x81\x82",
        )

        validator = Http01Validator(settings=None)
        with pytest.raises(ChallengeError, match="not valid UTF-8") as exc_info:
            validator.validate(
                token=TOKEN,
                jwk=JWK,
                identifier_type="dns",
                identifier_value=DOMAIN,
            )
        assert exc_info.value.retryable is False

    @patch("acmeeh.challenge.http01.urllib.request.build_opener")
    def test_read_error_is_retryable(self, mock_build_opener):
        """OSError while reading body -> ChallengeError(retryable=True)."""
        resp = MagicMock()
        resp.status = 200
        resp.read.side_effect = OSError("connection reset during read")
        _opener_open(mock_build_opener).return_value = resp

        validator = Http01Validator(settings=None)
        with pytest.raises(ChallengeError, match="error reading response") as exc_info:
            validator.validate(
                token=TOKEN,
                jwk=JWK,
                identifier_type="dns",
                identifier_value=DOMAIN,
            )
        assert exc_info.value.retryable is True

    @patch("acmeeh.challenge.http01.socket.getaddrinfo")
    def test_blocked_networks_all_ips_blocked(self, mock_getaddrinfo):
        """All resolved IPs in blocked networks -> ChallengeError."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 80)),
        ]

        settings = SimpleNamespace(
            port=80,
            timeout_seconds=10,
            blocked_networks=("10.0.0.0/8",),
            max_response_bytes=1048576,
        )
        validator = Http01Validator(settings=settings)
        with pytest.raises(ChallengeError, match="blocked networks") as exc_info:
            validator.validate(
                token=TOKEN,
                jwk=JWK,
                identifier_type="dns",
                identifier_value=DOMAIN,
            )
        assert exc_info.value.retryable is False

    @patch("acmeeh.challenge.http01.urllib.request.build_opener")
    @patch("acmeeh.challenge.http01.socket.getaddrinfo")
    def test_dns_rebinding_allowed_ips(self, mock_getaddrinfo, mock_build_opener):
        """Some IPs allowed, some blocked -> proceeds with validation."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.1", 80)),
        ]

        _opener_open(mock_build_opener).return_value = _make_response(
            KEY_AUTHZ.encode("utf-8"),
        )

        settings = SimpleNamespace(
            port=80,
            timeout_seconds=10,
            blocked_networks=("10.0.0.0/8",),
            max_response_bytes=1048576,
        )
        validator = Http01Validator(settings=settings)
        # Should not raise because 203.0.113.1 is not blocked
        validator.validate(
            token=TOKEN,
            jwk=JWK,
            identifier_type="dns",
            identifier_value=DOMAIN,
        )

    @patch("acmeeh.challenge.http01.socket.getaddrinfo")
    def test_dns_resolution_failure_is_retryable(self, mock_getaddrinfo):
        """DNS resolution failure during rebinding check -> retryable."""
        mock_getaddrinfo.side_effect = socket.gaierror("Name resolution failed")

        settings = SimpleNamespace(
            port=80,
            timeout_seconds=10,
            blocked_networks=("10.0.0.0/8",),
            max_response_bytes=1048576,
        )
        validator = Http01Validator(settings=settings)
        with pytest.raises(ChallengeError, match="could not resolve") as exc_info:
            validator.validate(
                token=TOKEN,
                jwk=JWK,
                identifier_type="dns",
                identifier_value=DOMAIN,
            )
        assert exc_info.value.retryable is True

    @patch("acmeeh.challenge.http01.urllib.request.build_opener")
    def test_body_with_whitespace_stripped(self, mock_build_opener):
        """Response body with surrounding whitespace should be stripped."""
        _opener_open(mock_build_opener).return_value = _make_response(
            f"  {KEY_AUTHZ}  \n".encode(),
        )

        validator = Http01Validator(settings=None)
        # Should not raise -- body is stripped before comparison
        validator.validate(
            token=TOKEN,
            jwk=JWK,
            identifier_type="dns",
            identifier_value=DOMAIN,
        )

    def test_challenge_type(self):
        """Verify the validator reports the correct challenge type."""
        v = Http01Validator(settings=None)
        assert v.challenge_type == ChallengeType.HTTP_01

    def test_supported_identifier_types(self):
        """HTTP-01 only supports dns identifiers."""
        v = Http01Validator(settings=None)
        assert v.supports_identifier("dns")
        assert not v.supports_identifier("ip")

    @patch("acmeeh.challenge.http01.urllib.request.build_opener")
    def test_no_blocked_networks_skips_rebinding_check(self, mock_build_opener):
        """No blocked_networks configured -> rebinding check skipped."""
        _opener_open(mock_build_opener).return_value = _make_response(
            KEY_AUTHZ.encode("utf-8"),
        )

        settings = SimpleNamespace(
            port=80,
            timeout_seconds=10,
            blocked_networks=(),
            max_response_bytes=1048576,
        )
        validator = Http01Validator(settings=settings)
        # Should work without calling getaddrinfo
        validator.validate(
            token=TOKEN,
            jwk=JWK,
            identifier_type="dns",
            identifier_value=DOMAIN,
        )

    @patch("acmeeh.challenge.http01.urllib.request.build_opener")
    @patch("acmeeh.challenge.http01.socket.getaddrinfo")
    def test_redirect_to_blocked_ip_is_rejected(self, mock_getaddrinfo, mock_build_opener):
        """A redirect to an internal address must be blocked, not followed.

        Regression test: urllib's default HTTPRedirectHandler follows
        redirects transparently, which would let a malicious/compromised
        target bypass the pre-request blocklist check by 3xx-ing to an
        internal address. The opener must be built with
        _RebindingCheckedRedirectHandler so the same blocklist check runs
        on the redirect target before the handler follows it.
        """
        # Initial identifier resolves to an allowed IP; the opener.open call
        # is mocked below so validate() completes without touching the
        # network. We then drive the redirect handler that was actually
        # passed to build_opener() directly, simulating what urllib would do
        # internally when the target responds with a 302.
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.1", 80)),
        ]

        settings = SimpleNamespace(
            port=80,
            timeout_seconds=10,
            blocked_networks=("169.254.0.0/16",),
            max_response_bytes=1048576,
        )
        validator = Http01Validator(settings=settings)

        _opener_open(mock_build_opener).return_value = _make_response(
            KEY_AUTHZ.encode("utf-8"),
        )

        validator.validate(
            token=TOKEN,
            jwk=JWK,
            identifier_type="dns",
            identifier_value=DOMAIN,
        )

        # The handler passed to build_opener() must re-check redirect
        # targets against the blocklist.
        handler = mock_build_opener.call_args[0][0]

        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80)),
        ]
        with pytest.raises(ChallengeError, match="blocked networks"):
            handler.redirect_request(
                MagicMock(),
                None,
                302,
                "Found",
                MagicMock(),
                "http://169.254.169.254/.well-known/acme-challenge/test-token",
            )
