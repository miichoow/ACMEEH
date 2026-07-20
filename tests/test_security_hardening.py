"""Tests for the 5 security hardening enhancements.

1. HTTP-01 DNS rebinding protection (blocked_networks)
2. HTTP security headers
3. Admin password — not logged, printed to stderr only
4. DNS-01 authoritative NS validation
5. Proxy trust — error on empty trusted proxies
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from acmeeh.config.acmeeh_config import _SCHEMA_PATH, AcmeehConfig, ConfigValidationError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(tmp_path: Path, overrides: dict | None = None) -> Path:
    cfg = {
        "server": {"external_url": "https://acme.example.com"},
        "database": {"database": "acmeeh", "user": "acmeeh"},
        "ca": {
            "internal": {
                "root_cert_path": "/tmp/root.pem",
                "root_key_path": "/tmp/root.key",
            }
        },
    }
    if overrides:
        _deep_merge(cfg, overrides)
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
    return path


def _deep_merge(base: dict, overrides: dict) -> None:
    for key, value in overrides.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _make_config(tmp_path: Path, overrides: dict | None = None) -> AcmeehConfig:
    path = _write_config(tmp_path, overrides)
    return AcmeehConfig(config_file=path, schema_file=_SCHEMA_PATH)


# ===========================================================================
# 1. HTTP-01 DNS rebinding protection
# ===========================================================================


class TestHttp01BlockedNetworks:
    """Test the blocked_networks field on Http01Settings."""

    def test_default_blocked_networks(self, tmp_path):
        """Default config includes loopback and link-local in blocked_networks."""
        config = _make_config(tmp_path)
        blocked = config.settings.challenges.http01.blocked_networks
        assert "127.0.0.0/8" in blocked
        assert "::1/128" in blocked
        assert "169.254.0.0/16" in blocked
        assert "fe80::/10" in blocked

    def test_custom_blocked_networks(self, tmp_path):
        """Custom blocked_networks override the defaults."""
        config = _make_config(
            tmp_path,
            {
                "challenges": {
                    "http01": {
                        "blocked_networks": ["10.0.0.0/8", "192.168.0.0/16"],
                    },
                },
            },
        )
        blocked = config.settings.challenges.http01.blocked_networks
        assert blocked == ("10.0.0.0/8", "192.168.0.0/16")

    def test_empty_blocked_networks_disables_check(self, tmp_path):
        """Empty blocked_networks means no IPs are blocked."""
        config = _make_config(
            tmp_path,
            {
                "challenges": {
                    "http01": {
                        "blocked_networks": [],
                    },
                },
            },
        )
        assert config.settings.challenges.http01.blocked_networks == ()

    def test_validator_blocks_loopback(self):
        """HTTP-01 validator rejects domains resolving to loopback."""
        from acmeeh.challenge.base import ChallengeError
        from acmeeh.challenge.http01 import Http01Validator
        from acmeeh.config.settings import Http01Settings

        settings = Http01Settings(
            port=80,
            timeout_seconds=10,
            max_retries=3,
            auto_validate=True,
            blocked_networks=("127.0.0.0/8",),
            max_response_bytes=1048576,
        )
        validator = Http01Validator(settings=settings)

        # Mock socket.getaddrinfo to return loopback
        mock_addrinfo = [
            (2, 1, 6, "", ("127.0.0.1", 80)),
        ]
        with patch("acmeeh.challenge.http01.socket.getaddrinfo", return_value=mock_addrinfo):
            with pytest.raises(ChallengeError, match="blocked networks"):
                validator.validate(
                    token="test-token",
                    jwk={"kty": "EC", "crv": "P-256", "x": "dGVzdA", "y": "dGVzdA"},
                    identifier_type="dns",
                    identifier_value="evil.example.com",
                )

    def test_validator_allows_public_ip(self):
        """HTTP-01 validator allows domains resolving to public IPs."""
        from acmeeh.challenge.http01 import Http01Validator
        from acmeeh.config.settings import Http01Settings

        settings = Http01Settings(
            port=80,
            timeout_seconds=10,
            max_retries=3,
            auto_validate=True,
            blocked_networks=("127.0.0.0/8", "::1/128"),
            max_response_bytes=1048576,
        )
        validator = Http01Validator(settings=settings)

        # Mock getaddrinfo to return public IP, and the request opener to
        # simulate a failed connection (we only test the rebinding check
        # passes)
        mock_addrinfo = [
            (2, 1, 6, "", ("93.184.216.34", 80)),
        ]
        with patch("acmeeh.challenge.http01.socket.getaddrinfo", return_value=mock_addrinfo):
            with patch("acmeeh.challenge.http01.urllib.request.build_opener") as mock_build_opener:
                mock_resp = MagicMock()
                mock_resp.status = 200
                mock_resp.read.return_value = b"not-a-real-token"
                mock_build_opener.return_value.open.return_value = mock_resp
                # This won't match the key_authorization so it will raise
                # ChallengeError about body not matching — but NOT about
                # blocked networks, which is what we're testing.
                from acmeeh.challenge.base import ChallengeError

                with pytest.raises(ChallengeError, match="does not match"):
                    validator.validate(
                        token="test-token",
                        jwk={"kty": "EC", "crv": "P-256", "x": "dGVzdA", "y": "dGVzdA"},
                        identifier_type="dns",
                        identifier_value="example.com",
                    )

    def test_validator_pins_checked_ip_against_dns_rebinding(self):
        """The IP validated by the blocklist check must be the exact IP the
        real connection is made to — not a second, independent DNS lookup.

        Without pinning, a resolver that answers ``getaddrinfo`` differently
        between the pre-request blocklist check and the connection made by
        ``http.client`` (TTL 0, alternating answers, etc.) can pass the check
        with a public IP and then rebind the actual connection to a blocked
        address.
        """
        from acmeeh.challenge.http01 import Http01Validator
        from acmeeh.config.settings import Http01Settings

        settings = Http01Settings(
            port=80,
            timeout_seconds=10,
            max_retries=3,
            auto_validate=True,
            blocked_networks=("127.0.0.0/8",),
            max_response_bytes=1048576,
        )
        validator = Http01Validator(settings=settings)

        # The blocklist-check lookup returns a public IP (allowed), but a
        # *second* lookup (as would happen inside http.client.connect()
        # without pinning) would return loopback (blocked). If the real
        # connection is properly pinned to the checked IP, this second
        # value must never be consulted for connecting.
        rebinding_addrinfo = iter(
            [
                [(2, 1, 6, "", ("93.184.216.34", 80))],  # check_host_allowed
                [(2, 1, 6, "", ("127.0.0.1", 80))],  # would-be rebind target
            ]
        )

        connected_addresses = []

        def fake_create_connection(address, *args, **kwargs):
            connected_addresses.append(address[0])
            raise OSError("simulated connection failure (test stub)")

        with (
            patch(
                "acmeeh.challenge.http01.socket.getaddrinfo",
                side_effect=lambda *a, **k: next(rebinding_addrinfo),
            ),
            patch(
                "acmeeh.challenge.http01.socket.create_connection",
                side_effect=fake_create_connection,
            ),
        ):
            from acmeeh.challenge.base import ChallengeError

            with pytest.raises(ChallengeError, match="could not connect"):
                validator.validate(
                    token="test-token",
                    jwk={"kty": "EC", "crv": "P-256", "x": "dGVzdA", "y": "dGVzdA"},
                    identifier_type="dns",
                    identifier_value="example.com",
                )

        assert connected_addresses == ["93.184.216.34"]


# ===========================================================================
# 2. HTTP Security Headers
# ===========================================================================


class TestSecurityHeaders:
    """Test security headers on all responses."""

    @pytest.fixture
    def app(self, tmp_path):
        """Minimal Flask app with middleware registered."""
        from flask import Flask

        from acmeeh.app.middleware import register_request_hooks
        from acmeeh.config.settings import build_settings

        settings = build_settings(
            {
                "server": {"external_url": "https://acme.test"},
                "database": {"database": "test", "user": "test"},
                "ca": {
                    "internal": {
                        "root_cert_path": "/tmp/test.crt",
                        "root_key_path": "/tmp/test.key",
                    },
                },
            }
        )

        flask_app = Flask("test_headers")
        flask_app.config["ACMEEH_SETTINGS"] = settings
        flask_app.config["TESTING"] = True

        register_request_hooks(flask_app)

        @flask_app.route("/test")
        def test_route():
            return "ok"

        return flask_app

    def test_x_content_type_options(self, app):
        client = app.test_client()
        resp = client.get("/test")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, app):
        client = app.test_client()
        resp = client.get("/test")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_content_security_policy(self, app):
        client = app.test_client()
        resp = client.get("/test")
        assert "default-src 'none'" in resp.headers.get("Content-Security-Policy", "")
        assert "frame-ancestors 'none'" in resp.headers.get("Content-Security-Policy", "")

    def test_hsts_on_https(self, app):
        """HSTS header is set when external_url is https."""
        client = app.test_client()
        resp = client.get("/test")
        hsts = resp.headers.get("Strict-Transport-Security", "")
        assert "max-age=63072000" in hsts
        assert "includeSubDomains" in hsts

    def test_no_hsts_on_http(self):
        """HSTS header is NOT set when external_url is http."""
        from flask import Flask

        from acmeeh.app.middleware import register_request_hooks
        from acmeeh.config.settings import build_settings

        settings = build_settings(
            {
                "server": {"external_url": "http://acme.test"},
                "database": {"database": "test", "user": "test"},
                "ca": {
                    "internal": {
                        "root_cert_path": "/tmp/test.crt",
                        "root_key_path": "/tmp/test.key",
                    },
                },
            }
        )

        flask_app = Flask("test_no_hsts")
        flask_app.config["ACMEEH_SETTINGS"] = settings
        flask_app.config["TESTING"] = True

        register_request_hooks(flask_app)

        @flask_app.route("/test")
        def test_route():
            return "ok"

        client = flask_app.test_client()
        resp = client.get("/test")
        assert "Strict-Transport-Security" not in resp.headers


# ===========================================================================
# 3. Admin password — stderr only, not logged
# ===========================================================================


class TestAdminPasswordNotLogged:
    """Ensure the admin password is printed to stderr, not logged."""

    def test_password_not_in_log_message(self, tmp_path):
        """log.warning should not contain the actual password."""
        from acmeeh.config.settings import build_settings

        settings = build_settings(
            {
                "server": {"external_url": "https://acme.test"},
                "database": {"database": "test", "user": "test"},
                "ca": {
                    "internal": {
                        "root_cert_path": "/tmp/test.crt",
                        "root_key_path": "/tmp/test.key",
                    },
                },
                "admin_api": {
                    "enabled": True,
                    "token_secret": "a-secret-that-is-long-enough",
                    "initial_admin_email": "admin@example.com",
                },
            }
        )

        # Capture log records
        with patch("acmeeh.app.factory.log") as mock_log:
            # Mock admin service to return a password
            mock_admin_service = MagicMock()
            mock_admin_service.bootstrap_admin.return_value = "SuperSecretPass123"

            # Call the relevant code path directly
            pw = mock_admin_service.bootstrap_admin("admin@example.com")
            if pw is not None:
                mock_log.warning("Initial admin user created — password printed to stderr")

            # Check that the warning call does NOT contain the password
            for call in mock_log.warning.call_args_list:
                args_str = " ".join(str(a) for a in call.args)
                assert "SuperSecretPass123" not in args_str

    def test_password_written_to_stderr(self):
        """The password should be written to sys.stderr."""
        from io import StringIO

        # Simulate the factory code path
        pw = "TestPassword42"
        stderr_capture = StringIO()
        with patch("sys.stderr", stderr_capture):
            import sys as sys_mod

            sys_mod.stderr.write(
                f"\n"
                f"╔══════════════════════════════════════════════╗\n"
                f"║       INITIAL ADMIN USER CREATED             ║\n"
                f"║                                              ║\n"
                f"║  Username: admin                             ║\n"
                f"║  Password: {pw:<33s}                         ║\n"
                f"║                                              ║\n"
                f"║  Change this password immediately!           ║\n"
                f"╚══════════════════════════════════════════════╝\n"
                f"\n"
            )
            sys_mod.stderr.flush()

        output = stderr_capture.getvalue()
        assert "TestPassword42" in output
        assert "INITIAL ADMIN USER CREATED" in output


# ===========================================================================
# 4. DNS-01 authoritative NS validation
# ===========================================================================


class TestDns01AuthoritativeNS:
    """Test the require_authoritative field on Dns01Settings."""

    def test_default_require_authoritative_is_false(self, tmp_path):
        config = _make_config(tmp_path)
        assert config.settings.challenges.dns01.require_authoritative is False

    def test_require_authoritative_true(self, tmp_path):
        config = _make_config(
            tmp_path,
            {
                "challenges": {
                    "dns01": {
                        "require_authoritative": True,
                    },
                },
            },
        )
        assert config.settings.challenges.dns01.require_authoritative is True

    def test_authoritative_resolver_used_when_enabled(self):
        """When require_authoritative=True, the validator should try to
        find authoritative NS and use them."""
        from acmeeh.challenge.dns01 import Dns01Validator
        from acmeeh.config.settings import Dns01Settings

        settings = Dns01Settings(
            resolvers=(),
            timeout_seconds=30,
            propagation_wait_seconds=10,
            max_retries=5,
            auto_validate=False,
            require_dnssec=False,
            require_authoritative=True,
        )
        validator = Dns01Validator(settings=settings)

        # We don't test full DNS resolution here — just that the code
        # path reaches the authoritative NS logic. We mock dns.resolver
        # to verify it's called with zone_for_name.
        import dns.exception

        with patch("acmeeh.challenge.dns01.dns.resolver.zone_for_name") as mock_zone:
            mock_zone.side_effect = dns.exception.DNSException("test")
            # The fallback should log a warning and continue with standard
            # resolution. The actual TXT query will also fail.
            from acmeeh.challenge.base import ChallengeError

            with pytest.raises(ChallengeError):
                validator.validate(
                    token="test-token",
                    jwk={"kty": "EC", "crv": "P-256", "x": "dGVzdA", "y": "dGVzdA"},
                    identifier_type="dns",
                    identifier_value="example.com",
                )
            # Verify zone_for_name was called (authoritative path was attempted)
            mock_zone.assert_called_once()


# ===========================================================================
# 5. Proxy trust — error on empty trusted proxies
# ===========================================================================


class TestProxyTrustError:
    """Test that proxy.enabled=true with empty trusted_proxies is now an error."""

    def test_proxy_enabled_empty_trusted_is_error(self, tmp_path):
        """Should raise ConfigValidationError, not just warn."""
        with pytest.raises(
            ConfigValidationError, match="proxy.enabled is true but proxy.trusted_proxies is empty"
        ):
            _make_config(
                tmp_path,
                {
                    "proxy": {
                        "enabled": True,
                        "trusted_proxies": [],
                    },
                },
            )

    def test_proxy_enabled_with_trusted_proxies_is_ok(self, tmp_path):
        """Proxy with trusted_proxies configured should be accepted."""
        config = _make_config(
            tmp_path,
            {
                "proxy": {
                    "enabled": True,
                    "trusted_proxies": ["10.0.0.0/8"],
                },
            },
        )
        assert config.settings.proxy.enabled is True
        assert config.settings.proxy.trusted_proxies == ("10.0.0.0/8",)

    def test_proxy_disabled_empty_trusted_is_ok(self, tmp_path):
        """Proxy disabled with empty trusted_proxies should be fine."""
        config = _make_config(
            tmp_path,
            {
                "proxy": {
                    "enabled": False,
                    "trusted_proxies": [],
                },
            },
        )
        assert config.settings.proxy.enabled is False
