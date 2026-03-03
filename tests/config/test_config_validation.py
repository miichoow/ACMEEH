"""Tests for invalid configuration detection in AcmeehConfig.additional_checks().

Tests cover invalid combinations that should be rejected:
- max_rsa_key_size < min_rsa_key_size
- rate limit rules with window_seconds = 0
- database connection pool misconfigurations
- CA validity day contradictions
- HSM backend without PKCS#11 library
- SMTP enabled without required fields
- Admin API contradictions
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from acmeeh.config.acmeeh_config import _SCHEMA_PATH, AcmeehConfig, ConfigValidationError


def _write_config(tmp_path: Path, overrides: dict | None = None) -> Path:
    """Write a complete valid config, merging *overrides*, return path."""
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
    """Recursively merge overrides into base."""
    for key, value in overrides.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _make_config(tmp_path: Path, overrides: dict | None = None) -> AcmeehConfig:
    path = _write_config(tmp_path, overrides)
    return AcmeehConfig(config_file=path, schema_file=_SCHEMA_PATH)


class TestSecurityValidation:
    """Test security-related config validation."""

    def test_min_rsa_key_size_below_2048_rejected(self, tmp_path):
        """min_rsa_key_size below 2048 should be rejected.

        The JSON schema enforces a minimum of 2048, so schema validation
        raises ValueError before additional_checks() runs.
        """
        with pytest.raises((ConfigValidationError, ValueError), match="2048|min_rsa_key_size"):
            _make_config(
                tmp_path,
                {
                    "security": {"min_rsa_key_size": 1024},
                },
            )

    def test_min_rsa_key_size_at_2048_accepted(self, tmp_path):
        """min_rsa_key_size at 2048 should be accepted."""
        config = _make_config(
            tmp_path,
            {
                "security": {"min_rsa_key_size": 2048},
            },
        )
        assert config.settings.security.min_rsa_key_size == 2048

    def test_nonce_length_below_16_rejected(self, tmp_path):
        """Nonce length below 16 bytes is cryptographically unsafe.

        The JSON schema enforces a minimum of 16, so schema validation
        raises ValueError before additional_checks() runs.
        """
        with pytest.raises((ConfigValidationError, ValueError), match="16|nonce"):
            _make_config(
                tmp_path,
                {
                    "nonce": {"length": 8},
                },
            )


class TestCAValidation:
    """Test CA backend config validation."""

    def test_default_validity_exceeds_max_rejected(self, tmp_path):
        """default_validity_days > max_validity_days should be rejected."""
        with pytest.raises(ConfigValidationError, match="default_validity_days"):
            _make_config(
                tmp_path,
                {
                    "ca": {
                        "default_validity_days": 500,
                        "max_validity_days": 397,
                        "internal": {
                            "root_cert_path": "/tmp/root.pem",
                            "root_key_path": "/tmp/root.key",
                        },
                    },
                },
            )

    def test_internal_backend_without_cert_path_rejected(self, tmp_path):
        """Internal CA backend without root_cert_path should be rejected."""
        with pytest.raises(ConfigValidationError, match="root_cert_path"):
            _make_config(
                tmp_path,
                {
                    "ca": {
                        "backend": "internal",
                        "internal": {
                            "root_cert_path": "",
                            "root_key_path": "/tmp/root.key",
                        },
                    },
                },
            )

    def test_internal_backend_without_key_path_rejected(self, tmp_path):
        """Internal CA backend without root_key_path should be rejected."""
        with pytest.raises(ConfigValidationError, match="root_key_path"):
            _make_config(
                tmp_path,
                {
                    "ca": {
                        "backend": "internal",
                        "internal": {
                            "root_cert_path": "/tmp/root.pem",
                            "root_key_path": "",
                        },
                    },
                },
            )

    def test_hsm_backend_without_pkcs11_library_rejected(self, tmp_path):
        """HSM backend without pkcs11_library should be rejected."""
        with pytest.raises(ConfigValidationError, match="pkcs11_library"):
            _make_config(
                tmp_path,
                {
                    "ca": {
                        "backend": "hsm",
                        "hsm": {
                            "pkcs11_library": "",
                            "token_label": "mytoken",
                            "key_label": "mykey",
                            "issuer_cert_path": "/tmp/issuer.pem",
                            "pin": "1234",
                        },
                    },
                },
            )

    def test_hsm_backend_without_token_or_slot_rejected(self, tmp_path):
        """HSM backend without token_label or slot_id should be rejected."""
        with pytest.raises(ConfigValidationError, match="token_label"):
            _make_config(
                tmp_path,
                {
                    "ca": {
                        "backend": "hsm",
                        "hsm": {
                            "pkcs11_library": "/usr/lib/libpkcs11.so",
                            "key_label": "mykey",
                            "issuer_cert_path": "/tmp/issuer.pem",
                            "pin": "1234",
                        },
                    },
                },
            )

    def test_hsm_backend_without_key_rejected(self, tmp_path):
        """HSM backend without key_label or key_id should be rejected."""
        with pytest.raises(ConfigValidationError, match="key_label"):
            _make_config(
                tmp_path,
                {
                    "ca": {
                        "backend": "hsm",
                        "hsm": {
                            "pkcs11_library": "/usr/lib/libpkcs11.so",
                            "token_label": "mytoken",
                            "issuer_cert_path": "/tmp/issuer.pem",
                            "pin": "1234",
                        },
                    },
                },
            )

    def test_hsm_backend_login_required_without_pin_rejected(self, tmp_path):
        """HSM backend with login_required but no PIN should be rejected."""
        with pytest.raises(ConfigValidationError, match="pin"):
            _make_config(
                tmp_path,
                {
                    "ca": {
                        "backend": "hsm",
                        "hsm": {
                            "pkcs11_library": "/usr/lib/libpkcs11.so",
                            "token_label": "mytoken",
                            "key_label": "mykey",
                            "issuer_cert_path": "/tmp/issuer.pem",
                            "login_required": True,
                            "pin": "",
                        },
                    },
                },
            )

    def test_acme_proxy_without_directory_url_rejected(self, tmp_path):
        """ACME proxy backend without directory_url should be rejected."""
        with pytest.raises(ConfigValidationError, match="directory_url"):
            _make_config(
                tmp_path,
                {
                    "ca": {
                        "backend": "acme_proxy",
                        "acme_proxy": {
                            "directory_url": "",
                            "email": "admin@example.com",
                            "challenge_handler": "my.handler.Class",
                        },
                    },
                },
            )


class TestDatabaseValidation:
    """Test database config validation."""

    def test_min_connections_exceeds_max_rejected(self, tmp_path):
        """min_connections > max_connections should be rejected."""
        with pytest.raises(ConfigValidationError, match="min_connections"):
            _make_config(
                tmp_path,
                {
                    "database": {
                        "database": "acmeeh",
                        "user": "acmeeh",
                        "min_connections": 20,
                        "max_connections": 5,
                    },
                },
            )

    def test_low_max_connections_warns(self, tmp_path, caplog):
        """Low max_connections relative to workers should warn."""
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "server": {
                        "external_url": "https://acme.example.com",
                        "workers": 8,
                    },
                    "database": {
                        "database": "acmeeh",
                        "user": "acmeeh",
                        "max_connections": 5,
                    },
                },
            )
        assert "max_connections" in caplog.text
        assert "low" in caplog.text.lower() or "recommended" in caplog.text.lower()


class TestSmtpValidation:
    """Test SMTP config validation."""

    def test_smtp_enabled_without_host_rejected(self, tmp_path):
        """SMTP enabled without host should be rejected."""
        with pytest.raises(ConfigValidationError, match="smtp.host"):
            _make_config(
                tmp_path,
                {
                    "smtp": {
                        "enabled": True,
                        "host": "",
                        "from_address": "noreply@example.com",
                    },
                },
            )

    def test_smtp_enabled_without_from_address_rejected(self, tmp_path):
        """SMTP enabled without from_address should be rejected."""
        with pytest.raises(ConfigValidationError, match="from_address"):
            _make_config(
                tmp_path,
                {
                    "smtp": {
                        "enabled": True,
                        "host": "smtp.example.com",
                        "from_address": "",
                    },
                },
            )


class TestTosValidation:
    """Test TOS config validation."""

    def test_tos_require_agreement_without_url_rejected(self, tmp_path):
        """Requiring TOS agreement without URL should be rejected."""
        with pytest.raises(ConfigValidationError, match="tos.url"):
            _make_config(
                tmp_path,
                {
                    "tos": {
                        "require_agreement": True,
                    },
                },
            )


class TestAdminApiValidation:
    """Test admin API config validation."""

    def test_admin_enabled_without_email_rejected(self, tmp_path):
        """Admin API enabled without initial_admin_email should be rejected."""
        with pytest.raises(ConfigValidationError, match="initial_admin_email"):
            _make_config(
                tmp_path,
                {
                    "admin_api": {
                        "enabled": True,
                        "token_secret": "super-secret-key-1234",
                        "initial_admin_email": "",
                        "base_path": "/admin",
                    },
                },
            )

    def test_admin_enabled_without_token_secret_rejected(self, tmp_path):
        """Admin API enabled without token_secret should be rejected."""
        with pytest.raises(ConfigValidationError, match="token_secret"):
            _make_config(
                tmp_path,
                {
                    "admin_api": {
                        "enabled": True,
                        "token_secret": "",
                        "initial_admin_email": "admin@example.com",
                        "base_path": "/admin",
                    },
                },
            )

    def test_admin_short_token_secret_rejected(self, tmp_path):
        """Admin API with short token_secret should be rejected."""
        with pytest.raises(ConfigValidationError, match="too short"):
            _make_config(
                tmp_path,
                {
                    "admin_api": {
                        "enabled": True,
                        "token_secret": "short",
                        "initial_admin_email": "admin@example.com",
                        "base_path": "/admin",
                    },
                },
            )

    def test_admin_base_path_collision_rejected(self, tmp_path):
        """Admin base path colliding with ACME base path should be rejected."""
        with pytest.raises(ConfigValidationError, match="collide"):
            _make_config(
                tmp_path,
                {
                    "admin_api": {
                        "enabled": True,
                        "token_secret": "super-secret-key-1234",
                        "initial_admin_email": "admin@example.com",
                        "base_path": "",
                    },
                    "api": {"base_path": ""},
                },
            )


class TestCtLoggingValidation:
    """Test CT logging config validation."""

    def test_ct_enabled_without_logs_rejected(self, tmp_path):
        """CT logging enabled without log servers should be rejected."""
        with pytest.raises(ConfigValidationError, match="ct_logging"):
            _make_config(
                tmp_path,
                {
                    "ct_logging": {
                        "enabled": True,
                        "logs": [],
                    },
                },
            )


class TestChallengeValidation:
    """Test challenge config validation."""

    def test_unknown_challenge_type_rejected(self, tmp_path):
        """Unknown challenge type should be rejected."""
        with pytest.raises(ConfigValidationError, match="unknown type"):
            _make_config(
                tmp_path,
                {
                    "challenges": {
                        "enabled": ["http-01", "bogus-99"],
                    },
                },
            )


class TestServerValidation:
    """Test server config validation."""

    def test_external_url_trailing_slash_rejected(self, tmp_path):
        """external_url with trailing slash should be rejected."""
        with pytest.raises(ConfigValidationError, match="external_url"):
            _make_config(
                tmp_path,
                {
                    "server": {"external_url": "https://acme.example.com/"},
                },
            )


class TestWarnings:
    """Test configuration warnings (non-fatal)."""

    def test_memory_rate_limiter_multi_worker_warns(self, tmp_path, caplog):
        """Memory rate limiter with multiple workers should warn."""
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "server": {
                        "external_url": "https://acme.example.com",
                        "workers": 4,
                    },
                    "security": {
                        "rate_limits": {
                            "enabled": True,
                            "backend": "memory",
                        },
                    },
                },
            )
        assert "rate_limits" in caplog.text.lower() or "rate" in caplog.text.lower()

    def test_notifications_without_smtp_warns(self, tmp_path, caplog):
        """Notifications enabled without SMTP should warn."""
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "notifications": {"enabled": True},
                },
            )
        assert "smtp" in caplog.text.lower()

    def test_crl_with_non_internal_backend_warns(self, tmp_path, caplog):
        """CRL enabled with non-internal backend should warn."""
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "ca": {
                        "backend": "external",
                        "external": {
                            "sign_url": "https://ca.example.com/sign",
                            "revoke_url": "https://ca.example.com/revoke",
                        },
                    },
                    "crl": {"enabled": True},
                },
            )
        assert "crl" in caplog.text.lower()


class TestQuotaValidation:
    """Test quota-related config validation."""

    def test_quotas_defaults(self, tmp_path):
        """Default quota settings: disabled, both limits 0."""
        config = _make_config(tmp_path)
        assert config.settings.quotas.enabled is False
        assert config.settings.quotas.max_certificates_per_account_per_day == 0
        assert config.settings.quotas.max_orders_per_account_per_day == 0

    def test_quotas_custom_values(self, tmp_path):
        """Custom quota values should round-trip."""
        config = _make_config(
            tmp_path,
            {
                "quotas": {
                    "enabled": True,
                    "max_certificates_per_account_per_day": 50,
                    "max_orders_per_account_per_day": 100,
                },
            },
        )
        assert config.settings.quotas.enabled is True
        assert config.settings.quotas.max_certificates_per_account_per_day == 50
        assert config.settings.quotas.max_orders_per_account_per_day == 100

    def test_quotas_enabled_all_zero_warns(self, tmp_path, caplog):
        """Quotas enabled with both limits at 0 should warn."""
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "quotas": {
                        "enabled": True,
                        "max_certificates_per_account_per_day": 0,
                        "max_orders_per_account_per_day": 0,
                    },
                },
            )
        assert "quotas" in caplog.text.lower()
        assert "no effect" in caplog.text.lower()


class TestChallengeBackoffValidation:
    """Test challenge backoff config validation."""

    def test_backoff_defaults(self, tmp_path):
        """Default backoff: base=5, max=300."""
        config = _make_config(tmp_path)
        assert config.settings.challenges.backoff_base_seconds == 5
        assert config.settings.challenges.backoff_max_seconds == 300

    def test_backoff_custom_values(self, tmp_path):
        """Custom backoff values should round-trip."""
        config = _make_config(
            tmp_path,
            {
                "challenges": {
                    "backoff_base_seconds": 10,
                    "backoff_max_seconds": 600,
                },
            },
        )
        assert config.settings.challenges.backoff_base_seconds == 10
        assert config.settings.challenges.backoff_max_seconds == 600

    def test_backoff_base_exceeds_max_rejected(self, tmp_path):
        """backoff_base > backoff_max should be rejected."""
        with pytest.raises(ConfigValidationError, match="backoff_base_seconds"):
            _make_config(
                tmp_path,
                {
                    "challenges": {
                        "backoff_base_seconds": 500,
                        "backoff_max_seconds": 100,
                    },
                },
            )


class TestCircuitBreakerValidation:
    """Test CA circuit breaker config validation."""

    def test_circuit_breaker_defaults(self, tmp_path):
        """Default circuit breaker: threshold=5, timeout=30.0."""
        config = _make_config(tmp_path)
        assert config.settings.ca.circuit_breaker_failure_threshold == 5
        assert config.settings.ca.circuit_breaker_recovery_timeout == 30.0

    def test_circuit_breaker_custom_values(self, tmp_path):
        """Custom circuit breaker values should round-trip."""
        config = _make_config(
            tmp_path,
            {
                "ca": {
                    "circuit_breaker_failure_threshold": 10,
                    "circuit_breaker_recovery_timeout": 60.0,
                    "internal": {
                        "root_cert_path": "/tmp/root.pem",
                        "root_key_path": "/tmp/root.key",
                    },
                },
            },
        )
        assert config.settings.ca.circuit_breaker_failure_threshold == 10
        assert config.settings.ca.circuit_breaker_recovery_timeout == 60.0


class TestSchemaCompleteness:
    """Verify all Part 1 schema gaps are closed — settings fields round-trip."""

    def test_challenge_per_type_auto_validate(self, tmp_path):
        """Per-challenge-type auto_validate fields round-trip."""
        config = _make_config(
            tmp_path,
            {
                "challenges": {
                    "http01": {"auto_validate": False},
                    "dns01": {"auto_validate": True},
                    "tlsalpn01": {"auto_validate": False},
                },
            },
        )
        assert config.settings.challenges.http01.auto_validate is False
        assert config.settings.challenges.dns01.auto_validate is True
        assert config.settings.challenges.tlsalpn01.auto_validate is False

    def test_challenge_retry_after_seconds(self, tmp_path):
        """challenges.retry_after_seconds custom value round-trip."""
        config = _make_config(
            tmp_path,
            {
                "challenges": {"retry_after_seconds": 10},
            },
        )
        assert config.settings.challenges.retry_after_seconds == 10

    def test_order_retry_after_seconds(self, tmp_path):
        """order.retry_after_seconds custom value round-trip."""
        config = _make_config(
            tmp_path,
            {
                "order": {"retry_after_seconds": 5},
            },
        )
        assert config.settings.order.retry_after_seconds == 5

    def test_metrics_auth_required(self, tmp_path):
        """metrics.auth_required True round-trip."""
        config = _make_config(
            tmp_path,
            {
                "metrics": {"auth_required": True},
            },
        )
        assert config.settings.metrics.auth_required is True

    def test_hsts_max_age(self, tmp_path):
        """security.hsts_max_age_seconds custom value round-trip."""
        config = _make_config(
            tmp_path,
            {
                "security": {"hsts_max_age_seconds": 31536000},
            },
        )
        assert config.settings.security.hsts_max_age_seconds == 31536000

    def test_hsts_low_value_warns(self, tmp_path, caplog):
        """HSTS max-age less than 1 day should warn."""
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "security": {"hsts_max_age_seconds": 3600},
                },
            )
        assert "hsts" in caplog.text.lower()
        assert "less than" in caplog.text.lower() or "1 day" in caplog.text.lower()

    def test_audit_rotation_settings(self, tmp_path):
        """Audit log rotation settings round-trip."""
        config = _make_config(
            tmp_path,
            {
                "logging": {
                    "audit": {
                        "max_file_size_bytes": 52428800,
                        "backup_count": 5,
                    },
                },
            },
        )
        assert config.settings.logging.audit.max_file_size_bytes == 52428800
        assert config.settings.logging.audit.backup_count == 5

    def test_http01_max_response_bytes(self, tmp_path):
        """challenges.http01.max_response_bytes custom value round-trip."""
        config = _make_config(
            tmp_path,
            {
                "challenges": {
                    "http01": {"max_response_bytes": 2097152},
                },
            },
        )
        assert config.settings.challenges.http01.max_response_bytes == 2097152

    def test_acme_orders_page_size(self, tmp_path):
        """acme.orders_page_size custom value round-trip."""
        config = _make_config(
            tmp_path,
            {
                "acme": {"orders_page_size": 25},
            },
        )
        assert config.settings.acme.orders_page_size == 25

    def test_retention_cleanup_loop_interval(self, tmp_path):
        """retention.cleanup_loop_interval_seconds custom value round-trip."""
        config = _make_config(
            tmp_path,
            {
                "retention": {"cleanup_loop_interval_seconds": 30},
            },
        )
        assert config.settings.retention.cleanup_loop_interval_seconds == 30

    def test_identifier_policy_max_value_length(self, tmp_path):
        """security.identifier_policy.max_identifier_value_length round-trip."""
        config = _make_config(
            tmp_path,
            {
                "security": {
                    "identifier_policy": {"max_identifier_value_length": 128},
                },
            },
        )
        assert config.settings.security.identifier_policy.max_identifier_value_length == 128


# ===========================================================================
# Additional coverage tests for acmeeh_config.py uncovered lines
# ===========================================================================


class TestGetConfigNotInitialised:
    """Line 77-81: get_config() before AcmeehConfig is created."""

    def test_get_config_raises_runtime_error(self):
        """get_config() should raise RuntimeError when no config exists."""
        from acmeeh.config.acmeeh_config import get_config

        with pytest.raises(RuntimeError, match="Configuration not initialised"):
            get_config()


class TestEabRequiredWithoutAdminApi:
    """eab_required=true without admin_api.enabled should error."""

    def test_eab_required_without_admin_api_raises(self, tmp_path):
        with pytest.raises(ConfigValidationError, match="eab_required.*admin_api"):
            _make_config(
                tmp_path,
                {
                    "acme": {"eab_required": True},
                },
            )

    def test_eab_required_with_admin_api_passes(self, tmp_path):
        """No error when both eab_required and admin_api are enabled."""
        _make_config(
            tmp_path,
            {
                "acme": {"eab_required": True},
                "admin_api": {
                    "enabled": True,
                    "initial_admin_email": "admin@example.com",
                    "token_secret": "super-secret-token-123",
                },
            },
        )


class TestEabReusableWarning:
    """Line 328: eab_reusable without eab_required should warn."""

    def test_eab_reusable_without_required_warns(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "acme": {"eab_reusable": True, "eab_required": False},
                },
            )
        assert "eab_reusable" in caplog.text


class TestMxValidationWarning:
    """Line 391: validate_mx without resolvers should warn."""

    def test_mx_validate_without_resolvers_warns(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "email": {"validate_mx": True},
                    "dns": {"resolvers": []},
                },
            )
        assert "validate_mx" in caplog.text.lower() or "mx" in caplog.text.lower()


class TestHookClassPathValidation:
    """Line 408: invalid hook class path should error."""

    def test_invalid_hook_class_path_rejected(self, tmp_path):
        """Schema or additional_checks rejects bad class paths."""
        with pytest.raises((ConfigValidationError, ValueError)):
            _make_config(
                tmp_path,
                {
                    "hooks": {
                        "registered": [
                            {"class": "not a valid path!", "enabled": True},
                        ],
                    },
                },
            )


class TestHookUnknownEvent:
    """Line 415: unknown hook event should error."""

    def test_unknown_hook_event_rejected(self, tmp_path):
        """Schema or additional_checks rejects unknown events."""
        with pytest.raises((ConfigValidationError, ValueError)):
            _make_config(
                tmp_path,
                {
                    "hooks": {
                        "registered": [
                            {
                                "class": "some.valid.ClassName",
                                "enabled": True,
                                "events": ["totally.bogus.event"],
                            },
                        ],
                    },
                },
            )


class TestHookTimeoutWarning:
    """Line 399: hook timeout exceeding server timeout should warn."""

    def test_hook_timeout_exceeds_server_warns(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "server": {
                        "external_url": "https://acme.example.com",
                        "timeout": 30,
                    },
                    "hooks": {"timeout_seconds": 60},
                },
            )
        assert "timeout" in caplog.text.lower()


class TestConfigRepr:
    """Lines 595-596: __repr__ method."""

    def test_repr_contains_config_file(self, tmp_path):
        config = _make_config(tmp_path)
        r = repr(config)
        assert "AcmeehConfig" in r
        assert "config_file=" in r


class TestConfigReload:
    """Lines 574-575, 581: reload_settings method."""

    def test_reload_without_source_raises(self, tmp_path):
        """Reload without _source recorded should raise RuntimeError."""
        config = _make_config(tmp_path)
        with pytest.raises(RuntimeError, match="Cannot reload"):
            config.reload_settings()

    def test_reload_yaml_file(self, tmp_path):
        """Reload from a YAML config file returns fresh settings."""
        path = _write_config(tmp_path)
        config = AcmeehConfig(config_file=path, schema_file=_SCHEMA_PATH)
        # Manually set _source so reload can find the file
        config._data["_source"] = str(path)
        settings = config.reload_settings()
        assert settings.server.external_url == "https://acme.example.com"

    def test_reload_json_file(self, tmp_path):
        """Reload from a JSON config file (non-.yaml extension)."""
        import json as _json

        cfg = {
            "server": {"external_url": "https://acme.example.com"},
            "database": {"database": "acmeeh", "user": "acmeeh"},
            "ca": {
                "internal": {
                    "root_cert_path": "/tmp/root.pem",
                    "root_key_path": "/tmp/root.key",
                },
            },
        }
        json_path = tmp_path / "config.json"
        json_path.write_text(_json.dumps(cfg), encoding="utf-8")
        config = AcmeehConfig(config_file=json_path, schema_file=_SCHEMA_PATH)
        # Manually set _source to the JSON path
        config._data["_source"] = str(json_path)
        settings = config.reload_settings()
        assert settings.server.external_url == "https://acme.example.com"
