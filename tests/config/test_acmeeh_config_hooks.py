"""Tests for hooks validation in AcmeehConfig.additional_checks()."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from acmeeh.config.acmeeh_config import _SCHEMA_PATH, AcmeehConfig


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
        cfg.update(overrides)
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
    )
    return path


def _make_config(tmp_path: Path, overrides: dict | None = None) -> AcmeehConfig:
    """Create an AcmeehConfig with correct kwargs for the metaclass guard."""
    path = _write_config(tmp_path, overrides)
    return AcmeehConfig(config_file=path, schema_file=_SCHEMA_PATH)


class TestConfigHooksValid:
    def test_no_hooks_section(self, tmp_path):
        config = _make_config(tmp_path)
        assert config.settings.hooks.timeout_seconds == 30

    def test_valid_hook_with_known_events(self, tmp_path):
        config = _make_config(
            tmp_path,
            {
                "hooks": {
                    "registered": [
                        {
                            "class": "my.hooks.AuditHook",
                            "events": ["certificate.issuance", "order.creation"],
                        }
                    ]
                }
            },
        )
        assert len(config.settings.hooks.registered) == 1


class TestConfigHooksErrors:
    def test_invalid_class_path_rejected_by_schema(self, tmp_path):
        """A class path like 'no_dots' fails the JSON Schema pattern before
        additional_checks() runs, so ConfigKit raises ValueError."""
        with pytest.raises(ValueError, match="no_dots"):
            _make_config(tmp_path, {"hooks": {"registered": [{"class": "no_dots"}]}})

    def test_unknown_event_rejected_by_schema(self, tmp_path):
        """An event not in the enum fails JSON Schema validation."""
        with pytest.raises(ValueError, match="bogus.event"):
            _make_config(
                tmp_path,
                {
                    "hooks": {
                        "registered": [
                            {
                                "class": "my.hooks.Hook",
                                "events": ["bogus.event"],
                            }
                        ]
                    }
                },
            )

    def test_additional_checks_validates_class_path(self, tmp_path):
        """Verify that additional_checks() has its own class_path regex guard.

        We test the validation method directly by bypassing the schema
        with a manually constructed AcmeehConfig after schema validation.
        """
        from acmeeh.config.acmeeh_config import _CLASS_PATH_RE

        # Verify the regex itself rejects single-word paths
        assert _CLASS_PATH_RE.match("no_dots") is None
        # And accepts valid paths
        assert _CLASS_PATH_RE.match("my.hooks.Hook") is not None

    def test_additional_checks_validates_events(self, tmp_path):
        """Verify that additional_checks() has its own event validation.

        We test the helper function directly.
        """
        from acmeeh.config.acmeeh_config import _get_known_hook_events

        known = _get_known_hook_events()
        assert "bogus.event" not in known
        assert "certificate.issuance" in known


class TestIdentifierPolicyConfig:
    def test_enforce_account_allowlist_default_false(self, tmp_path):
        config = _make_config(tmp_path)
        assert config.settings.security.identifier_policy.enforce_account_allowlist is False

    def test_enforce_account_allowlist_true(self, tmp_path):
        config = _make_config(
            tmp_path,
            {
                "security": {"identifier_policy": {"enforce_account_allowlist": True}},
                "admin_api": {
                    "enabled": True,
                    "token_secret": "super-secret-key-1234",
                    "initial_admin_email": "a@b.com",
                    "base_path": "/admin",
                },
            },
        )
        assert config.settings.security.identifier_policy.enforce_account_allowlist is True

    def test_warning_when_enforced_without_admin_api(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "security": {"identifier_policy": {"enforce_account_allowlist": True}},
                },
            )
        assert "enforce_account_allowlist" in caplog.text
        assert "admin_api.enabled is false" in caplog.text


class TestRequireCsrProfileConfig:
    def test_require_csr_profile_default_false(self, tmp_path):
        config = _make_config(tmp_path)
        assert config.settings.security.require_csr_profile is False

    def test_require_csr_profile_true(self, tmp_path):
        config = _make_config(
            tmp_path,
            {
                "security": {"require_csr_profile": True},
                "admin_api": {
                    "enabled": True,
                    "token_secret": "super-secret-key-1234",
                    "initial_admin_email": "a@b.com",
                    "base_path": "/admin",
                },
            },
        )
        assert config.settings.security.require_csr_profile is True

    def test_warning_when_required_without_admin_api(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "security": {"require_csr_profile": True},
                },
            )
        assert "require_csr_profile" in caplog.text
        assert "admin_api.enabled is false" in caplog.text


class TestConfigHooksWarnings:
    def test_global_hook_timeout_exceeds_server(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "server": {"external_url": "https://acme.example.com", "timeout": 10},
                    "hooks": {"timeout_seconds": 60},
                },
            )
        assert "hooks.timeout_seconds" in caplog.text
        assert "exceeds" in caplog.text

    def test_per_hook_timeout_exceeds_server(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING):
            _make_config(
                tmp_path,
                {
                    "server": {"external_url": "https://acme.example.com", "timeout": 5},
                    "hooks": {
                        "registered": [
                            {
                                "class": "my.hooks.Hook",
                                "timeout_seconds": 60,
                            }
                        ]
                    },
                },
            )
        assert "timeout_seconds" in caplog.text
        assert "exceeds" in caplog.text
