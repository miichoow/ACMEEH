"""Tests for acme_proxy configuration: schema, settings, and validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import ValidationError, validate

from acmeeh.config.acmeeh_config import AcmeehConfig, ConfigValidationError
from acmeeh.config.settings import AcmeProxySettings, build_settings

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent / "src" / "acmeeh" / "config" / "schema.json"
)


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _minimal_config(**ca_overrides) -> dict:
    """Return a minimal valid config with CA section overrides."""
    ca = {
        "backend": "acme_proxy",
        "acme_proxy": {
            "directory_url": "https://acme.upstream.example/directory",
            "email": "admin@example.com",
            "challenge_handler": "callback_dns",
        },
    }
    ca.update(ca_overrides)
    return {
        "server": {"external_url": "https://acme.example.com"},
        "database": {"database": "acmeeh", "user": "acmeeh"},
        "ca": ca,
    }


# ---------------------------------------------------------------------------
# JSON Schema tests
# ---------------------------------------------------------------------------


class TestSchemaValidation:
    def test_valid_acme_proxy_config(self, schema):
        cfg = _minimal_config()
        validate(instance=cfg, schema=schema)

    def test_full_acme_proxy_config(self, schema):
        cfg = _minimal_config(
            acme_proxy={
                "directory_url": "https://acme.upstream.example/directory",
                "email": "admin@example.com",
                "storage_path": "/var/lib/acmeeh/upstream",
                "challenge_type": "dns-01",
                "challenge_handler": "callback_dns",
                "challenge_handler_config": {
                    "create_script": "/bin/create.sh",
                    "delete_script": "/bin/delete.sh",
                },
                "eab_kid": "kid123",
                "eab_hmac_key": "hmackey",
                "proxy_url": "http://proxy:3128",
                "verify_ssl": False,
                "timeout_seconds": 600,
            }
        )
        validate(instance=cfg, schema=schema)

    def test_invalid_challenge_type(self, schema):
        cfg = _minimal_config(
            acme_proxy={
                "directory_url": "https://example.com",
                "email": "admin@example.com",
                "challenge_handler": "callback_dns",
                "challenge_type": "invalid-type",
            }
        )
        with pytest.raises(ValidationError):
            validate(instance=cfg, schema=schema)

    def test_http01_challenge_type_valid(self, schema):
        cfg = _minimal_config(
            acme_proxy={
                "directory_url": "https://example.com",
                "email": "admin@example.com",
                "challenge_handler": "callback_dns",
                "challenge_type": "http-01",
            }
        )
        validate(instance=cfg, schema=schema)

    def test_no_additional_properties(self, schema):
        cfg = _minimal_config(
            acme_proxy={
                "directory_url": "https://example.com",
                "email": "admin@example.com",
                "challenge_handler": "callback_dns",
                "unknown_field": True,
            }
        )
        with pytest.raises(ValidationError, match="additionalProperties"):
            validate(instance=cfg, schema=schema)

    def test_timeout_must_be_positive(self, schema):
        cfg = _minimal_config(
            acme_proxy={
                "directory_url": "https://example.com",
                "email": "admin@example.com",
                "challenge_handler": "callback_dns",
                "timeout_seconds": 0,
            }
        )
        with pytest.raises(ValidationError, match="minimum"):
            validate(instance=cfg, schema=schema)


# ---------------------------------------------------------------------------
# Settings dataclass tests
# ---------------------------------------------------------------------------


class TestSettingsBuilding:
    def test_build_acme_proxy_settings_defaults(self):
        data = {
            "server": {"external_url": "https://acme.example.com"},
            "database": {"database": "acmeeh", "user": "acmeeh"},
            "ca": {},
        }
        settings = build_settings(data)
        proxy = settings.ca.acme_proxy

        assert isinstance(proxy, AcmeProxySettings)
        assert proxy.directory_url == ""
        assert proxy.email == ""
        assert proxy.storage_path == "./acme_proxy_storage"
        assert proxy.challenge_type == "dns-01"
        assert proxy.challenge_handler == ""
        assert proxy.challenge_handler_config == {}
        assert proxy.eab_kid is None
        assert proxy.eab_hmac_key is None
        assert proxy.proxy_url is None
        assert proxy.verify_ssl is True
        assert proxy.timeout_seconds == 300

    def test_build_acme_proxy_settings_custom(self):
        data = {
            "server": {"external_url": "https://acme.example.com"},
            "database": {"database": "acmeeh", "user": "acmeeh"},
            "ca": {
                "acme_proxy": {
                    "directory_url": "https://upstream.example/dir",
                    "email": "ops@example.com",
                    "storage_path": "/custom/path",
                    "challenge_type": "http-01",
                    "challenge_handler": "file_http",
                    "challenge_handler_config": {"webroot": "/var/www"},
                    "eab_kid": "myKid",
                    "eab_hmac_key": "myKey",
                    "proxy_url": "http://proxy:8080",
                    "verify_ssl": False,
                    "timeout_seconds": 600,
                }
            },
        }
        settings = build_settings(data)
        proxy = settings.ca.acme_proxy

        assert proxy.directory_url == "https://upstream.example/dir"
        assert proxy.email == "ops@example.com"
        assert proxy.storage_path == "/custom/path"
        assert proxy.challenge_type == "http-01"
        assert proxy.challenge_handler == "file_http"
        assert proxy.challenge_handler_config == {"webroot": "/var/www"}
        assert proxy.eab_kid == "myKid"
        assert proxy.eab_hmac_key == "myKey"
        assert proxy.proxy_url == "http://proxy:8080"
        assert proxy.verify_ssl is False
        assert proxy.timeout_seconds == 600

    def test_acme_proxy_settings_frozen(self):
        data = {
            "server": {"external_url": "https://acme.example.com"},
            "database": {"database": "acmeeh", "user": "acmeeh"},
            "ca": {},
        }
        settings = build_settings(data)
        proxy = settings.ca.acme_proxy

        with pytest.raises(AttributeError):
            proxy.directory_url = "changed"


# ---------------------------------------------------------------------------
# Cross-field validation (additional_checks) tests
# ---------------------------------------------------------------------------


class TestAdditionalChecks:
    def test_proxy_backend_valid(self, tmp_path):
        cfg = _minimal_config()
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="unused")
        assert config.settings.ca.backend == "acme_proxy"

    def test_proxy_missing_directory_url(self, tmp_path):
        cfg = _minimal_config(
            acme_proxy={
                "directory_url": "",
                "email": "admin@example.com",
                "challenge_handler": "callback_dns",
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        with pytest.raises(ConfigValidationError, match="directory_url"):
            AcmeehConfig(config_file=str(cfg_path), schema_file="unused")

    def test_proxy_missing_email(self, tmp_path):
        cfg = _minimal_config(
            acme_proxy={
                "directory_url": "https://acme.upstream.example/directory",
                "email": "",
                "challenge_handler": "callback_dns",
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        with pytest.raises(ConfigValidationError, match="email"):
            AcmeehConfig(config_file=str(cfg_path), schema_file="unused")

    def test_proxy_missing_challenge_handler(self, tmp_path):
        cfg = _minimal_config(
            acme_proxy={
                "directory_url": "https://acme.upstream.example/directory",
                "email": "admin@example.com",
                "challenge_handler": "",
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        with pytest.raises(ConfigValidationError, match="challenge_handler"):
            AcmeehConfig(config_file=str(cfg_path), schema_file="unused")

    def test_proxy_all_missing_collects_all_errors(self, tmp_path):
        cfg = _minimal_config(
            acme_proxy={
                "directory_url": "",
                "email": "",
                "challenge_handler": "",
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        with pytest.raises(ConfigValidationError) as exc_info:
            AcmeehConfig(config_file=str(cfg_path), schema_file="unused")
        errors = exc_info.value.errors
        assert len(errors) == 3
        assert any("directory_url" in e for e in errors)
        assert any("email" in e for e in errors)
        assert any("challenge_handler" in e for e in errors)

    def test_auto_accept_with_standard_types(self, tmp_path):
        cfg = _minimal_config()
        cfg["challenges"] = {
            "enabled": ["http-01", "dns-01", "tls-alpn-01"],
            "auto_accept": True,
        }
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="unused")
        assert config.settings.challenges.auto_accept is True
        assert "http-01" in config.settings.challenges.enabled
        assert "dns-01" in config.settings.challenges.enabled
        assert "tls-alpn-01" in config.settings.challenges.enabled
