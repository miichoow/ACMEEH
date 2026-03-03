"""Comprehensive unit tests for acmeeh.ca.registry (load_ca_backend, etc.)."""

from __future__ import annotations

import types
from unittest.mock import MagicMock, patch

import pytest

from acmeeh.ca.base import CABackend, CAError
from acmeeh.ca.registry import (
    _BUILTIN_BACKENDS,
    _load_external,
    _validate_class,
    load_ca_backend,
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


def _make_ca_settings(backend: str = "internal") -> CASettings:
    return CASettings(
        backend=backend,
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
            serial_source="random",
            hash_algorithm="sha256",
        ),
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


class _ConcreteBackend(CABackend):
    """A concrete CABackend for testing registry validation."""

    def sign(self, csr, *, profile, validity_days, serial_number=None, ct_submitter=None):
        pass

    def revoke(self, *, serial_number, certificate_pem, reason=None):
        pass


class _IncompleteBackend(CABackend):
    """A backend that does not implement sign/revoke (abstract methods)."""

    pass


class _NotABackend:
    """A class that is NOT a CABackend subclass."""

    def sign(self):
        pass

    def revoke(self):
        pass


# ---------------------------------------------------------------------------
# Tests: load_ca_backend with builtin names
# ---------------------------------------------------------------------------


class TestLoadBuiltinBackend:
    """Tests for loading built-in CA backends."""

    @patch("acmeeh.ca.registry.importlib.import_module")
    def test_load_internal_backend(self, mock_import: MagicMock) -> None:
        """Loading 'internal' should import acmeeh.ca.internal."""
        fake_module = types.ModuleType("acmeeh.ca.internal")
        fake_module.InternalCABackend = _ConcreteBackend  # type: ignore[attr-defined]
        mock_import.return_value = fake_module

        settings = _make_ca_settings("internal")
        backend = load_ca_backend(settings)

        mock_import.assert_called_once_with("acmeeh.ca.internal")
        assert isinstance(backend, CABackend)

    @patch("acmeeh.ca.registry.importlib.import_module")
    def test_load_external_backend(self, mock_import: MagicMock) -> None:
        fake_module = types.ModuleType("acmeeh.ca.external")
        fake_module.ExternalCABackend = _ConcreteBackend  # type: ignore[attr-defined]
        mock_import.return_value = fake_module

        settings = _make_ca_settings("external")
        backend = load_ca_backend(settings)

        mock_import.assert_called_once_with("acmeeh.ca.external")
        assert isinstance(backend, CABackend)

    @patch("acmeeh.ca.registry.importlib.import_module")
    def test_load_hsm_backend(self, mock_import: MagicMock) -> None:
        fake_module = types.ModuleType("acmeeh.ca.hsm")
        fake_module.HsmCABackend = _ConcreteBackend  # type: ignore[attr-defined]
        mock_import.return_value = fake_module

        settings = _make_ca_settings("hsm")
        backend = load_ca_backend(settings)

        mock_import.assert_called_once_with("acmeeh.ca.hsm")
        assert isinstance(backend, CABackend)

    @patch("acmeeh.ca.registry.importlib.import_module")
    def test_load_acme_proxy_backend(self, mock_import: MagicMock) -> None:
        fake_module = types.ModuleType("acmeeh.ca.acme_proxy")
        fake_module.AcmeProxyBackend = _ConcreteBackend  # type: ignore[attr-defined]
        mock_import.return_value = fake_module

        settings = _make_ca_settings("acme_proxy")
        backend = load_ca_backend(settings)

        mock_import.assert_called_once_with("acmeeh.ca.acme_proxy")
        assert isinstance(backend, CABackend)

    @patch("acmeeh.ca.registry.importlib.import_module")
    def test_import_error_raises_ca_error(self, mock_import: MagicMock) -> None:
        mock_import.side_effect = ImportError("module not found")
        settings = _make_ca_settings("internal")
        with pytest.raises(CAError, match="Failed to load built-in CA backend"):
            load_ca_backend(settings)

    @patch("acmeeh.ca.registry.importlib.import_module")
    def test_attribute_error_raises_ca_error(self, mock_import: MagicMock) -> None:
        fake_module = types.ModuleType("acmeeh.ca.internal")
        # No InternalCABackend attribute
        mock_import.return_value = fake_module
        settings = _make_ca_settings("internal")
        with pytest.raises(CAError, match="Failed to load built-in CA backend"):
            load_ca_backend(settings)


# ---------------------------------------------------------------------------
# Tests: Unknown backend name
# ---------------------------------------------------------------------------


class TestUnknownBackend:
    """Tests for unknown backend names."""

    def test_unknown_name_raises_ca_error(self) -> None:
        settings = _make_ca_settings("totally_unknown")
        with pytest.raises(CAError, match="Unknown CA backend 'totally_unknown'"):
            load_ca_backend(settings)

    def test_unknown_name_lists_options(self) -> None:
        settings = _make_ca_settings("bogus")
        with pytest.raises(CAError, match="built-in options"):
            load_ca_backend(settings)


# ---------------------------------------------------------------------------
# Tests: ext: prefix (external/custom backends)
# ---------------------------------------------------------------------------


class TestExtPrefix:
    """Tests for loading external backends via ext: prefix."""

    @patch("acmeeh.ca.registry.importlib.import_module")
    def test_ext_prefix_loads_class(self, mock_import: MagicMock) -> None:
        fake_module = types.ModuleType("mycompany.ca")
        fake_module.CustomBackend = _ConcreteBackend  # type: ignore[attr-defined]
        mock_import.return_value = fake_module

        settings = _make_ca_settings("ext:mycompany.ca.CustomBackend")
        backend = load_ca_backend(settings)

        mock_import.assert_called_once_with("mycompany.ca")
        assert isinstance(backend, CABackend)

    @patch("acmeeh.ca.registry.importlib.import_module")
    def test_ext_import_error_raises(self, mock_import: MagicMock) -> None:
        mock_import.side_effect = ImportError("no such module")
        settings = _make_ca_settings("ext:mycompany.ca.Missing")
        with pytest.raises(CAError, match="Failed to load external CA backend"):
            load_ca_backend(settings)

    @patch("acmeeh.ca.registry.importlib.import_module")
    def test_ext_attribute_error_raises(self, mock_import: MagicMock) -> None:
        fake_module = types.ModuleType("mycompany.ca")
        mock_import.return_value = fake_module
        settings = _make_ca_settings("ext:mycompany.ca.NoSuchClass")
        with pytest.raises(CAError, match="Failed to load external CA backend"):
            load_ca_backend(settings)


# ---------------------------------------------------------------------------
# Tests: _load_external
# ---------------------------------------------------------------------------


class TestLoadExternal:
    """Tests for _load_external helper."""

    def test_invalid_fqn_no_dot(self) -> None:
        """FQN without a dot should fail."""
        settings = _make_ca_settings()
        with pytest.raises(CAError, match="must be fully qualified"):
            _load_external("ClassName", settings)

    @patch("acmeeh.ca.registry.importlib.import_module")
    def test_non_ca_backend_subclass_raises(self, mock_import: MagicMock) -> None:
        fake_module = types.ModuleType("mycompany.ca")
        fake_module.NotBackend = _NotABackend  # type: ignore[attr-defined]
        mock_import.return_value = fake_module

        settings = _make_ca_settings()
        with pytest.raises(CAError, match="must be a subclass of CABackend"):
            _load_external("mycompany.ca.NotBackend", settings)

    @patch("acmeeh.ca.registry.importlib.import_module")
    def test_string_not_class_raises(self, mock_import: MagicMock) -> None:
        fake_module = types.ModuleType("mycompany.ca")
        fake_module.SomeString = "not a class"  # type: ignore[attr-defined]
        mock_import.return_value = fake_module

        settings = _make_ca_settings()
        with pytest.raises(CAError, match="must be a subclass of CABackend"):
            _load_external("mycompany.ca.SomeString", settings)


# ---------------------------------------------------------------------------
# Tests: _validate_class
# ---------------------------------------------------------------------------


class TestValidateClass:
    """Tests for _validate_class."""

    def test_valid_concrete_backend(self) -> None:
        """A proper CABackend subclass with sign/revoke should pass."""
        # Should not raise
        _validate_class(_ConcreteBackend, "test_backend")

    def test_not_a_subclass_raises(self) -> None:
        with pytest.raises(CAError, match="not a subclass of CABackend"):
            _validate_class(_NotABackend, "bad_backend")

    def test_not_a_type_raises(self) -> None:
        with pytest.raises(CAError, match="not a subclass of CABackend"):
            _validate_class("a string", "bad_label")  # type: ignore[arg-type]

    def test_abstract_sign_raises(self) -> None:
        """A class whose sign is still abstract should be rejected."""
        # _IncompleteBackend has abstract sign and revoke, but trying to
        # instantiate will fail. _validate_class should catch that the
        # methods are still abstract.
        with pytest.raises(CAError, match="does not implement 'sign\\(\\)'"):
            _validate_class(_IncompleteBackend, "incomplete")

    def test_missing_revoke_method(self) -> None:
        """A class that only has sign but not revoke should be rejected."""

        class OnlySign(CABackend):
            def sign(self, csr, *, profile, validity_days, serial_number=None, ct_submitter=None):
                pass

        # revoke is still abstract
        with pytest.raises(CAError, match="does not implement 'revoke\\(\\)'"):
            _validate_class(OnlySign, "only_sign")

    def test_missing_sign_method(self) -> None:
        """A class that only has revoke but not sign should be rejected."""

        class OnlyRevoke(CABackend):
            def revoke(self, *, serial_number, certificate_pem, reason=None):
                pass

        with pytest.raises(CAError, match="does not implement 'sign\\(\\)'"):
            _validate_class(OnlyRevoke, "only_revoke")


# ---------------------------------------------------------------------------
# Tests: Builtin backend names coverage
# ---------------------------------------------------------------------------


class TestBuiltinBackendNames:
    """Ensure the registry has the expected builtin backend names."""

    def test_builtin_names(self) -> None:
        assert "internal" in _BUILTIN_BACKENDS
        assert "external" in _BUILTIN_BACKENDS
        assert "hsm" in _BUILTIN_BACKENDS
        assert "acme_proxy" in _BUILTIN_BACKENDS

    def test_builtin_entries_are_tuples(self) -> None:
        for name, entry in _BUILTIN_BACKENDS.items():
            assert isinstance(entry, tuple), f"{name} entry should be a tuple"
            assert len(entry) == 2, f"{name} entry should have (module, class)"
            mod_path, cls_name = entry
            assert isinstance(mod_path, str)
            assert isinstance(cls_name, str)
