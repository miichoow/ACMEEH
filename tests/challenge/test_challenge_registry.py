"""Tests for acmeeh.challenge.registry.ChallengeRegistry."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from acmeeh.challenge.base import ChallengeValidator
from acmeeh.challenge.registry import ChallengeRegistry
from acmeeh.core.types import ChallengeType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(enabled: list[str], **kwargs) -> SimpleNamespace:
    """Create a mock ChallengeSettings with given enabled types."""
    kwargs.setdefault("auto_accept", False)
    return SimpleNamespace(enabled=enabled, **kwargs)


class _FakeValidator(ChallengeValidator):
    """Minimal concrete ChallengeValidator for testing."""

    challenge_type = ChallengeType.HTTP_01
    supported_identifier_types = frozenset({"dns"})

    def validate(self, *, token, jwk, identifier_type, identifier_value):
        pass


class _FakeDnsValidator(ChallengeValidator):
    """A fake DNS-01 validator."""

    challenge_type = ChallengeType.DNS_01
    supported_identifier_types = frozenset({"dns"})

    def validate(self, *, token, jwk, identifier_type, identifier_value):
        pass


class _NotAValidator:
    """A class that is NOT a ChallengeValidator subclass."""

    pass


class _MissingChallengeType(ChallengeValidator):
    """Validator that never sets challenge_type (inherits only the annotation)."""

    supported_identifier_types = frozenset({"dns"})

    def validate(self, *, token, jwk, identifier_type, identifier_value):
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestChallengeRegistryLoadBuiltin:
    """Tests for loading built-in validators."""

    @patch("acmeeh.challenge.registry.importlib.import_module")
    def test_load_builtin_http01(self, mock_import):
        """Loading 'http-01' imports the correct module and class."""
        mock_module = MagicMock()
        mock_module.Http01Validator = _FakeValidator
        mock_import.return_value = mock_module

        settings = _make_settings(["http-01"], http01=None)
        registry = ChallengeRegistry(settings)

        assert registry.is_enabled(ChallengeType.HTTP_01)
        mock_import.assert_called_with("acmeeh.challenge.http01")

    def test_unknown_type_logs_warning(self):
        """Unknown challenge type logs a warning and continues."""
        settings = _make_settings(["unknown-type"])

        with patch("acmeeh.challenge.registry.log") as mock_log:
            registry = ChallengeRegistry(settings)

        mock_log.warning.assert_called_once()
        assert "Unknown challenge type" in mock_log.warning.call_args[0][0]
        assert registry.enabled_types == []

    @patch("acmeeh.challenge.registry.importlib.import_module")
    def test_load_external_validator(self, mock_import):
        """External validator loaded via 'ext:' prefix."""
        mock_module = MagicMock()
        mock_module.CustomValidator = _FakeDnsValidator
        mock_import.return_value = mock_module

        settings = _make_settings(["ext:mycompany.challenge.CustomValidator"])
        registry = ChallengeRegistry(settings)

        assert registry.is_enabled(ChallengeType.DNS_01)
        mock_import.assert_called_with("mycompany.challenge")

    def test_invalid_external_fqn_raises(self):
        """External validator with no module part raises ValueError."""
        settings = _make_settings(["ext:NoModulePart"])

        with patch("acmeeh.challenge.registry.log"):
            # The ValueError is caught by the generic exception handler in _load
            # and logged, not re-raised
            registry = ChallengeRegistry(settings)

        assert registry.enabled_types == []

    @patch("acmeeh.challenge.registry.importlib.import_module")
    def test_non_challenge_validator_class_raises(self, mock_import):
        """External class not a ChallengeValidator subclass -> TypeError."""
        mock_module = MagicMock()
        mock_module.BadValidator = _NotAValidator
        mock_import.return_value = mock_module

        settings = _make_settings(["ext:mycompany.challenge.BadValidator"])

        with patch("acmeeh.challenge.registry.log"):
            registry = ChallengeRegistry(settings)

        # Should be caught and logged, not registered
        assert registry.enabled_types == []


class TestChallengeRegistryLookup:
    """Tests for get_validator, get_validator_or_none, is_enabled."""

    @patch("acmeeh.challenge.registry.importlib.import_module")
    def test_get_validator_registered(self, mock_import):
        """get_validator returns the validator for a registered type."""
        mock_module = MagicMock()
        mock_module.Http01Validator = _FakeValidator
        mock_import.return_value = mock_module

        settings = _make_settings(["http-01"], http01=None)
        registry = ChallengeRegistry(settings)

        validator = registry.get_validator(ChallengeType.HTTP_01)
        assert isinstance(validator, _FakeValidator)

    @patch("acmeeh.challenge.registry.importlib.import_module")
    def test_get_validator_unregistered_raises_keyerror(self, mock_import):
        """get_validator raises KeyError for an unregistered type."""
        mock_module = MagicMock()
        mock_module.Http01Validator = _FakeValidator
        mock_import.return_value = mock_module

        settings = _make_settings(["http-01"], http01=None)
        registry = ChallengeRegistry(settings)

        with pytest.raises(KeyError, match="No validator registered"):
            registry.get_validator(ChallengeType.DNS_01)

    @patch("acmeeh.challenge.registry.importlib.import_module")
    def test_get_validator_or_none_returns_none(self, mock_import):
        """get_validator_or_none returns None for missing type."""
        mock_module = MagicMock()
        mock_module.Http01Validator = _FakeValidator
        mock_import.return_value = mock_module

        settings = _make_settings(["http-01"], http01=None)
        registry = ChallengeRegistry(settings)

        result = registry.get_validator_or_none(ChallengeType.DNS_01)
        assert result is None

    @patch("acmeeh.challenge.registry.importlib.import_module")
    def test_get_validator_or_none_returns_validator(self, mock_import):
        """get_validator_or_none returns validator when registered."""
        mock_module = MagicMock()
        mock_module.Http01Validator = _FakeValidator
        mock_import.return_value = mock_module

        settings = _make_settings(["http-01"], http01=None)
        registry = ChallengeRegistry(settings)

        result = registry.get_validator_or_none(ChallengeType.HTTP_01)
        assert isinstance(result, _FakeValidator)

    @patch("acmeeh.challenge.registry.importlib.import_module")
    def test_is_enabled_true(self, mock_import):
        """is_enabled returns True for a loaded type."""
        mock_module = MagicMock()
        mock_module.Http01Validator = _FakeValidator
        mock_import.return_value = mock_module

        settings = _make_settings(["http-01"], http01=None)
        registry = ChallengeRegistry(settings)

        assert registry.is_enabled(ChallengeType.HTTP_01) is True

    @patch("acmeeh.challenge.registry.importlib.import_module")
    def test_is_enabled_false(self, mock_import):
        """is_enabled returns False for a type that was not loaded."""
        mock_module = MagicMock()
        mock_module.Http01Validator = _FakeValidator
        mock_import.return_value = mock_module

        settings = _make_settings(["http-01"], http01=None)
        registry = ChallengeRegistry(settings)

        assert registry.is_enabled(ChallengeType.DNS_01) is False

    @patch("acmeeh.challenge.registry.importlib.import_module")
    def test_enabled_types_property(self, mock_import):
        """enabled_types returns list of all loaded ChallengeType values."""
        mock_module = MagicMock()
        mock_module.Http01Validator = _FakeValidator
        mock_import.return_value = mock_module

        settings = _make_settings(["http-01"], http01=None)
        registry = ChallengeRegistry(settings)

        assert registry.enabled_types == [ChallengeType.HTTP_01]

    def test_empty_enabled_list(self):
        """Empty enabled list produces an empty registry."""
        settings = _make_settings([])
        registry = ChallengeRegistry(settings)
        assert registry.enabled_types == []

    def test_load_failure_is_logged_and_skipped(self):
        """ImportError during load is caught and logged."""
        settings = _make_settings(["http-01"], http01=None)

        with (
            patch("acmeeh.challenge.registry.log") as mock_log,
            patch(
                "acmeeh.challenge.registry.importlib.import_module",
                side_effect=ImportError("no such module"),
            ),
        ):
            registry = ChallengeRegistry(settings)

        mock_log.exception.assert_called_once()
        assert registry.enabled_types == []

    @patch("acmeeh.challenge.registry.importlib.import_module")
    def test_missing_challenge_type_attribute_logged(self, mock_import):
        """Validator class missing challenge_type is caught and logged."""
        mock_module = MagicMock()
        mock_module.Http01Validator = _MissingChallengeType
        mock_import.return_value = mock_module

        settings = _make_settings(["http-01"], http01=None)

        with patch("acmeeh.challenge.registry.log"):
            registry = ChallengeRegistry(settings)

        assert registry.enabled_types == []
