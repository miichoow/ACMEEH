"""Challenge validator registry.

Loads validators from configuration (built-in types and custom
``ext:`` extensions) and provides lookup by :class:`ChallengeType`.

Validates loaded classes on registration, supports ``is_enabled()``
queries, and logs warnings (without crashing) when a single type
fails to load.

Usage::

    from acmeeh.challenge.registry import ChallengeRegistry

    registry = ChallengeRegistry(challenge_settings)
    validator = registry.get_validator(ChallengeType.TLS_ALPN_01)
    validator.validate(token=..., jwk=..., ...)
"""

from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING

from acmeeh.challenge.base import ChallengeValidator
from acmeeh.core.types import ChallengeType

if TYPE_CHECKING:
    from acmeeh.config.settings import ChallengeSettings

log = logging.getLogger(__name__)

# Maps config string → (module_path, class_name, per-type settings attribute)
# settings_attr may be None for validators that don't need per-type settings.
_BUILTIN_VALIDATORS: dict[str, tuple[str, str, str | None]] = {
    "http-01": ("acmeeh.challenge.http01", "Http01Validator", "http01"),
    "dns-01": ("acmeeh.challenge.dns01", "Dns01Validator", "dns01"),
    "tls-alpn-01": ("acmeeh.challenge.tls_alpn01", "TlsAlpn01Validator", "tlsalpn01"),
}

# Auto-accept counterparts for built-in validators, keyed by the same
# standard ACME type name.  Used when ``challenges.auto_accept`` is true.
_AUTO_ACCEPT_VALIDATORS: dict[str, tuple[str, str, str | None]] = {
    "http-01": ("acmeeh.challenge.auto_accept", "AutoAcceptHttpValidator", None),
    "dns-01": ("acmeeh.challenge.auto_accept", "AutoAcceptDnsValidator", None),
    "tls-alpn-01": ("acmeeh.challenge.auto_accept", "AutoAcceptTlsValidator", None),
}


class ChallengeRegistry:
    """Registry of enabled challenge validators.

    Parameters
    ----------
    settings:
        The ``challenges`` section from :class:`AcmeehSettings`.

    """

    def __init__(self, settings: ChallengeSettings) -> None:
        self._settings = settings
        self._validators: dict[ChallengeType, ChallengeValidator] = {}
        self._load()

    def _load(self) -> None:
        """Load all enabled validators from configuration.

        When ``auto_accept`` is enabled and the type has an auto-accept
        counterpart, the auto-accept validator is loaded instead of the
        real one.

        Failures for individual types are logged as warnings — other
        types still load successfully.
        """
        for type_str in self._settings.enabled:
            try:
                if self._settings.auto_accept and type_str in _AUTO_ACCEPT_VALIDATORS:
                    self._load_builtin_from(
                        type_str,
                        _AUTO_ACCEPT_VALIDATORS[type_str],
                    )
                elif type_str in _BUILTIN_VALIDATORS:
                    self._load_builtin_from(
                        type_str,
                        _BUILTIN_VALIDATORS[type_str],
                    )
                elif type_str.startswith("ext:"):
                    self._load_external(type_str[4:])
                else:
                    log.warning(
                        "Unknown challenge type '%s', skipping",
                        type_str,
                    )
            except Exception:
                log.exception(
                    "Failed to load challenge validator '%s', skipping",
                    type_str,
                )

    def _load_builtin_from(
        self,
        type_str: str,
        entry: tuple[str, str, str | None],
    ) -> None:
        """Load a validator from a registry entry and register it."""
        mod_path, cls_name, settings_attr = entry
        module = importlib.import_module(mod_path)
        cls = getattr(module, cls_name)

        self._validate_class(cls, type_str)

        per_type_settings = getattr(self._settings, settings_attr, None) if settings_attr else None
        validator = cls(settings=per_type_settings)

        self._validators[validator.challenge_type] = validator
        log.info("Loaded challenge validator: %s", type_str)

    def _load_external(self, fqn: str) -> None:
        """Load an external validator by fully-qualified class name.

        Parameters
        ----------
        fqn:
            e.g. ``"mycompany.acme.challenges.CustomValidator"``

        """
        module_path, _, cls_name = fqn.rpartition(".")
        if not module_path:
            msg = (
                f"Invalid external validator '{fqn}': must be fully "
                "qualified (e.g. 'mypackage.module.ClassName')"
            )
            raise ValueError(
                msg,
            )

        module = importlib.import_module(module_path)
        cls = getattr(module, cls_name)

        if not (isinstance(cls, type) and issubclass(cls, ChallengeValidator)):
            msg = f"External validator '{fqn}' must be a subclass of ChallengeValidator"
            raise TypeError(
                msg,
            )

        self._validate_class(cls, f"ext:{fqn}")

        validator = cls(settings=None)
        self._validators[validator.challenge_type] = validator
        log.info("Loaded external challenge validator: %s", fqn)

    @staticmethod
    def _validate_class(cls: type, label: str) -> None:
        """Verify that a validator class has the required attributes."""
        if not hasattr(cls, "challenge_type"):
            msg = f"Validator class '{label}' is missing the 'challenge_type' class attribute"
            raise TypeError(
                msg,
            )

        challenge_type = cls.challenge_type
        if not isinstance(challenge_type, ChallengeType):
            msg = (
                f"Validator class '{label}' has challenge_type="
                f"{challenge_type!r}, which is not a valid ChallengeType"
            )
            raise TypeError(
                msg,
            )

    def get_validator(self, challenge_type: ChallengeType) -> ChallengeValidator:
        """Return the validator for a given challenge type.

        Raises
        ------
        KeyError
            If the challenge type is not enabled.

        """
        try:
            return self._validators[challenge_type]
        except KeyError:
            msg = f"No validator registered for challenge type '{challenge_type.value}'"
            raise KeyError(
                msg,
            )

    def get_validator_or_none(
        self,
        challenge_type: ChallengeType,
    ) -> ChallengeValidator | None:
        """Return the validator for a challenge type, or ``None``."""
        return self._validators.get(challenge_type)

    def is_enabled(self, challenge_type: ChallengeType) -> bool:
        """Check whether a challenge type is enabled and loaded."""
        return challenge_type in self._validators

    @property
    def enabled_types(self) -> list[ChallengeType]:
        """Return the list of enabled challenge types."""
        return list(self._validators.keys())
