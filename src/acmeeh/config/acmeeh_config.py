"""ACMEEH configuration loader built on ConfigKit.

Lifecycle::

    # 1. CLI creates the singleton (once, at startup)
    AcmeehConfig(config_file="/etc/acmeeh/config.yaml")

    # 2. Any module retrieves it afterwards
    from acmeeh.config import get_config
    cfg = get_config()
    cfg.settings.server.port  # typed access

    # 3. Extension / dynamic access
    cfg.get("ca.vault.url", default="http://localhost:8200")
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

from configkit import ConfigKit, ConfigKitMeta

from acmeeh.config.settings import AcmeehSettings, build_settings

_SCHEMA_PATH = Path(__file__).parent / "schema.json"

_ENV_RE = re.compile(
    r"^\$\{([^}:]+?)(?::-(.*))?\}$",
    re.DOTALL,
)

_KNOWN_CHALLENGE_TYPES = frozenset(
    {
        "http-01",
        "dns-01",
        "tls-alpn-01",
    }
)

_CLASS_PATH_RE = re.compile(
    r"^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)+$",
)

_MIN_NONCE_LENGTH = 16
_MIN_RSA_KEY_SIZE = 2048
_MIN_TOKEN_SECRET_LENGTH = 16
_MIN_HSTS_ONE_DAY = 86400

# Imported lazily to avoid circular imports at module-load time, but
# the constant is cached at the module level on first use.
_KNOWN_HOOK_EVENTS: frozenset[str] | None = None


def _get_known_hook_events() -> frozenset[str]:
    """Return the known hook event names, loading lazily."""
    global _KNOWN_HOOK_EVENTS  # noqa: PLW0603
    if _KNOWN_HOOK_EVENTS is None:
        from acmeeh.hooks.events import KNOWN_EVENTS  # noqa: PLC0415

        _KNOWN_HOOK_EVENTS = KNOWN_EVENTS
    return _KNOWN_HOOK_EVENTS


log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singleton reference
# ---------------------------------------------------------------------------
_instance: AcmeehConfig | None = None


def get_config() -> AcmeehConfig:
    """Return the initialised configuration singleton.

    Raises :class:`RuntimeError` if :class:`AcmeehConfig` has not been
    created yet (i.e. the CLI entry point has not run).
    """
    if _instance is None:
        msg = (
            "Configuration not initialised. "
            "AcmeehConfig must be created with config_file= before calling get_config()."
        )
        raise RuntimeError(
            msg,
        )
    return _instance


# ---------------------------------------------------------------------------
# Validation error collector
# ---------------------------------------------------------------------------


class ConfigValidationError(Exception):
    """Raised when cross-field validation finds one or more problems."""

    def __init__(self, errors: list[str]) -> None:
        """Store *errors* and build a human-readable message."""
        self.errors = errors
        body = "\n".join(f"  - {e}" for e in errors)
        super().__init__(f"Configuration validation failed:\n{body}")


# ---------------------------------------------------------------------------
# Environment variable resolution
# ---------------------------------------------------------------------------


def _resolve_value(value: str, path: str) -> str:
    """Replace ``${VAR}`` or ``${VAR:-default}`` with env var value."""
    match = _ENV_RE.match(value)
    if match is None:
        return value
    var_name = match.group(1)
    fallback = match.group(2)
    resolved = os.environ.get(var_name)
    if resolved is not None:
        return resolved
    if fallback is not None:
        return fallback
    raise ConfigValidationError(
        [
            f"Environment variable '${{{var_name}}}' referenced "
            f"at '{path}' is not set and has no default",
        ],
    )


def _resolve_env_vars(
    data: Any,  # noqa: ANN401
    path: str = "",
) -> None:
    """Walk *data* in-place and resolve ``${VAR}``/``${VAR:-default}`` strings."""
    if isinstance(data, dict):
        for key in data:
            child_path = f"{path}.{key}" if path else key
            if isinstance(data[key], str):
                data[key] = _resolve_value(data[key], child_path)
            elif isinstance(data[key], (dict, list)):
                _resolve_env_vars(data[key], child_path)
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            child_path = f"{path}[{idx}]"
            if isinstance(item, str):
                data[idx] = _resolve_value(item, child_path)
            elif isinstance(item, (dict, list)):
                _resolve_env_vars(item, child_path)


# ---------------------------------------------------------------------------
# Config class
# ---------------------------------------------------------------------------


class AcmeehConfig(ConfigKit):
    """Central configuration for the ACMEEH server.

    Subclasses :class:`configkit.ConfigKit`.  The JSON schema is
    bundled at ``config/schema.json``; users supply only ``config_file``.

    After construction the typed settings tree is available at
    :pyattr:`settings` and the raw dict via :pyattr:`data` /
    :pymeth:`get`.
    """

    def __init__(
        self,
        *,
        config_file: str | Path,
        schema_file: str | Path | None = None,  # noqa: ARG002
    ) -> None:
        """Initialise the ACMEEH configuration singleton.

        Parameters
        ----------
        config_file:
            Path to the YAML/JSON configuration file.
        schema_file:
            Ignored.  Exists only to satisfy the
            :class:`ConfigKitMeta` singleton guard.

        """
        global _instance  # noqa: PLW0603

        # Always use the bundled schema regardless of what was passed.
        # The schema_file parameter exists only to satisfy ConfigKitMeta's
        # __call__ guard — callers should never provide it.
        super().__init__(
            config_file=config_file,
            schema_file=_SCHEMA_PATH,
        )

        # Now materialise the typed settings tree from the resolved data.
        self._settings: AcmeehSettings = build_settings(self.data)  # noqa: SLF001
        _instance = self

    # -- lifecycle overrides ------------------------------------------------

    def _load(self) -> None:
        """Load config file then resolve ``${VAR}`` env-var references.

        Runs env-var resolution **before** schema validation so that
        substituted values (e.g. ``${LOG_LEVEL:-INFO}``) are checked
        against enum constraints in the schema.
        """
        super()._load()
        _resolve_env_vars(self._data)  # noqa: SLF001

    # -- typed access -------------------------------------------------------

    @property
    def settings(self) -> AcmeehSettings:
        """Fully-typed, frozen settings tree."""
        return self._settings

    # -- cross-field validation ---------------------------------------------

    def additional_checks(self) -> None:  # noqa: C901, PLR0912, PLR0915
        """Semantic & cross-field validation.

        Called automatically by ConfigKit **after** schema validation
        passes.  Runs env-var resolution first so that all subsequent
        checks see real values.
        """
        # Env vars are already resolved in _load() (before schema
        # validation).  Collect cross-field errors.
        errors: list[str] = []
        warnings: list[str] = []

        server = self.data.get("server") or {}
        ca = self.data.get("ca") or {}
        smtp = self.data.get("smtp") or {}
        tos = self.data.get("tos") or {}
        proxy = self.data.get("proxy") or {}
        challenges = self.data.get("challenges") or {}
        email = self.data.get("email") or {}
        dns_cfg = self.data.get("dns") or {}
        nonce = self.data.get("nonce") or {}
        security = self.data.get("security") or {}

        # -- server --
        ext_url = server.get("external_url", "")
        if ext_url.endswith("/"):
            errors.append(
                f"server.external_url must not end with '/' (got '{ext_url}')",
            )

        # -- CA --
        ca_backend = ca.get("backend", "internal")
        if ca_backend == "internal":
            internal = ca.get("internal") or {}
            if not internal.get("root_cert_path"):
                errors.append(
                    "ca.internal.root_cert_path is required when ca.backend is 'internal'",
                )
            if not internal.get("root_key_path"):
                errors.append(
                    "ca.internal.root_key_path is required when ca.backend is 'internal'",
                )
        elif ca_backend == "acme_proxy":
            proxy_ca = ca.get("acme_proxy") or {}
            if not proxy_ca.get("directory_url"):
                errors.append(
                    "ca.acme_proxy.directory_url is required when ca.backend is 'acme_proxy'",
                )
            if not proxy_ca.get("email"):
                errors.append(
                    "ca.acme_proxy.email is required when ca.backend is 'acme_proxy'",
                )
            if not proxy_ca.get("challenge_handler"):
                errors.append(
                    "ca.acme_proxy.challenge_handler is required when ca.backend is 'acme_proxy'",
                )
        elif ca_backend == "hsm":
            hsm = ca.get("hsm") or {}
            if not hsm.get("pkcs11_library"):
                errors.append(
                    "ca.hsm.pkcs11_library is required when ca.backend is 'hsm'",
                )
            if not hsm.get("token_label") and hsm.get("slot_id") is None:
                errors.append(
                    "ca.hsm.token_label or ca.hsm.slot_id is required when ca.backend is 'hsm'",
                )
            if not hsm.get("key_label") and not hsm.get("key_id"):
                errors.append(
                    "ca.hsm.key_label or ca.hsm.key_id is required when ca.backend is 'hsm'",
                )
            if not hsm.get("issuer_cert_path"):
                errors.append(
                    "ca.hsm.issuer_cert_path is required when ca.backend is 'hsm'",
                )
            if hsm.get("login_required", True) and not hsm.get("pin"):
                errors.append(
                    "ca.hsm.pin is required "
                    "when ca.backend is 'hsm' and ca.hsm.login_required is true",
                )

        default_days = ca.get("default_validity_days", 90)
        max_days = ca.get("max_validity_days", 397)
        if default_days > max_days:
            errors.append(
                f"ca.default_validity_days ({default_days}) must be <= "
                f"ca.max_validity_days ({max_days})",
            )

        # -- SMTP --
        if smtp.get("enabled"):
            if not smtp.get("host"):
                errors.append("smtp.host is required when smtp.enabled is true")
            if not smtp.get("from_address"):
                errors.append(
                    "smtp.from_address is required when smtp.enabled is true",
                )

        # -- TOS --
        if tos.get("require_agreement") and not tos.get("url"):
            errors.append(
                "tos.url is required when tos.require_agreement is true",
            )

        # -- EAB --
        acme_cfg = self.data.get("acme") or {}
        if acme_cfg.get("eab_reusable") and not acme_cfg.get("eab_required"):
            warnings.append(
                "acme.eab_reusable is true but acme.eab_required is false — "
                "eab_reusable has no effect when EAB is not required",
            )

        # -- Challenges --
        enabled_types = challenges.get("enabled", ["http-01"])
        for ctype in enabled_types:
            is_known = ctype in _KNOWN_CHALLENGE_TYPES
            if not is_known and not ctype.startswith("ext:"):
                errors.append(
                    f"challenges.enabled contains unknown type '{ctype}'. "
                    f"Known types: {sorted(_KNOWN_CHALLENGE_TYPES)}. "
                    "Use 'ext:fully.qualified.Class' for custom validators.",
                )

        # -- Nonce --
        nonce_len = nonce.get("length", 32)
        if nonce_len < _MIN_NONCE_LENGTH:
            errors.append(
                f"nonce.length ({nonce_len}) must be >= "
                f"{_MIN_NONCE_LENGTH} for cryptographic safety",
            )

        # -- Security --
        min_rsa = security.get("min_rsa_key_size", _MIN_RSA_KEY_SIZE)
        if min_rsa < _MIN_RSA_KEY_SIZE:
            errors.append(
                f"security.min_rsa_key_size ({min_rsa}) must be >= {_MIN_RSA_KEY_SIZE}",
            )

        # -- Database --
        db = self.data.get("database") or {}
        min_conn = db.get("min_connections", 2)
        max_conn = db.get("max_connections", 10)
        if min_conn > max_conn:
            errors.append(
                f"database.min_connections ({min_conn}) must be <= "
                f"database.max_connections ({max_conn})",
            )

        # -- Warnings (logged, not fatal) --
        workers = server.get("workers", 4)
        if proxy.get("enabled") and not proxy.get("trusted_proxies"):
            errors.append(
                "proxy.enabled is true but proxy.trusted_proxies is empty — "
                "this trusts all sources for forwarded headers. "
                "Configure trusted proxy CIDRs or disable proxy.",
            )
        if max_conn < workers:
            warnings.append(
                f"database.max_connections ({max_conn}) is low relative to "
                f"server.workers ({workers}) — recommended at least 1 "
                "connection per worker",
            )
        notifications = self.data.get("notifications") or {}
        if notifications.get("enabled", True) and not smtp.get("enabled"):
            warnings.append(
                "notifications.enabled is true but smtp.enabled is false — "
                "notifications will be recorded but not sent",
            )
        if email.get("validate_mx") and not dns_cfg.get("resolvers"):
            warnings.append(
                "email.validate_mx is true but dns.resolvers is empty — "
                "MX validation will use system resolvers",
            )
        hooks = self.data.get("hooks") or {}
        server_timeout = server.get("timeout", 30)
        global_hook_timeout = hooks.get("timeout_seconds", 30)
        if global_hook_timeout > server_timeout:
            warnings.append(
                f"hooks.timeout_seconds ({global_hook_timeout}) exceeds "
                f"server.timeout ({server_timeout}) — hook threads may "
                "outlive the HTTP request",
            )
        known_events = _get_known_hook_events()
        for idx, entry in enumerate(hooks.get("registered", [])):
            class_path = entry.get("class", "")
            if class_path and not _CLASS_PATH_RE.match(class_path):
                errors.append(
                    f"hooks.registered[{idx}].class '{class_path}' is not a "
                    "valid fully qualified Python class path "
                    "(expected 'package.module.ClassName')",
                )
            for evt in entry.get("events", []):
                if evt not in known_events:
                    errors.append(
                        f"hooks.registered[{idx}].events contains unknown "
                        f"event '{evt}'. Known events: {sorted(known_events)}",
                    )
            per_hook_timeout = entry.get("timeout_seconds")
            if per_hook_timeout is not None and per_hook_timeout > server_timeout:
                warnings.append(
                    f"hooks.registered[{idx}].timeout_seconds "
                    f"({per_hook_timeout}) exceeds server.timeout "
                    f"({server_timeout}) — hook thread may outlive the "
                    "HTTP request",
                )

        # -- Rate limiter HA --
        rate_limits = security.get("rate_limits") or {}
        if (
            rate_limits.get("enabled", True)
            and rate_limits.get("backend", "memory") == "memory"
            and workers > 1
        ):
            warnings.append(
                "security.rate_limits.backend is 'memory' with "
                f"server.workers={workers} — rate limits are per-process "
                "and will be ineffective in multi-instance/HA deployments. "
                "Use 'database' backend for shared rate limiting.",
            )

        # -- Quotas --
        quotas = self.data.get("quotas") or {}
        if quotas.get("enabled") and (
            quotas.get("max_certificates_per_account_per_day", 0) == 0
            and quotas.get("max_orders_per_account_per_day", 0) == 0
        ):
            warnings.append(
                "quotas.enabled is true but both limits are 0 — quotas have no effect",
            )

        # -- Challenge backoff --
        backoff_base = challenges.get("backoff_base_seconds", 5)
        backoff_max = challenges.get("backoff_max_seconds", 300)
        if backoff_base > backoff_max:
            errors.append(
                f"challenges.backoff_base_seconds ({backoff_base}) must be <= "
                f"challenges.backoff_max_seconds ({backoff_max})",
            )

        # -- HSTS --
        hsts_max_age = security.get("hsts_max_age_seconds", 63072000)
        if 0 < hsts_max_age < _MIN_HSTS_ONE_DAY:
            warnings.append(
                f"security.hsts_max_age_seconds ({hsts_max_age}) is "
                f"less than 1 day ({_MIN_HSTS_ONE_DAY}) — consider a "
                "longer duration for effective HSTS",
            )

        # -- CRL --
        crl = self.data.get("crl") or {}
        if crl.get("enabled") and ca_backend != "internal":
            warnings.append(
                "crl.enabled is true but ca.backend is not 'internal' — "
                "CRL generation requires access to the signing key",
            )

        # -- Database connection pool vs workers --
        database = self.data.get("database") or {}
        max_conn = database.get("max_connections", 10)
        min_conn = database.get("min_connections", 2)
        if min_conn > max_conn:
            errors.append(
                f"database.min_connections ({min_conn}) must be <= "
                f"database.max_connections ({max_conn})",
            )
        recommended_min = workers * 2 + 5
        if max_conn < recommended_min:
            warnings.append(
                f"database.max_connections ({max_conn}) is low for "
                f"server.workers={workers} — recommended at least "
                f"{recommended_min} (workers * 2 + 5)",
            )

        # -- CT Logging --
        ct = self.data.get("ct_logging") or {}
        if ct.get("enabled") and not ct.get("logs"):
            errors.append(
                "ct_logging.enabled is true but ct_logging.logs is empty — "
                "at least one CT log must be configured",
            )

        # -- Identifier policy --
        id_policy = security.get("identifier_policy") or {}
        admin_api_data = self.data.get("admin_api") or {}
        if id_policy.get("enforce_account_allowlist") and not admin_api_data.get("enabled"):
            warnings.append(
                "security.identifier_policy.enforce_account_allowlist is true "
                "but admin_api.enabled is false — allowlist cannot be managed",
            )

        # -- Admin API --
        admin_api = self.data.get("admin_api") or {}
        api_cfg = self.data.get("api") or {}
        if admin_api.get("enabled"):
            if not admin_api.get("initial_admin_email"):
                errors.append(
                    "admin_api.initial_admin_email is required when admin_api.enabled is true",
                )
            admin_base = admin_api.get("base_path", "/api").rstrip("/")
            acme_base = api_cfg.get("base_path", "").rstrip("/")
            if admin_base == acme_base:
                errors.append(
                    f"admin_api.base_path ({admin_base!r}) must not collide "
                    f"with api.base_path ({acme_base!r})",
                )
            if not smtp.get("enabled"):
                warnings.append(
                    "admin_api.enabled is true but smtp.enabled is false — "
                    "admin passwords will be printed to log only",
                )
            token_secret = admin_api.get("token_secret", "")
            if not token_secret:
                errors.append(
                    "admin_api.token_secret is required when admin_api.enabled "
                    "is true (min 16 characters)",
                )
            elif len(token_secret) < _MIN_TOKEN_SECRET_LENGTH:
                errors.append(
                    "admin_api.token_secret is too short "
                    f"({len(token_secret)} chars) "
                    f"— minimum {_MIN_TOKEN_SECRET_LENGTH} characters required",
                )

        for w in warnings:
            log.warning("Config warning: %s", w)

        if errors:
            raise ConfigValidationError(errors)

    # -- helpers ------------------------------------------------------------

    def reload_settings(self) -> AcmeehSettings:
        """Re-read the config file and rebuild settings.

        Does not reset the singleton.  Used for config hot-reload
        (SIGHUP).  Re-reads the file, resolves env vars, and returns
        a fresh :class:`AcmeehSettings` tree.
        """
        import json  # noqa: PLC0415

        import yaml  # noqa: PLC0415

        source_file = self.data.get("_source", "")
        if not source_file:
            msg = "Cannot reload: no source file recorded"
            raise RuntimeError(msg)

        with open(source_file, encoding="utf-8") as f:  # noqa: PTH123
            if source_file.endswith((".yaml", ".yml")):
                new_data = yaml.safe_load(f)
            else:
                new_data = json.load(f)

        _resolve_env_vars(new_data)
        return build_settings(new_data)

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton -- testing only."""
        global _instance  # noqa: PLW0603
        _instance = None
        ConfigKitMeta.reset()

    def __repr__(self) -> str:
        """Return a developer-friendly representation."""
        source = self.data.get("_source", "?")
        return f"<AcmeehConfig config_file={source}>"
