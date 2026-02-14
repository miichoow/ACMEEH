"""Typed, frozen dataclasses for every configuration section.

This module is the **single source of truth** for default values.
JSON Schema defaults exist only for documentation — these builders
are what the application actually reads.

Access pattern::

    from acmeeh.config import get_config

    db = get_config().settings.database
    print(db.host, db.port)        # typed, IDE-autocompleted
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServerSettings:
    """HTTP server configuration (bind address, workers, timeouts)."""

    external_url: str
    bind: str
    port: int
    workers: int
    worker_class: str
    timeout: int
    graceful_timeout: int
    keepalive: int
    max_requests: int
    max_requests_jitter: int


def _build_server(data: dict | None) -> ServerSettings:
    d = data or {}
    return ServerSettings(
        external_url=d["external_url"],
        bind=d.get("bind", "0.0.0.0"),  # noqa: S104
        port=d.get("port", 8443),
        workers=d.get("workers", 4),
        worker_class=d.get("worker_class", "sync"),
        timeout=d.get("timeout", 30),
        graceful_timeout=d.get("graceful_timeout", 30),
        keepalive=d.get("keepalive", 2),
        max_requests=d.get("max_requests", 0),
        max_requests_jitter=d.get("max_requests_jitter", 0),
    )


# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProxySettings:
    """Reverse proxy configuration (trusted headers, forwarded-for)."""

    enabled: bool
    trusted_proxies: tuple[str, ...]
    forwarded_for_header: str
    forwarded_proto_header: str


def _build_proxy(data: dict | None) -> ProxySettings:
    d = data or {}
    return ProxySettings(
        enabled=d.get("enabled", False),
        trusted_proxies=tuple(d.get("trusted_proxies", [])),
        forwarded_for_header=d.get("forwarded_for_header", "X-Forwarded-For"),
        forwarded_proto_header=d.get("forwarded_proto_header", "X-Forwarded-Proto"),
    )


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RateLimitRule:
    """Single rate limit rule with request count and time window."""

    requests: int
    window_seconds: int


@dataclass(frozen=True)
class RateLimitSettings:
    """Rate limiting configuration for all ACME endpoints."""

    enabled: bool
    backend: str
    new_nonce: RateLimitRule
    new_account: RateLimitRule
    new_order: RateLimitRule
    new_order_per_identifier: RateLimitRule
    challenge: RateLimitRule
    challenge_validation: RateLimitRule
    gc_interval_seconds: int
    gc_max_age_seconds: int


def _build_rate_limit_rule(
    data: dict | None,
    default_req: int,
    default_win: int,
) -> RateLimitRule:
    d = data or {}
    return RateLimitRule(
        requests=d.get("requests", default_req),
        window_seconds=d.get("window_seconds", default_win),
    )


def _build_rate_limits(data: dict | None) -> RateLimitSettings:
    d = data or {}
    return RateLimitSettings(
        enabled=d.get("enabled", True),
        backend=d.get("backend", "memory"),
        new_nonce=_build_rate_limit_rule(d.get("new_nonce"), 100, 60),
        new_account=_build_rate_limit_rule(d.get("new_account"), 10, 3600),
        new_order=_build_rate_limit_rule(d.get("new_order"), 300, 3600),
        new_order_per_identifier=_build_rate_limit_rule(
            d.get("new_order_per_identifier"),
            50,
            604800,
        ),
        challenge=_build_rate_limit_rule(
            d.get("challenge"),
            60,
            60,
        ),
        challenge_validation=_build_rate_limit_rule(
            d.get("challenge_validation"),
            30,
            60,
        ),
        gc_interval_seconds=d.get("gc_interval_seconds", 300),
        gc_max_age_seconds=d.get("gc_max_age_seconds", 7200),
    )


@dataclass(frozen=True)
class IdentifierPolicySettings:
    """Policy rules for allowed identifiers in certificate orders."""

    allowed_domains: tuple[str, ...]
    forbidden_domains: tuple[str, ...]
    allow_wildcards: bool
    allow_ip: bool
    max_identifiers_per_order: int
    max_identifier_value_length: int
    enforce_account_allowlist: bool


def _build_identifier_policy(data: dict | None) -> IdentifierPolicySettings:
    d = data or {}
    return IdentifierPolicySettings(
        allowed_domains=tuple(d.get("allowed_domains", [])),
        forbidden_domains=tuple(d.get("forbidden_domains", [])),
        allow_wildcards=d.get("allow_wildcards", True),
        allow_ip=d.get("allow_ip", False),
        max_identifiers_per_order=d.get("max_identifiers_per_order", 100),
        max_identifier_value_length=d.get("max_identifier_value_length", 253),
        enforce_account_allowlist=d.get("enforce_account_allowlist", False),
    )


@dataclass(frozen=True)
class SecuritySettings:
    """Security constraints (algorithms, key sizes, rate limits)."""

    allowed_algorithms: tuple[str, ...]
    min_rsa_key_size: int
    max_rsa_key_size: int
    allowed_ec_curves: tuple[str, ...]
    rate_limits: RateLimitSettings
    identifier_policy: IdentifierPolicySettings
    max_request_body_bytes: int
    allowed_csr_signature_algorithms: tuple[str, ...]
    min_csr_rsa_key_size: int
    min_csr_ec_key_size: int
    hsts_max_age_seconds: int


def _build_security(data: dict | None) -> SecuritySettings:
    d = data or {}
    return SecuritySettings(
        allowed_algorithms=tuple(d.get("allowed_algorithms", ["ES256", "RS256"])),
        min_rsa_key_size=d.get("min_rsa_key_size", 2048),
        max_rsa_key_size=d.get("max_rsa_key_size", 8192),
        allowed_ec_curves=tuple(d.get("allowed_ec_curves", ["P-256", "P-384"])),
        rate_limits=_build_rate_limits(d.get("rate_limits")),
        identifier_policy=_build_identifier_policy(d.get("identifier_policy")),
        max_request_body_bytes=d.get("max_request_body_bytes", 65536),
        allowed_csr_signature_algorithms=tuple(
            d.get(
                "allowed_csr_signature_algorithms",
                [
                    "SHA256withRSA",
                    "SHA384withRSA",
                    "SHA512withRSA",
                    "SHA256withECDSA",
                    "SHA384withECDSA",
                    "SHA512withECDSA",
                ],
            ),
        ),
        min_csr_rsa_key_size=d.get("min_csr_rsa_key_size", 2048),
        min_csr_ec_key_size=d.get("min_csr_ec_key_size", 256),
        hsts_max_age_seconds=d.get("hsts_max_age_seconds", 63072000),
    )


# ---------------------------------------------------------------------------
# ACME
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AcmePathSettings:
    """URL path configuration for ACME protocol endpoints."""

    directory: str
    new_nonce: str
    new_account: str
    new_order: str
    new_authz: str
    revoke_cert: str
    key_change: str


def _build_acme_paths(data: dict | None) -> AcmePathSettings:
    d = data or {}
    return AcmePathSettings(
        directory=d.get("directory", "/directory"),
        new_nonce=d.get("new_nonce", "/new-nonce"),
        new_account=d.get("new_account", "/new-account"),
        new_order=d.get("new_order", "/new-order"),
        new_authz=d.get("new_authz", "/new-authz"),
        revoke_cert=d.get("revoke_cert", "/revoke-cert"),
        key_change=d.get("key_change", "/key-change"),
    )


@dataclass(frozen=True)
class AcmeSettings:
    """ACME protocol settings (paths, EAB, CAA, pagination)."""

    paths: AcmePathSettings
    website_url: str | None
    caa_identities: tuple[str, ...]
    eab_required: bool
    eab_reusable: bool
    caa_enforce: bool
    orders_page_size: int


def _build_acme(data: dict | None) -> AcmeSettings:
    d = data or {}
    return AcmeSettings(
        paths=_build_acme_paths(d.get("paths")),
        website_url=d.get("website_url"),
        caa_identities=tuple(d.get("caa_identities", [])),
        eab_required=d.get("eab_required", False),
        eab_reusable=d.get("eab_reusable", False),
        caa_enforce=d.get("caa_enforce", True),
        orders_page_size=d.get("orders_page_size", 50),
    )


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApiSettings:
    """General API settings (base path prefix)."""

    base_path: str


def _build_api(data: dict | None) -> ApiSettings:
    d = data or {}
    return ApiSettings(
        base_path=d.get("base_path", ""),
    )


# ---------------------------------------------------------------------------
# Challenges
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Http01Settings:
    """HTTP-01 challenge validation settings."""

    port: int
    timeout_seconds: int
    max_retries: int
    auto_validate: bool
    blocked_networks: tuple[str, ...]
    max_response_bytes: int


@dataclass(frozen=True)
class Dns01Settings:
    """DNS-01 challenge validation settings."""

    resolvers: tuple[str, ...]
    timeout_seconds: int
    propagation_wait_seconds: int
    max_retries: int
    auto_validate: bool
    require_dnssec: bool
    require_authoritative: bool


@dataclass(frozen=True)
class TlsAlpn01Settings:
    """TLS-ALPN-01 challenge validation settings."""

    port: int
    timeout_seconds: int
    max_retries: int
    auto_validate: bool


@dataclass(frozen=True)
class BackgroundWorkerSettings:
    """Background worker polling and stale-detection settings."""

    enabled: bool
    poll_seconds: int
    stale_seconds: int


@dataclass(frozen=True)
class ChallengeSettings:
    """Aggregate challenge configuration for all challenge types."""

    enabled: tuple[str, ...]
    auto_accept: bool
    http01: Http01Settings
    dns01: Dns01Settings
    tlsalpn01: TlsAlpn01Settings
    background_worker: BackgroundWorkerSettings
    retry_after_seconds: int
    backoff_base_seconds: int
    backoff_max_seconds: int


def _build_challenges(data: dict | None) -> ChallengeSettings:
    d = data or {}
    h = d.get("http01") or {}
    dn = d.get("dns01") or {}
    t = d.get("tlsalpn01") or {}
    bw = d.get("background_worker") or {}
    return ChallengeSettings(
        enabled=tuple(d.get("enabled", ["http-01"])),
        auto_accept=d.get("auto_accept", False),
        http01=Http01Settings(
            port=h.get("port", 80),
            timeout_seconds=h.get("timeout_seconds", 10),
            max_retries=h.get("max_retries", 3),
            auto_validate=h.get("auto_validate", True),
            blocked_networks=tuple(
                h.get(
                    "blocked_networks",
                    [
                        "127.0.0.0/8",
                        "::1/128",
                        "169.254.0.0/16",
                        "fe80::/10",
                    ],
                )
            ),
            max_response_bytes=h.get("max_response_bytes", 1048576),
        ),
        dns01=Dns01Settings(
            resolvers=tuple(dn.get("resolvers", [])),
            timeout_seconds=dn.get("timeout_seconds", 30),
            propagation_wait_seconds=dn.get("propagation_wait_seconds", 10),
            max_retries=dn.get("max_retries", 5),
            auto_validate=dn.get("auto_validate", False),
            require_dnssec=dn.get("require_dnssec", False),
            require_authoritative=dn.get("require_authoritative", False),
        ),
        tlsalpn01=TlsAlpn01Settings(
            port=t.get("port", 443),
            timeout_seconds=t.get("timeout_seconds", 10),
            max_retries=t.get("max_retries", 3),
            auto_validate=t.get("auto_validate", True),
        ),
        background_worker=BackgroundWorkerSettings(
            enabled=bw.get("enabled", False),
            poll_seconds=bw.get("poll_seconds", 10),
            stale_seconds=bw.get("stale_seconds", 300),
        ),
        retry_after_seconds=d.get("retry_after_seconds", 3),
        backoff_base_seconds=d.get("backoff_base_seconds", 5),
        backoff_max_seconds=d.get("backoff_max_seconds", 300),
    )


# ---------------------------------------------------------------------------
# CA
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CAProfileSettings:
    """Certificate profile with key usages and validity constraints."""

    key_usages: tuple[str, ...]
    extended_key_usages: tuple[str, ...]
    validity_days: int | None
    max_validity_days: int | None


@dataclass(frozen=True)
class CAInternalSettings:
    """Internal CA backend settings (root cert, key, signing)."""

    root_cert_path: str
    root_key_path: str
    key_provider: str
    chain_path: str | None
    serial_source: str
    hash_algorithm: str


@dataclass(frozen=True)
class ExternalCASettings:
    """External CA backend settings (API URLs, auth, TLS)."""

    sign_url: str
    revoke_url: str
    auth_header: str
    auth_value: str
    ca_cert_path: str | None
    client_cert_path: str | None
    client_key_path: str | None
    timeout_seconds: int
    max_retries: int
    retry_delay_seconds: float


@dataclass(frozen=True)
class AcmeProxySettings:
    """ACME proxy backend settings (upstream ACME directory)."""

    directory_url: str
    email: str
    storage_path: str
    challenge_type: str
    challenge_handler: str
    challenge_handler_config: dict[str, Any]
    eab_kid: str | None
    eab_hmac_key: str | None
    proxy_url: str | None
    verify_ssl: bool
    timeout_seconds: int


@dataclass(frozen=True)
class HsmSettings:
    """HSM/PKCS#11 CA backend settings (token, key, session pool)."""

    pkcs11_library: str
    token_label: str | None
    slot_id: int | None
    pin: str
    key_label: str | None
    key_id: str | None
    key_type: str
    hash_algorithm: str
    issuer_cert_path: str
    chain_path: str | None
    serial_source: str
    login_required: bool
    session_pool_size: int
    session_pool_timeout_seconds: int


@dataclass(frozen=True)
class CASettings:
    """Certificate Authority configuration (backend, profiles)."""

    backend: str
    default_validity_days: int
    max_validity_days: int
    profiles: dict[str, CAProfileSettings]
    internal: CAInternalSettings
    external: ExternalCASettings
    acme_proxy: AcmeProxySettings
    hsm: HsmSettings
    circuit_breaker_failure_threshold: int
    circuit_breaker_recovery_timeout: float


_DEFAULT_PROFILE = CAProfileSettings(
    key_usages=("digital_signature", "key_encipherment"),
    extended_key_usages=("server_auth",),
    validity_days=None,
    max_validity_days=None,
)


def _build_ca(data: dict | None) -> CASettings:
    d = data or {}
    int_d = d.get("internal") or {}
    ext_d = d.get("external") or {}
    proxy_d = d.get("acme_proxy") or {}
    hsm_d = d.get("hsm") or {}
    raw_profiles = d.get("profiles") or {}

    profiles: dict[str, CAProfileSettings] = {}
    for name, pdata in raw_profiles.items():
        profiles[name] = CAProfileSettings(
            key_usages=tuple(pdata.get("key_usages", [])),
            extended_key_usages=tuple(pdata.get("extended_key_usages", [])),
            validity_days=pdata.get("validity_days"),
            max_validity_days=pdata.get("max_validity_days"),
        )
    if "default" not in profiles:
        profiles["default"] = _DEFAULT_PROFILE

    return CASettings(
        backend=d.get("backend", "internal"),
        default_validity_days=d.get("default_validity_days", 90),
        max_validity_days=d.get("max_validity_days", 397),
        profiles=profiles,
        internal=CAInternalSettings(
            root_cert_path=int_d.get("root_cert_path", ""),
            root_key_path=int_d.get("root_key_path", ""),
            key_provider=int_d.get("key_provider", "file"),
            chain_path=int_d.get("chain_path"),
            serial_source=int_d.get("serial_source", "database"),
            hash_algorithm=int_d.get("hash_algorithm", "sha256"),
        ),
        external=ExternalCASettings(
            sign_url=ext_d.get("sign_url", ""),
            revoke_url=ext_d.get("revoke_url", ""),
            auth_header=ext_d.get("auth_header", "Authorization"),
            auth_value=ext_d.get("auth_value", ""),
            ca_cert_path=ext_d.get("ca_cert_path"),
            client_cert_path=ext_d.get("client_cert_path"),
            client_key_path=ext_d.get("client_key_path"),
            timeout_seconds=ext_d.get("timeout_seconds", 30),
            max_retries=ext_d.get("max_retries", 0),
            retry_delay_seconds=ext_d.get("retry_delay_seconds", 1.0),
        ),
        acme_proxy=AcmeProxySettings(
            directory_url=proxy_d.get("directory_url", ""),
            email=proxy_d.get("email", ""),
            storage_path=proxy_d.get("storage_path", "./acme_proxy_storage"),
            challenge_type=proxy_d.get("challenge_type", "dns-01"),
            challenge_handler=proxy_d.get("challenge_handler", ""),
            challenge_handler_config=proxy_d.get("challenge_handler_config", {}),
            eab_kid=proxy_d.get("eab_kid"),
            eab_hmac_key=proxy_d.get("eab_hmac_key"),
            proxy_url=proxy_d.get("proxy_url"),
            verify_ssl=proxy_d.get("verify_ssl", True),
            timeout_seconds=proxy_d.get("timeout_seconds", 300),
        ),
        hsm=HsmSettings(
            pkcs11_library=hsm_d.get("pkcs11_library", ""),
            token_label=hsm_d.get("token_label"),
            slot_id=hsm_d.get("slot_id"),
            pin=hsm_d.get("pin", ""),
            key_label=hsm_d.get("key_label"),
            key_id=hsm_d.get("key_id"),
            key_type=hsm_d.get("key_type", "ec"),
            hash_algorithm=hsm_d.get("hash_algorithm", "sha256"),
            issuer_cert_path=hsm_d.get("issuer_cert_path", ""),
            chain_path=hsm_d.get("chain_path"),
            serial_source=hsm_d.get("serial_source", "database"),
            login_required=hsm_d.get("login_required", True),
            session_pool_size=hsm_d.get("session_pool_size", 4),
            session_pool_timeout_seconds=hsm_d.get("session_pool_timeout_seconds", 30),
        ),
        circuit_breaker_failure_threshold=d.get("circuit_breaker_failure_threshold", 5),
        circuit_breaker_recovery_timeout=float(
            d.get("circuit_breaker_recovery_timeout", 30),
        ),
    )


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DnsSettings:
    """DNS resolver settings for domain validation."""

    resolvers: tuple[str, ...]
    timeout_seconds: int
    retries: int


def _build_dns(data: dict | None) -> DnsSettings:
    d = data or {}
    return DnsSettings(
        resolvers=tuple(d.get("resolvers", [])),
        timeout_seconds=d.get("timeout_seconds", 10),
        retries=d.get("retries", 3),
    )


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EmailSettings:
    """Account email contact validation settings."""

    require_contact: bool
    allowed_domains: tuple[str, ...]
    validate_mx: bool


def _build_email(data: dict | None) -> EmailSettings:
    d = data or {}
    return EmailSettings(
        require_contact=d.get("require_contact", False),
        allowed_domains=tuple(d.get("allowed_domains", [])),
        validate_mx=d.get("validate_mx", False),
    )


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AccountSettings:
    """Account modification lockdown settings."""

    allow_contact_update: bool
    allow_deactivation: bool


def _build_account(data: dict | None) -> AccountSettings:
    d = data or {}
    return AccountSettings(
        allow_contact_update=d.get("allow_contact_update", True),
        allow_deactivation=d.get("allow_deactivation", True),
    )


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SmtpSettings:
    """SMTP outbound email delivery settings."""

    enabled: bool
    host: str
    port: int
    username: str
    password: str
    use_tls: bool
    from_address: str
    templates_path: str | None
    timeout_seconds: int


def _build_smtp(data: dict | None) -> SmtpSettings:
    d = data or {}
    return SmtpSettings(
        enabled=d.get("enabled", False),
        host=d.get("host", ""),
        port=d.get("port", 587),
        username=d.get("username", ""),
        password=d.get("password", ""),
        use_tls=d.get("use_tls", True),
        from_address=d.get("from_address", ""),
        templates_path=d.get("templates_path"),
        timeout_seconds=d.get("timeout_seconds", 30),
    )


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditLogSettings:
    """Audit log output settings (file, syslog, rotation)."""

    enabled: bool
    file: str | None
    syslog: bool
    max_file_size_bytes: int
    backup_count: int


@dataclass(frozen=True)
class LoggingSettings:
    """Application logging configuration (level, format, audit)."""

    level: str
    format: str
    audit: AuditLogSettings


def _build_logging(data: dict | None) -> LoggingSettings:
    d = data or {}
    a = d.get("audit") or {}
    return LoggingSettings(
        level=d.get("level", "INFO"),
        format=d.get("format", "json"),
        audit=AuditLogSettings(
            enabled=a.get("enabled", True),
            file=a.get("file"),
            syslog=a.get("syslog", False),
            max_file_size_bytes=a.get("max_file_size_bytes", 104857600),
            backup_count=a.get("backup_count", 10),
        ),
    )


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DatabaseSettings:
    """PostgreSQL connection and pool settings."""

    host: str
    port: int
    database: str
    user: str
    password: str
    sslmode: str
    min_connections: int
    max_connections: int
    connection_timeout: float
    auto_setup: bool


def _build_database(data: dict | None) -> DatabaseSettings:
    d = data or {}
    return DatabaseSettings(
        host=d.get("host", "localhost"),
        port=d.get("port", 5432),
        database=d["database"],
        user=d["user"],
        password=d.get("password", ""),
        sslmode=d.get("sslmode", "prefer"),
        min_connections=d.get("min_connections", 2),
        max_connections=d.get("max_connections", 10),
        connection_timeout=d.get("connection_timeout", 30.0),
        auto_setup=d.get("auto_setup", False),
    )


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NotificationSettings:
    """Certificate lifecycle notification settings."""

    enabled: bool
    max_retries: int
    retry_delay_seconds: int
    batch_size: int
    retry_interval_seconds: int
    expiration_warning_days: tuple[int, ...]
    expiration_check_interval_seconds: int
    retry_backoff_multiplier: float
    retry_max_delay_seconds: int


def _build_notifications(data: dict | None) -> NotificationSettings:
    d = data or {}
    return NotificationSettings(
        enabled=d.get("enabled", True),
        max_retries=d.get("max_retries", 3),
        retry_delay_seconds=d.get("retry_delay_seconds", 60),
        batch_size=d.get("batch_size", 50),
        retry_interval_seconds=d.get("retry_interval_seconds", 300),
        expiration_warning_days=tuple(
            d.get("expiration_warning_days", [30, 14, 7, 1]),
        ),
        expiration_check_interval_seconds=d.get("expiration_check_interval_seconds", 3600),
        retry_backoff_multiplier=d.get("retry_backoff_multiplier", 2.0),
        retry_max_delay_seconds=d.get("retry_max_delay_seconds", 3600),
    )


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HookEntrySettings:
    """Single registered hook entry with events and config."""

    class_path: str
    enabled: bool
    events: tuple[str, ...]
    timeout_seconds: int | None
    config: dict[str, Any]


@dataclass(frozen=True)
class HookSettings:
    """Lifecycle hook system settings (workers, retries, registry)."""

    timeout_seconds: int
    max_workers: int
    max_retries: int
    dead_letter_log: str | None
    registered: tuple[HookEntrySettings, ...]


def _build_hooks(data: dict | None) -> HookSettings:
    from acmeeh.hooks.events import KNOWN_EVENTS  # noqa: PLC0415

    d = data or {}
    registered = []
    for idx, entry in enumerate(d.get("registered", [])):
        events = tuple(entry.get("events", []))
        for evt in events:
            if evt not in KNOWN_EVENTS:
                msg = (
                    f"hooks.registered[{idx}].events: unknown event "
                    f"'{evt}'. Known events: {sorted(KNOWN_EVENTS)}"
                )
                raise ValueError(
                    msg,
                )
        registered.append(
            HookEntrySettings(
                class_path=entry["class"],
                enabled=entry.get("enabled", True),
                events=events,
                timeout_seconds=entry.get("timeout_seconds"),
                config=entry.get("config", {}),
            )
        )
    return HookSettings(
        timeout_seconds=d.get("timeout_seconds", 30),
        max_workers=d.get("max_workers", 4),
        max_retries=d.get("max_retries", 0),
        dead_letter_log=d.get("dead_letter_log"),
        registered=tuple(registered),
    )


# ---------------------------------------------------------------------------
# Nonce
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NonceSettings:
    """Nonce generation and expiration settings."""

    expiry_seconds: int
    gc_interval_seconds: int
    length: int
    audit_consumed: bool
    max_age_seconds: int


def _build_nonce(data: dict | None) -> NonceSettings:
    d = data or {}
    expiry = d.get("expiry_seconds", 3600)
    return NonceSettings(
        expiry_seconds=expiry,
        gc_interval_seconds=d.get("gc_interval_seconds", 300),
        length=d.get("length", 32),
        audit_consumed=d.get("audit_consumed", False),
        max_age_seconds=d.get("max_age_seconds", min(expiry, 300)),
    )


# ---------------------------------------------------------------------------
# Order
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OrderSettings:
    """Order lifecycle and cleanup timing settings."""

    expiry_seconds: int
    authorization_expiry_seconds: int
    cleanup_interval_seconds: int
    stale_processing_threshold_seconds: int
    pre_authorization_lifetime_days: int
    retry_after_seconds: int


def _build_order(data: dict | None) -> OrderSettings:
    d = data or {}
    return OrderSettings(
        expiry_seconds=d.get("expiry_seconds", 604800),
        authorization_expiry_seconds=d.get("authorization_expiry_seconds", 2592000),
        cleanup_interval_seconds=d.get("cleanup_interval_seconds", 3600),
        stale_processing_threshold_seconds=d.get("stale_processing_threshold_seconds", 600),
        pre_authorization_lifetime_days=d.get("pre_authorization_lifetime_days", 30),
        retry_after_seconds=d.get("retry_after_seconds", 3),
    )


# ---------------------------------------------------------------------------
# Quotas
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QuotaSettings:
    enabled: bool
    max_certificates_per_account_per_day: int
    max_orders_per_account_per_day: int


def _build_quotas(data: dict | None) -> QuotaSettings:
    d = data or {}
    return QuotaSettings(
        enabled=d.get("enabled", False),
        max_certificates_per_account_per_day=d.get("max_certificates_per_account_per_day", 0),
        max_orders_per_account_per_day=d.get("max_orders_per_account_per_day", 0),
    )


# ---------------------------------------------------------------------------
# TOS
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TosSettings:
    url: str | None
    require_agreement: bool


def _build_tos(data: dict | None) -> TosSettings:
    d = data or {}
    return TosSettings(
        url=d.get("url"),
        require_agreement=d.get("require_agreement", False),
    )


# ---------------------------------------------------------------------------
# Admin API
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdminApiSettings:
    enabled: bool
    base_path: str
    token_secret: str
    token_expiry_seconds: int
    initial_admin_email: str
    password_length: int
    default_page_size: int
    max_page_size: int


def _build_admin_api(data: dict | None) -> AdminApiSettings:
    d = data or {}
    return AdminApiSettings(
        enabled=d.get("enabled", False),
        base_path=d.get("base_path", "/api"),
        token_secret=d.get("token_secret", ""),
        token_expiry_seconds=d.get("token_expiry_seconds", 3600),
        initial_admin_email=d.get("initial_admin_email", ""),
        password_length=d.get("password_length", 20),
        default_page_size=d.get("default_page_size", 50),
        max_page_size=d.get("max_page_size", 1000),
    )


# ---------------------------------------------------------------------------
# CRL
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrlSettings:
    enabled: bool
    path: str
    rebuild_interval_seconds: int
    next_update_seconds: int
    hash_algorithm: str


def _build_crl(data: dict | None) -> CrlSettings:
    d = data or {}
    return CrlSettings(
        enabled=d.get("enabled", False),
        path=d.get("path", "/crl"),
        rebuild_interval_seconds=d.get("rebuild_interval_seconds", 3600),
        next_update_seconds=d.get("next_update_seconds", 86400),
        hash_algorithm=d.get("hash_algorithm", "sha256"),
    )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricsSettings:
    enabled: bool
    path: str
    auth_required: bool


def _build_metrics(data: dict | None) -> MetricsSettings:
    d = data or {}
    return MetricsSettings(
        enabled=d.get("enabled", False),
        path=d.get("path", "/metrics"),
        auth_required=d.get("auth_required", False),
    )


# ---------------------------------------------------------------------------
# CT Logging
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CtLogEntry:
    url: str
    public_key_path: str | None
    timeout_seconds: int


@dataclass(frozen=True)
class CtLoggingSettings:
    enabled: bool
    logs: tuple[CtLogEntry, ...]
    submit_precert: bool


def _build_ct_logging(data: dict | None) -> CtLoggingSettings:
    d = data or {}
    logs = []
    for entry in d.get("logs", []):
        logs.append(
            CtLogEntry(
                url=entry["url"],
                public_key_path=entry.get("public_key_path"),
                timeout_seconds=entry.get("timeout_seconds", 10),
            )
        )
    return CtLoggingSettings(
        enabled=d.get("enabled", False),
        logs=tuple(logs),
        submit_precert=d.get("submit_precert", False),
    )


# ---------------------------------------------------------------------------
# Audit Retention
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditRetentionSettings:
    enabled: bool
    max_age_days: int
    cleanup_interval_seconds: int


def _build_audit_retention(data: dict | None) -> AuditRetentionSettings:
    d = data or {}
    return AuditRetentionSettings(
        enabled=d.get("enabled", False),
        max_age_days=d.get("max_age_days", 90),
        cleanup_interval_seconds=d.get("cleanup_interval_seconds", 86400),
    )


# ---------------------------------------------------------------------------
# ARI (ACME Renewal Information)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AriSettings:
    enabled: bool
    renewal_percentage: float
    path: str


def _build_ari(data: dict | None) -> AriSettings:
    d = data or {}
    return AriSettings(
        enabled=d.get("enabled", False),
        renewal_percentage=d.get("renewal_percentage", 0.6667),
        path=d.get("path", "/renewalInfo"),
    )


# ---------------------------------------------------------------------------
# OCSP
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OcspSettings:
    enabled: bool
    path: str
    response_validity_seconds: int
    hash_algorithm: str


def _build_ocsp(data: dict | None) -> OcspSettings:
    d = data or {}
    return OcspSettings(
        enabled=d.get("enabled", False),
        path=d.get("path", "/ocsp"),
        response_validity_seconds=d.get("response_validity_seconds", 86400),
        hash_algorithm=d.get("hash_algorithm", "sha256"),
    )


# ---------------------------------------------------------------------------
# Audit Export
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditExportSettings:
    webhook_url: str | None
    syslog_host: str | None
    syslog_port: int


def _build_audit_export(data: dict | None) -> AuditExportSettings:
    d = data or {}
    return AuditExportSettings(
        webhook_url=d.get("webhook_url"),
        syslog_host=d.get("syslog_host"),
        syslog_port=d.get("syslog_port", 514),
    )


# ---------------------------------------------------------------------------
# Data Retention
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetentionSettings:
    enabled: bool
    invalid_order_max_age_days: int
    expired_authz_max_age_days: int
    invalid_challenge_max_age_days: int
    expiration_notice_max_age_days: int
    cleanup_interval_seconds: int
    cleanup_loop_interval_seconds: int


def _build_retention(data: dict | None) -> RetentionSettings:
    d = data or {}
    return RetentionSettings(
        enabled=d.get("enabled", True),
        invalid_order_max_age_days=d.get("invalid_order_max_age_days", 30),
        expired_authz_max_age_days=d.get("expired_authz_max_age_days", 30),
        invalid_challenge_max_age_days=d.get("invalid_challenge_max_age_days", 30),
        expiration_notice_max_age_days=d.get("expiration_notice_max_age_days", 90),
        cleanup_interval_seconds=d.get("cleanup_interval_seconds", 86400),
        cleanup_loop_interval_seconds=d.get("cleanup_loop_interval_seconds", 60),
    )


# ---------------------------------------------------------------------------
# Root settings aggregate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AcmeehSettings:
    server: ServerSettings
    proxy: ProxySettings
    security: SecuritySettings
    acme: AcmeSettings
    api: ApiSettings
    challenges: ChallengeSettings
    ca: CASettings
    dns: DnsSettings
    email: EmailSettings
    account: AccountSettings
    smtp: SmtpSettings
    logging: LoggingSettings
    database: DatabaseSettings
    notifications: NotificationSettings
    hooks: HookSettings
    nonce: NonceSettings
    order: OrderSettings
    quotas: QuotaSettings
    tos: TosSettings
    admin_api: AdminApiSettings
    crl: CrlSettings
    metrics: MetricsSettings
    ct_logging: CtLoggingSettings
    audit_retention: AuditRetentionSettings
    ari: AriSettings
    ocsp: OcspSettings
    audit_export: AuditExportSettings
    retention: RetentionSettings


def build_settings(data: dict) -> AcmeehSettings:
    """Build the full typed settings tree from raw config data.

    Called once during :class:`AcmeehConfig` initialization after
    schema validation and environment-variable resolution.
    """
    return AcmeehSettings(
        server=_build_server(data.get("server")),
        proxy=_build_proxy(data.get("proxy")),
        security=_build_security(data.get("security")),
        acme=_build_acme(data.get("acme")),
        api=_build_api(data.get("api")),
        challenges=_build_challenges(data.get("challenges")),
        ca=_build_ca(data.get("ca")),
        dns=_build_dns(data.get("dns")),
        email=_build_email(data.get("email")),
        account=_build_account(data.get("account")),
        smtp=_build_smtp(data.get("smtp")),
        logging=_build_logging(data.get("logging")),
        database=_build_database(data.get("database")),
        notifications=_build_notifications(data.get("notifications")),
        hooks=_build_hooks(data.get("hooks")),
        nonce=_build_nonce(data.get("nonce")),
        order=_build_order(data.get("order")),
        quotas=_build_quotas(data.get("quotas")),
        tos=_build_tos(data.get("tos")),
        admin_api=_build_admin_api(data.get("admin_api")),
        crl=_build_crl(data.get("crl")),
        metrics=_build_metrics(data.get("metrics")),
        ct_logging=_build_ct_logging(data.get("ct_logging")),
        audit_retention=_build_audit_retention(data.get("audit_retention")),
        ari=_build_ari(data.get("ari")),
        ocsp=_build_ocsp(data.get("ocsp")),
        audit_export=_build_audit_export(data.get("audit_export")),
        retention=_build_retention(data.get("retention")),
    )
