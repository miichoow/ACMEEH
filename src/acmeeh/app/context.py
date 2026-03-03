"""Dependency injection container for ACMEEH.

Created once during application startup and stored on the Flask app
via ``app.extensions["container"]``.  Accessible from any request
context with :func:`get_container`.

Usage::

    from acmeeh.app.context import get_container

    c = get_container()
    account = c.accounts.find_by_id(account_id)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flask import current_app

if TYPE_CHECKING:
    from pypgkit import Database

    from acmeeh.admin.repository import (
        AdminUserRepository,
        AllowedIdentifierRepository,
        AuditLogRepository,
        CsrProfileRepository,
        EabCredentialRepository,
    )
    from acmeeh.admin.service import AdminUserService
    from acmeeh.app.rate_limiter import (
        DatabaseRateLimiter,
        InMemoryRateLimiter,
    )
    from acmeeh.app.shutdown import ShutdownCoordinator
    from acmeeh.ca.base import CABackend
    from acmeeh.ca.crl import CRLManager
    from acmeeh.challenge.registry import ChallengeRegistry
    from acmeeh.config.settings import AcmeehSettings
    from acmeeh.core.urls import AcmeUrls
    from acmeeh.hooks.registry import HookRegistry
    from acmeeh.metrics.collector import MetricsCollector
    from acmeeh.repositories import (
        AccountContactRepository,
        AccountRepository,
        AuthorizationRepository,
        CertificateRepository,
        ChallengeRepository,
        NonceRepository,
        NotificationRepository,
        OrderRepository,
    )
    from acmeeh.services import (
        AccountService,
        AuthorizationService,
        CertificateService,
        ChallengeService,
        KeyChangeService,
        NonceService,
        NotificationService,
        OrderService,
    )
    from acmeeh.services.cleanup_worker import CleanupWorker
    from acmeeh.services.expiration_worker import ExpirationWorker
    from acmeeh.services.renewal_info import RenewalInfoService
    from acmeeh.services.workers import ChallengeWorker


class Container:
    """Application-wide dependency container.

    Holds a reference to the :class:`Database` singleton and
    pre-built repository instances.  All repositories share the
    same database connection pool.
    """

    def __init__(  # noqa: C901, PLR0912, PLR0915, PLR0913
        self,
        db: Database,
        settings: AcmeehSettings,
        shutdown_coordinator: ShutdownCoordinator | None = None,
        rate_limiter: (InMemoryRateLimiter | DatabaseRateLimiter | None) = None,
    ) -> None:
        """Initialise the container and wire up all dependencies."""
        from acmeeh.repositories import (  # noqa: PLC0415
            AccountContactRepository as _ACR,  # noqa: N814
        )
        from acmeeh.repositories import (  # noqa: PLC0415
            AccountRepository as _AR,  # noqa: N814
        )
        from acmeeh.repositories import (  # noqa: PLC0415
            AuthorizationRepository as _AuR,  # noqa: N814
        )
        from acmeeh.repositories import (  # noqa: PLC0415
            CertificateRepository as _CeR,  # noqa: N814
        )
        from acmeeh.repositories import (  # noqa: PLC0415
            ChallengeRepository as _ChR,  # noqa: N814
        )
        from acmeeh.repositories import (  # noqa: PLC0415
            NonceRepository as _NR,  # noqa: N814
        )
        from acmeeh.repositories import (  # noqa: PLC0415
            NotificationRepository as _NoR,  # noqa: N814
        )
        from acmeeh.repositories import (  # noqa: PLC0415
            OrderRepository as _OR,  # noqa: N814
        )

        self.db: Database = db
        self.settings: AcmeehSettings = settings
        self.shutdown_coordinator = shutdown_coordinator

        # Repositories
        self.accounts: AccountRepository = _AR(db)
        self.account_contacts: AccountContactRepository = _ACR(db)
        self.orders: OrderRepository = _OR(db)
        self.authorizations: AuthorizationRepository = _AuR(db)
        self.challenges: ChallengeRepository = _ChR(db)
        self.certificates: CertificateRepository = _CeR(db)
        self.nonces: NonceRepository = _NR(
            db,
            audit_consumed=settings.nonce.audit_consumed,
        )
        self.notification_repo: NotificationRepository = _NoR(db)

        # Core utilities
        from acmeeh.ca.registry import load_ca_backend as _load_ca  # noqa: PLC0415
        from acmeeh.challenge.registry import ChallengeRegistry as _CR  # noqa: E501, N814, PLC0415
        from acmeeh.core.urls import AcmeUrls as _AU  # noqa: N814, PLC0415
        from acmeeh.hooks.registry import HookRegistry as _HR  # noqa: N814, PLC0415

        self.urls: AcmeUrls = _AU(settings)
        self.challenge_registry: ChallengeRegistry = _CR(
            settings.challenges,
        )
        _raw_ca: CABackend = _load_ca(settings.ca)

        # Wrap CA backend with circuit breaker for resilience
        from acmeeh.ca.circuit_breaker import (
            CircuitBreakerCABackend as _CB,  # noqa: E501, N814, PLC0415
        )

        cb_threshold = settings.ca.circuit_breaker_failure_threshold
        cb_timeout = settings.ca.circuit_breaker_recovery_timeout
        self.ca_backend: CABackend = _CB(
            _raw_ca,
            settings.ca,
            failure_threshold=cb_threshold,
            recovery_timeout=cb_timeout,
        )
        self.hook_registry: HookRegistry = _HR(settings.hooks)

        # Services
        from acmeeh.notifications.renderer import (
            TemplateRenderer as _TR,  # noqa: E501, N814, PLC0415
        )
        from acmeeh.services import (  # noqa: PLC0415
            AccountService as _AccS,  # noqa: N814
        )
        from acmeeh.services import (  # noqa: PLC0415
            AuthorizationService as _AuS,  # noqa: N814
        )
        from acmeeh.services import (  # noqa: PLC0415
            CertificateService as _CeS,  # noqa: N814
        )
        from acmeeh.services import (  # noqa: PLC0415
            ChallengeService as _ChS,  # noqa: N814
        )
        from acmeeh.services import (  # noqa: PLC0415
            KeyChangeService as _KCS,  # noqa: N814
        )
        from acmeeh.services import (  # noqa: PLC0415
            NonceService as _NS,  # noqa: N814
        )
        from acmeeh.services import (  # noqa: PLC0415
            NotificationService as _NotS,  # noqa: N814
        )
        from acmeeh.services import (  # noqa: PLC0415
            OrderService as _OS,  # noqa: N814
        )

        renderer = _TR(settings.smtp.templates_path)
        self.notification_service: NotificationService = _NotS(
            self.notification_repo,
            self.account_contacts,
            settings.smtp,
            settings.notifications,
            renderer,
            settings.server.external_url,
        )

        self.nonce_service: NonceService = _NS(
            self.nonces,
            settings.nonce,
        )
        # Admin API (optional -- guarded by config).  Must be
        # created before AccountService and OrderService so the
        # EAB and allowlist repos are available.
        self.admin_user_repo: AdminUserRepository | None = None
        self.admin_audit_repo: AuditLogRepository | None = None
        self.admin_eab_repo: EabCredentialRepository | None = None
        self.admin_allowlist_repo: AllowedIdentifierRepository | None = None
        self.admin_csr_profile_repo: CsrProfileRepository | None = None
        self.admin_service: AdminUserService | None = None

        if settings.admin_api.enabled:
            from acmeeh.admin.auth import get_token_blacklist  # noqa: PLC0415
            from acmeeh.admin.repository import (  # noqa: PLC0415
                AdminUserRepository as _AUR,  # noqa: N814
            )
            from acmeeh.admin.repository import (  # noqa: PLC0415
                AllowedIdentifierRepository as _AIR,  # noqa: N814
            )
            from acmeeh.admin.repository import (  # noqa: PLC0415
                AuditLogRepository as _ALR,  # noqa: N814
            )
            from acmeeh.admin.repository import (  # noqa: PLC0415
                CsrProfileRepository as _CPR,  # noqa: N814
            )
            from acmeeh.admin.repository import (  # noqa: PLC0415
                EabCredentialRepository as _EAB,  # noqa: N814
            )
            from acmeeh.admin.service import AdminUserService as _AUS  # noqa: E501, N814, PLC0415

            # Wire DB into token blacklist for HA-safe revocation
            get_token_blacklist().set_db(db)

            self.admin_user_repo = _AUR(db)
            self.admin_audit_repo = _ALR(db)
            self.admin_eab_repo = _EAB(db)
            self.admin_allowlist_repo = _AIR(db)
            self.admin_csr_profile_repo = _CPR(db)
            self.admin_service = _AUS(
                self.admin_user_repo,
                self.admin_audit_repo,
                settings.admin_api,
                self.notification_service,
                eab_repo=self.admin_eab_repo,
                allowlist_repo=self.admin_allowlist_repo,
                csr_profile_repo=(self.admin_csr_profile_repo),
                notification_repo=self.notification_repo,
                cert_repo=self.certificates,
            )

        self.account_service: AccountService = _AccS(
            self.accounts,
            self.account_contacts,
            settings.email,
            settings.tos,
            self.notification_service,
            hook_registry=self.hook_registry,
            eab_repo=self.admin_eab_repo,
            eab_required=settings.acme.eab_required,
            eab_reusable=settings.acme.eab_reusable,
            authz_repo=self.authorizations,
            account_settings=settings.account,
        )
        self.order_service: OrderService = _OS(
            self.orders,
            self.authorizations,
            self.challenges,
            settings.order,
            settings.challenges,
            settings.security.identifier_policy,
            db,
            hook_registry=self.hook_registry,
            allowlist_repo=self.admin_allowlist_repo,
            quota_settings=settings.quotas,
            rate_limiter=rate_limiter,
            notifier=self.notification_service,
        )
        self.authorization_service: AuthorizationService = _AuS(
            self.authorizations,
            self.challenges,
            pre_authorization_lifetime_days=(settings.order.pre_authorization_lifetime_days),
            order_repo=self.orders,
            enabled_challenge_types=settings.challenges.enabled,
            notifier=self.notification_service,
        )
        self.challenge_service: ChallengeService = _ChS(
            self.challenges,
            self.authorizations,
            self.orders,
            self.challenge_registry,
            hook_registry=self.hook_registry,
            challenge_settings=settings.challenges,
            notifier=self.notification_service,
        )

        # Background challenge worker (optional)
        self.challenge_worker: ChallengeWorker | None = None
        if settings.challenges.background_worker.enabled:
            from acmeeh.services.workers import ChallengeWorker as _CW  # noqa: E501, N814, PLC0415

            bw = settings.challenges.background_worker
            self.challenge_worker = _CW(
                self.challenge_service,
                self.challenges,
                self.authorizations,
                self.accounts,
                poll_seconds=bw.poll_seconds,
                stale_seconds=bw.stale_seconds,
                db=db,
            )

        # CAA validator (optional -- only when configured)
        caa_validator = None
        if settings.acme.caa_identities and settings.acme.caa_enforce:
            from acmeeh.ca.caa import CAAValidator as _CAA  # noqa: N814, PLC0415

            caa_validator = _CAA(
                settings.acme.caa_identities,
                settings.dns,
            )

        # CT pre-certificate submitter (optional)
        ct_submitter = None
        if settings.ct_logging.enabled and settings.ct_logging.submit_precert:
            from acmeeh.ca.ct import CTPreCertSubmitter as _CTP  # noqa: N814, PLC0415

            ct_submitter = _CTP(settings.ct_logging)

        allowed_algs = settings.security.allowed_csr_signature_algorithms
        self.certificate_service: CertificateService = _CeS(
            self.certificates,
            self.orders,
            settings.ca,
            self.ca_backend,
            self.notification_service,
            hook_registry=self.hook_registry,
            caa_validator=caa_validator,
            csr_profile_repo=self.admin_csr_profile_repo,
            ct_submitter=ct_submitter,
            allowed_csr_signature_algorithms=allowed_algs,
            db=db,
            min_csr_rsa_key_size=(settings.security.min_csr_rsa_key_size),
            min_csr_ec_key_size=(settings.security.min_csr_ec_key_size),
            require_csr_profile=(settings.security.require_csr_profile),
            db_pool_max_connections=settings.database.max_connections,
        )
        self.key_change_service: KeyChangeService = _KCS(
            self.accounts,
            notifier=self.notification_service,
        )

        # ARI service (optional)
        self.renewal_info_service: RenewalInfoService | None = None
        if settings.ari.enabled:
            from acmeeh.services.renewal_info import (
                RenewalInfoService as _RIS,  # noqa: E501, N814, PLC0415
            )

            self.renewal_info_service = _RIS(
                self.certificates,
                settings.ari,
            )

        # CRL manager (optional -- internal CA with CRL)
        self.crl_manager: CRLManager | None = None
        if settings.crl.enabled and settings.ca.backend == "internal":
            from acmeeh.ca.crl import CRLManager as _CRL  # noqa: N814, PLC0415

            # Trigger loading of internal CA keys
            self.ca_backend.startup_check()
            # Access root_cert/root_key on the unwrapped backend — the
            # CircuitBreakerCABackend wrapper does not expose these attrs.
            if hasattr(_raw_ca, "root_cert") and _raw_ca.root_cert:
                self.crl_manager = _CRL(
                    _raw_ca.root_cert,  # type: ignore[attr-defined]
                    _raw_ca.root_key,  # type: ignore[attr-defined]
                    self.certificates,
                    settings.crl,
                    shutdown_coordinator=(shutdown_coordinator),
                    db=db,
                )

        # Metrics collector (optional)
        self.metrics_collector: MetricsCollector | None = None
        if settings.metrics.enabled:
            from acmeeh.metrics.collector import MetricsCollector as _MC  # noqa: N814, PLC0415

            self.metrics_collector = _MC()

        # Back-patch metrics into services created before collector
        _mc: Any = self.metrics_collector
        self.account_service._metrics = _mc  # noqa: SLF001
        self.order_service._metrics = _mc  # noqa: SLF001
        self.challenge_service._metrics = _mc  # noqa: SLF001
        self.certificate_service._metrics = _mc  # noqa: SLF001

        # Cleanup worker
        from acmeeh.services.cleanup_worker import CleanupWorker as _CUW  # noqa: N814, PLC0415

        self.cleanup_worker: CleanupWorker = _CUW(
            nonce_service=self.nonce_service,
            order_repo=self.orders,
            settings=settings,
            db=db,
            notifier=self.notification_service,
        )

        # Expiration worker
        from acmeeh.services.expiration_worker import ExpirationWorker as _EW  # noqa: N814, PLC0415

        self.expiration_worker: ExpirationWorker = _EW(
            cert_repo=self.certificates,
            notification_service=self.notification_service,
            settings=settings.notifications,
            db=db,
        )


def get_container() -> Container:
    """Return the :class:`Container` from the current Flask app.

    Raises :class:`RuntimeError` if the database was not
    initialised (i.e. ``create_app`` was called without a
    ``database`` argument).
    """
    container = current_app.extensions.get("container")
    if container is None:
        msg = (
            "Dependency container not available -- "
            "was the database initialised before "
            "create_app()?"
        )
        raise RuntimeError(
            msg,
        )
    return container
