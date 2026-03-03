"""Tests for the Container constructor and get_container() in acmeeh.app.context.

Covers lines 89-457 (constructor) and 460-477 (get_container) which were
previously untested.  Each optional subsystem (admin, challenge worker,
CAA, CT, ARI, CRL, metrics) is toggled individually to exercise
all constructor branches.

Strategy:
    - MagicMock for the database (BaseRepository stores it without calling
      methods on it during __init__).
    - MagicMock-based settings with concrete values wherever a constructor
      performs arithmetic, comparison, or iteration (e.g. NonceService,
      CleanupWorker, AcmeUrls).
    - Targeted patches on modules whose constructors have heavy side
      effects (load_ca_backend, CircuitBreakerCABackend, ChallengeRegistry,
      HookRegistry, TemplateRenderer) to avoid loading real CA keys,
      importing Jinja2 templates, or iterating challenge types.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from acmeeh.app.context import Container, get_container

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(**overrides):  # noqa: C901, PLR0912
    """Build a MagicMock settings tree with concrete values where needed.

    All optional subsystems are *disabled* by default.  Callers can
    selectively enable branches via ``overrides`` (dot-separated keys).
    """
    s = MagicMock()

    # -- nonce (NonceService.__init__ does timedelta arithmetic) ------------
    s.nonce.audit_consumed = False
    s.nonce.max_age_seconds = 300
    s.nonce.expiry_seconds = 300
    s.nonce.gc_interval_seconds = 60

    # -- server / api (AcmeUrls.__init__) ----------------------------------
    s.server.external_url = "https://acme.example.com"
    s.api.base_path = "/acme"
    s.acme.paths.directory = "/directory"
    s.ari.enabled = False
    s.ari.path = "/ari"

    # -- CA (load_ca_backend / circuit breaker) ----------------------------
    s.ca.backend = "internal"
    s.ca.circuit_breaker_failure_threshold = 5
    s.ca.circuit_breaker_recovery_timeout = 30

    # -- challenges --------------------------------------------------------
    s.challenges.background_worker.enabled = False

    # -- ACME (EAB, CAA) ---------------------------------------------------
    s.acme.eab_required = False
    s.acme.eab_reusable = False
    s.acme.caa_identities = []
    s.acme.caa_enforce = False

    # -- CT logging --------------------------------------------------------
    s.ct_logging.enabled = False
    s.ct_logging.submit_precert = False

    # -- order (AuthorizationService needs a concrete int) -----------------
    s.order.pre_authorization_lifetime_days = 30
    s.order.cleanup_interval_seconds = 3600
    s.order.stale_processing_threshold_seconds = 600

    # -- security ----------------------------------------------------------
    s.security.allowed_csr_signature_algorithms = ("sha256WithRSAEncryption",)
    s.security.min_csr_rsa_key_size = 2048
    s.security.min_csr_ec_key_size = 256
    s.security.rate_limits.gc_interval_seconds = 300

    # -- smtp / notifications / email / tos / account ----------------------
    s.smtp.templates_path = None
    s.notifications.enabled = False
    s.notifications.expiration_warning_days = []
    s.email.allowed_domains = []
    s.tos.url = None
    s.account.max_contacts = 5

    # -- admin API ---------------------------------------------------------
    s.admin_api.enabled = False

    # -- CRL ---------------------------------------------------------------
    s.crl.enabled = False

    # -- metrics -----------------------------------------------------------
    s.metrics.enabled = False

    # -- retention / audit retention (CleanupWorker) -----------------------
    s.retention.enabled = False
    s.retention.cleanup_loop_interval_seconds = 60
    s.retention.cleanup_interval_seconds = 3600
    s.retention.expired_authz_max_age_days = 90
    s.audit_retention.enabled = False
    s.audit_retention.cleanup_interval_seconds = 3600
    s.audit_retention.max_age_days = 365

    # -- quotas ------------------------------------------------------------
    s.quotas = MagicMock()

    # -- hooks (empty registered list so HookRegistry._load does nothing) --
    s.hooks.registered = []
    s.hooks.max_workers = 2

    # Apply caller overrides (dot-separated keys) -------------------------
    for dotted_key, value in overrides.items():
        parts = dotted_key.split(".")
        obj = s
        for part in parts[:-1]:
            obj = getattr(obj, part)
        setattr(obj, parts[-1], value)

    return s


# Modules whose constructors are patched in every test to avoid heavy
# side effects (CA key loading, Jinja template scanning, challenge type
# iteration).  Each string is the *source module* attribute — lazy imports
# inside the Container constructor resolve against these.
_ALWAYS_PATCHED = (
    "acmeeh.ca.registry.load_ca_backend",
    "acmeeh.ca.circuit_breaker.CircuitBreakerCABackend",
    "acmeeh.challenge.registry.ChallengeRegistry",
    "acmeeh.hooks.registry.HookRegistry",
    "acmeeh.notifications.renderer.TemplateRenderer",
)


@pytest.fixture()
def mock_db():
    """Return a MagicMock pretending to be a pypgkit.Database."""
    return MagicMock(name="Database")


@pytest.fixture()
def base_settings():
    """Return a MagicMock settings tree with all optional features off."""
    return _make_settings()


def _apply_patches():
    """Return a list of started patchers that must be stopped later."""
    patchers = [patch(target) for target in _ALWAYS_PATCHED]
    mocks = [p.start() for p in patchers]
    # load_ca_backend should return a MagicMock CA backend
    mocks[0].return_value = MagicMock(name="RawCABackend")
    # CircuitBreakerCABackend wraps the raw backend; return a MagicMock
    mocks[1].return_value = MagicMock(name="CircuitBreakerCABackend")
    # ChallengeRegistry and HookRegistry return MagicMock instances
    mocks[2].return_value = MagicMock(name="ChallengeRegistry")
    mocks[3].return_value = MagicMock(name="HookRegistry")
    # TemplateRenderer returns a MagicMock
    mocks[4].return_value = MagicMock(name="TemplateRenderer")
    return patchers, mocks


@pytest.fixture(autouse=False)
def _patched():
    """Activate the standard set of constructor patches for a test."""
    patchers, _mocks = _apply_patches()
    yield _mocks
    for p in patchers:
        p.stop()


# ---------------------------------------------------------------------------
# Tests — Container with all optional features disabled (minimal path)
# ---------------------------------------------------------------------------


class TestContainerMinimal:
    """Exercise the constructor with every optional feature disabled."""

    @pytest.fixture(autouse=True)
    def _setup_patches(self, _patched):
        """Ensure patches are active for every test in this class."""

    def test_core_attributes_assigned(self, mock_db, base_settings):
        c = Container(mock_db, base_settings)

        assert c.db is mock_db
        assert c.settings is base_settings
        assert c.shutdown_coordinator is None

    def test_repositories_created(self, mock_db, base_settings):
        c = Container(mock_db, base_settings)

        assert c.accounts is not None
        assert c.account_contacts is not None
        assert c.orders is not None
        assert c.authorizations is not None
        assert c.challenges is not None
        assert c.certificates is not None
        assert c.nonces is not None
        assert c.notification_repo is not None

    def test_core_utilities_created(self, mock_db, base_settings):
        c = Container(mock_db, base_settings)

        assert c.urls is not None
        assert c.challenge_registry is not None
        assert c.ca_backend is not None
        assert c.hook_registry is not None

    def test_services_created(self, mock_db, base_settings):
        c = Container(mock_db, base_settings)

        assert c.notification_service is not None
        assert c.nonce_service is not None
        assert c.account_service is not None
        assert c.order_service is not None
        assert c.authorization_service is not None
        assert c.challenge_service is not None
        assert c.certificate_service is not None
        assert c.key_change_service is not None

    def test_workers_created(self, mock_db, base_settings):
        c = Container(mock_db, base_settings)

        assert c.cleanup_worker is not None
        assert c.expiration_worker is not None

    def test_optional_features_are_none(self, mock_db, base_settings):
        c = Container(mock_db, base_settings)

        assert c.admin_service is None
        assert c.admin_user_repo is None
        assert c.admin_audit_repo is None
        assert c.admin_eab_repo is None
        assert c.admin_allowlist_repo is None
        assert c.admin_csr_profile_repo is None
        assert c.challenge_worker is None
        assert c.renewal_info_service is None
        assert c.crl_manager is None
        assert c.metrics_collector is None

    def test_metrics_backpatch_sets_none(self, mock_db, base_settings):
        """When metrics are disabled, services get None for _metrics."""
        c = Container(mock_db, base_settings)

        assert c.account_service._metrics is None
        assert c.order_service._metrics is None
        assert c.challenge_service._metrics is None
        assert c.certificate_service._metrics is None

    def test_shutdown_coordinator_forwarded(self, mock_db, base_settings):
        sc = MagicMock(name="ShutdownCoordinator")
        c = Container(mock_db, base_settings, shutdown_coordinator=sc)

        assert c.shutdown_coordinator is sc

    def test_rate_limiter_forwarded_to_order_service(
        self,
        mock_db,
        base_settings,
    ):
        rl = MagicMock(name="RateLimiter")
        c = Container(mock_db, base_settings, rate_limiter=rl)

        assert c.order_service._rate_limiter is rl


# ---------------------------------------------------------------------------
# Tests — Admin API enabled
# ---------------------------------------------------------------------------


class TestContainerAdminEnabled:
    """Exercise the admin_api.enabled branch (lines 217-256)."""

    @pytest.fixture(autouse=True)
    def _setup_patches(self, _patched):
        pass

    def test_admin_repos_and_service_created(self, mock_db):
        settings = _make_settings(**{"admin_api.enabled": True})
        c = Container(mock_db, settings)

        assert c.admin_user_repo is not None
        assert c.admin_audit_repo is not None
        assert c.admin_eab_repo is not None
        assert c.admin_allowlist_repo is not None
        assert c.admin_csr_profile_repo is not None
        assert c.admin_service is not None

    def test_token_blacklist_receives_db(self, mock_db):
        settings = _make_settings(**{"admin_api.enabled": True})

        with patch(
            "acmeeh.admin.auth.get_token_blacklist",
        ) as mock_gtb:
            blacklist = MagicMock()
            mock_gtb.return_value = blacklist
            Container(mock_db, settings)
            blacklist.set_db.assert_called_once_with(mock_db)

    def test_eab_repo_wired_into_account_service(self, mock_db):
        settings = _make_settings(**{"admin_api.enabled": True})
        c = Container(mock_db, settings)

        # AccountService receives the EAB repo from admin
        assert c.account_service._eab_repo is c.admin_eab_repo

    def test_allowlist_repo_wired_into_order_service(self, mock_db):
        settings = _make_settings(**{"admin_api.enabled": True})
        c = Container(mock_db, settings)

        assert c.order_service._allowlist_repo is c.admin_allowlist_repo


# ---------------------------------------------------------------------------
# Tests — Challenge background worker enabled
# ---------------------------------------------------------------------------


class TestContainerChallengeWorker:
    """Exercise the challenges.background_worker.enabled branch (303-317)."""

    @pytest.fixture(autouse=True)
    def _setup_patches(self, _patched):
        pass

    def test_challenge_worker_created(self, mock_db):
        settings = _make_settings(
            **{
                "challenges.background_worker.enabled": True,
                "challenges.background_worker.poll_seconds": 5,
                "challenges.background_worker.stale_seconds": 120,
            }
        )
        c = Container(mock_db, settings)

        assert c.challenge_worker is not None

    def test_challenge_worker_none_when_disabled(self, mock_db, base_settings):
        c = Container(mock_db, base_settings)

        assert c.challenge_worker is None


# ---------------------------------------------------------------------------
# Tests — CAA validator enabled
# ---------------------------------------------------------------------------


class TestContainerCAAValidator:
    """Exercise the CAA branch (lines 319-330)."""

    @pytest.fixture(autouse=True)
    def _setup_patches(self, _patched):
        pass

    def test_caa_validator_created_and_passed_to_cert_service(self, mock_db):
        settings = _make_settings(
            **{
                "acme.caa_identities": ("ca.example.com",),
                "acme.caa_enforce": True,
            }
        )

        with patch("acmeeh.ca.caa.CAAValidator") as mock_caa_cls:
            mock_caa_cls.return_value = MagicMock(name="CAAValidator")
            c = Container(mock_db, settings)

            mock_caa_cls.assert_called_once_with(
                ("ca.example.com",),
                settings.dns,
            )
            assert c.certificate_service._caa is mock_caa_cls.return_value

    def test_caa_validator_not_created_without_identities(
        self,
        mock_db,
        base_settings,
    ):
        """Empty caa_identities -> no CAA validator."""
        c = Container(mock_db, base_settings)
        assert c.certificate_service._caa is None

    def test_caa_validator_not_created_when_enforce_false(self, mock_db):
        settings = _make_settings(
            **{
                "acme.caa_identities": ("ca.example.com",),
                "acme.caa_enforce": False,
            }
        )
        c = Container(mock_db, settings)
        assert c.certificate_service._caa is None


# ---------------------------------------------------------------------------
# Tests — CT pre-certificate submitter enabled
# ---------------------------------------------------------------------------


class TestContainerCTSubmitter:
    """Exercise the CT logging branch (lines 332-340)."""

    @pytest.fixture(autouse=True)
    def _setup_patches(self, _patched):
        pass

    def test_ct_submitter_created(self, mock_db):
        settings = _make_settings(
            **{
                "ct_logging.enabled": True,
                "ct_logging.submit_precert": True,
            }
        )

        with patch("acmeeh.ca.ct.CTPreCertSubmitter") as mock_ct_cls:
            mock_ct_cls.return_value = MagicMock(name="CTSubmitter")
            c = Container(mock_db, settings)

            mock_ct_cls.assert_called_once_with(settings.ct_logging)
            assert c.certificate_service._ct_submitter is mock_ct_cls.return_value

    def test_ct_submitter_none_when_disabled(self, mock_db, base_settings):
        c = Container(mock_db, base_settings)
        assert c.certificate_service._ct_submitter is None

    def test_ct_submitter_none_when_submit_precert_false(self, mock_db):
        settings = _make_settings(
            **{
                "ct_logging.enabled": True,
                "ct_logging.submit_precert": False,
            }
        )
        c = Container(mock_db, settings)
        assert c.certificate_service._ct_submitter is None


# ---------------------------------------------------------------------------
# Tests — ARI service enabled
# ---------------------------------------------------------------------------


class TestContainerARI:
    """Exercise the ARI branch (lines 368-378)."""

    @pytest.fixture(autouse=True)
    def _setup_patches(self, _patched):
        pass

    def test_ari_service_created(self, mock_db):
        settings = _make_settings(**{"ari.enabled": True})
        c = Container(mock_db, settings)

        assert c.renewal_info_service is not None

    def test_ari_service_none_when_disabled(self, mock_db, base_settings):
        c = Container(mock_db, base_settings)
        assert c.renewal_info_service is None


# ---------------------------------------------------------------------------
# Tests — CRL manager enabled
# ---------------------------------------------------------------------------


class TestContainerCRL:
    """Exercise the CRL branch (lines 380-403)."""

    @pytest.fixture(autouse=True)
    def _setup_patches(self, _patched):
        pass

    def test_crl_manager_created_when_internal_backend(self, mock_db, _patched):
        settings = _make_settings(
            **{
                "crl.enabled": True,
                "ca.backend": "internal",
            }
        )

        # root_cert / root_key live on the unwrapped (raw) backend —
        # _patched[0] is load_ca_backend, whose return_value is _raw_ca.
        raw_mock = _patched[0].return_value
        raw_mock.root_cert = MagicMock(name="root_cert")
        raw_mock.root_key = MagicMock(name="root_key")
        cb_mock = _patched[1].return_value

        with patch("acmeeh.ca.crl.CRLManager") as mock_crl_cls:
            mock_crl_cls.return_value = MagicMock(name="CRLManager")
            c = Container(mock_db, settings)

            # startup_check() should have been called
            cb_mock.startup_check.assert_called()
            assert c.crl_manager is mock_crl_cls.return_value

    def test_crl_manager_none_when_no_root_cert(self, mock_db, _patched):
        """When startup_check is called but root_cert is missing on raw backend."""
        settings = _make_settings(
            **{
                "crl.enabled": True,
                "ca.backend": "internal",
            }
        )

        raw_mock = _patched[0].return_value
        # Simulate no root_cert attribute on the unwrapped backend
        del raw_mock.root_cert

        c = Container(mock_db, settings)
        assert c.crl_manager is None

    def test_crl_manager_none_when_not_internal(self, mock_db):
        settings = _make_settings(
            **{
                "crl.enabled": True,
                "ca.backend": "external",
            }
        )
        c = Container(mock_db, settings)
        assert c.crl_manager is None

    def test_crl_manager_none_when_disabled(self, mock_db, base_settings):
        c = Container(mock_db, base_settings)
        assert c.crl_manager is None


# ---------------------------------------------------------------------------
# Tests — Metrics collector enabled
# ---------------------------------------------------------------------------


class TestContainerMetrics:
    """Exercise the metrics branch (lines 425-437)."""

    @pytest.fixture(autouse=True)
    def _setup_patches(self, _patched):
        pass

    def test_metrics_collector_created(self, mock_db):
        settings = _make_settings(**{"metrics.enabled": True})

        with patch(
            "acmeeh.metrics.collector.MetricsCollector",
        ) as mock_mc_cls:
            mock_mc_cls.return_value = MagicMock(name="MetricsCollector")
            c = Container(mock_db, settings)

            assert c.metrics_collector is mock_mc_cls.return_value

    def test_metrics_backpatch_into_services(self, mock_db):
        settings = _make_settings(**{"metrics.enabled": True})

        with patch(
            "acmeeh.metrics.collector.MetricsCollector",
        ) as mock_mc_cls:
            collector = MagicMock(name="MetricsCollector")
            mock_mc_cls.return_value = collector
            c = Container(mock_db, settings)

            assert c.account_service._metrics is collector
            assert c.order_service._metrics is collector
            assert c.challenge_service._metrics is collector
            assert c.certificate_service._metrics is collector

    def test_metrics_none_when_disabled(self, mock_db, base_settings):
        c = Container(mock_db, base_settings)
        assert c.metrics_collector is None


# ---------------------------------------------------------------------------
# Tests — All optional features enabled simultaneously
# ---------------------------------------------------------------------------


class TestContainerAllFeaturesEnabled:
    """Smoke test: construct Container with everything turned on."""

    @pytest.fixture(autouse=True)
    def _setup_patches(self, _patched):
        pass

    def test_full_construction(self, mock_db, _patched):
        settings = _make_settings(
            **{
                "admin_api.enabled": True,
                "challenges.background_worker.enabled": True,
                "challenges.background_worker.poll_seconds": 5,
                "challenges.background_worker.stale_seconds": 120,
                "acme.caa_identities": ("ca.example.com",),
                "acme.caa_enforce": True,
                "ct_logging.enabled": True,
                "ct_logging.submit_precert": True,
                "ari.enabled": True,
                "crl.enabled": True,
                "ca.backend": "internal",
                "metrics.enabled": True,
            }
        )

        raw_mock = _patched[0].return_value
        raw_mock.root_cert = MagicMock(name="root_cert")
        raw_mock.root_key = MagicMock(name="root_key")

        with (
            patch("acmeeh.ca.caa.CAAValidator"),
            patch("acmeeh.ca.ct.CTPreCertSubmitter"),
            patch("acmeeh.ca.crl.CRLManager"),
            patch("acmeeh.metrics.collector.MetricsCollector"),
        ):
            c = Container(mock_db, settings)

            # Every optional attribute should be non-None
            assert c.admin_service is not None
            assert c.challenge_worker is not None
            assert c.renewal_info_service is not None
            assert c.crl_manager is not None
            assert c.metrics_collector is not None

            # Core attributes still present
            assert c.cleanup_worker is not None
            assert c.expiration_worker is not None
            assert c.account_service is not None
            assert c.certificate_service is not None


# ---------------------------------------------------------------------------
# Tests — get_container()
# ---------------------------------------------------------------------------


class TestGetContainer:
    """Exercise get_container() (lines 460-477)."""

    def test_returns_container_from_extensions(self):
        app = Flask("test_get_container")
        container = MagicMock(name="Container")
        app.extensions["container"] = container

        with app.app_context():
            result = get_container()
            assert result is container

    def test_raises_runtime_error_when_missing(self):
        app = Flask("test_get_container_missing")

        with app.app_context():
            with pytest.raises(RuntimeError, match="Dependency container not available"):
                get_container()

    def test_raises_runtime_error_when_none(self):
        app = Flask("test_get_container_none")
        app.extensions["container"] = None

        with app.app_context():
            with pytest.raises(RuntimeError, match="Dependency container not available"):
                get_container()
