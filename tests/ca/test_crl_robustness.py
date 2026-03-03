"""Tests for CRL robustness (caching, staleness, error recovery)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acmeeh.ca.crl import CRLManager
from acmeeh.config.settings import CrlSettings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _crl_settings(**kwargs) -> CrlSettings:
    defaults = dict(
        enabled=True,
        path="/crl",
        rebuild_interval_seconds=300,
        next_update_seconds=3600,
        hash_algorithm="sha256",
    )
    defaults.update(kwargs)
    return CrlSettings(**defaults)


def _generate_ca():
    """Generate a self-signed CA cert and key for test signing."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CRL CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


@dataclass(frozen=True)
class FakeRevokedCert:
    serial_number: str
    revoked_at: datetime


class StubCertRepo:
    """Minimal stub for the certificate repository."""

    def __init__(self, revoked: list[FakeRevokedCert] | None = None):
        self._revoked = revoked or []

    def find_revoked(self) -> list:
        return self._revoked


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ca_pair():
    return _generate_ca()


@pytest.fixture
def settings():
    return _crl_settings()


@pytest.fixture
def cert_repo():
    return StubCertRepo()


@pytest.fixture
def crl_manager(ca_pair, cert_repo, settings):
    root_cert, root_key = ca_pair
    return CRLManager(root_cert, root_key, cert_repo, settings)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestForceRebuild:
    """force_rebuild() returns fresh CRL."""

    def test_force_rebuild_returns_bytes(self, crl_manager):
        result = crl_manager.force_rebuild()
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_force_rebuild_updates_cache(self, crl_manager):
        crl1 = crl_manager.force_rebuild()
        # Subsequent get_crl should return cached version
        crl2 = crl_manager.get_crl()
        assert crl1 == crl2

    def test_force_rebuild_with_revoked_certs(self, ca_pair):
        root_cert, root_key = ca_pair
        now = datetime.now(UTC)
        repo = StubCertRepo(
            [
                FakeRevokedCert(serial_number="1a2b3c", revoked_at=now - timedelta(hours=1)),
                FakeRevokedCert(serial_number="4d5e6f", revoked_at=now),
            ]
        )
        manager = CRLManager(root_cert, root_key, repo, _crl_settings())
        result = manager.force_rebuild()
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestStaleDetection:
    """Stale detection when cache age > 2x rebuild interval."""

    def test_fresh_cache_is_not_stale(self, crl_manager):
        crl_manager.force_rebuild()
        status = crl_manager.health_status()
        assert status["stale"] is False

    def test_no_cache_not_stale_during_grace_period(self, crl_manager):
        status = crl_manager.health_status()
        assert status["stale"] is False

    def test_no_cache_is_stale_after_grace_period(self, crl_manager):
        crl_manager._created_at = time.monotonic() - 9999
        status = crl_manager.health_status()
        assert status["stale"] is True

    def test_expired_cache_is_stale(self, ca_pair, cert_repo):
        root_cert, root_key = ca_pair
        # Very short rebuild interval so we can simulate staleness
        settings = _crl_settings(rebuild_interval_seconds=0)
        manager = CRLManager(root_cert, root_key, cert_repo, settings)
        manager.force_rebuild()
        # Even with interval=0, the build just happened so monotonic time diff is ~0.
        # Force the cache timestamp to the past.
        manager._cached_at = time.monotonic() - 10.0
        assert manager._is_stale() is True


class TestBuildFailureServesStale:
    """Build failure -> stale CRL still served."""

    def test_stale_crl_served_on_failure(self, crl_manager):
        # First build succeeds
        good_crl = crl_manager.force_rebuild()
        assert good_crl is not None

        # Force cache to be stale so get_crl triggers rebuild
        crl_manager._cached_at = 0.0

        # Make _build raise on next call
        original_build = crl_manager._build
        call_count = [0]

        def failing_build():
            call_count[0] += 1
            if call_count[0] > 0:
                raise RuntimeError("Simulated build failure")
            return original_build()

        crl_manager._build = failing_build

        # get_crl should return the stale CRL without raising
        result = crl_manager.get_crl()
        assert result == good_crl


class TestHealthStatus:
    """health_status() returns correct fields."""

    def test_health_status_fields(self, crl_manager):
        status = crl_manager.health_status()
        assert "last_rebuild" in status
        assert "stale" in status
        assert "error" in status
        assert "revoked_count" in status

    def test_health_after_successful_build(self, crl_manager):
        crl_manager.force_rebuild()
        status = crl_manager.health_status()
        assert status["stale"] is False
        assert status["error"] is None
        assert status["revoked_count"] == 0
        assert status["last_rebuild"] is not None

    def test_health_with_revoked_certs(self, ca_pair):
        root_cert, root_key = ca_pair
        now = datetime.now(UTC)
        repo = StubCertRepo(
            [
                FakeRevokedCert(serial_number="aa", revoked_at=now),
                FakeRevokedCert(serial_number="bb", revoked_at=now),
            ]
        )
        manager = CRLManager(root_cert, root_key, repo, _crl_settings())
        manager.force_rebuild()
        status = manager.health_status()
        assert status["revoked_count"] == 2


class TestFirstTimeBuildFailure:
    """First-time build failure raises appropriately."""

    def test_first_build_failure_raises(self, ca_pair, settings):
        root_cert, root_key = ca_pair
        repo = MagicMock()
        repo.find_revoked.side_effect = RuntimeError("DB connection failed")

        manager = CRLManager(root_cert, root_key, repo, settings)
        with pytest.raises(RuntimeError, match="DB connection failed"):
            manager.get_crl()

    def test_first_force_rebuild_failure_raises(self, ca_pair, settings):
        root_cert, root_key = ca_pair
        repo = MagicMock()
        repo.find_revoked.side_effect = RuntimeError("DB down")

        manager = CRLManager(root_cert, root_key, repo, settings)
        with pytest.raises(RuntimeError, match="DB down"):
            manager.force_rebuild()
