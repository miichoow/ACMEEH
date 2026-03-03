"""Comprehensive unit tests for acmeeh.ca.circuit_breaker.CircuitBreakerCABackend."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from acmeeh.ca.base import CABackend, CAError, IssuedCertificate
from acmeeh.ca.circuit_breaker import CircuitBreakerCABackend
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


def _make_ca_settings() -> CASettings:
    return CASettings(
        backend="internal",
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


def _make_issued_cert() -> IssuedCertificate:
    """Build a fake IssuedCertificate for testing."""
    from datetime import UTC, datetime

    return IssuedCertificate(
        pem_chain="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        not_before=datetime.now(UTC),
        not_after=datetime.now(UTC),
        serial_number="abc123",
        fingerprint="deadbeef" * 8,
    )


def _make_mock_backend(
    sign_result: IssuedCertificate | None = None,
    sign_side_effect=None,
    revoke_side_effect=None,
) -> MagicMock:
    """Build a MagicMock that satisfies the CABackend interface."""
    mock = MagicMock(spec=CABackend)
    if sign_side_effect:
        mock.sign.side_effect = sign_side_effect
    elif sign_result:
        mock.sign.return_value = sign_result
    else:
        mock.sign.return_value = _make_issued_cert()
    if revoke_side_effect:
        mock.revoke.side_effect = revoke_side_effect
    return mock


def _default_profile() -> CAProfileSettings:
    return CAProfileSettings(
        key_usages=("digital_signature",),
        extended_key_usages=("server_auth",),
        validity_days=None,
        max_validity_days=None,
    )


def _make_csr_mock() -> MagicMock:
    return MagicMock()


# ---------------------------------------------------------------------------
# Tests: Initial state
# ---------------------------------------------------------------------------


class TestInitialState:
    """Tests that the circuit breaker starts in the correct state."""

    def test_initial_state_is_closed(self) -> None:
        mock_backend = _make_mock_backend()
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=3,
            recovery_timeout=10.0,
        )
        assert cb.state == "closed"


# ---------------------------------------------------------------------------
# Tests: Successful operations
# ---------------------------------------------------------------------------


class TestSuccessfulOperations:
    """Tests that success resets failures and passes through."""

    def test_sign_passes_through(self) -> None:
        issued = _make_issued_cert()
        mock_backend = _make_mock_backend(sign_result=issued)
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=3,
        )
        csr = _make_csr_mock()
        result = cb.sign(csr, profile=_default_profile(), validity_days=90)
        assert result is issued
        mock_backend.sign.assert_called_once()

    def test_revoke_passes_through(self) -> None:
        mock_backend = _make_mock_backend()
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=3,
        )
        cb.revoke(
            serial_number="abc",
            certificate_pem="pem",
            reason=None,
        )
        mock_backend.revoke.assert_called_once()

    def test_success_resets_failure_count(self) -> None:
        """After some failures, a success should reset the counter."""
        call_count = [0]

        def sign_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 2:
                raise CAError("transient", retryable=True)
            return _make_issued_cert()

        mock_backend = _make_mock_backend(sign_side_effect=sign_side_effect)
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=5,
        )
        csr = _make_csr_mock()

        # First two calls fail
        with pytest.raises(CAError):
            cb.sign(csr, profile=_default_profile(), validity_days=90)
        with pytest.raises(CAError):
            cb.sign(csr, profile=_default_profile(), validity_days=90)

        # Third call succeeds and should reset
        result = cb.sign(csr, profile=_default_profile(), validity_days=90)
        assert isinstance(result, IssuedCertificate)
        assert cb.state == "closed"


# ---------------------------------------------------------------------------
# Tests: Failure counting and open state
# ---------------------------------------------------------------------------


class TestFailureThreshold:
    """Tests for failure counting and transition to open state."""

    def test_failures_counted_toward_threshold(self) -> None:
        mock_backend = _make_mock_backend(
            sign_side_effect=CAError("fail", retryable=True),
        )
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=3,
            recovery_timeout=60.0,
        )
        csr = _make_csr_mock()

        for _ in range(2):
            with pytest.raises(CAError, match="fail"):
                cb.sign(csr, profile=_default_profile(), validity_days=90)
        # Still closed after 2 failures (threshold=3)
        assert cb.state == "closed"

    def test_threshold_reached_opens_circuit(self) -> None:
        mock_backend = _make_mock_backend(
            sign_side_effect=CAError("fail", retryable=True),
        )
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=3,
            recovery_timeout=60.0,
        )
        csr = _make_csr_mock()

        for _ in range(3):
            with pytest.raises(CAError):
                cb.sign(csr, profile=_default_profile(), validity_days=90)

        assert cb.state == "open"

    def test_open_circuit_raises_immediately(self) -> None:
        """Once open, calls should fail fast without hitting the backend."""
        mock_backend = _make_mock_backend(
            sign_side_effect=CAError("fail", retryable=True),
        )
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=2,
            recovery_timeout=60.0,
        )
        csr = _make_csr_mock()

        # Trip the circuit
        for _ in range(2):
            with pytest.raises(CAError):
                cb.sign(csr, profile=_default_profile(), validity_days=90)

        assert cb.state == "open"
        call_count_before = mock_backend.sign.call_count

        # Next call should fail fast
        with pytest.raises(CAError, match="circuit breaker is open"):
            cb.sign(csr, profile=_default_profile(), validity_days=90)

        # Backend should NOT have been called again
        assert mock_backend.sign.call_count == call_count_before

    def test_open_state_retryable_flag(self) -> None:
        mock_backend = _make_mock_backend(
            sign_side_effect=CAError("fail", retryable=True),
        )
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=1,
            recovery_timeout=60.0,
        )
        csr = _make_csr_mock()

        with pytest.raises(CAError):
            cb.sign(csr, profile=_default_profile(), validity_days=90)

        try:
            cb.sign(csr, profile=_default_profile(), validity_days=90)
        except CAError as exc:
            assert exc.retryable is True


# ---------------------------------------------------------------------------
# Tests: Half-open state
# ---------------------------------------------------------------------------


class TestHalfOpenState:
    """Tests for the half-open state transition."""

    def _trip_circuit(self, cb, mock_backend, threshold):
        """Helper to trip the circuit to open state."""
        csr = _make_csr_mock()
        for _ in range(threshold):
            with pytest.raises(CAError):
                cb.sign(csr, profile=_default_profile(), validity_days=90)

    def test_open_transitions_to_half_open_after_timeout(self) -> None:
        mock_backend = _make_mock_backend(
            sign_side_effect=CAError("fail", retryable=True),
        )
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=2,
            recovery_timeout=0.01,
        )
        self._trip_circuit(cb, mock_backend, 2)
        assert cb.state == "open"

        # Wait for recovery timeout
        time.sleep(0.02)

        # Now make the backend succeed for the probe
        mock_backend.sign.side_effect = None
        mock_backend.sign.return_value = _make_issued_cert()

        csr = _make_csr_mock()
        result = cb.sign(csr, profile=_default_profile(), validity_days=90)
        assert isinstance(result, IssuedCertificate)
        assert cb.state == "closed"

    def test_half_open_probe_success_resets_to_closed(self) -> None:
        mock_backend = _make_mock_backend(
            sign_side_effect=CAError("fail", retryable=True),
        )
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=1,
            recovery_timeout=0.01,
        )
        self._trip_circuit(cb, mock_backend, 1)
        assert cb.state == "open"

        time.sleep(0.02)
        mock_backend.sign.side_effect = None
        mock_backend.sign.return_value = _make_issued_cert()

        csr = _make_csr_mock()
        cb.sign(csr, profile=_default_profile(), validity_days=90)
        assert cb.state == "closed"

    def test_half_open_probe_failure_reopens(self) -> None:
        mock_backend = _make_mock_backend(
            sign_side_effect=CAError("fail", retryable=True),
        )
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=1,
            recovery_timeout=0.01,
        )
        self._trip_circuit(cb, mock_backend, 1)
        assert cb.state == "open"

        time.sleep(0.02)
        # Backend still fails
        csr = _make_csr_mock()
        with pytest.raises(CAError, match="fail"):
            cb.sign(csr, profile=_default_profile(), validity_days=90)

        assert cb.state == "open"

    def test_half_open_max_calls_exceeded_raises(self) -> None:
        mock_backend = _make_mock_backend(
            sign_side_effect=CAError("fail", retryable=True),
        )
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=1,
            recovery_timeout=0.01,
            half_open_max_calls=1,
        )
        self._trip_circuit(cb, mock_backend, 1)
        assert cb.state == "open"

        time.sleep(0.02)

        # Manually transition to half_open and simulate an active probe
        # by incrementing the counter
        with cb._lock:
            cb._state = cb._state  # keep as open
        # Let the first call transition to half_open
        # Make the backend hang (we use side_effect to control behavior)
        # Instead, we manually set the state
        with cb._lock:
            from acmeeh.ca.circuit_breaker import _State

            cb._state = _State.HALF_OPEN
            cb._half_open_calls = 1  # simulate one probe already in progress

        csr = _make_csr_mock()
        with pytest.raises(CAError, match="half-open"):
            cb.sign(csr, profile=_default_profile(), validity_days=90)


# ---------------------------------------------------------------------------
# Tests: Non-retryable errors
# ---------------------------------------------------------------------------


class TestNonRetryableErrors:
    """Non-retryable CAErrors should not count toward threshold."""

    def test_non_retryable_ca_error_not_counted(self) -> None:
        mock_backend = _make_mock_backend(
            sign_side_effect=CAError("bad input", retryable=False),
        )
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=2,
            recovery_timeout=60.0,
        )
        csr = _make_csr_mock()

        # Even after many non-retryable failures, circuit stays closed
        for _ in range(10):
            with pytest.raises(CAError, match="bad input"):
                cb.sign(csr, profile=_default_profile(), validity_days=90)

        assert cb.state == "closed"


# ---------------------------------------------------------------------------
# Tests: Non-CAError exceptions
# ---------------------------------------------------------------------------


class TestNonCAErrorExceptions:
    """Non-CAError exceptions should be wrapped in CAError."""

    def test_non_ca_error_wrapped(self) -> None:
        mock_backend = _make_mock_backend(
            sign_side_effect=RuntimeError("unexpected"),
        )
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=3,
        )
        csr = _make_csr_mock()

        with pytest.raises(CAError, match="unexpected") as exc_info:
            cb.sign(csr, profile=_default_profile(), validity_days=90)
        assert exc_info.value.retryable is True
        assert isinstance(exc_info.value.__cause__, RuntimeError)

    def test_non_ca_error_on_revoke_wrapped(self) -> None:
        mock_backend = _make_mock_backend(
            revoke_side_effect=RuntimeError("revoke fail"),
        )
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=3,
        )
        with pytest.raises(CAError, match="revoke fail") as exc_info:
            cb.revoke(
                serial_number="abc",
                certificate_pem="pem",
                reason=None,
            )
        assert exc_info.value.retryable is True


# ---------------------------------------------------------------------------
# Tests: Revoke through circuit breaker
# ---------------------------------------------------------------------------


class TestRevokeThroughCircuitBreaker:
    """Tests for revoke with circuit breaker states."""

    def test_revoke_success_resets_failures(self) -> None:
        call_count = [0]

        def sign_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 1:
                raise CAError("transient", retryable=True)
            return _make_issued_cert()

        mock_backend = _make_mock_backend(sign_side_effect=sign_side_effect)
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=3,
        )
        csr = _make_csr_mock()

        # One sign failure
        with pytest.raises(CAError):
            cb.sign(csr, profile=_default_profile(), validity_days=90)

        # Successful revoke should reset
        cb.revoke(
            serial_number="abc",
            certificate_pem="pem",
            reason=None,
        )
        assert cb.state == "closed"

    def test_revoke_failure_counts(self) -> None:
        mock_backend = _make_mock_backend(
            revoke_side_effect=CAError("revoke fail", retryable=True),
        )
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
            failure_threshold=2,
        )
        for _ in range(2):
            with pytest.raises(CAError):
                cb.revoke(
                    serial_number="abc",
                    certificate_pem="pem",
                    reason=None,
                )
        assert cb.state == "open"


# ---------------------------------------------------------------------------
# Tests: startup_check
# ---------------------------------------------------------------------------


class TestStartupCheck:
    """Tests for startup_check delegation."""

    def test_startup_check_delegates(self) -> None:
        mock_backend = _make_mock_backend()
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
        )
        cb.startup_check()
        mock_backend.startup_check.assert_called_once()

    def test_startup_check_propagates_error(self) -> None:
        mock_backend = _make_mock_backend()
        mock_backend.startup_check.side_effect = CAError("startup fail")
        cb = CircuitBreakerCABackend(
            mock_backend,
            _make_ca_settings(),
        )
        with pytest.raises(CAError, match="startup fail"):
            cb.startup_check()
