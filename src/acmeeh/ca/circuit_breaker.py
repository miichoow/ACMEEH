"""Circuit breaker for CA backend calls.

Wraps a :class:`CABackend` to protect against cascading failures when
the backend is unreachable or overloaded.  Implements the standard
closed/open/half-open state machine.

States:
    **closed** — requests pass through normally.  Failures are counted.
    **open** — requests fail immediately with ``CAError``.
    **half-open** — one probe request is allowed through; success resets
    to closed, failure reopens.

Usage::

    from acmeeh.ca.circuit_breaker import CircuitBreakerCABackend

    protected = CircuitBreakerCABackend(real_backend, settings)
    cert = protected.sign(csr, profile=..., validity_days=90)
"""

from __future__ import annotations

import logging
import threading
import time
from enum import Enum
from typing import TYPE_CHECKING

from acmeeh.ca.base import CABackend, CAError, IssuedCertificate

if TYPE_CHECKING:
    from cryptography import x509

    from acmeeh.config.settings import CAProfileSettings, CASettings
    from acmeeh.core.types import RevocationReason

log = logging.getLogger(__name__)


class _State(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerCABackend(CABackend):
    """Transparent circuit breaker wrapper around a real CA backend.

    Parameters
    ----------
    backend:
        The real CA backend to protect.
    ca_settings:
        CA configuration (passed to the base class).
    failure_threshold:
        Number of consecutive failures before opening the circuit.
    recovery_timeout:
        Seconds to wait in the open state before allowing a probe.
    half_open_max_calls:
        Maximum concurrent probe calls in half-open state.

    """

    def __init__(
        self,
        backend: CABackend,
        ca_settings: CASettings,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 1,
    ) -> None:
        super().__init__(ca_settings)
        self._backend = backend
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._half_open_max_calls = half_open_max_calls

        self._lock = threading.Lock()
        self._state = _State.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._half_open_calls = 0

    @property
    def deferred(self) -> bool:
        """Delegate to the wrapped backend."""
        return self._backend.deferred

    @property
    def state(self) -> str:
        """Current circuit state as a string."""
        with self._lock:
            return self._state.value

    def sign(
        self,
        csr: x509.CertificateSigningRequest,
        *,
        profile: CAProfileSettings,
        validity_days: int,
        serial_number: int | None = None,
        ct_submitter=None,
    ) -> IssuedCertificate:
        self._check_state()
        try:
            result = self._backend.sign(
                csr,
                profile=profile,
                validity_days=validity_days,
                serial_number=serial_number,
                ct_submitter=ct_submitter,
            )
            self._on_success()
            return result
        except CAError as exc:
            self._on_failure(exc)
            raise
        except Exception as exc:
            self._on_failure(exc)
            raise CAError(str(exc), retryable=True) from exc

    def revoke(
        self,
        *,
        serial_number: str,
        certificate_pem: str,
        reason: RevocationReason | None = None,
    ) -> None:
        self._check_state()
        try:
            self._backend.revoke(
                serial_number=serial_number,
                certificate_pem=certificate_pem,
                reason=reason,
            )
            self._on_success()
        except CAError as exc:
            self._on_failure(exc)
            raise
        except Exception as exc:
            self._on_failure(exc)
            raise CAError(str(exc), retryable=True) from exc

    def startup_check(self) -> None:
        self._backend.startup_check()

    def _check_state(self) -> None:
        """Raise immediately if the circuit is open (fail-fast)."""
        with self._lock:
            if self._state == _State.CLOSED:
                return

            if self._state == _State.OPEN:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self._recovery_timeout:
                    self._state = _State.HALF_OPEN
                    self._half_open_calls = 0
                    log.info(
                        "CA circuit breaker: open -> half_open (recovery timeout %.1fs elapsed)",
                        elapsed,
                    )
                else:
                    msg = (
                        "CA backend circuit breaker is open — "
                        f"failing fast (retry in {self._recovery_timeout - elapsed:.0f}s)"
                    )
                    raise CAError(
                        msg,
                        retryable=True,
                    )

            if self._state == _State.HALF_OPEN:
                if self._half_open_calls >= self._half_open_max_calls:
                    msg = (
                        "CA backend circuit breaker is half-open — "
                        "probe in progress, rejecting additional calls"
                    )
                    raise CAError(
                        msg,
                        retryable=True,
                    )
                self._half_open_calls += 1

    def _on_success(self) -> None:
        with self._lock:
            if self._state == _State.HALF_OPEN:
                log.info("CA circuit breaker: half_open -> closed (probe succeeded)")
            self._state = _State.CLOSED
            self._failure_count = 0
            self._half_open_calls = 0

    def _on_failure(self, exc: Exception) -> None:
        with self._lock:
            if self._state == _State.HALF_OPEN:
                self._state = _State.OPEN
                self._last_failure_time = time.monotonic()
                self._half_open_calls = 0
                log.warning(
                    "CA circuit breaker: half_open -> open (probe failed: %s)",
                    exc,
                )
                return

            # Only count retryable CA errors toward the threshold
            if isinstance(exc, CAError) and not exc.retryable:
                return

            self._failure_count += 1
            if self._failure_count >= self._failure_threshold:
                self._state = _State.OPEN
                self._last_failure_time = time.monotonic()
                log.warning(
                    "CA circuit breaker: closed -> open (threshold %d reached: %s)",
                    self._failure_threshold,
                    exc,
                )
