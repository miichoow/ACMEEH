"""Comprehensive unit tests for acmeeh.ca.failover.FailoverCABackend."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from acmeeh.ca.base import CABackend, CAError, IssuedCertificate
from acmeeh.ca.failover import FailoverCABackend
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


def _make_issued_cert(serial: str = "abc123") -> IssuedCertificate:
    return IssuedCertificate(
        pem_chain="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        not_before=datetime.now(UTC),
        not_after=datetime.now(UTC),
        serial_number=serial,
        fingerprint="deadbeef" * 8,
    )


def _make_mock_backend(
    name: str = "mock",
    sign_result: IssuedCertificate | None = None,
    sign_side_effect=None,
    revoke_side_effect=None,
    startup_side_effect=None,
) -> MagicMock:
    mock = MagicMock(spec=CABackend)
    if sign_side_effect:
        mock.sign.side_effect = sign_side_effect
    elif sign_result:
        mock.sign.return_value = sign_result
    else:
        mock.sign.return_value = _make_issued_cert()
    if revoke_side_effect:
        mock.revoke.side_effect = revoke_side_effect
    if startup_side_effect:
        mock.startup_check.side_effect = startup_side_effect
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
# Tests: Constructor
# ---------------------------------------------------------------------------


class TestFailoverConstructor:
    """Tests for FailoverCABackend.__init__."""

    def test_empty_backends_raises(self) -> None:
        with pytest.raises(CAError, match="at least one backend"):
            FailoverCABackend([], _make_ca_settings())

    def test_single_backend_accepted(self) -> None:
        mock = _make_mock_backend()
        fo = FailoverCABackend([("primary", mock)], _make_ca_settings())
        assert fo._backends == [("primary", mock)]

    def test_multiple_backends_accepted(self) -> None:
        b1 = _make_mock_backend()
        b2 = _make_mock_backend()
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )
        assert len(fo._backends) == 2

    def test_initial_health_all_true(self) -> None:
        b1 = _make_mock_backend()
        b2 = _make_mock_backend()
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )
        assert fo._healthy == {"primary": True, "secondary": True}


# ---------------------------------------------------------------------------
# Tests: sign
# ---------------------------------------------------------------------------


class TestFailoverSign:
    """Tests for FailoverCABackend.sign."""

    def test_sign_returns_first_success(self) -> None:
        issued = _make_issued_cert("first")
        b1 = _make_mock_backend(sign_result=issued)
        b2 = _make_mock_backend(sign_result=_make_issued_cert("second"))
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )
        csr = _make_csr_mock()
        result = fo.sign(csr, profile=_default_profile(), validity_days=90)
        assert result.serial_number == "first"
        b1.sign.assert_called_once()
        b2.sign.assert_not_called()

    def test_sign_skips_unhealthy_backends(self) -> None:
        b1 = _make_mock_backend(sign_result=_make_issued_cert("primary"))
        b2 = _make_mock_backend(sign_result=_make_issued_cert("secondary"))
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )
        fo._healthy["primary"] = False

        csr = _make_csr_mock()
        result = fo.sign(csr, profile=_default_profile(), validity_days=90)
        assert result.serial_number == "secondary"
        b1.sign.assert_not_called()
        b2.sign.assert_called_once()

    def test_sign_fails_over_on_ca_error(self) -> None:
        b1 = _make_mock_backend(
            sign_side_effect=CAError("b1 down", retryable=True),
        )
        issued2 = _make_issued_cert("secondary")
        b2 = _make_mock_backend(sign_result=issued2)
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )

        csr = _make_csr_mock()
        result = fo.sign(csr, profile=_default_profile(), validity_days=90)
        assert result.serial_number == "secondary"
        b1.sign.assert_called_once()
        b2.sign.assert_called_once()
        # Primary should be marked unhealthy
        assert fo._healthy["primary"] is False

    def test_sign_raises_last_error_when_all_fail(self) -> None:
        b1 = _make_mock_backend(
            sign_side_effect=CAError("b1 fail", retryable=True),
        )
        b2 = _make_mock_backend(
            sign_side_effect=CAError("b2 fail", retryable=True),
        )
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )

        csr = _make_csr_mock()
        with pytest.raises(CAError, match="b2 fail"):
            fo.sign(csr, profile=_default_profile(), validity_days=90)

    def test_sign_all_unhealthy_raises(self) -> None:
        b1 = _make_mock_backend()
        b2 = _make_mock_backend()
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )
        fo._healthy["primary"] = False
        fo._healthy["secondary"] = False

        csr = _make_csr_mock()
        with pytest.raises(CAError, match="All CA backends failed"):
            fo.sign(csr, profile=_default_profile(), validity_days=90)

    def test_sign_passes_all_kwargs(self) -> None:
        b1 = _make_mock_backend()
        fo = FailoverCABackend(
            [("primary", b1)],
            _make_ca_settings(),
        )
        csr = _make_csr_mock()
        ct_mock = MagicMock()
        fo.sign(
            csr,
            profile=_default_profile(),
            validity_days=30,
            serial_number=42,
            ct_submitter=ct_mock,
        )
        b1.sign.assert_called_once_with(
            csr,
            profile=_default_profile(),
            validity_days=30,
            serial_number=42,
            ct_submitter=ct_mock,
        )


# ---------------------------------------------------------------------------
# Tests: revoke
# ---------------------------------------------------------------------------


class TestFailoverRevoke:
    """Tests for FailoverCABackend.revoke."""

    def test_revoke_succeeds_on_first(self) -> None:
        b1 = _make_mock_backend()
        b2 = _make_mock_backend()
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )
        fo.revoke(serial_number="abc", certificate_pem="pem", reason=None)
        b1.revoke.assert_called_once()
        b2.revoke.assert_not_called()

    def test_revoke_tries_all_raises_last(self) -> None:
        b1 = _make_mock_backend(
            revoke_side_effect=CAError("b1 revoke fail"),
        )
        b2 = _make_mock_backend(
            revoke_side_effect=CAError("b2 revoke fail"),
        )
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )
        with pytest.raises(CAError, match="b2 revoke fail"):
            fo.revoke(
                serial_number="abc",
                certificate_pem="pem",
                reason=None,
            )
        # Both should have been attempted
        b1.revoke.assert_called_once()
        b2.revoke.assert_called_once()

    def test_revoke_failover_to_second(self) -> None:
        b1 = _make_mock_backend(
            revoke_side_effect=CAError("b1 revoke fail"),
        )
        b2 = _make_mock_backend()
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )
        fo.revoke(serial_number="abc", certificate_pem="pem", reason=None)
        b1.revoke.assert_called_once()
        b2.revoke.assert_called_once()

    def test_revoke_no_error_when_all_succeed(self) -> None:
        b1 = _make_mock_backend()
        fo = FailoverCABackend(
            [("primary", b1)],
            _make_ca_settings(),
        )
        # Should not raise
        fo.revoke(serial_number="abc", certificate_pem="pem", reason=None)

    def test_revoke_passes_kwargs(self) -> None:
        from acmeeh.core.types import RevocationReason

        b1 = _make_mock_backend()
        fo = FailoverCABackend(
            [("primary", b1)],
            _make_ca_settings(),
        )
        fo.revoke(
            serial_number="def456",
            certificate_pem="---PEM---",
            reason=RevocationReason.KEY_COMPROMISE,
        )
        b1.revoke.assert_called_once_with(
            serial_number="def456",
            certificate_pem="---PEM---",
            reason=RevocationReason.KEY_COMPROMISE,
        )


# ---------------------------------------------------------------------------
# Tests: startup_check
# ---------------------------------------------------------------------------


class TestFailoverStartupCheck:
    """Tests for FailoverCABackend.startup_check."""

    def test_startup_check_all_healthy(self) -> None:
        b1 = _make_mock_backend()
        b2 = _make_mock_backend()
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )
        fo.startup_check()
        assert fo._healthy["primary"] is True
        assert fo._healthy["secondary"] is True

    def test_startup_check_marks_unhealthy(self) -> None:
        b1 = _make_mock_backend(startup_side_effect=CAError("b1 fail"))
        b2 = _make_mock_backend()
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )
        fo.startup_check()  # should not raise -- secondary is healthy
        assert fo._healthy["primary"] is False
        assert fo._healthy["secondary"] is True

    def test_startup_check_all_fail_raises(self) -> None:
        b1 = _make_mock_backend(startup_side_effect=CAError("b1 fail"))
        b2 = _make_mock_backend(startup_side_effect=CAError("b2 fail"))
        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )
        with pytest.raises(CAError, match="All CA backends failed startup"):
            fo.startup_check()
        assert fo._healthy["primary"] is False
        assert fo._healthy["secondary"] is False

    def test_startup_check_calls_all_backends(self) -> None:
        b1 = _make_mock_backend()
        b2 = _make_mock_backend()
        b3 = _make_mock_backend()
        fo = FailoverCABackend(
            [("a", b1), ("b", b2), ("c", b3)],
            _make_ca_settings(),
        )
        fo.startup_check()
        b1.startup_check.assert_called_once()
        b2.startup_check.assert_called_once()
        b3.startup_check.assert_called_once()

    def test_startup_check_unhealthy_recovers_on_recheck(self) -> None:
        """A previously unhealthy backend can become healthy on re-check."""
        call_count = [0]

        def startup_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                raise CAError("first call fails")
            # Second call succeeds

        b1 = _make_mock_backend()
        b1.startup_check.side_effect = startup_side_effect
        b2 = _make_mock_backend()

        fo = FailoverCABackend(
            [("primary", b1), ("secondary", b2)],
            _make_ca_settings(),
        )

        # First startup_check: b1 fails
        fo.startup_check()
        assert fo._healthy["primary"] is False

        # Second startup_check: b1 succeeds
        fo.startup_check()
        assert fo._healthy["primary"] is True
