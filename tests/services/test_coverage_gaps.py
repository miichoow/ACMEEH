"""Tests covering uncovered lines in several service modules.

Targets:
1. acmeeh.logging.security_events — 14 uncovered functions
2. acmeeh.services.key_change.KeyChangeService — 4 branches
3. acmeeh.services.nonce.NonceService — expired nonce + gc
"""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import uuid4

import pytest

# ===================================================================
# Section 1: security_events — exercise all 14 uncovered functions
# ===================================================================
from acmeeh.logging import security_events


class TestSecurityEventsKeyChanged:
    """security_events.key_changed"""

    def test_key_changed_does_not_raise(self):
        security_events.key_changed(uuid4(), "old-thumb", "new-thumb")

    def test_key_changed_with_specific_ids(self):
        aid = uuid4()
        security_events.key_changed(aid, "abc123", "def456")


class TestSecurityEventsAdminLogin:
    """admin_login_failed / succeeded / lockout"""

    def test_admin_login_failed(self):
        security_events.admin_login_failed("admin", "192.168.1.1")

    def test_admin_login_failed_empty_ip(self):
        security_events.admin_login_failed("root", "")

    def test_admin_login_succeeded(self):
        security_events.admin_login_succeeded("admin", "10.0.0.1")

    def test_admin_login_succeeded_different_user(self):
        security_events.admin_login_succeeded("operator", "172.16.0.1")

    def test_admin_login_lockout(self):
        security_events.admin_login_lockout("admin:192.168.1.1")

    def test_admin_login_lockout_empty_key(self):
        security_events.admin_login_lockout("")


class TestSecurityEventsEab:
    """eab_credential_used"""

    def test_eab_credential_used(self):
        security_events.eab_credential_used(uuid4(), "eab-kid-001")

    def test_eab_credential_used_long_kid(self):
        security_events.eab_credential_used(uuid4(), "a" * 200)


class TestSecurityEventsOrderRejected:
    """order_rejected"""

    def test_order_rejected(self):
        security_events.order_rejected(uuid4(), ["example.com"], "policy")

    def test_order_rejected_multiple_identifiers(self):
        security_events.order_rejected(uuid4(), ["a.com", "b.com", "c.com"], "rate-limit")


class TestSecurityEventsNonceInvalid:
    """nonce_invalid — short and long nonce values"""

    def test_nonce_invalid_short_value(self):
        security_events.nonce_invalid("10.0.0.1", "abc", "expired")

    def test_nonce_invalid_exact_16(self):
        security_events.nonce_invalid("10.0.0.1", "a" * 16, "expired")

    def test_nonce_invalid_long_value_truncated(self):
        # Longer than _NONCE_PREVIEW_LENGTH (16) → triggers truncation
        security_events.nonce_invalid("10.0.0.1", "x" * 100, "replayed")

    def test_nonce_invalid_17_chars(self):
        # Just over the limit
        security_events.nonce_invalid("10.0.0.1", "a" * 17, "unknown")


class TestSecurityEventsJwsAuthFailed:
    """jws_auth_failed"""

    def test_jws_auth_failed_no_thumbprint(self):
        security_events.jws_auth_failed("10.0.0.1", "bad signature")

    def test_jws_auth_failed_with_thumbprint(self):
        security_events.jws_auth_failed("10.0.0.1", "bad signature", thumbprint="abc123")


class TestSecurityEventsKeyPolicyViolation:
    """key_policy_violation"""

    def test_key_policy_violation(self):
        security_events.key_policy_violation("10.0.0.1", "RSA key too short")


class TestSecurityEventsAuthzDeactivated:
    """authorization_deactivated"""

    def test_authorization_deactivated(self):
        security_events.authorization_deactivated(uuid4(), uuid4(), "example.com")


class TestSecurityEventsExternalCa:
    """external_ca_call"""

    def test_external_ca_call_success(self):
        security_events.external_ca_call("sign", "internal", success=True)

    def test_external_ca_call_failure(self):
        security_events.external_ca_call("revoke", "external", success=False, detail="timeout")

    def test_external_ca_call_with_serial(self):
        security_events.external_ca_call("sign", "hsm", serial_number="abcdef", success=True)


class TestSecurityEventsMaintenanceMode:
    """maintenance_mode_changed"""

    def test_maintenance_enabled(self):
        security_events.maintenance_mode_changed(True, "admin")

    def test_maintenance_disabled(self):
        security_events.maintenance_mode_changed(False, "operator")


class TestSecurityEventsBulkRevocation:
    """bulk_revocation"""

    def test_bulk_revocation_basic(self):
        security_events.bulk_revocation("admin", 42)

    def test_bulk_revocation_with_reason_and_filter(self):
        security_events.bulk_revocation(
            "admin", 10, reason="key_compromise", filter_desc="serial=abc*"
        )


# ===================================================================
# Section 2: KeyChangeService — 4 uncovered branches
# ===================================================================


from acmeeh.app.errors import AcmeProblem
from acmeeh.core.jws import compute_thumbprint
from acmeeh.services.key_change import KeyChangeService

_JWK_A = {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
}
_JWK_B = {
    "kty": "EC",
    "crv": "P-256",
    "x": "iGpR3MZjpMZW8lG9bwDMJUjbFYyIyP0t63xYP-kJuZo",
    "y": "fU8HcVgA-zd5WGjjHbWYPJVfCJnVACnRwZxNKIJiEBs",
}

_THUMB_A = compute_thumbprint(_JWK_A)
_THUMB_B = compute_thumbprint(_JWK_B)


def _mock_account(thumbprint: str) -> MagicMock:
    acct = MagicMock()
    acct.jwk_thumbprint = thumbprint
    return acct


class TestKeyChangeNewKeyAlreadyInUse:
    """Line 66 — new key already associated with another account."""

    def test_raises_409_when_new_key_exists(self):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = _mock_account(_THUMB_B)

        svc = KeyChangeService(repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.rollover(uuid4(), _JWK_A, _JWK_B)

        assert exc_info.value.status == 409
        assert "already associated" in str(exc_info.value.detail)


class TestKeyChangeAccountNotFound:
    """Line 76 — account not found."""

    def test_raises_404_when_account_missing(self):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None
        repo.find_by_id.return_value = None

        svc = KeyChangeService(repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.rollover(uuid4(), _JWK_A, _JWK_B)

        assert exc_info.value.status == 404
        assert "not found" in str(exc_info.value.detail).lower()


class TestKeyChangeOldKeyMismatch:
    """Line 78 — old key does not match the account's current key."""

    def test_raises_malformed_when_old_key_wrong(self):
        different_thumb = "totally-different-thumbprint"
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None
        repo.find_by_id.return_value = _mock_account(different_thumb)

        svc = KeyChangeService(repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.rollover(uuid4(), _JWK_A, _JWK_B)

        assert "does not match" in str(exc_info.value.detail).lower()


class TestKeyChangeUpdateFails:
    """Line 86 — update_jwk returns None."""

    def test_raises_500_when_update_returns_none(self):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None
        repo.find_by_id.return_value = _mock_account(_THUMB_A)
        repo.update_jwk.return_value = None

        svc = KeyChangeService(repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.rollover(uuid4(), _JWK_A, _JWK_B)

        assert exc_info.value.status == 500
        assert "rollover failed" in str(exc_info.value.detail).lower()


class TestKeyChangeSuccess:
    """Happy-path: key rollover succeeds."""

    def test_returns_updated_account(self):
        updated = _mock_account(_THUMB_B)
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None
        repo.find_by_id.return_value = _mock_account(_THUMB_A)
        repo.update_jwk.return_value = updated

        svc = KeyChangeService(repo)
        result = svc.rollover(uuid4(), _JWK_A, _JWK_B)
        assert result is updated


# ===================================================================
# Section 3: NonceService — expired nonce (lines 85-90) + gc (line 100)
# ===================================================================


from acmeeh.services.nonce import NonceService


def _nonce_settings(**overrides):
    """Build a minimal NonceSettings-like object."""
    defaults = dict(
        expiry_seconds=3600,
        gc_interval_seconds=300,
        length=32,
        audit_consumed=False,
        max_age_seconds=60,
    )
    defaults.update(overrides)
    ns = MagicMock()
    for k, v in defaults.items():
        setattr(ns, k, v)
    return ns


class TestNonceServiceConsume:
    """consume() delegates directly to repo.consume() (single DB round-trip)."""

    def test_valid_nonce_consumed(self):
        repo = MagicMock()
        repo.consume.return_value = True

        settings = _nonce_settings(max_age_seconds=60)
        svc = NonceService(repo, settings)

        assert svc.consume("good-nonce") is True
        repo.consume.assert_called_once_with("good-nonce")

    def test_unknown_nonce_rejected(self):
        repo = MagicMock()
        repo.consume.return_value = False

        settings = _nonce_settings(max_age_seconds=60)
        svc = NonceService(repo, settings)

        assert svc.consume("missing") is False

    def test_expired_nonce_rejected(self):
        """repo.consume() returns False for expired nonces (SQL WHERE expires_at > now())."""
        repo = MagicMock()
        repo.consume.return_value = False

        settings = _nonce_settings(max_age_seconds=60)
        svc = NonceService(repo, settings)

        assert svc.consume("expired-nonce") is False


class TestNonceServiceGc:
    """Line 100 — gc() delegates to repo.gc_expired()."""

    def test_gc_returns_count(self):
        repo = MagicMock()
        repo.gc_expired.return_value = 7

        settings = _nonce_settings(max_age_seconds=60)
        svc = NonceService(repo, settings)

        assert svc.gc() == 7
        repo.gc_expired.assert_called_once()

    def test_gc_returns_zero(self):
        repo = MagicMock()
        repo.gc_expired.return_value = 0

        settings = _nonce_settings(max_age_seconds=60)
        svc = NonceService(repo, settings)

        assert svc.gc() == 0


class TestNonceServiceBatchCreation:
    """Nonce batch pre-generation creates nonces via bulk_create."""

    def test_create_refills_buffer_on_empty(self):
        repo = MagicMock()
        repo.bulk_create.return_value = 100

        settings = _nonce_settings()
        svc = NonceService(repo, settings)

        token = svc.create()
        assert token is not None
        repo.bulk_create.assert_called_once()
        # Buffer should now have 99 remaining nonces (100 - 1 returned)
        assert len(svc._buffer) == 99

    def test_create_falls_back_to_single_on_batch_failure(self):
        repo = MagicMock()
        repo.bulk_create.side_effect = RuntimeError("pool exhausted")
        repo.create.return_value = None

        settings = _nonce_settings()
        svc = NonceService(repo, settings)

        token = svc.create()
        assert token is not None
        repo.create.assert_called_once()
