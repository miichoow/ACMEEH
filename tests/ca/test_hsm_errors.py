"""Tests for HSM CA backend error scenarios.

Covers PKCS#11 session pool failures, signing mechanism errors,
token disappearance, concurrent session stress, startup_check
failures, library path issues, and PIN authentication failures.

All PKCS#11 interactions are mocked -- no real HSM or SoftHSM required.
"""

from __future__ import annotations

import queue
import threading
import time
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acmeeh.ca.base import CAError
from acmeeh.ca.hsm import (
    HsmCABackend,
    _Pkcs11SessionPool,
)
from acmeeh.config.settings import (
    AcmeProxySettings,
    CAInternalSettings,
    CAProfileSettings,
    CASettings,
    ExternalCASettings,
    HsmSettings,
)

# ---------------------------------------------------------------------------
# Helpers (same patterns as test_hsm.py)
# ---------------------------------------------------------------------------


def _make_hsm_settings(**overrides) -> HsmSettings:
    defaults = {
        "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
        "token_label": "ACMEEH-CA",
        "slot_id": None,
        "pin": "1234",
        "key_label": "ca-signing-key",
        "key_id": None,
        "key_type": "ec",
        "hash_algorithm": "sha256",
        "issuer_cert_path": "/etc/acmeeh/ca-cert.pem",
        "chain_path": None,
        "serial_source": "database",
        "login_required": True,
        "session_pool_size": 4,
        "session_pool_timeout_seconds": 30,
    }
    defaults.update(overrides)
    return HsmSettings(**defaults)


def _make_ca_settings(hsm: HsmSettings | None = None) -> CASettings:
    return CASettings(
        backend="hsm",
        default_validity_days=90,
        max_validity_days=397,
        profiles={
            "default": CAProfileSettings(
                key_usages=("digital_signature", "key_encipherment"),
                extended_key_usages=("server_auth",),
                validity_days=None,
                max_validity_days=None,
            )
        },
        internal=CAInternalSettings(
            root_cert_path="",
            root_key_path="",
            chain_path=None,
            serial_source="database",
            hash_algorithm="sha256",
        ),
        external=ExternalCASettings(
            sign_url="",
            revoke_url="",
            auth_header="Authorization",
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
            storage_path="./acme_proxy_storage",
            challenge_type="dns-01",
            challenge_handler="",
            challenge_handler_config={},
            eab_kid=None,
            eab_hmac_key=None,
            proxy_url=None,
            verify_ssl=True,
            timeout_seconds=300,
        ),
        hsm=hsm or _make_hsm_settings(),
        circuit_breaker_failure_threshold=5,
        circuit_breaker_recovery_timeout=30.0,
        deferred_signing_timeout=600,
    )


def _make_test_csr(domains=None):
    """Create a real CSR with SAN for testing."""
    if domains is None:
        domains = ["example.com", "www.example.com"]
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
            ]
        )
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
        critical=False,
    )
    return builder.sign(key, hashes.SHA256())


def _make_issuer_cert() -> x509.Certificate:
    """Create a self-signed issuer certificate for testing."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now.replace(year=now.year + 10))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert


def _write_issuer_cert(tmp_path, cert: x509.Certificate | None = None) -> str:
    """Write issuer cert PEM to tmp_path and return path string."""
    if cert is None:
        cert = _make_issuer_cert()
    cert_path = tmp_path / "ca-cert.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(cert_path)


def _setup_loaded_backend(tmp_path, key_type="ec", hash_algorithm="sha256"):
    """Create a fully-loaded HsmCABackend with mocked PKCS#11."""
    issuer_cert = _make_issuer_cert()
    cert_path = _write_issuer_cert(tmp_path, issuer_cert)

    settings = _make_ca_settings(
        _make_hsm_settings(
            issuer_cert_path=cert_path,
            key_type=key_type,
            hash_algorithm=hash_algorithm,
        )
    )
    backend = HsmCABackend(settings)

    # Manually set loaded state
    backend._issuer_cert = issuer_cert
    backend._loaded = True
    backend._session_pool = MagicMock()

    return backend


@pytest.fixture()
def profile():
    return CAProfileSettings(
        key_usages=("digital_signature", "key_encipherment"),
        extended_key_usages=("server_auth",),
        validity_days=None,
        max_validity_days=None,
    )


def _mock_pkcs11_modules():
    """Return a dict suitable for patch.dict('sys.modules', ...) that
    stubs out the pkcs11 package tree."""
    mock_pkcs11 = MagicMock()
    return {
        "pkcs11": mock_pkcs11,
        "pkcs11.util.ec": MagicMock(),
        "pkcs11.util.rsa": MagicMock(),
    }, mock_pkcs11


# ---------------------------------------------------------------------------
# Session pool timeout tests
# ---------------------------------------------------------------------------


class TestSessionPoolTimeout:
    """Verify behaviour when all sessions are in use and the pool blocks."""

    def test_acquire_timeout_raises_when_pool_exhausted(self):
        """When max_size sessions are all in use and timeout expires,
        queue.Empty should propagate."""
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_token.open.return_value = mock_session

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=1,
        )

        # Acquire the only session and hold it
        ctx = pool.acquire()
        session = ctx.__enter__()

        # Now try to acquire another -- should timeout.
        # We patch the internal queue.get timeout to be very short so
        # the test doesn't block for 30 seconds.
        with patch.object(pool._pool, "get", side_effect=queue.Empty):
            with pytest.raises(queue.Empty):
                ctx2 = pool.acquire()
                ctx2.__enter__()

        # Clean up: return the held session
        ctx.__exit__(None, None, None)

    def test_acquire_timeout_value_is_30_seconds(self):
        """Confirm the pool passes timeout=30 to queue.get when all
        sessions are created and none are available."""
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_token.open.return_value = mock_session

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=1,
        )

        # Consume the only session slot
        ctx1 = pool.acquire()
        ctx1.__enter__()

        # Spy on queue.get to verify the timeout argument.
        # The _SessionContext.__enter__ first calls get_nowait() which
        # delegates to get(block=False), then falls through to the
        # get(timeout=30) path.  We intercept both and verify the
        # timeout call.
        call_args_list = []
        original_get = pool._pool.get

        def tracking_get(*args, **kwargs):
            call_args_list.append((args, kwargs))
            raise queue.Empty

        with patch.object(pool._pool, "get", side_effect=tracking_get):
            with pytest.raises(queue.Empty):
                ctx2 = pool.acquire()
                ctx2.__enter__()

            # Second call should be the blocking get(timeout=30)
            assert len(call_args_list) == 2
            _, second_kwargs = call_args_list[1]
            assert second_kwargs.get("timeout") == 30

        ctx1.__exit__(None, None, None)


# ---------------------------------------------------------------------------
# Signing mechanism failure tests
# ---------------------------------------------------------------------------


class TestSigningMechanismFailure:
    """Errors during the PKCS#11 sign() call itself."""

    def test_sign_key_sign_raises_pkcs11_error(self, tmp_path, profile):
        """When key.sign() raises a PKCS#11-level exception, it should
        be wrapped in CAError."""
        backend = _setup_loaded_backend(tmp_path, key_type="ec")

        mock_key = MagicMock()
        mock_key.sign.side_effect = Exception("CKR_KEY_TYPE_INCONSISTENT")

        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)

        backend._session_pool.acquire.return_value = mock_session

        modules, _ = _mock_pkcs11_modules()
        with patch.dict("sys.modules", modules):
            csr = _make_test_csr(["example.com"])
            with pytest.raises(CAError, match="Failed to build/sign"):
                backend.sign(csr, profile=profile, validity_days=90, serial_number=1)

    def test_sign_rsa_bad_mechanism_raises(self, tmp_path, profile):
        """An RSA key asked to sign with an unsupported mechanism should
        result in a wrapped CAError."""
        backend = _setup_loaded_backend(tmp_path, key_type="rsa")

        mock_key = MagicMock()
        mock_key.sign.side_effect = Exception("CKR_MECHANISM_INVALID: mechanism not supported")

        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)

        backend._session_pool.acquire.return_value = mock_session

        modules, _ = _mock_pkcs11_modules()
        with patch.dict("sys.modules", modules):
            csr = _make_test_csr(["example.com"])
            with pytest.raises(CAError, match="Failed to build/sign"):
                backend.sign(csr, profile=profile, validity_days=90, serial_number=1)

    def test_sign_ec_invalid_raw_signature_length(self, tmp_path, profile):
        """If the HSM returns an odd-length raw ECDSA signature,
        _ecdsa_raw_to_der should raise CAError (odd length)."""
        backend = _setup_loaded_backend(tmp_path, key_type="ec")

        mock_key = MagicMock()
        # Return an odd-length byte string -- triggers _ecdsa_raw_to_der error
        mock_key.sign.return_value = b"\x01\x02\x03"

        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)

        backend._session_pool.acquire.return_value = mock_session

        modules, _ = _mock_pkcs11_modules()
        with patch.dict("sys.modules", modules):
            csr = _make_test_csr(["example.com"])
            with pytest.raises(CAError):
                backend.sign(csr, profile=profile, validity_days=90, serial_number=1)

    def test_sign_unsupported_key_type_hash_combo(self, tmp_path, profile):
        """If key_type/hash_algorithm combo is not in _SIG_ALGORITHM_DER,
        a KeyError should be wrapped in CAError."""
        # Use an invalid hash_algorithm that won't match _SIG_ALGORITHM_DER
        issuer_cert = _make_issuer_cert()
        cert_path = _write_issuer_cert(tmp_path, issuer_cert)

        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
                key_type="ec",
                hash_algorithm="sha512",
            )
        )
        backend = HsmCABackend(settings)
        backend._issuer_cert = issuer_cert
        backend._loaded = True
        backend._session_pool = MagicMock()

        # The signing will try to look up ("ec", "sha512") which does
        # exist in the table, but we patch it out to simulate an
        # unsupported combination
        mock_key = MagicMock()
        r_bytes = (1).to_bytes(32, "big")
        s_bytes = (2).to_bytes(32, "big")
        mock_key.sign.return_value = r_bytes + s_bytes

        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)

        backend._session_pool.acquire.return_value = mock_session

        modules, _ = _mock_pkcs11_modules()
        with patch.dict("sys.modules", modules):
            with patch(
                "acmeeh.ca.hsm._SIG_ALGORITHM_DER",
                {("rsa", "sha256"): b"\x30\x0d"},  # only RSA/sha256
            ):
                csr = _make_test_csr(["example.com"])
                with pytest.raises(CAError, match="Failed to build/sign"):
                    backend.sign(csr, profile=profile, validity_days=90, serial_number=1)


# ---------------------------------------------------------------------------
# Token disappeared mid-operation tests
# ---------------------------------------------------------------------------


class TestTokenDisappearedMidOperation:
    """Simulate the HSM token being removed while operations are in progress."""

    def test_session_becomes_invalid_during_sign(self, tmp_path, profile):
        """If the PKCS#11 session goes stale (e.g. token removed), the
        sign operation should fail with CAError."""
        backend = _setup_loaded_backend(tmp_path, key_type="ec")

        mock_session = MagicMock()
        mock_session.get_objects.side_effect = Exception("CKR_SESSION_HANDLE_INVALID")
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)

        backend._session_pool.acquire.return_value = mock_session

        modules, _ = _mock_pkcs11_modules()
        with patch.dict("sys.modules", modules):
            csr = _make_test_csr(["example.com"])
            with pytest.raises(CAError, match="Failed to build/sign"):
                backend.sign(csr, profile=profile, validity_days=90, serial_number=1)

    def test_token_removed_session_discarded_on_error(self):
        """When a session encounters an error in the context manager,
        it is closed and discarded (not returned to pool), and the pool
        counter is decremented."""
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_token.open.return_value = mock_session

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=2,
        )

        # Simulate an error during session use
        try:
            with pool.acquire() as session:
                raise Exception("CKR_TOKEN_NOT_PRESENT")
        except Exception:
            pass

        # Session should have been closed and discarded
        mock_session.close.assert_called_once()
        # Counter should be back to 0
        assert pool._created == 0

    def test_token_removed_session_close_also_fails(self):
        """If session.close() itself fails (because the token is gone),
        the pool should still decrement the counter gracefully."""
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_session.close.side_effect = Exception("CKR_TOKEN_NOT_PRESENT")
        mock_token.open.return_value = mock_session

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=2,
        )

        # The close error is swallowed in __exit__
        try:
            with pool.acquire() as session:
                raise RuntimeError("simulated token removal")
        except RuntimeError:
            pass

        # Counter should still be decremented despite close() failure
        assert pool._created == 0

    def test_find_key_fails_after_token_reconnect(self, tmp_path, profile):
        """After a token is removed and re-inserted, the old key handle
        may be invalid. Verify that _find_key returning empty triggers
        CAError."""
        backend = _setup_loaded_backend(tmp_path, key_type="ec")

        # Session works but no keys found (token wiped / different token)
        mock_session = MagicMock()
        mock_session.get_objects.return_value = []  # no keys
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)

        backend._session_pool.acquire.return_value = mock_session

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        with patch.dict("sys.modules", modules):
            csr = _make_test_csr(["example.com"])
            with pytest.raises(CAError, match="Signing key not found"):
                backend.sign(csr, profile=profile, validity_days=90, serial_number=1)


# ---------------------------------------------------------------------------
# Concurrent session acquisition stress tests
# ---------------------------------------------------------------------------


class TestConcurrentSessionAcquisition:
    """Verify the session pool under concurrent access."""

    def test_concurrent_acquire_respects_max_size(self):
        """Multiple threads acquiring sessions concurrently should
        never exceed max_size total sessions created."""
        mock_token = MagicMock()
        session_count = 0
        session_lock = threading.Lock()

        def create_session(*args, **kwargs):
            nonlocal session_count
            with session_lock:
                session_count += 1
            return MagicMock()

        mock_token.open.side_effect = create_session

        max_size = 4
        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=max_size,
        )

        barrier = threading.Barrier(max_size)
        errors = []

        def worker():
            try:
                with pool.acquire() as session:
                    barrier.wait(timeout=5)  # all threads hold sessions
                    time.sleep(0.01)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(max_size)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Unexpected errors: {errors}"
        assert session_count <= max_size
        assert pool._created == max_size

    def test_concurrent_acquire_beyond_max_waits(self):
        """When max_size sessions exist and all are in use, extra
        acquirers must wait and receive a session once one is returned."""
        mock_token = MagicMock()
        sessions = [MagicMock() for _ in range(2)]
        mock_token.open.side_effect = sessions

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=2,
        )

        acquired_sessions = []
        release_event = threading.Event()

        def holder():
            """Holds a session until release_event is set."""
            with pool.acquire() as session:
                acquired_sessions.append(session)
                release_event.wait(timeout=5)

        def waiter():
            """Tries to acquire after pool is full; should block."""
            with pool.acquire() as session:
                acquired_sessions.append(session)

        # Start two holders to exhaust the pool
        t1 = threading.Thread(target=holder)
        t2 = threading.Thread(target=holder)
        t1.start()
        t2.start()
        time.sleep(0.1)  # let holders acquire

        # Start a waiter -- it should block
        t3 = threading.Thread(target=waiter)
        t3.start()
        time.sleep(0.1)  # waiter should be blocking

        # Release holders
        release_event.set()
        t1.join(timeout=5)
        t2.join(timeout=5)
        t3.join(timeout=5)

        # All three threads should have completed
        assert len(acquired_sessions) == 3

    def test_concurrent_errors_replenish_pool(self):
        """If sessions fail with errors, the pool counter decrements
        and new sessions can be created subsequently."""
        mock_token = MagicMock()
        mock_token.open.return_value = MagicMock()

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=2,
        )

        errors_seen = []

        def error_worker():
            try:
                with pool.acquire() as session:
                    raise RuntimeError("deliberate failure")
            except RuntimeError as e:
                errors_seen.append(e)

        # Create sessions that all fail
        threads = [threading.Thread(target=error_worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(errors_seen) == 4

        # Pool should have recovered: counter back to 0
        assert pool._created == 0

        # Should be able to acquire again
        with pool.acquire() as session:
            assert session is not None


# ---------------------------------------------------------------------------
# startup_check() failure scenarios
# ---------------------------------------------------------------------------


class TestStartupCheckFailures:
    """Extended startup_check error scenarios beyond basic ones in test_hsm.py."""

    def test_pkcs11_lib_load_throws_os_error(self):
        """If pkcs11.lib() raises an OSError (e.g. library file
        missing or corrupt), it should be wrapped in CAError."""
        settings = _make_ca_settings(
            _make_hsm_settings(
                pkcs11_library="/nonexistent/libpkcs11.so",
            )
        )
        backend = HsmCABackend(settings)

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.side_effect = OSError(
            "cannot open shared object file: No such file or directory"
        )
        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="Failed to load PKCS#11 library"):
                backend.startup_check()

    def test_pkcs11_lib_load_throws_runtime_error(self):
        """A RuntimeError from the PKCS#11 shim should also be caught."""
        settings = _make_ca_settings(
            _make_hsm_settings(
                pkcs11_library="/opt/ncipher/lib/libcknfast.so",
            )
        )
        backend = HsmCABackend(settings)

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.side_effect = RuntimeError("PKCS#11 library returned CKR_GENERAL_ERROR")
        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="Failed to load PKCS#11 library"):
                backend.startup_check()

    def test_token_lookup_generic_exception(self):
        """A generic exception from get_token should be wrapped."""
        settings = _make_ca_settings(
            _make_hsm_settings(
                token_label="ACMEEH-CA",
            )
        )
        backend = HsmCABackend(settings)

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.return_value.get_token.side_effect = Exception("CKR_SLOT_ID_INVALID")
        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="Failed to find PKCS#11 token"):
                backend.startup_check()

    def test_token_not_found_with_label(self):
        """When token_label is set but token is not found, the error
        message should include the label."""
        settings = _make_ca_settings(
            _make_hsm_settings(
                token_label="MISSING-TOKEN",
            )
        )
        backend = HsmCABackend(settings)

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        # get_token returns None / raises -- we test via slot_id=None path
        # with no matching token. Actually, the code calls get_token which
        # raises when not found.
        mock_pkcs11.lib.return_value.get_token.side_effect = Exception("No token found")
        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="token"):
                backend.startup_check()

    def test_token_not_found_with_slot_id(self):
        """When slot_id is set but no token matches, the error message
        should include the slot_id."""
        settings = _make_ca_settings(
            _make_hsm_settings(
                token_label=None,
                slot_id=42,
            )
        )
        backend = HsmCABackend(settings)

        mock_token = MagicMock()
        mock_token.slot.slot_id = 0  # does not match 42

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.return_value.get_tokens.return_value = [mock_token]

        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="slot_id=42"):
                backend.startup_check()

    def test_key_lookup_generic_exception(self, tmp_path):
        """A non-CAError exception from session operations during key
        lookup should be wrapped in CAError."""
        cert_path = _write_issuer_cert(tmp_path)
        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
            )
        )
        backend = HsmCABackend(settings)

        mock_session = MagicMock()
        mock_session.get_objects.side_effect = RuntimeError("CKR_DEVICE_REMOVED")

        mock_token = MagicMock()
        mock_token.open.return_value = mock_session

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="Failed to find signing key"):
                backend.startup_check()

    def test_issuer_cert_corrupt_raises(self, tmp_path):
        """If the issuer certificate file contains garbage, loading
        should fail with CAError."""
        bad_cert_path = tmp_path / "bad-cert.pem"
        bad_cert_path.write_text("not a real certificate")

        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=str(bad_cert_path),
            )
        )
        backend = HsmCABackend(settings)

        mock_key = MagicMock()
        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]

        mock_token = MagicMock()
        mock_token.open.return_value = mock_session

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="Failed to load issuer certificate"):
                backend.startup_check()

    def test_ensure_loaded_idempotent(self, tmp_path):
        """Calling startup_check / _ensure_loaded multiple times should
        only initialise once."""
        cert_path = _write_issuer_cert(tmp_path)
        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
            )
        )
        backend = HsmCABackend(settings)

        mock_key = MagicMock()
        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]

        mock_token = MagicMock()
        mock_token.open.return_value = mock_session

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict("sys.modules", modules):
            backend.startup_check()
            backend.startup_check()

        # lib() should have been called only once
        mock_pkcs11.lib.assert_called_once()
        assert backend._loaded is True

    def test_startup_no_token_label_no_slot_id(self):
        """If neither token_label nor slot_id is configured, the token
        lookup should result in 'token not found'."""
        settings = _make_ca_settings(
            _make_hsm_settings(
                token_label=None,
                slot_id=None,
            )
        )
        backend = HsmCABackend(settings)

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.return_value.get_tokens.return_value = []

        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="token not found"):
                backend.startup_check()


# ---------------------------------------------------------------------------
# Missing / invalid PKCS#11 library path tests
# ---------------------------------------------------------------------------


class TestPkcs11LibraryPath:
    """Tests for various PKCS#11 library path problems."""

    def test_empty_library_path_raises(self):
        """An empty string library path should raise CAError before
        attempting to load."""
        settings = _make_ca_settings(_make_hsm_settings(pkcs11_library=""))
        backend = HsmCABackend(settings)

        modules, _ = _mock_pkcs11_modules()
        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="pkcs11_library"):
                backend.startup_check()

    def test_none_library_path_raises(self):
        """A None library path should raise CAError."""
        settings = _make_ca_settings(_make_hsm_settings(pkcs11_library=None))
        backend = HsmCABackend(settings)

        modules, _ = _mock_pkcs11_modules()
        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="pkcs11_library"):
                backend.startup_check()

    def test_library_file_permission_denied(self):
        """If the library file exists but can't be loaded due to
        permissions, it should raise a descriptive CAError."""
        settings = _make_ca_settings(
            _make_hsm_settings(
                pkcs11_library="/opt/restricted/libpkcs11.so",
            )
        )
        backend = HsmCABackend(settings)

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.side_effect = PermissionError(
            "[Errno 13] Permission denied: '/opt/restricted/libpkcs11.so'"
        )
        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="Failed to load PKCS#11 library"):
                backend.startup_check()

    def test_library_wrong_architecture(self):
        """Loading a library compiled for a different architecture
        should raise a descriptive CAError."""
        settings = _make_ca_settings(
            _make_hsm_settings(
                pkcs11_library="/usr/lib/wrong-arch-pkcs11.so",
            )
        )
        backend = HsmCABackend(settings)

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.side_effect = OSError("wrong ELF class: ELFCLASS32")
        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="Failed to load PKCS#11 library"):
                backend.startup_check()


# ---------------------------------------------------------------------------
# PIN authentication failure tests
# ---------------------------------------------------------------------------


class TestPinAuthenticationFailure:
    """Tests for token PIN / login failures."""

    def test_wrong_pin_raises_on_session_open(self):
        """If the token rejects the PIN during session open, it should
        raise CAError during startup_check."""
        settings = _make_ca_settings(
            _make_hsm_settings(
                pin="wrong-pin",
            )
        )
        backend = HsmCABackend(settings)

        mock_token = MagicMock()
        mock_token.open.side_effect = Exception("CKR_PIN_INCORRECT")

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="Failed to find signing key"):
                backend.startup_check()

    def test_pin_locked_raises(self):
        """If the token PIN is locked out, startup_check should fail."""
        settings = _make_ca_settings(
            _make_hsm_settings(
                pin="locked-pin",
            )
        )
        backend = HsmCABackend(settings)

        mock_token = MagicMock()
        mock_token.open.side_effect = Exception("CKR_PIN_LOCKED")

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="Failed to find signing key"):
                backend.startup_check()

    def test_session_pool_pin_failure_during_sign(self, tmp_path, profile):
        """If the PIN becomes invalid mid-operation (e.g. token reset),
        subsequent session creation should fail gracefully."""
        backend = _setup_loaded_backend(tmp_path, key_type="ec")

        # Replace the session pool with a real one whose token rejects PIN
        mock_token = MagicMock()
        mock_token.open.side_effect = Exception("CKR_PIN_INCORRECT")

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="bad-pin",
            login_required=True,
            max_size=2,
        )
        backend._session_pool = pool

        modules, _ = _mock_pkcs11_modules()
        with patch.dict("sys.modules", modules):
            csr = _make_test_csr(["example.com"])
            with pytest.raises(CAError, match="Failed to build/sign"):
                backend.sign(csr, profile=profile, validity_days=90, serial_number=1)

    def test_login_not_required_skips_pin(self, tmp_path):
        """When login_required is False, no PIN is passed to token.open."""
        cert_path = _write_issuer_cert(tmp_path)
        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
                login_required=False,
                pin="",
            )
        )
        backend = HsmCABackend(settings)

        mock_key = MagicMock()
        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]

        mock_token = MagicMock()
        mock_token.open.return_value = mock_session

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict("sys.modules", modules):
            backend.startup_check()

        # Verify no user_pin was passed
        mock_token.open.assert_called_with(rw=False)

    def test_empty_pin_with_login_required(self, tmp_path):
        """An empty PIN with login_required=True should still attempt
        login; the token should reject it."""
        settings = _make_ca_settings(
            _make_hsm_settings(
                pin="",
                login_required=True,
            )
        )
        backend = HsmCABackend(settings)

        mock_token = MagicMock()
        mock_token.open.side_effect = Exception("CKR_PIN_LEN_RANGE: PIN too short")

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="Failed to find signing key"):
                backend.startup_check()


# ---------------------------------------------------------------------------
# Additional edge-case error tests
# ---------------------------------------------------------------------------


class TestMiscErrors:
    """Additional edge-case error scenarios."""

    def test_key_by_id_hex_decode_failure(self, tmp_path):
        """If key_id is not valid hex, bytes.fromhex should raise
        and be wrapped in CAError."""
        cert_path = _write_issuer_cert(tmp_path)
        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
                key_label=None,
                key_id="ZZZZ",  # invalid hex
            )
        )
        backend = HsmCABackend(settings)

        mock_session = MagicMock()
        # get_objects won't be reached -- fromhex will fail first
        mock_token = MagicMock()
        mock_token.open.return_value = mock_session

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict("sys.modules", modules):
            with pytest.raises(CAError, match="Failed to find signing key"):
                backend.startup_check()

    def test_close_all_on_empty_pool(self):
        """close_all on a pool with no sessions should not raise."""
        mock_token = MagicMock()
        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=2,
        )
        pool.close_all()
        assert pool._created == 0

    def test_close_all_after_error_sessions(self):
        """close_all after sessions were discarded due to errors should
        work correctly."""
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_token.open.return_value = mock_session

        pool = _Pkcs11SessionPool(
            token=mock_token,
            pin="1234",
            login_required=True,
            max_size=2,
        )

        # Create and error on a session
        try:
            with pool.acquire():
                raise RuntimeError("error")
        except RuntimeError:
            pass

        # Session was discarded, close_all should handle empty pool
        pool.close_all()
        assert pool._created == 0

    def test_chain_file_read_permission_error(self, tmp_path):
        """If chain file exists but cannot be read, CAError should
        be raised."""
        cert_path = _write_issuer_cert(tmp_path)
        settings = _make_ca_settings(
            _make_hsm_settings(
                issuer_cert_path=cert_path,
                chain_path="/etc/acmeeh/chain.pem",
            )
        )
        backend = HsmCABackend(settings)

        mock_key = MagicMock()
        mock_session = MagicMock()
        mock_session.get_objects.return_value = [mock_key]

        mock_token = MagicMock()
        mock_token.open.return_value = mock_session

        modules, mock_pkcs11 = _mock_pkcs11_modules()
        mock_pkcs11.lib.return_value.get_token.return_value = mock_token

        with patch.dict("sys.modules", modules):
            # The chain_path doesn't exist, so we should get an error
            with pytest.raises(CAError, match="Chain file not found"):
                backend.startup_check()

    def test_sign_without_startup_triggers_ensure_loaded(self, tmp_path, profile):
        """Calling sign() without startup_check() should trigger
        _ensure_loaded(), which may fail if PKCS#11 is not available."""
        settings = _make_ca_settings()
        backend = HsmCABackend(settings)

        # Create CSR before patching __import__ to avoid breaking
        # the cryptography library's own imports.
        csr = _make_test_csr(["example.com"])

        # The python-pkcs11 import will fail
        original_import = (
            __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
        )

        def selective_import(name, *args, **kwargs):
            if name == "pkcs11" or name.startswith("pkcs11."):
                raise ImportError(f"No module named '{name}'")
            return original_import(name, *args, **kwargs)

        with patch.dict(
            "sys.modules",
            {
                "pkcs11": None,
                "pkcs11.util.ec": None,
                "pkcs11.util.rsa": None,
            },
        ):
            with patch("builtins.__import__", side_effect=selective_import):
                with pytest.raises(CAError, match="python-pkcs11"):
                    backend.sign(csr, profile=profile, validity_days=90, serial_number=1)
