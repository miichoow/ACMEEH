"""Miscellaneous coverage-gap tests across multiple small modules.

Targets remaining uncovered lines in:
- app/shutdown.py (signal handlers, track-during-shutdown, reload)
- cli/commands/inspect.py (error paths, success paths)
- logging/setup.py (audit file OSError, stack_info, context filter)
- api/decorators.py (add_acme_headers, _extract_account_id)
- core/jws.py (AcmeProblem re-raise paths in parse_jws/validate_eab_jws)
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest

# ===========================================================================
# app/shutdown.py
# ===========================================================================
from acmeeh.app.shutdown import ShutdownCoordinator


class TestShutdownTrackDuringShutdown:
    """Track starting an operation after shutdown has been initiated."""

    def test_track_during_shutdown_warns(self):
        sc = ShutdownCoordinator()
        sc._shutdown_flag.set()  # simulate shutdown already initiated
        with sc.track("late-op"):
            pass
        # Should not raise; the warning is logged


class TestShutdownInitiate:
    def test_already_shutting_down_early_return(self):
        sc = ShutdownCoordinator()
        sc._shutdown_flag.set()
        # Second call should return immediately
        sc.initiate()
        assert sc.is_shutting_down is True

    def test_timeout_with_in_flight_ops(self):
        """Initiate with 0 timeout and in-flight ops logs warning."""
        sc = ShutdownCoordinator(graceful_timeout=0)
        started = threading.Event()
        stop = threading.Event()

        def blocking_op():
            with sc.track("blocker"):
                started.set()
                stop.wait(timeout=5)

        t = threading.Thread(target=blocking_op, daemon=True)
        t.start()
        started.wait(timeout=2)

        sc.initiate()  # should return quickly (timeout=0)
        assert sc._in_flight > 0  # op still running

        stop.set()
        t.join(timeout=2)

    def test_all_ops_complete(self):
        """When no in-flight ops, initiate logs completion."""
        sc = ShutdownCoordinator()
        sc.initiate()
        assert sc.in_flight_count == 0


class TestMaintenanceModeFull:
    def test_set_and_clear(self):
        sc = ShutdownCoordinator()
        sc.set_maintenance(True)
        assert sc.maintenance_mode is True
        sc.set_maintenance(False)
        assert sc.maintenance_mode is False


class TestReloadFull:
    def test_reload_requested_and_consume(self):
        sc = ShutdownCoordinator()
        assert sc.reload_requested is False
        sc._reload_flag.set()
        assert sc.reload_requested is True
        sc.consume_reload()
        assert sc.reload_requested is False


class TestRegisterSignals:
    def test_not_main_thread_catches_value_error(self):
        """When not in main thread, ValueError is caught silently."""
        sc = ShutdownCoordinator()
        result = []

        def run():
            try:
                sc.register_signals()
                result.append("ok")
            except Exception as e:
                result.append(f"error: {e}")

        t = threading.Thread(target=run)
        t.start()
        t.join(timeout=5)
        # Should not have raised; either registered or caught ValueError
        assert len(result) == 1
        assert result[0] == "ok"


class TestRegisterReloadSignal:
    def test_no_sighup_on_windows(self):
        """On Windows where SIGHUP doesn't exist, it's a no-op."""
        sc = ShutdownCoordinator()
        # Temporarily remove SIGHUP if it exists
        sighup = getattr(signal, "SIGHUP", None)
        if sighup is not None:
            with patch.object(signal, "SIGHUP", create=False) as _:
                # Delete the attribute temporarily
                saved = signal.SIGHUP
                delattr(signal, "SIGHUP")
                try:
                    sc.register_reload_signal()  # should be no-op
                finally:
                    signal.SIGHUP = saved
        else:
            # Already on Windows — SIGHUP doesn't exist
            sc.register_reload_signal()  # should be no-op

    def test_register_reload_success(self):
        """When SIGHUP is available, register it."""
        sc = ShutdownCoordinator()
        if hasattr(signal, "SIGHUP"):
            # Save original handler
            original = signal.getsignal(signal.SIGHUP)
            try:
                sc.register_reload_signal()
                # Verify our handler was registered
                current = signal.getsignal(signal.SIGHUP)
                assert current == sc._reload_handler
            finally:
                signal.signal(signal.SIGHUP, original)
        else:
            # On Windows, just verify no-op doesn't raise
            sc.register_reload_signal()


class TestDrainProcessingChallengesFull:
    def test_none_repo(self):
        sc = ShutdownCoordinator()
        assert sc.drain_processing_challenges(None) == 0

    def test_success(self):
        sc = ShutdownCoordinator()
        repo = MagicMock()
        repo.drain_processing.return_value = 3
        assert sc.drain_processing_challenges(repo) == 3

    def test_zero_count(self):
        sc = ShutdownCoordinator()
        repo = MagicMock()
        repo.drain_processing.return_value = 0
        assert sc.drain_processing_challenges(repo) == 0

    def test_exception(self):
        sc = ShutdownCoordinator()
        repo = MagicMock()
        repo.drain_processing.side_effect = RuntimeError("db error")
        assert sc.drain_processing_challenges(repo) == 0


class TestSignalHandler:
    def test_signal_handler_starts_thread(self):
        """_signal_handler starts a thread that calls initiate."""
        sc = ShutdownCoordinator()
        with patch.object(sc, "initiate") as mock_initiate:
            sc._signal_handler(signal.SIGTERM, None)
            # Wait a bit for the daemon thread to run
            import time

            time.sleep(0.2)
            mock_initiate.assert_called_once()


class TestReloadHandler:
    def test_reload_handler_sets_flag(self):
        sc = ShutdownCoordinator()
        assert sc.reload_requested is False
        sc._reload_handler(signal.SIGTERM, None)  # signum doesn't matter
        assert sc.reload_requested is True


# ===========================================================================
# cli/commands/inspect.py
# ===========================================================================


class TestRunInspect:
    """Tests for the run_inspect dispatcher."""

    def test_no_inspect_command_exits(self):
        """Missing inspect_command attribute causes sys.exit(1)."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = MagicMock()
        args = SimpleNamespace()  # no inspect_command attribute
        with pytest.raises(SystemExit) as exc_info:
            run_inspect(config, args)
        assert exc_info.value.code == 1

    def test_unknown_subcommand_exits(self):
        """Unknown subcommand causes sys.exit(1)."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = MagicMock()
        args = SimpleNamespace(inspect_command="unknown_sub", resource_id="abc")
        with patch("acmeeh.db.init_database"):
            with pytest.raises(SystemExit) as exc_info:
                run_inspect(config, args)
            assert exc_info.value.code == 1


class TestInspectOrder:
    """Tests for _inspect_order."""

    def test_invalid_uuid_exits(self):
        from acmeeh.cli.commands.inspect import _inspect_order

        mock_db = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            _inspect_order(mock_db, "not-a-valid-uuid")
        assert exc_info.value.code == 1

    def test_order_not_found_exits(self):
        from acmeeh.cli.commands.inspect import _inspect_order

        mock_db = MagicMock()
        test_uuid = str(uuid4())
        with (
            patch("acmeeh.repositories.order.OrderRepository") as MockRepo,
            patch("acmeeh.repositories.authorization.AuthorizationRepository"),
            patch("acmeeh.repositories.challenge.ChallengeRepository"),
        ):
            mock_repo = MagicMock()
            mock_repo.find_by_id.return_value = None
            MockRepo.return_value = mock_repo
            with pytest.raises(SystemExit) as exc_info:
                _inspect_order(mock_db, test_uuid)
            assert exc_info.value.code == 1

    def test_success_with_authorizations(self):
        from acmeeh.cli.commands.inspect import _inspect_order

        mock_db = MagicMock()
        test_uuid = str(uuid4())

        mock_order = MagicMock()
        mock_order.id = uuid4()
        mock_order.account_id = uuid4()
        mock_order.status.value = "valid"
        mock_order.identifiers = [
            MagicMock(type=MagicMock(value="dns"), value="example.com"),
        ]
        mock_order.expires = None
        mock_order.created_at = None
        mock_order.certificate_id = None
        mock_order.error = None

        mock_authz = MagicMock()
        mock_authz.id = uuid4()
        mock_authz.identifier_type.value = "dns"
        mock_authz.identifier_value = "example.com"
        mock_authz.status.value = "valid"
        mock_authz.wildcard = False
        mock_authz.expires = None

        mock_challenge = MagicMock()
        mock_challenge.id = uuid4()
        mock_challenge.type.value = "http-01"
        mock_challenge.status.value = "valid"
        mock_challenge.token = "a" * 32
        mock_challenge.retry_count = 0
        mock_challenge.error = None

        authz_id = uuid4()

        with (
            patch("acmeeh.repositories.order.OrderRepository") as MockOrderRepo,
            patch("acmeeh.repositories.authorization.AuthorizationRepository") as MockAuthzRepo,
            patch("acmeeh.repositories.challenge.ChallengeRepository") as MockChalRepo,
        ):
            mock_order_repo = MagicMock()
            mock_order_repo.find_by_id.return_value = mock_order
            mock_order_repo.find_authorization_ids.return_value = [authz_id]
            MockOrderRepo.return_value = mock_order_repo

            mock_authz_repo = MagicMock()
            mock_authz_repo.find_by_id.return_value = mock_authz
            MockAuthzRepo.return_value = mock_authz_repo

            mock_chal_repo = MagicMock()
            mock_chal_repo.find_by_authorization.return_value = [mock_challenge]
            MockChalRepo.return_value = mock_chal_repo

            # Should not raise
            _inspect_order(mock_db, test_uuid)


class TestInspectCertificate:
    """Tests for _inspect_certificate."""

    def test_uuid_lookup(self):
        from acmeeh.cli.commands.inspect import _inspect_certificate

        mock_db = MagicMock()
        test_uuid = str(uuid4())

        mock_cert = MagicMock()
        mock_cert.id = uuid4()
        mock_cert.account_id = uuid4()
        mock_cert.order_id = None
        mock_cert.serial_number = "abc123"
        mock_cert.fingerprint = "aabb"
        mock_cert.not_before_cert = None
        mock_cert.not_after_cert = None
        mock_cert.revoked_at = None
        mock_cert.revocation_reason = None
        mock_cert.san_values = ["example.com"]
        mock_cert.public_key_fingerprint = "ccdd"
        mock_cert.created_at = None

        with patch("acmeeh.repositories.certificate.CertificateRepository") as MockRepo:
            mock_repo = MagicMock()
            mock_repo.find_by_id.return_value = mock_cert
            MockRepo.return_value = mock_repo
            _inspect_certificate(mock_db, test_uuid)

    def test_serial_lookup(self):
        from acmeeh.cli.commands.inspect import _inspect_certificate

        mock_db = MagicMock()

        mock_cert = MagicMock()
        mock_cert.id = uuid4()
        mock_cert.account_id = uuid4()
        mock_cert.order_id = uuid4()
        mock_cert.serial_number = "abc123def"
        mock_cert.fingerprint = "aabb"
        mock_cert.not_before_cert = None
        mock_cert.not_after_cert = None
        mock_cert.revoked_at = None
        mock_cert.revocation_reason = None
        mock_cert.san_values = []
        mock_cert.public_key_fingerprint = "ccdd"
        mock_cert.created_at = None

        with patch("acmeeh.repositories.certificate.CertificateRepository") as MockRepo:
            mock_repo = MagicMock()
            mock_repo.find_by_id.side_effect = Exception("not uuid")
            mock_repo.find_by_serial.return_value = mock_cert
            MockRepo.return_value = mock_repo
            # "abc123def" is not a valid UUID, so it falls through to serial lookup
            _inspect_certificate(mock_db, "abc123def")

    def test_not_found_exits(self):
        from acmeeh.cli.commands.inspect import _inspect_certificate

        mock_db = MagicMock()

        with patch("acmeeh.repositories.certificate.CertificateRepository") as MockRepo:
            mock_repo = MagicMock()
            mock_repo.find_by_id.return_value = None
            mock_repo.find_by_serial.return_value = None
            MockRepo.return_value = mock_repo
            with pytest.raises(SystemExit) as exc_info:
                _inspect_certificate(mock_db, str(uuid4()))
            assert exc_info.value.code == 1


class TestInspectAccount:
    """Tests for _inspect_account."""

    def test_invalid_uuid_exits(self):
        from acmeeh.cli.commands.inspect import _inspect_account

        mock_db = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            _inspect_account(mock_db, "not-a-uuid-at-all")
        assert exc_info.value.code == 1

    def test_account_not_found_exits(self):
        from acmeeh.cli.commands.inspect import _inspect_account

        mock_db = MagicMock()
        test_uuid = str(uuid4())

        with (
            patch("acmeeh.repositories.account.AccountRepository") as MockAcctRepo,
            patch("acmeeh.repositories.AccountContactRepository"),
            patch("acmeeh.repositories.order.OrderRepository"),
        ):
            mock_acct_repo = MagicMock()
            mock_acct_repo.find_by_id.return_value = None
            MockAcctRepo.return_value = mock_acct_repo

            with pytest.raises(SystemExit) as exc_info:
                _inspect_account(mock_db, test_uuid)
            assert exc_info.value.code == 1

    def test_success_with_orders(self):
        from acmeeh.cli.commands.inspect import _inspect_account

        mock_db = MagicMock()
        test_uuid = str(uuid4())

        mock_account = MagicMock()
        mock_account.id = uuid4()
        mock_account.status.value = "valid"
        mock_account.tos_agreed = True
        mock_account.created_at = None

        mock_contact = MagicMock()
        mock_contact.contact_uri = "mailto:test@example.com"

        mock_order1 = MagicMock()
        mock_order1.status.value = "valid"
        mock_order2 = MagicMock()
        mock_order2.status.value = "valid"
        mock_order3 = MagicMock()
        mock_order3.status.value = "pending"

        with (
            patch("acmeeh.repositories.account.AccountRepository") as MockAcctRepo,
            patch("acmeeh.repositories.AccountContactRepository") as MockContactRepo,
            patch("acmeeh.repositories.order.OrderRepository") as MockOrderRepo,
        ):
            mock_acct_repo = MagicMock()
            mock_acct_repo.find_by_id.return_value = mock_account
            MockAcctRepo.return_value = mock_acct_repo

            mock_contact_repo = MagicMock()
            mock_contact_repo.find_by_account.return_value = [mock_contact]
            MockContactRepo.return_value = mock_contact_repo

            mock_order_repo = MagicMock()
            mock_order_repo.find_by_account.return_value = [mock_order1, mock_order2, mock_order3]
            MockOrderRepo.return_value = mock_order_repo

            # Should not raise
            _inspect_account(mock_db, test_uuid)


# ===========================================================================
# logging/setup.py
# ===========================================================================


class TestConfigureLoggingGaps:
    """Tests for configure_logging targeting uncovered lines."""

    def _make_settings(
        self,
        *,
        log_format="json",
        level="INFO",
        audit_enabled=False,
        audit_file=None,
    ):
        audit = SimpleNamespace(
            enabled=audit_enabled,
            file=audit_file,
            max_file_size_bytes=10485760,
            backup_count=5,
        )
        return SimpleNamespace(
            format=log_format,
            level=level,
            audit=audit,
        )

    def test_json_format(self):
        from acmeeh.logging.setup import StructuredFormatter, configure_logging

        settings = self._make_settings(log_format="json")
        root = configure_logging(settings)
        assert isinstance(root.handlers[0].formatter, StructuredFormatter)

    def test_text_format(self):
        from acmeeh.logging.setup import TextFormatter, configure_logging

        settings = self._make_settings(log_format="text")
        root = configure_logging(settings)
        assert isinstance(root.handlers[0].formatter, TextFormatter)

    def test_audit_enabled_with_file(self, tmp_path):
        from acmeeh.logging.setup import configure_logging

        audit_file = str(tmp_path / "audit.log")
        settings = self._make_settings(audit_enabled=True, audit_file=audit_file)
        configure_logging(settings)

        audit_logger = logging.getLogger("acmeeh.audit")
        assert len(audit_logger.handlers) >= 1

        # Clean up
        for handler in audit_logger.handlers[:]:
            handler.close()
            audit_logger.removeHandler(handler)

    def test_audit_file_oserror(self, tmp_path):
        """OSError opening audit file logs warning, does not raise."""
        from acmeeh.logging.setup import configure_logging

        # Use an invalid path that will fail
        settings = self._make_settings(
            audit_enabled=True,
            audit_file=str(tmp_path / "nonexistent_dir" / "subdir" / "audit.log"),
        )
        # Should not raise — warning is logged
        root = configure_logging(settings)
        assert root.name == "acmeeh"


class TestRequestContextFilterGaps:
    """Tests for RequestContextFilter targeting uncovered branches."""

    def test_outside_request_context(self):
        """Without Flask context, defaults are set."""
        from acmeeh.logging.setup import RequestContextFilter

        ctx_filter = RequestContextFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="msg",
            args=(),
            exc_info=None,
        )

        result = ctx_filter.filter(record)
        assert result is True
        assert record.request_id == "-"
        assert record.client_ip == "-"
        assert record.account_id is None

    def test_inside_request_context_with_account(self):
        """With Flask context and account, all fields are populated."""
        from acmeeh.logging.setup import RequestContextFilter

        ctx_filter = RequestContextFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="msg",
            args=(),
            exc_info=None,
        )

        mock_g = MagicMock()
        mock_g.request_id = "req-xyz"
        mock_g.account = MagicMock()
        mock_g.account.id = "acct-id-999"

        mock_request = MagicMock()
        mock_request.remote_addr = "10.0.0.5"
        mock_request.method = "POST"
        mock_request.path = "/new-order"

        with (
            patch("flask.has_request_context", return_value=True),
            patch("flask.g", mock_g),
            patch("flask.request", mock_request),
        ):
            result = ctx_filter.filter(record)

        assert result is True
        assert record.request_id == "req-xyz"
        assert record.client_ip == "10.0.0.5"
        assert record.account_id == "acct-id-999"
        assert record.method == "POST"
        assert record.path == "/new-order"


class TestStructuredFormatterGaps:
    """Tests for StructuredFormatter targeting uncovered branches."""

    def test_with_exception_info(self):
        from acmeeh.logging.setup import StructuredFormatter

        formatter = StructuredFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="error occurred",
                args=(),
                exc_info=sys.exc_info(),
            )

        output = formatter.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert "ValueError" in data["exception"]

    def test_with_stack_info(self):
        from acmeeh.logging.setup import StructuredFormatter

        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="stack trace",
            args=(),
            exc_info=None,
        )
        record.stack_info = "Stack (most recent call last):\n  File test.py, line 1"

        output = formatter.format(record)
        data = json.loads(output)
        assert "stack_info" in data
        assert "test.py" in data["stack_info"]


# ===========================================================================
# api/decorators.py
# ===========================================================================


class TestAddAcmeHeaders:
    """Tests for the add_acme_headers after-request hook."""

    def test_admin_endpoint_skipped(self):
        """Admin API endpoints are skipped entirely."""
        from flask import Flask

        from acmeeh.api.decorators import add_acme_headers

        app = Flask(__name__)
        mock_container = MagicMock()
        app.extensions["container"] = mock_container

        @app.route("/admin/users", endpoint="admin_api.get_users")
        def admin_dummy():
            return "ok"

        app.after_request(add_acme_headers)

        with patch("acmeeh.api.decorators.get_container", return_value=mock_container):
            with app.test_client() as client:
                resp = client.get("/admin/users")
                assert "Replay-Nonce" not in resp.headers

    def test_normal_endpoint_adds_headers(self):
        """Normal endpoints get nonce, link, and cache-control headers."""
        from flask import Flask

        from acmeeh.api.decorators import add_acme_headers

        app = Flask(__name__)
        mock_container = MagicMock()
        mock_container.nonce_service.create_if_healthy.return_value = "fresh-nonce-abc"
        mock_container.urls.directory = "https://acme.example.com/directory"
        app.extensions["container"] = mock_container

        @app.route("/test-endpoint", endpoint="acme.new_nonce")
        def dummy():
            return "ok"

        app.after_request(add_acme_headers)

        with patch("acmeeh.api.decorators.get_container", return_value=mock_container):
            with app.test_client() as client:
                resp = client.get("/test-endpoint")
                assert resp.headers.get("Replay-Nonce") == "fresh-nonce-abc"
                assert 'rel="index"' in resp.headers.get("Link", "")
                assert resp.headers.get("Cache-Control") == "no-store"

    def test_nonce_generation_failure(self):
        """Nonce generation failure is caught; other headers still added."""
        from flask import Flask

        from acmeeh.api.decorators import add_acme_headers

        app = Flask(__name__)
        mock_container = MagicMock()
        mock_container.nonce_service.create_if_healthy.side_effect = RuntimeError("db down")
        mock_container.urls.directory = "https://acme.example.com/directory"
        app.extensions["container"] = mock_container

        @app.route("/test-endpoint", endpoint="acme.new_order")
        def dummy():
            return "ok"

        app.after_request(add_acme_headers)

        with patch("acmeeh.api.decorators.get_container", return_value=mock_container):
            with app.test_client() as client:
                resp = client.get("/test-endpoint")
                # Link and Cache-Control should still be set
                assert 'rel="index"' in resp.headers.get("Link", "")
                assert resp.headers.get("Cache-Control") == "no-store"

    def test_empty_endpoint(self):
        """When endpoint is None, treated as non-admin."""
        from flask import Flask

        from acmeeh.api.decorators import add_acme_headers

        app = Flask(__name__)
        mock_container = MagicMock()
        mock_container.nonce_service.create_if_healthy.return_value = "nonce-123"
        mock_container.urls.directory = "https://acme.example.com/directory"
        app.extensions["container"] = mock_container

        @app.route("/no-endpoint")
        def dummy():
            return "ok"

        app.after_request(add_acme_headers)

        with patch("acmeeh.api.decorators.get_container", return_value=mock_container):
            with app.test_client() as client:
                resp = client.get("/no-endpoint")
                assert resp.headers.get("Replay-Nonce") == "nonce-123"


class TestExtractAccountId:
    """Tests for _extract_account_id utility."""

    def test_valid_url(self):
        from acmeeh.api.decorators import _extract_account_id

        kid_url = "https://acme.example.com/acme/acct/550e8400-e29b-41d4-a716-446655440000"
        mock_urls = MagicMock()
        result = _extract_account_id(kid_url, mock_urls)
        assert result == UUID("550e8400-e29b-41d4-a716-446655440000")

    def test_no_acct_in_url(self):
        from acmeeh.api.decorators import _extract_account_id
        from acmeeh.app.errors import AcmeProblem

        kid_url = "https://acme.example.com/something/else"
        mock_urls = MagicMock()
        with pytest.raises(AcmeProblem, match="Cannot extract account ID"):
            _extract_account_id(kid_url, mock_urls)

    def test_invalid_uuid_after_acct(self):
        from acmeeh.api.decorators import _extract_account_id
        from acmeeh.app.errors import AcmeProblem

        kid_url = "https://acme.example.com/acme/acct/not-a-uuid"
        mock_urls = MagicMock()
        with pytest.raises(AcmeProblem, match="Invalid account ID"):
            _extract_account_id(kid_url, mock_urls)

    def test_with_trailing_path_segments(self):
        from acmeeh.api.decorators import _extract_account_id

        uid = "550e8400-e29b-41d4-a716-446655440000"
        kid_url = f"https://acme.example.com/acme/acct/{uid}/orders"
        mock_urls = MagicMock()
        result = _extract_account_id(kid_url, mock_urls)
        assert result == UUID(uid)


# ===========================================================================
# core/jws.py — AcmeProblem re-raise paths
# ===========================================================================


class TestJwsAcmeProblemReRaisePaths:
    """Tests for the `except AcmeProblem: raise` paths in parse_jws and validate_eab_jws.

    These cover lines 238-239, 247-248 in parse_jws and 919-920, 946-947, 979-980
    in validate_eab_jws. Each tests that when _b64url_decode is patched to raise
    AcmeProblem, it is re-raised (not caught by the generic except).
    """

    def test_parse_jws_payload_decode_acme_problem_reraise(self):
        """AcmeProblem during payload decode is re-raised."""
        import base64

        from acmeeh.app.errors import MALFORMED, AcmeProblem
        from acmeeh.core.jws import parse_jws

        # Build a valid JWS body with a non-empty payload
        protected = {"alg": "RS256"}
        prot_b64 = base64.urlsafe_b64encode(json.dumps(protected).encode()).rstrip(b"=").decode()
        pay_b64 = base64.urlsafe_b64encode(b'{"test": 1}').rstrip(b"=").decode()
        sig_b64 = base64.urlsafe_b64encode(b"\x00").rstrip(b"=").decode()

        body = json.dumps(
            {
                "protected": prot_b64,
                "payload": pay_b64,
                "signature": sig_b64,
            }
        ).encode()

        call_count = 0
        original_decode = __import__("acmeeh.core.jws", fromlist=["_b64url_decode"])._b64url_decode

        def patched_decode(s):
            nonlocal call_count
            call_count += 1
            # First call decodes protected header successfully
            if call_count == 1:
                return original_decode(s)
            # Second call (payload) raises AcmeProblem
            if call_count == 2:
                raise AcmeProblem(MALFORMED, "injected payload error")
            return original_decode(s)

        with patch("acmeeh.core.jws._b64url_decode", side_effect=patched_decode):
            with pytest.raises(AcmeProblem, match="injected payload error"):
                parse_jws(body)

    def test_parse_jws_signature_decode_acme_problem_reraise(self):
        """AcmeProblem during signature decode is re-raised."""
        import base64

        from acmeeh.app.errors import MALFORMED, AcmeProblem
        from acmeeh.core.jws import parse_jws

        protected = {"alg": "RS256"}
        prot_b64 = base64.urlsafe_b64encode(json.dumps(protected).encode()).rstrip(b"=").decode()
        sig_b64 = base64.urlsafe_b64encode(b"\x00").rstrip(b"=").decode()

        body = json.dumps(
            {
                "protected": prot_b64,
                "payload": "",  # empty payload (POST-as-GET)
                "signature": sig_b64,
            }
        ).encode()

        call_count = 0
        original_decode = __import__("acmeeh.core.jws", fromlist=["_b64url_decode"])._b64url_decode

        def patched_decode(s):
            nonlocal call_count
            call_count += 1
            # First call decodes protected header successfully
            if call_count == 1:
                return original_decode(s)
            # Second call (signature since payload is empty) raises AcmeProblem
            if call_count == 2:
                raise AcmeProblem(MALFORMED, "injected signature error")
            return original_decode(s)

        with patch("acmeeh.core.jws._b64url_decode", side_effect=patched_decode):
            with pytest.raises(AcmeProblem, match="injected signature error"):
                parse_jws(body)

    def test_validate_eab_inner_header_decode_acme_problem_reraise(self):
        """AcmeProblem during EAB inner header decode is re-raised."""
        import base64

        from acmeeh.app.errors import MALFORMED, AcmeProblem
        from acmeeh.core.jws import validate_eab_jws

        inner_header = {
            "alg": "HS256",
            "kid": "eab-kid-1",
            "url": "https://example.com/new-account",
        }
        inner_prot_b64 = (
            base64.urlsafe_b64encode(json.dumps(inner_header).encode()).rstrip(b"=").decode()
        )
        inner_pay_b64 = (
            base64.urlsafe_b64encode(json.dumps({"kty": "EC"}).encode()).rstrip(b"=").decode()
        )
        inner_sig_b64 = base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode()

        eab_jws = {
            "protected": inner_prot_b64,
            "payload": inner_pay_b64,
            "signature": inner_sig_b64,
        }

        def fail_decode(s):
            raise AcmeProblem(MALFORMED, "injected header decode error")

        with patch("acmeeh.core.jws._b64url_decode", side_effect=fail_decode):
            with pytest.raises(AcmeProblem, match="injected header decode error"):
                validate_eab_jws(eab_jws, {"kty": "EC"}, "hmac-key-b64")

    def test_validate_eab_payload_decode_acme_problem_reraise(self):
        """AcmeProblem during EAB payload decode is re-raised."""
        import base64

        from acmeeh.app.errors import MALFORMED, AcmeProblem
        from acmeeh.core.jws import validate_eab_jws

        inner_header = {"alg": "HS256", "kid": "eab-kid-1"}
        inner_prot_b64 = (
            base64.urlsafe_b64encode(json.dumps(inner_header).encode()).rstrip(b"=").decode()
        )
        inner_pay_b64 = (
            base64.urlsafe_b64encode(json.dumps({"kty": "EC"}).encode()).rstrip(b"=").decode()
        )
        inner_sig_b64 = base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode()

        eab_jws = {
            "protected": inner_prot_b64,
            "payload": inner_pay_b64,
            "signature": inner_sig_b64,
        }

        call_count = 0
        original_decode = __import__("acmeeh.core.jws", fromlist=["_b64url_decode"])._b64url_decode

        def patched_decode(s):
            nonlocal call_count
            call_count += 1
            # First call: inner header decode succeeds
            if call_count == 1:
                return original_decode(s)
            # Second call: payload decode raises AcmeProblem
            if call_count == 2:
                raise AcmeProblem(MALFORMED, "injected EAB payload error")
            return original_decode(s)

        with patch("acmeeh.core.jws._b64url_decode", side_effect=patched_decode):
            with pytest.raises(AcmeProblem, match="injected EAB payload error"):
                validate_eab_jws(eab_jws, {"kty": "EC"}, "hmac-key-b64")

    def test_validate_eab_signature_decode_acme_problem_reraise(self):
        """AcmeProblem during EAB signature decode is re-raised."""
        import base64

        from acmeeh.app.errors import MALFORMED, AcmeProblem
        from acmeeh.core.jws import validate_eab_jws

        outer_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}
        inner_header = {"alg": "HS256", "kid": "eab-kid-1"}
        inner_prot_b64 = (
            base64.urlsafe_b64encode(json.dumps(inner_header).encode()).rstrip(b"=").decode()
        )
        inner_pay_b64 = (
            base64.urlsafe_b64encode(json.dumps(outer_jwk).encode()).rstrip(b"=").decode()
        )

        # Compute a valid HMAC so payload check passes
        hmac_key_b64 = base64.urlsafe_b64encode(b"secret-hmac-key").rstrip(b"=").decode()

        inner_sig_b64 = base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode()

        eab_jws = {
            "protected": inner_prot_b64,
            "payload": inner_pay_b64,
            "signature": inner_sig_b64,
        }

        call_count = 0
        original_decode = __import__("acmeeh.core.jws", fromlist=["_b64url_decode"])._b64url_decode

        def patched_decode(s):
            nonlocal call_count
            call_count += 1
            # 1st call: inner header decode
            if call_count == 1:
                return original_decode(s)
            # 2nd call: payload decode
            if call_count == 2:
                return original_decode(s)
            # 3rd call: hmac_key decode (hmac_key_b64)
            if call_count == 3:
                return original_decode(s)
            # 4th call: signature decode raises AcmeProblem
            if call_count == 4:
                raise AcmeProblem(MALFORMED, "injected EAB sig error")
            return original_decode(s)

        with patch("acmeeh.core.jws._b64url_decode", side_effect=patched_decode):
            with pytest.raises(AcmeProblem, match="injected EAB sig error"):
                validate_eab_jws(eab_jws, outer_jwk, hmac_key_b64)
