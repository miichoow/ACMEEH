"""Unit tests for acmeeh.app.errors — RFC 7807 Problem Details."""

from __future__ import annotations

import json

import flask
import psycopg
import pytest

from acmeeh.app.errors import (
    ACCOUNT_DOES_NOT_EXIST,
    ALREADY_REVOKED,
    BAD_CSR,
    BAD_NONCE,
    BAD_PUBLIC_KEY,
    BAD_REVOCATION_REASON,
    BAD_SIGNATURE_ALGORITHM,
    CAA,
    COMPOUND,
    CONNECTION,
    DNS,
    EXTERNAL_ACCOUNT_REQUIRED,
    INCORRECT_RESPONSE,
    INVALID_CONTACT,
    MALFORMED,
    ORDER_NOT_READY,
    PROBLEM_CONTENT_TYPE,
    RATE_LIMITED,
    REJECTED_IDENTIFIER,
    SERVER_INTERNAL,
    TLS,
    UNAUTHORIZED,
    UNSUPPORTED_CONTACT,
    UNSUPPORTED_IDENTIFIER,
    USER_ACTION_REQUIRED,
    AcmeProblem,
    register_error_handlers,
)

# ---------------------------------------------------------------------------
# TestAcmeProblem
# ---------------------------------------------------------------------------


class TestAcmeProblem:
    def test_to_dict_basic(self):
        p = AcmeProblem(MALFORMED, "bad request")
        d = p.to_dict()
        assert d["type"] == MALFORMED
        assert d["detail"] == "bad request"
        assert d["status"] == 400

    def test_to_dict_with_title(self):
        p = AcmeProblem(MALFORMED, "bad", title="Malformed Request")
        d = p.to_dict()
        assert d["title"] == "Malformed Request"

    def test_to_dict_without_title(self):
        p = AcmeProblem(MALFORMED, "bad")
        assert "title" not in p.to_dict()

    def test_to_dict_with_subproblems(self):
        subs = [{"type": REJECTED_IDENTIFIER, "detail": "foo"}]
        p = AcmeProblem(MALFORMED, "multi", subproblems=subs)
        d = p.to_dict()
        assert d["subproblems"] == subs

    def test_to_dict_without_subproblems(self):
        p = AcmeProblem(MALFORMED, "no subs")
        assert "subproblems" not in p.to_dict()

    def test_default_status_is_400(self):
        p = AcmeProblem(MALFORMED, "test")
        assert p.status == 400

    def test_custom_status(self):
        p = AcmeProblem(RATE_LIMITED, "slow down", status=429)
        assert p.status == 429

    def test_extra_headers(self):
        p = AcmeProblem(
            BAD_NONCE,
            "try again",
            headers={"Retry-After": "5"},
        )
        assert p.extra_headers == {"Retry-After": "5"}


# ---------------------------------------------------------------------------
# TestToResponse
# ---------------------------------------------------------------------------


class TestToResponse:
    @pytest.fixture
    def app(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        return app

    def test_content_type(self, app):
        with app.app_context():
            p = AcmeProblem(MALFORMED, "test")
            resp = p.to_response()
            assert resp.headers["Content-Type"] == PROBLEM_CONTENT_TYPE

    def test_cache_control(self, app):
        with app.app_context():
            p = AcmeProblem(MALFORMED, "test")
            resp = p.to_response()
            assert resp.headers["Cache-Control"] == "no-store"

    def test_status_code(self, app):
        with app.app_context():
            p = AcmeProblem(UNAUTHORIZED, "denied", status=403)
            resp = p.to_response()
            assert resp.status_code == 403

    def test_body_matches_to_dict(self, app):
        with app.app_context():
            p = AcmeProblem(MALFORMED, "bad data", title="Bad")
            resp = p.to_response()
            body = json.loads(resp.get_data(as_text=True))
            assert body == p.to_dict()

    def test_extra_headers_on_response(self, app):
        with app.app_context():
            p = AcmeProblem(BAD_NONCE, "retry", headers={"Retry-After": "10"})
            resp = p.to_response()
            assert resp.headers["Retry-After"] == "10"


# ---------------------------------------------------------------------------
# TestErrorConstants
# ---------------------------------------------------------------------------


class TestErrorConstants:
    ALL_ERRORS = [
        ACCOUNT_DOES_NOT_EXIST,
        ALREADY_REVOKED,
        BAD_CSR,
        BAD_NONCE,
        BAD_PUBLIC_KEY,
        BAD_REVOCATION_REASON,
        BAD_SIGNATURE_ALGORITHM,
        CAA,
        COMPOUND,
        CONNECTION,
        DNS,
        EXTERNAL_ACCOUNT_REQUIRED,
        INCORRECT_RESPONSE,
        INVALID_CONTACT,
        MALFORMED,
        ORDER_NOT_READY,
        RATE_LIMITED,
        REJECTED_IDENTIFIER,
        SERVER_INTERNAL,
        TLS,
        UNAUTHORIZED,
        UNSUPPORTED_CONTACT,
        UNSUPPORTED_IDENTIFIER,
        USER_ACTION_REQUIRED,
    ]

    def test_all_start_with_urn_prefix(self):
        for urn in self.ALL_ERRORS:
            assert urn.startswith("urn:ietf:params:acme:error:"), f"{urn} missing prefix"

    def test_all_unique(self):
        assert len(set(self.ALL_ERRORS)) == len(self.ALL_ERRORS)

    def test_count(self):
        # There should be exactly 24 error URNs
        assert len(self.ALL_ERRORS) == 24


# ---------------------------------------------------------------------------
# TestRegisterErrorHandlers
# ---------------------------------------------------------------------------


class TestRegisterErrorHandlers:
    @pytest.fixture
    def app(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        register_error_handlers(app)

        @app.route("/raise-acme")
        def raise_acme():
            raise AcmeProblem(MALFORMED, "test error")

        @app.route("/raise-404")
        def raise_404():
            flask.abort(404)

        @app.route("/raise-generic")
        def raise_generic():
            raise RuntimeError("boom")

        return app

    def test_acme_problem_handler(self, app):
        with app.test_client() as c:
            resp = c.get("/raise-acme")
            assert resp.status_code == 400
            assert resp.content_type == PROBLEM_CONTENT_TYPE
            data = json.loads(resp.data)
            assert data["type"] == MALFORMED

    def test_http_exception_404(self, app):
        with app.test_client() as c:
            resp = c.get("/raise-404")
            assert resp.status_code == 404
            assert resp.content_type == PROBLEM_CONTENT_TYPE
            data = json.loads(resp.data)
            assert data["type"] == "about:blank"

    def test_generic_exception_500(self, app):
        with app.test_client() as c:
            resp = c.get("/raise-generic")
            assert resp.status_code == 500
            assert resp.content_type == PROBLEM_CONTENT_TYPE
            data = json.loads(resp.data)
            assert data["type"] == SERVER_INTERNAL


# ---------------------------------------------------------------------------
# TestTransientDatabaseErrors
# ---------------------------------------------------------------------------


def _wrapped(exc: Exception) -> Exception:
    """Raise-and-catch *exc* as the ``__cause__`` of a service-layer error."""
    try:
        try:
            raise exc
        except Exception as inner:
            raise RuntimeError("repository failure") from inner
    except RuntimeError as outer:
        return outer


class TestTransientDatabaseErrors:
    """A database failover must surface as a retryable 503, not a 500."""

    @pytest.fixture
    def make_client(self):
        def _make(exc: Exception):
            app = flask.Flask(__name__)
            app.config["TESTING"] = True
            register_error_handlers(app)

            @app.route("/boom")
            def boom():
                raise exc

            return app.test_client()

        return _make

    @pytest.mark.parametrize(
        "exc",
        [
            psycopg.errors.AdminShutdown("terminating connection due to administrator command"),
            psycopg.errors.CrashShutdown("terminating connection due to crash of another server"),
            psycopg.errors.CannotConnectNow("the database system is starting up"),
            psycopg.OperationalError("consuming input failed: server closed the connection"),
            psycopg.errors.ReadOnlySqlTransaction(
                "cannot execute INSERT in a read-only transaction",
            ),
            psycopg.InterfaceError("the connection is closed"),
        ],
        ids=lambda e: type(e).__name__,
    )
    def test_connection_loss_is_503_with_retry_after(self, make_client, exc):
        resp = make_client(exc).get("/boom")
        assert resp.status_code == 503
        assert resp.content_type == PROBLEM_CONTENT_TYPE
        assert resp.headers["Retry-After"] == "5"
        assert json.loads(resp.data)["type"] == SERVER_INTERNAL

    def test_wrapped_cause_is_503(self, make_client):
        exc = _wrapped(psycopg.errors.AdminShutdown("terminating connection"))
        resp = make_client(exc).get("/boom")
        assert resp.status_code == 503
        assert resp.headers["Retry-After"] == "5"

    def test_connection_loss_logged_as_warning_without_traceback(self, make_client, caplog):
        with caplog.at_level("WARNING", logger="acmeeh.app.errors"):
            make_client(psycopg.OperationalError("server closed the connection")).get("/boom")
        records = [r for r in caplog.records if r.name == "acmeeh.app.errors"]
        assert records
        assert all(r.levelname == "WARNING" and r.exc_info is None for r in records)

    @pytest.mark.parametrize(
        "exc",
        [
            psycopg.errors.UniqueViolation("duplicate key value"),
            psycopg.errors.SyntaxError("syntax error at or near"),
            psycopg.InterfaceError("cursor not bound to a connection"),
            RuntimeError("boom"),
        ],
        ids=lambda e: type(e).__name__,
    )
    def test_genuine_errors_stay_500(self, make_client, exc):
        resp = make_client(exc).get("/boom")
        assert resp.status_code == 500
        assert "Retry-After" not in resp.headers
