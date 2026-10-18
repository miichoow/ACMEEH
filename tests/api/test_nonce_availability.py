"""A request must not burn its single-use nonce when the database is unreachable.

Found with a real ACME client (lego) during a database failover: the nonce was consumed first and
the request failed afterwards with 503; the client replayed the same signed request and got
``badNonce``, repeatedly, until it gave up.  Refusing *before* the nonce is consumed makes the
replay valid.
"""

from __future__ import annotations

from tests.api.test_acme_routes_full import (
    _BASE,
    _container,
    _jws_patches,
    _make_app,
    _make_jws_object,
    _mock_account,
)


def _post_to_account(container):
    from acmeeh.api.account import account_bp

    acct = _mock_account()
    jws_obj = _make_jws_object(payload={}, kid=f"{_BASE}/acct/{acct.id}")
    app = _make_app(account_bp, "", container)
    p1, p2, p3, p4, p5 = _jws_patches(jws_obj)
    with p1, p2, p3, p4, p5:
        with app.test_client() as c:
            return c.post(
                f"/acct/{acct.id}",
                data=b"{}",
                content_type="application/jose+json",
            )


class TestNonceNotBurnedWhenDatabaseIsDown:
    def test_503_with_retry_after_and_nonce_untouched(self):
        container = _container()
        container.db_gate.check.side_effect = ConnectionError("database unreachable")

        resp = _post_to_account(container)

        assert resp.status_code == 503
        assert resp.headers["Retry-After"] == "5"
        assert resp.get_json()["type"].endswith("serverInternal")
        container.nonce_service.consume.assert_not_called()

    def test_nonce_consumed_once_when_database_is_up(self):
        container = _container()
        container.db_gate.check.return_value = None

        _post_to_account(container)

        container.nonce_service.consume.assert_called_once()

    def test_works_without_a_gate(self):
        container = _container()
        container.db_gate = None

        _post_to_account(container)

        container.nonce_service.consume.assert_called_once()
