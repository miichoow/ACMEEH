"""Integration test fixtures for ACMEEH.

Provides a Flask test client with mocked database and CA backend,
plus JWS request builders for ACME protocol testing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acmeeh.config.settings import build_settings
from acmeeh.core.types import ChallengeStatus, ChallengeType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_json(obj: Any) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _ec_key():
    """Generate a fresh P-256 key pair."""
    return ec.generate_private_key(ec.SECP256R1())


def _jwk_from_ec(public_key: ec.EllipticCurvePublicKey) -> dict:
    """Convert an EC public key to a JWK dict."""
    nums = public_key.public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(x),
        "y": _b64url(y),
    }


def _thumbprint(jwk: dict) -> str:
    """Compute JWK thumbprint (RFC 7638)."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("ascii")).digest()
    return _b64url(digest)


def _sign_es256(private_key, payload: bytes) -> bytes:
    """Sign with ES256 and return raw r||s (not DER)."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    der_sig = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# JWS Request Builder
# ---------------------------------------------------------------------------


class JWSBuilder:
    """Builds ACME JWS requests for testing."""

    def __init__(self, private_key, base_url: str, nonce_getter):
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.jwk = _jwk_from_ec(self.public_key)
        self.thumbprint = _thumbprint(self.jwk)
        self.base_url = base_url
        self._get_nonce = nonce_getter
        self.kid: str | None = None

    def post(self, client, path: str, payload: Any = None, use_kid: bool = True):
        """Build and send a JWS-authenticated POST."""
        url = self.base_url + path
        nonce = self._get_nonce(client)

        protected: dict[str, Any] = {
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
        }

        if use_kid and self.kid:
            protected["kid"] = self.kid
        else:
            protected["jwk"] = self.jwk

        protected_b64 = _b64url_json(protected)

        if payload is None:
            payload_b64 = ""
        else:
            payload_b64 = _b64url_json(payload)

        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = _sign_es256(self.private_key, signing_input)
        signature_b64 = _b64url(signature)

        body = json.dumps(
            {
                "protected": protected_b64,
                "payload": payload_b64,
                "signature": signature_b64,
            }
        )

        return client.post(
            path,
            data=body,
            content_type="application/jose+json",
        )

    def post_as_get(self, client, path: str):
        """Send a POST-as-GET (empty payload)."""
        url = self.base_url + path
        nonce = self._get_nonce(client)

        protected = {
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
            "kid": self.kid,
        }
        protected_b64 = _b64url_json(protected)
        payload_b64 = ""

        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = _sign_es256(self.private_key, signing_input)
        signature_b64 = _b64url(signature)

        body = json.dumps(
            {
                "protected": protected_b64,
                "payload": payload_b64,
                "signature": signature_b64,
            }
        )

        return client.post(
            path,
            data=body,
            content_type="application/jose+json",
        )


# ---------------------------------------------------------------------------
# Mock Database
# ---------------------------------------------------------------------------


class _MockTransaction:
    """Minimal mock transaction context manager for MockDB."""

    def __init__(self, db):
        self._db = db

    def __enter__(self):
        return self._db

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class MockDB:
    """Minimal mock for pypgkit.Database.

    Supports basic UnitOfWork operations (INSERT/UPDATE with RETURNING *)
    via an in-memory table store so that finalization flows work properly
    in integration tests.

    Set ``on_update`` to a callback ``(table, set_values, where) -> None``
    to receive notifications when UnitOfWork performs updates; this lets
    the fixture keep mock repos in sync.
    """

    _instance = None

    def __init__(self):
        self._tables: dict[str, dict[Any, dict]] = {}
        self._sequences: dict[str, int] = {"certificate_serial_seq": 0}
        self.on_update = None  # callback for UnitOfWork sync
        MockDB._instance = self

    @classmethod
    def get_instance(cls):
        return cls._instance

    def transaction(self):
        return _MockTransaction(self)

    def fetch_one(self, query: str, params=None, as_dict=False):
        return None

    def fetch_all(self, query: str, params=None, as_dict=False):
        return []

    def fetch_value(self, query: str, params=None):
        if "nextval" in query:
            seq = "certificate_serial_seq"
            self._sequences[seq] = self._sequences.get(seq, 0) + 1
            return self._sequences[seq]
        if "pg_try_advisory_xact_lock" in query:
            return True
        if "SELECT 1" in query:
            return 1
        return None

    def execute(self, query: str, params=None):
        return 0

    def cursor(self, **kwargs):
        return _MockCursor(self)


class _MockCursor:
    """Mock cursor with basic INSERT/UPDATE support for UnitOfWork."""

    def __init__(self, db: MockDB):
        self._db = db
        self._last_result = None
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def execute(self, sql, params=None):
        sql_upper = sql.strip().upper()
        if sql_upper.startswith("INSERT"):
            self._handle_insert(sql, params)
        elif sql_upper.startswith("UPDATE"):
            self._handle_update(sql, params)
        else:
            self._last_result = None
            self.rowcount = 0

    def _handle_insert(self, sql, params):
        """Parse INSERT INTO table (cols) VALUES (...) RETURNING *."""
        import re

        m = re.match(r"INSERT\s+INTO\s+(\w+)\s*\(([^)]+)\)", sql, re.IGNORECASE)
        if not m or not params:
            self._last_result = None
            self.rowcount = 0
            return
        table = m.group(1)
        columns = [c.strip() for c in m.group(2).split(",")]
        row = dict(zip(columns, params))
        self._db._tables.setdefault(table, {})[row.get("id"),] = row
        self._last_result = row
        self.rowcount = 1

    def _handle_update(self, sql, params):
        """Parse UPDATE table SET ... WHERE ... RETURNING *."""
        import re

        m = re.match(
            r"UPDATE\s+(\w+)\s+SET\s+(.+?)\s+WHERE\s+(.+?)(?:\s+RETURNING)",
            sql,
            re.IGNORECASE | re.DOTALL,
        )
        if not m or not params:
            self._last_result = None
            self.rowcount = 0
            return
        table = m.group(1)
        set_cols = [c.strip().split("=")[0].strip() for c in m.group(2).split(",")]
        where_cols = [c.strip().split("=")[0].strip() for c in m.group(3).split(" AND ")]
        n_set = len(set_cols)
        set_vals = list(params[:n_set])
        where_vals = list(params[n_set:])
        set_values = dict(zip(set_cols, set_vals))
        where_values = dict(zip(where_cols, where_vals))
        # Build a result row from set + where values
        row = {**where_values, **set_values}
        self._last_result = row
        self.rowcount = 1
        # Notify callback so mock repos stay in sync
        if self._db.on_update:
            self._db.on_update(table, set_values, where_values)

    def fetchone(self):
        return self._last_result

    def fetchall(self):
        return [self._last_result] if self._last_result else []


# ---------------------------------------------------------------------------
# Mock Repositories (in-memory)
# ---------------------------------------------------------------------------


class InMemoryRepo:
    """Base in-memory repository."""

    def __init__(self):
        self._data: dict[Any, Any] = {}

    def create(self, entity):
        self._data[entity.id] = entity

    def find_by_id(self, entity_id):
        return self._data.get(entity_id)

    def find_all(self):
        return list(self._data.values())

    def delete(self, entity_id):
        self._data.pop(entity_id, None)

    def find_by(self, criteria: dict):
        results = []
        for entity in self._data.values():
            match = True
            for k, v in criteria.items():
                if getattr(entity, k, None) != v:
                    match = False
                    break
            if match:
                results.append(entity)
        return results

    def find_one_by(self, criteria: dict):
        for entity in self._data.values():
            match = True
            for k, v in criteria.items():
                if getattr(entity, k, None) != v:
                    match = False
                    break
            if match:
                return entity
        return None


class MockAccountRepo(InMemoryRepo):
    def find_by_thumbprint(self, thumbprint):
        for acct in self._data.values():
            if acct.jwk_thumbprint == thumbprint:
                return acct
        return None

    def update_jwk(self, account_id, jwk, jwk_thumbprint):
        acct = self._data.get(account_id)
        if acct is None:
            return None
        new_fields = {}
        for f in acct.__dataclass_fields__:
            new_fields[f] = getattr(acct, f)
        new_fields["jwk"] = jwk
        new_fields["jwk_thumbprint"] = jwk_thumbprint
        new_acct = type(acct)(**new_fields)
        self._data[account_id] = new_acct
        return new_acct

    def update_status(self, account_id, status):
        acct = self._data.get(account_id)
        if acct is None:
            return None
        new_fields = {}
        for f in acct.__dataclass_fields__:
            new_fields[f] = getattr(acct, f)
        new_fields["status"] = status
        new_acct = type(acct)(**new_fields)
        self._data[account_id] = new_acct
        return new_acct

    def deactivate(self, account_id):
        from acmeeh.core.types import AccountStatus

        acct = self._data.get(account_id)
        if acct is None or acct.status != AccountStatus.VALID:
            return None
        return self.update_status(account_id, AccountStatus.DEACTIVATED)


class MockNonceRepo(InMemoryRepo):
    def __init__(self, audit_consumed=False):
        super().__init__()
        self._audit_consumed = audit_consumed

    def create(self, entity):
        self._data[entity.nonce] = entity

    def find_by_id(self, nonce_value):
        return self._data.get(nonce_value)

    def consume(self, nonce_value, client_ip=None):
        entity = self._data.pop(nonce_value, None)
        if entity is None:
            return False
        if entity.expires_at < datetime.now(UTC):
            return False
        return True

    def gc_expired(self):
        return 0


class MockOrderRepo(InMemoryRepo):
    def __init__(self):
        super().__init__()
        self._authz_links: dict[UUID, list[UUID]] = {}

    def link_authorization(self, order_id, authz_id):
        self._authz_links.setdefault(order_id, []).append(authz_id)

    def find_authorization_ids(self, order_id):
        return self._authz_links.get(order_id, [])

    def find_pending_for_dedup(self, account_id, id_hash):
        return None

    def find_by_account(self, account_id):
        return [o for o in self._data.values() if o.account_id == account_id]

    def find_by_account_paginated(self, account_id, cursor=None, limit=50):
        orders = sorted(
            [o for o in self._data.values() if o.account_id == account_id],
            key=lambda o: str(o.id),
        )
        if cursor is not None:
            orders = [o for o in orders if str(o.id) > str(cursor)]
        page = orders[:limit]
        next_cursor = page[-1].id if len(orders) > limit else None
        return page, next_cursor

    def transition_status(self, order_id, from_status, to_status, **kwargs):
        order = self._data.get(order_id)
        if order is None or order.status != from_status:
            return None
        # Create new frozen dataclass instance with updated status
        updates = {"status": to_status}
        updates.update(kwargs)
        new_fields = {}
        for f in order.__dataclass_fields__:
            new_fields[f] = updates.get(f, getattr(order, f))
        new_order = type(order)(**new_fields)
        self._data[order_id] = new_order
        return new_order

    def find_orders_by_authorization(self, authz_id):
        result = []
        for order_id, authz_ids in self._authz_links.items():
            if authz_id in authz_ids:
                order = self._data.get(order_id)
                if order:
                    result.append(order)
        return result


class MockAuthzRepo(InMemoryRepo):
    def find_reusable(self, account_id, id_type, id_value):
        return None

    def find_by_order(self, order_id):
        return []

    def find_expired_pending(self):
        return []

    def transition_status(self, authz_id, from_status, to_status):
        authz = self._data.get(authz_id)
        if authz is None or authz.status != from_status:
            return None
        new_fields = {}
        for f in authz.__dataclass_fields__:
            new_fields[f] = getattr(authz, f)
        new_fields["status"] = to_status
        new_authz = type(authz)(**new_fields)
        self._data[authz_id] = new_authz
        return new_authz


class MockChallengeRepo(InMemoryRepo):
    def find_by_authorization(self, authz_id):
        return [c for c in self._data.values() if c.authorization_id == authz_id]

    def claim_for_processing(self, challenge_id, worker_id):
        return self._data.get(challenge_id)

    def complete_validation(self, challenge_id, worker_id, success, error=None):
        ch = self._data.get(challenge_id)
        if ch is None:
            return None
        new_fields = {}
        for f in ch.__dataclass_fields__:
            new_fields[f] = getattr(ch, f)
        new_fields["status"] = ChallengeStatus.VALID if success else ChallengeStatus.INVALID
        new_fields["locked_by"] = None
        if error:
            new_fields["error"] = error
        new_ch = type(ch)(**new_fields)
        self._data[challenge_id] = new_ch
        return new_ch

    def claim_with_advisory_lock(self, challenge_id):
        return True

    def retry_challenge(self, challenge_id, worker_id=None, backoff_seconds=0):
        ch = self._data.get(challenge_id)
        if ch is None:
            return None
        # Create a copy with incremented retry_count
        new_fields = {}
        for f in ch.__dataclass_fields__:
            new_fields[f] = getattr(ch, f)
        new_fields["retry_count"] = ch.retry_count + 1
        new_fields["status"] = ChallengeStatus.PENDING
        new_fields["locked_by"] = None
        new_ch = type(ch)(**new_fields)
        self._data[challenge_id] = new_ch
        return new_ch

    def find_processing_stale(self, max_age_seconds=300):
        return []

    def release_stale_locks(self, max_age_seconds=300):
        return 0


class MockCertRepo(InMemoryRepo):
    _serial = 0

    def _entity_to_row(self, entity) -> dict:
        """Convert a Certificate entity to a row dict for UnitOfWork."""
        from psycopg.types.json import Jsonb

        row = {
            "id": entity.id,
            "account_id": entity.account_id,
            "order_id": entity.order_id,
            "serial_number": entity.serial_number,
            "fingerprint": entity.fingerprint,
            "pem_chain": entity.pem_chain,
            "not_before_cert": entity.not_before_cert,
            "not_after_cert": entity.not_after_cert,
            "revoked_at": getattr(entity, "revoked_at", None),
            "revocation_reason": None,
        }
        pk_fp = getattr(entity, "public_key_fingerprint", None)
        if pk_fp is not None:
            row["public_key_fingerprint"] = pk_fp
        san = getattr(entity, "san_values", None)
        if san is not None:
            row["san_values"] = Jsonb(san)
        # Also store in-memory for later retrieval
        self._data[entity.id] = entity
        return row

    def find_by_fingerprint(self, fingerprint):
        for c in self._data.values():
            if c.fingerprint == fingerprint:
                return c
        return None

    def find_by_serial(self, serial):
        for c in self._data.values():
            if c.serial_number == serial:
                return c
        return None

    def next_serial(self):
        MockCertRepo._serial += 1
        return MockCertRepo._serial

    def revoke(self, cert_id, reason=None):
        cert = self._data.get(cert_id)
        if cert is None:
            return None
        if getattr(cert, "revoked_at", None) is not None:
            return None  # already revoked
        new_fields = {}
        for f in cert.__dataclass_fields__:
            new_fields[f] = getattr(cert, f)
        new_fields["revoked_at"] = datetime.now(UTC)
        new_fields["revocation_reason"] = reason
        new_cert = type(cert)(**new_fields)
        self._data[cert_id] = new_cert
        return new_cert

    def find_revoked(self):
        return [c for c in self._data.values() if getattr(c, "revoked_at", None) is not None]

    def find_expiring(self, before):
        return []


class MockContactRepo(InMemoryRepo):
    def find_by_account(self, account_id):
        return [c for c in self._data.values() if c.account_id == account_id]

    def delete_by_account(self, account_id):
        to_del = [k for k, v in self._data.items() if v.account_id == account_id]
        for k in to_del:
            del self._data[k]

    def replace_for_account(self, account_id, contacts):
        self.delete_by_account(account_id)
        for c in contacts:
            self._data[c.id] = c
        return contacts


class MockNotificationRepo(InMemoryRepo):
    pass


# ---------------------------------------------------------------------------
# Test CA Backend
# ---------------------------------------------------------------------------


def _generate_test_ca():
    """Generate a self-signed test CA cert + key."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
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


class TestCABackend:
    """Minimal CA backend that signs certs immediately."""

    def __init__(self):
        self._root_cert, self._root_key = _generate_test_ca()

    @property
    def root_cert(self):
        return self._root_cert

    @property
    def root_key(self):
        return self._root_key

    @property
    def deferred(self):
        return False

    def startup_check(self):
        pass

    def sign(self, csr, *, profile, validity_days, serial_number=None, **kwargs):
        from acmeeh.ca.base import IssuedCertificate

        now = datetime.now(UTC)
        sn = serial_number or secrets.randbelow(2**128)

        try:
            san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            cn = dns_names[0] if dns_names else "test"
        except x509.ExtensionNotFound:
            cn = "test"

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(self._root_cert.subject)
            .public_key(csr.public_key())
            .serial_number(sn)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(san_ext.value, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._root_key, hashes.SHA256())
        )

        pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        root_pem = self._root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        chain = pem + root_pem
        der = cert.public_bytes(serialization.Encoding.DER)

        return IssuedCertificate(
            pem_chain=chain,
            not_before=now,
            not_after=now + timedelta(days=validity_days),
            serial_number=format(sn, "x"),
            fingerprint=hashlib.sha256(der).hexdigest(),
        )

    def revoke(self, *, serial_number, certificate_pem, reason=None):
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def _min_config_data():
    """Minimal valid config data dict."""
    return {
        "server": {"external_url": "https://acme.test"},
        "database": {"database": "test", "user": "test"},
        "ca": {
            "backend": "internal",
            "internal": {
                "root_cert_path": "/tmp/test.crt",
                "root_key_path": "/tmp/test.key",
            },
        },
    }


@pytest.fixture
def app(_min_config_data):
    """Create a Flask test app with mocked components."""
    from flask import Flask

    from acmeeh.app.errors import register_error_handlers
    from acmeeh.app.middleware import register_request_hooks

    settings = build_settings(_min_config_data)

    flask_app = Flask("acmeeh_test")
    flask_app.config["ACMEEH_SETTINGS"] = settings
    flask_app.config["TESTING"] = True

    register_error_handlers(flask_app)
    register_request_hooks(flask_app)

    # Build mock container
    mock_db = MockDB()

    from acmeeh.core.urls import AcmeUrls
    from acmeeh.hooks.registry import HookRegistry
    from acmeeh.services import (
        AccountService,
        AuthorizationService,
        CertificateService,
        ChallengeService,
        KeyChangeService,
        NonceService,
        OrderService,
    )

    class MockContainer:
        pass

    container = MockContainer()
    container.db = mock_db
    container.settings = settings
    container.urls = AcmeUrls(settings)

    # Repos
    container.accounts = MockAccountRepo()
    container.account_contacts = MockContactRepo()
    container.orders = MockOrderRepo()
    container.authorizations = MockAuthzRepo()
    container.challenges = MockChallengeRepo()
    container.certificates = MockCertRepo()
    container.nonces = MockNonceRepo()
    container.notification_repo = MockNotificationRepo()
    container.crl_manager = None
    container.metrics_collector = None

    # Challenge registry — swap in auto-accept validators so tests don't
    # need real network access for challenge validation.
    from acmeeh.challenge.auto_accept import AutoAcceptHttpValidator
    from acmeeh.challenge.registry import ChallengeRegistry

    container.challenge_registry = ChallengeRegistry(settings.challenges)
    container.challenge_registry._validators[ChallengeType.HTTP_01] = AutoAcceptHttpValidator()

    # CA
    container.ca_backend = TestCABackend()

    # Hook registry (empty)
    from acmeeh.config.settings import HookSettings

    empty_hooks = HookSettings(
        timeout_seconds=30,
        max_workers=1,
        max_retries=0,
        dead_letter_log=None,
        registered=(),
    )
    container.hook_registry = HookRegistry(empty_hooks)

    # Services
    container.nonce_service = NonceService(container.nonces, settings.nonce)
    container.account_service = AccountService(
        container.accounts,
        container.account_contacts,
        settings.email,
        settings.tos,
        None,
        account_settings=settings.account,
    )
    container.order_service = OrderService(
        container.orders,
        container.authorizations,
        container.challenges,
        settings.order,
        settings.challenges,
        settings.security.identifier_policy,
        mock_db,
    )
    container.authorization_service = AuthorizationService(
        container.authorizations,
        container.challenges,
        order_repo=container.orders,
    )
    container.challenge_service = ChallengeService(
        container.challenges,
        container.authorizations,
        container.orders,
        container.challenge_registry,
    )
    container.certificate_service = CertificateService(
        container.certificates,
        container.orders,
        settings.ca,
        container.ca_backend,
        None,
        db=mock_db,
    )
    container.key_change_service = KeyChangeService(container.accounts)

    flask_app.extensions["container"] = container

    # Sync UnitOfWork updates back to mock repos so find_by_id works
    from acmeeh.core.types import OrderStatus

    def _on_uow_update(table, set_values, where_values):
        if table == "orders" and "status" in set_values:
            order_id = where_values.get("id")
            new_status_str = set_values["status"]
            new_status = OrderStatus(new_status_str)
            order = container.orders._data.get(order_id)
            if order is not None:
                new_fields = {}
                for f in order.__dataclass_fields__:
                    new_fields[f] = getattr(order, f)
                new_fields["status"] = new_status
                if "certificate_id" in set_values:
                    new_fields["certificate_id"] = set_values["certificate_id"]
                container.orders._data[order_id] = type(order)(**new_fields)

    mock_db.on_update = _on_uow_update

    # Register blueprints
    from acmeeh.api import register_blueprints

    register_blueprints(flask_app)

    return flask_app


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def ec_key():
    """Generate a fresh EC P-256 key pair."""
    return _ec_key()


@pytest.fixture
def jws(client, app):
    """JWS builder with nonce management."""
    key = _ec_key()
    base_url = "https://acme.test"

    def get_nonce(c):
        resp = c.head("/new-nonce")
        return resp.headers.get("Replay-Nonce", "test-nonce-" + uuid4().hex)

    return JWSBuilder(key, base_url, get_nonce)
