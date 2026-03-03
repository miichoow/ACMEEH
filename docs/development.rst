===========
Development
===========

*Project structure, testing, hooks, and contributing*

Project Structure
-----------------

.. code-block:: text

   src/acmeeh/
   ├── __init__.py              # Version: 1.0.0
   ├── __main__.py              # CLI entry point
   ├── cli/
   │   ├── main.py              # Argument parsing & dispatch
   │   └── commands/
   │       ├── admin.py         # admin create-user
   │       ├── ca.py            # ca test-sign
   │       ├── crl.py           # crl rebuild
   │       ├── db.py            # db status, db migrate
   │       ├── inspect.py       # inspect order/certificate/account
   │       └── serve.py         # serve (start server)
   ├── config/
   │   ├── __init__.py          # Exports AcmeehConfig, get_config
   │   ├── acmeeh_config.py     # ConfigKit subclass
   │   ├── settings.py          # Frozen dataclasses (27 sections)
   │   └── schema.json          # JSON Schema validation
   ├── app/
   │   ├── factory.py           # create_app(config, database)
   │   ├── context.py           # DI container: get_container()
   │   ├── errors.py            # AcmeProblem exception
   │   ├── middleware.py         # Request/response middleware
   │   ├── rate_limiter.py      # Per-endpoint rate limiting
   │   └── shutdown.py          # Graceful shutdown handler
   ├── core/
   │   ├── types.py             # Enums: OrderStatus, ChallengeType, etc.
   │   ├── state.py             # State machine transitions
   │   ├── jws.py               # JWS/JWK/JWK Thumbprint (RFC 7515/7517/7638)
   │   └── urls.py              # URL builder utilities
   ├── api/
   │   ├── __init__.py          # register_blueprints()
   │   ├── directory.py         # GET /directory
   │   ├── nonce.py             # HEAD/GET /new-nonce
   │   ├── account.py           # POST /new-account, /acct/{id}
   │   ├── order.py             # POST /new-order, /order/{id}, /order/{id}/finalize
   │   ├── authorization.py     # POST /authz/{id}
   │   ├── challenge_routes.py  # POST /chall/{id}
   │   ├── certificate.py       # POST /cert/{id}, /revoke-cert
   │   ├── key_change.py        # POST /key-change
   │   ├── new_authz.py         # POST /new-authz
   │   ├── crl.py               # GET /crl (optional)
   │   ├── renewal_info.py      # GET /renewalInfo/{id} (optional)
   │   ├── metrics.py           # GET /metrics (optional)
   │   ├── serializers.py       # JSON serialization helpers
   │   └── decorators.py        # ACME response headers
   ├── models/                  # Frozen dataclass models
   │   ├── account.py
   │   ├── authorization.py
   │   ├── certificate.py
   │   ├── challenge.py
   │   ├── nonce.py
   │   ├── notification.py
   │   └── order.py
   ├── repositories/            # BaseRepository[T] subclasses
   │   ├── account.py
   │   ├── authorization.py
   │   ├── certificate.py
   │   ├── challenge.py
   │   ├── nonce.py
   │   ├── notification.py
   │   └── order.py
   ├── services/                # Business logic
   │   ├── account.py           # Account creation, update, deactivation
   │   ├── authorization.py     # Authorization lifecycle
   │   ├── certificate.py       # Certificate issuance and revocation
   │   ├── challenge.py         # Challenge creation and validation
   │   ├── cleanup_worker.py    # Nonce GC, order expiry, data retention
   │   ├── csr_validator.py     # CSR validation against profiles
   │   ├── expiration_worker.py # Certificate expiration warnings
   │   ├── key_change.py        # Account key rollover
   │   ├── nonce.py             # Nonce generation and tracking
   │   ├── notification.py      # Email notifications with retry
   │   ├── order.py             # Order creation and finalization
   │   ├── renewal_info.py      # ARI renewal information
   │   └── workers.py           # Worker orchestrator (starts background threads)
   ├── ca/                      # CA backends
   │   ├── base.py              # CABackend ABC, IssuedCertificate, CAError
   │   ├── registry.py          # Backend loader/registry
   │   ├── internal.py          # File-based CA
   │   ├── external.py          # HTTP API CA
   │   ├── hsm.py               # PKCS#11 HSM CA
   │   ├── acme_proxy.py        # Upstream ACME CA
   │   ├── failover.py          # Multi-backend failover wrapper
   │   ├── circuit_breaker.py   # Circuit breaker for CA backends
   │   ├── crl.py               # CRL generation and management
   │   ├── ct.py                # Certificate Transparency submission
   │   ├── caa.py               # CAA record checking
   │   ├── cert_utils.py        # Certificate parsing utilities
   │   └── upstream_handlers.py # Challenge handlers for ACME proxy
   ├── challenge/               # Challenge validators
   │   ├── base.py              # ChallengeValidator ABC
   │   ├── registry.py          # Validator registry
   │   ├── http01.py            # HTTP-01 validator
   │   ├── dns01.py             # DNS-01 validator
   │   ├── tls_alpn01.py        # TLS-ALPN-01 validator
   │   └── auto_accept.py       # Auto-accept validator (for ACME proxy)
   ├── hooks/                   # Hook system
   │   ├── base.py              # Hook ABC
   │   ├── events.py            # Event definitions
   │   ├── registry.py          # Hook registry and dispatcher
   │   ├── ct_hook.py           # CT log submission hook
   │   └── audit_export_hook.py # Audit event export hook
   ├── admin/                   # Admin API
   │   ├── routes.py            # Flask blueprint (49 endpoints)
   │   ├── auth.py              # JWT auth, token blacklist, rate limiting
   │   ├── service.py           # AdminUserService
   │   ├── repository.py        # Admin repositories (users, audit, EAB, etc.)
   │   ├── models.py            # Admin data models
   │   ├── serializers.py       # JSON serializers
   │   ├── pagination.py        # Cursor-based pagination
   │   └── password.py          # Password hashing and generation
   ├── notifications/           # Email notification system
   │   ├── renderer.py          # Jinja2 template rendering
   │   └── templates/           # 17 notification type templates
   ├── logging/                 # Logging and audit
   │   ├── setup.py             # Log configuration (JSON/human format)
   │   ├── sanitize.py          # Log message sanitization
   │   ├── security_events.py   # Security event logging
   │   └── audit_cleanup.py     # Audit log retention cleanup
   ├── metrics/                 # Prometheus metrics
   │   └── collector.py         # Metric definitions and collector
   ├── server/                  # WSGI server
   │   ├── gunicorn_app.py      # Custom gunicorn application class
   │   └── wsgi.py              # WSGI entry point (ACMEEH_CONFIG env)
   └── db/
       ├── __init__.py          # Database initialization
       ├── init.py              # Schema auto-setup
       ├── unit_of_work.py      # Transaction unit of work
       └── schema.sql           # PostgreSQL schema

Running Tests
-------------

.. code-block:: bash

   # Run all tests
   PYTHONPATH=src python -m pytest tests/

   # Run a specific test file
   PYTHONPATH=src python -m pytest tests/test_config.py -v

   # Run a single test
   PYTHONPATH=src python -m pytest tests/test_config.py::test_name -v

   # Run with coverage
   PYTHONPATH=src python -m pytest tests/ --cov=acmeeh --cov-report=html

.. note::

   **Config Reset**

   The ``fresh_config`` autouse fixture in ``tests/conftest.py`` automatically resets the ConfigKit singleton before and after every test. You don't need to worry about config leaking between tests.

Test Structure
--------------

.. code-block:: text

   tests/
   ├── conftest.py              # Shared fixtures (fresh_config, etc.)
   ├── test_config.py
   ├── test_settings.py
   ├── test_jws.py
   ├── test_state.py
   ├── ...
   └── integration/
       ├── conftest.py          # Full app fixtures with mocked DB
       ├── test_directory.py
       ├── test_account.py
       ├── test_order.py
       └── ...

.. _hooks:

Hook System
-----------

ACMEEH has a pluggable hook system that fires on lifecycle events. Hooks run asynchronously in a thread pool and don't block the request.

For the full list of available events, context keys, and configuration options,
see the :doc:`extensibility` guide.

Writing a Hook
^^^^^^^^^^^^^^

All custom hooks must inherit from ``Hook`` and override the event methods they need. Unimplemented methods are no-ops. The constructor receives an optional ``config`` dict from the hook entry in the YAML configuration.

.. code-block:: python

   from acmeeh.hooks.base import Hook

   class SlackNotifier(Hook):
       def __init__(self, config: dict | None = None):
           super().__init__(config)
           self.webhook_url = self.config["webhook_url"]

       @classmethod
       def validate_config(cls, config: dict) -> None:
           # Called at load time — raise ValueError if invalid
           if "webhook_url" not in config:
               raise ValueError("webhook_url is required")

       def on_certificate_issuance(self, ctx: dict):
           # ctx contains: certificate_id, order_id, account_id,
           #   serial_number, domains, not_after, pem_chain
           domains = ctx["domains"]
           serial = ctx["serial_number"]
           # POST to Slack webhook...

       def on_certificate_revocation(self, ctx: dict):
           # ctx contains: certificate_id, account_id,
           #   serial_number, reason
           ...

Register the hook in config (see :doc:`extensibility` for the full YAML schema and
additional examples):

.. code-block:: yaml

   hooks:
     registered:
       - class: my_hooks.SlackNotifier
         events: [certificate.issuance, certificate.revocation]
         config:
           webhook_url: https://hooks.slack.com/...

Built-in Hooks
^^^^^^^^^^^^^^

ACMEEH ships with two built-in hook implementations:

.. list-table::
   :header-rows: 1
   :widths: 20 30 50

   * - Hook
     - Module
     - Purpose
   * - CT Log Hook
     - ``acmeeh.hooks.ct_hook``
     - Submits issued certificates to Certificate Transparency logs (configured via ``ct_logging`` settings)
   * - Audit Export Hook
     - ``acmeeh.hooks.audit_export_hook``
     - Exports audit events to external systems via webhook or syslog (configured via ``audit_export`` settings)

.. _enums:

Enum Reference
--------------

Core enumerated types from ``core/types.py`` used throughout the API and database.

AccountStatus
^^^^^^^^^^^^^

- ``valid`` --- Active account
- ``deactivated`` --- Self-deactivated by account holder
- ``revoked`` --- Revoked by administrator

OrderStatus
^^^^^^^^^^^

- ``pending`` --- Awaiting challenge validation
- ``ready`` --- All authorizations valid, ready for finalization
- ``processing`` --- CSR submitted, certificate being issued
- ``valid`` --- Certificate issued
- ``invalid`` --- One or more authorizations failed

AuthorizationStatus
^^^^^^^^^^^^^^^^^^^

- ``pending`` --- Awaiting challenge completion
- ``valid`` --- Successfully validated
- ``invalid`` --- Validation failed
- ``deactivated`` --- Deactivated by account holder
- ``expired`` --- Passed expiration time
- ``revoked`` --- Revoked by administrator

ChallengeStatus
^^^^^^^^^^^^^^^

- ``pending`` --- Waiting for client to respond
- ``processing`` --- Validation in progress
- ``valid`` --- Validation succeeded
- ``invalid`` --- Validation failed

RevocationReason (RFC 5280 \u00a75.3.1)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 10 25 65

   * - Code
     - Name
     - Description
   * - 0
     - ``unspecified``
     - No specific reason
   * - 1
     - ``keyCompromise``
     - Private key compromised
   * - 2
     - ``cACompromise``
     - CA key compromised
   * - 3
     - ``affiliationChanged``
     - Subject's affiliation changed
   * - 4
     - ``superseded``
     - Certificate replaced by a new one
   * - 5
     - ``cessationOfOperation``
     - Subject no longer operates
   * - 6
     - ``certificateHold``
     - Certificate temporarily suspended
   * - 8
     - ``removeFromCRL``
     - Remove from CRL (delta CRL)
   * - 9
     - ``privilegeWithdrawn``
     - Privilege for certificate withdrawn
   * - 10
     - ``aACompromise``
     - Attribute Authority compromised

NotificationType
^^^^^^^^^^^^^^^^

- ``delivery_succeeded``, ``delivery_failed`` --- Certificate delivery events
- ``revocation_succeeded``, ``revocation_failed`` --- Revocation events
- ``registration_succeeded``, ``registration_failed`` --- Account registration events
- ``admin_user_created``, ``admin_password_reset`` --- Admin user events
- ``expiration_warning`` --- Certificate expiration warning
- ``order_rejected`` --- Order rejected by policy
- ``order_quota_exceeded`` --- Account exceeded order quota
- ``order_stale_recovered`` --- Stale processing order recovered
- ``challenge_failed`` --- Challenge validation failed
- ``csr_validation_failed`` --- CSR validation failed against profile
- ``account_deactivated`` --- Account deactivated by holder
- ``key_rollover_succeeded`` --- Account key rollover succeeded
- ``authorization_deactivated`` --- Authorization deactivated

AdminRole
^^^^^^^^^

- ``admin`` --- Full access to all admin API endpoints
- ``auditor`` --- Read-only access to users, audit logs, certificates, and CSR profiles

Adding a CA Backend
-------------------

To add a new built-in CA backend, update all of the following:

#. **``config/settings.py``** --- Add a new frozen dataclass for the backend's settings and a ``_build_*`` function. Add the field to ``CASettings``.
#. **``config/schema.json``** --- Add the JSON Schema definition for the new backend's configuration.
#. **``config/acmeeh_config.py``** --- Add any validation rules in ``additional_checks()``.
#. **``ca/registry.py``** --- Register the new backend name in the registry so it can be loaded.
#. **``ca/your_backend.py``** --- Implement the ``CABackend`` subclass.
#. **Tests** --- Update all test files that construct ``CASettings`` directly to include the new field.

.. warning::

   **Important**

   Many tests construct ``CASettings`` directly. If you add a field, you must update every test that does so, or tests will fail with missing argument errors.

Adding a Challenge Validator
----------------------------

Challenge validators live in ``challenge/`` and implement the validation logic for each challenge type. To add a new type:

#. Add the challenge type to ``core/types.py`` in the ``ChallengeType`` enum
#. Create a validator class in ``challenge/``
#. Register it in the challenge registry
#. Add configuration in ``config/settings.py``
#. Update ``config/schema.json``

CLI Commands Reference
----------------------

See :doc:`deployment` for the full CLI reference (subcommands and global flags).

Code Conventions
----------------

- **Models** --- All model classes are frozen dataclasses (immutable after creation)
- **Repositories** --- Extend ``BaseRepository[T]`` from PyPGKit. Return model instances.
- **Services** --- Business logic layer. Coordinate between repositories and CA backends.
- **Errors** --- Use ``AcmeProblem`` for all user-facing errors. Follows RFC 7807 Problem Details.
- **JWS** --- Custom implementation in ``core/jws.py`` using the ``cryptography`` library (no josepy dependency).
- **Config** --- ConfigKit singleton via metaclass. Always reset between tests.
- **Contact validation** --- Email regex requires a dot in the domain part (``test@localhost`` is rejected).
- **SQL schema** --- Tables use ``IF NOT EXISTS``; triggers use ``DROP IF EXISTS`` + ``CREATE``.
