=======================
Configuration Reference
=======================

*Complete reference for all YAML configuration sections*

ACMEEH uses a single YAML configuration file validated against a JSON Schema.
The file is loaded via `ConfigKit <https://github.com/miichoow/ConfigKit>`_,
which provides schema validation, environment variable substitution, and typed access.

Environment Variables
---------------------

Use ``${VAR}`` or ``${VAR:-default}`` syntax anywhere in the YAML to reference environment variables:

.. code-block:: yaml

   database:
     password: ${DB_PASSWORD}
     host: ${DB_HOST:-localhost}

Variables are resolved during config loading in ``additional_checks()``. If a variable is missing and has no default, config loading fails with a clear error.

.. tip::

   **Inline Comments**

   Add a ``_comment`` field (string or array of strings) at the top level of your YAML for in-file documentation. It is ignored by the server.

Settings Sections
-----------------

The configuration tree has 27 top-level sections. Only ``server.external_url``, ``database.database``, and ``database.user`` are required --- everything else has sensible defaults.

server
------

HTTP server settings for both development and gunicorn production modes.

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``external_url``
     - string
     - **required**
     - Public-facing URL of the server (used in ACME directory)
   * - ``bind``
     - string
     - ``0.0.0.0``
     - Address to bind to
   * - ``port``
     - integer
     - ``8443``
     - Port to listen on
   * - ``workers``
     - integer
     - ``4``
     - Number of gunicorn workers
   * - ``worker_class``
     - string
     - ``sync``
     - Gunicorn worker class
   * - ``timeout``
     - integer
     - ``30``
     - Worker timeout in seconds
   * - ``graceful_timeout``
     - integer
     - ``30``
     - Graceful shutdown timeout
   * - ``keepalive``
     - integer
     - ``2``
     - Keep-alive timeout
   * - ``max_requests``
     - integer
     - ``0``
     - Max requests before worker restart (0 = disabled)
   * - ``max_requests_jitter``
     - integer
     - ``0``
     - Random jitter added to max_requests

proxy
-----

Reverse proxy configuration for extracting real client IP and protocol.

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``false``
     - Enable reverse proxy support
   * - ``trusted_proxies``
     - string[]
     - ``[]``
     - List of trusted proxy IP addresses/ranges
   * - ``forwarded_for_header``
     - string
     - ``X-Forwarded-For``
     - Header containing real client IP
   * - ``forwarded_proto_header``
     - string
     - ``X-Forwarded-Proto``
     - Header containing original protocol

.. note::

   **X-Forwarded-Prefix**

   The middleware also handles ``X-Forwarded-Prefix`` automatically (not configurable). When present on a trusted request, its value is used as the WSGI ``SCRIPT_NAME`` to support reverse proxies that mount ACMEEH under a sub-path.

security
--------

Cryptographic policies, rate limiting, and identifier restrictions.

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``allowed_algorithms``
     - string[]
     - ``[ES256, RS256]``
     - Allowed JWS signing algorithms
   * - ``min_rsa_key_size``
     - integer
     - ``2048``
     - Minimum RSA key size for account keys
   * - ``max_rsa_key_size``
     - integer
     - ``8192``
     - Maximum RSA key size
   * - ``allowed_ec_curves``
     - string[]
     - ``[P-256, P-384]``
     - Allowed EC curves for account keys
   * - ``max_request_body_bytes``
     - integer
     - ``65536``
     - Maximum request body size
   * - ``allowed_csr_signature_algorithms``
     - string[]
     - ``[SHA256withRSA, ...]``
     - Allowed CSR signature algorithms
   * - ``min_csr_rsa_key_size``
     - integer
     - ``2048``
     - Minimum RSA key size in CSRs
   * - ``min_csr_ec_key_size``
     - integer
     - ``256``
     - Minimum EC key size in CSRs
   * - ``hsts_max_age_seconds``
     - integer
     - ``63072000``
     - HSTS header max-age in seconds
   * - ``require_csr_profile``
     - boolean
     - ``false``
     - Require every account to have a CSR profile assigned before certificate finalization. See :ref:`csr-profile-enforcement`.

security.rate_limits
^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``true``
     - Enable rate limiting
   * - ``backend``
     - string
     - ``memory``
     - Rate limit storage backend
   * - ``new_nonce``
     - object
     - ``100/60s``
     - Nonce endpoint rate limit
   * - ``new_account``
     - object
     - ``10/3600s``
     - Account creation rate limit
   * - ``new_order``
     - object
     - ``300/3600s``
     - Order creation rate limit
   * - ``new_order_per_identifier``
     - object
     - ``50/604800s``
     - Per-identifier order rate limit
   * - ``challenge``
     - object
     - ``60/60s``
     - Challenge response rate limit
   * - ``challenge_validation``
     - object
     - ``30/60s``
     - Challenge validation rate limit
   * - ``gc_interval_seconds``
     - integer
     - ``300``
     - Rate limit GC interval
   * - ``gc_max_age_seconds``
     - integer
     - ``7200``
     - Max age for rate limit entries

Each rate limit rule has ``requests`` (count) and ``window_seconds`` (time window).

security.identifier_policy
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``allowed_domains``
     - string[]
     - ``[]``
     - Allowlist of domain suffixes (empty = allow all)
   * - ``forbidden_domains``
     - string[]
     - ``[]``
     - Blocklist of domain suffixes
   * - ``allow_wildcards``
     - boolean
     - ``true``
     - Allow wildcard identifiers
   * - ``allow_ip``
     - boolean
     - ``false``
     - Allow IP address identifiers
   * - ``max_identifiers_per_order``
     - integer
     - ``100``
     - Maximum identifiers per order
   * - ``max_identifier_value_length``
     - integer
     - ``253``
     - Maximum identifier string length
   * - ``enforce_account_allowlist``
     - boolean
     - ``false``
     - Enforce per-account allowed identifiers

acme
----

ACME protocol settings including URL paths and policy.

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``website_url``
     - string
     - ``null``
     - URL for terms of service / website
   * - ``caa_identities``
     - string[]
     - ``[]``
     - CAA record identities for validation
   * - ``eab_required``
     - boolean
     - ``false``
     - Require External Account Binding
   * - ``eab_reusable``
     - boolean
     - ``false``
     - Allow EAB credentials to be reused across multiple accounts
   * - ``caa_enforce``
     - boolean
     - ``true``
     - Enforce CAA DNS record checks
   * - ``orders_page_size``
     - integer
     - ``50``
     - Number of orders per page in account orders list

acme.paths
^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``directory``
     - string
     - ``/directory``
     - Directory endpoint path
   * - ``new_nonce``
     - string
     - ``/new-nonce``
     - New nonce endpoint path
   * - ``new_account``
     - string
     - ``/new-account``
     - New account endpoint path
   * - ``new_order``
     - string
     - ``/new-order``
     - New order endpoint path
   * - ``new_authz``
     - string
     - ``/new-authz``
     - Pre-authorization endpoint path
   * - ``revoke_cert``
     - string
     - ``/revoke-cert``
     - Certificate revocation endpoint path
   * - ``key_change``
     - string
     - ``/key-change``
     - Key change endpoint path

api
---

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``base_path``
     - string
     - ``""``
     - Base URL path prefix for all ACME endpoints

challenges
----------

Challenge validation configuration.

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - string[]
     - ``[http-01]``
     - Enabled challenge types: ``http-01``, ``dns-01``, ``tls-alpn-01``
   * - ``auto_accept``
     - boolean
     - ``false``
     - Automatically accept all challenges without validation
   * - ``retry_after_seconds``
     - integer
     - ``3``
     - Retry-After header value for pending challenges
   * - ``backoff_base_seconds``
     - integer
     - ``5``
     - Base delay for exponential backoff on retries
   * - ``backoff_max_seconds``
     - integer
     - ``300``
     - Maximum backoff delay

challenges.http01
^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``port``
     - integer
     - ``80``
     - Port to connect to for HTTP-01 validation
   * - ``timeout_seconds``
     - integer
     - ``10``
     - Connection timeout
   * - ``max_retries``
     - integer
     - ``3``
     - Maximum validation retries
   * - ``auto_validate``
     - boolean
     - ``true``
     - Auto-validate this challenge type
   * - ``blocked_networks``
     - string[]
     - ``[127.0.0.0/8, ...]``
     - Networks blocked from validation (SSRF protection)
   * - ``max_response_bytes``
     - integer
     - ``1048576``
     - Maximum response body size for HTTP-01 validation (1 MB)

challenges.dns01
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``resolvers``
     - string[]
     - ``[]``
     - DNS resolver addresses (empty = system default)
   * - ``timeout_seconds``
     - integer
     - ``30``
     - DNS query timeout
   * - ``propagation_wait_seconds``
     - integer
     - ``10``
     - Wait time for DNS propagation
   * - ``max_retries``
     - integer
     - ``5``
     - Maximum validation retries
   * - ``auto_validate``
     - boolean
     - ``false``
     - Auto-validate this challenge type
   * - ``require_dnssec``
     - boolean
     - ``false``
     - Require DNSSEC validation
   * - ``require_authoritative``
     - boolean
     - ``false``
     - Require response from authoritative nameserver

challenges.tlsalpn01
^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``port``
     - integer
     - ``443``
     - Port for TLS-ALPN-01 validation
   * - ``timeout_seconds``
     - integer
     - ``10``
     - Connection timeout
   * - ``max_retries``
     - integer
     - ``3``
     - Maximum validation retries
   * - ``auto_validate``
     - boolean
     - ``true``
     - Auto-validate this challenge type

challenges.background_worker
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``false``
     - Enable background challenge worker
   * - ``poll_seconds``
     - integer
     - ``10``
     - Polling interval
   * - ``stale_seconds``
     - integer
     - ``300``
     - Threshold for stale challenges

ca
--

Certificate Authority settings. See :doc:`ca-backends` for detailed backend configuration.

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``backend``
     - string
     - ``internal``
     - CA backend: ``internal``, ``external``, ``hsm``, ``acme_proxy``, or ``ext:pkg.mod.Class``
   * - ``default_validity_days``
     - integer
     - ``90``
     - Default certificate validity
   * - ``max_validity_days``
     - integer
     - ``397``
     - Maximum certificate validity
   * - ``circuit_breaker_failure_threshold``
     - integer
     - ``5``
     - Failures before circuit opens
   * - ``circuit_breaker_recovery_timeout``
     - float
     - ``30``
     - Seconds before circuit half-opens
   * - ``deferred_signing_timeout``
     - integer
     - ``600``
     - Timeout in seconds for deferred (background thread) signing. Used by backends where ``deferred=True`` (e.g., ``acme_proxy``).

ca.profiles
^^^^^^^^^^^

Named certificate profiles. A ``default`` profile is always present. Each profile supports:

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``key_usages``
     - array
     - ``[]``
     - Key Usage extension values (e.g., ``digital_signature``, ``key_encipherment``)
   * - ``extended_key_usages``
     - array
     - ``[]``
     - Extended Key Usage values (e.g., ``server_auth``, ``client_auth``)
   * - ``validity_days``
     - integer
     - ``null``
     - Override ``ca.default_validity_days`` for this profile
   * - ``max_validity_days``
     - integer
     - ``null``
     - Override ``ca.max_validity_days`` for this profile

Example:

.. code-block:: yaml

   ca:
     profiles:
       default:
         key_usages: [digital_signature, key_encipherment]
         extended_key_usages: [server_auth]
       client:
         key_usages: [digital_signature]
         extended_key_usages: [client_auth]
         validity_days: 365
         max_validity_days: 730

database
--------

PostgreSQL connection settings.

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``host``
     - string
     - ``localhost``
     - Database hostname
   * - ``port``
     - integer
     - ``5432``
     - Database port
   * - ``database``
     - string
     - **required**
     - Database name
   * - ``user``
     - string
     - **required**
     - Database user
   * - ``password``
     - string
     - ``""``
     - Database password
   * - ``sslmode``
     - string
     - ``prefer``
     - PostgreSQL SSL mode
   * - ``min_connections``
     - integer
     - ``5``
     - Minimum pool connections
   * - ``max_connections``
     - integer
     - ``50``
     - Maximum pool connections
   * - ``connection_timeout``
     - float
     - ``10.0``
     - Connection timeout in seconds
   * - ``max_idle_seconds``
     - float
     - ``300.0``
     - Maximum time (seconds) a connection can remain idle in the pool before being closed
   * - ``auto_setup``
     - boolean
     - ``false``
     - Automatically create tables on startup

dns
---

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``resolvers``
     - string[]
     - ``[]``
     - DNS resolver addresses
   * - ``timeout_seconds``
     - integer
     - ``10``
     - DNS query timeout
   * - ``retries``
     - integer
     - ``3``
     - DNS query retries

email
-----

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``require_contact``
     - boolean
     - ``false``
     - Require email contact on accounts
   * - ``allowed_domains``
     - string[]
     - ``[]``
     - Allowed email domains (empty = any)
   * - ``validate_mx``
     - boolean
     - ``false``
     - Validate MX records for email domain

account
-------

Account modification and lifecycle policy settings.

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``allow_contact_update``
     - boolean
     - ``true``
     - Allow accounts to update their contact information
   * - ``allow_deactivation``
     - boolean
     - ``true``
     - Allow accounts to self-deactivate

smtp
----

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``false``
     - Enable SMTP for notifications
   * - ``host``
     - string
     - ``""``
     - SMTP server hostname
   * - ``port``
     - integer
     - ``587``
     - SMTP server port
   * - ``username``
     - string
     - ``""``
     - SMTP username
   * - ``password``
     - string
     - ``""``
     - SMTP password
   * - ``use_tls``
     - boolean
     - ``true``
     - Use STARTTLS
   * - ``from_address``
     - string
     - ``""``
     - Sender email address
   * - ``cc``
     - list[string]
     - ``[]``
     - CC recipients added to every outgoing notification
   * - ``bcc``
     - list[string]
     - ``[]``
     - BCC recipients added to every outgoing notification (envelope only, not in headers)
   * - ``templates_path``
     - string
     - ``null``
     - Custom Jinja2 templates directory
   * - ``timeout_seconds``
     - integer
     - ``30``
     - SMTP operation timeout

logging
-------

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``level``
     - string
     - ``INFO``
     - Log level: DEBUG, INFO, WARNING, ERROR
   * - ``format``
     - string
     - ``json``
     - Log format: ``json`` or ``human``

logging.audit
^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``true``
     - Enable audit logging
   * - ``file``
     - string
     - ``null``
     - Audit log file path
   * - ``syslog``
     - boolean
     - ``false``
     - Send audit logs to syslog
   * - ``max_file_size_bytes``
     - integer
     - ``104857600``
     - Maximum audit log file size before rotation (100 MB)
   * - ``backup_count``
     - integer
     - ``10``
     - Number of rotated audit log backups to keep

notifications
-------------

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``true``
     - Enable notification system
   * - ``max_retries``
     - integer
     - ``3``
     - Max delivery retries
   * - ``retry_delay_seconds``
     - integer
     - ``60``
     - Initial retry delay
   * - ``batch_size``
     - integer
     - ``50``
     - Notifications per batch
   * - ``retry_interval_seconds``
     - integer
     - ``300``
     - Retry worker interval
   * - ``expiration_warning_days``
     - integer[]
     - ``[30, 14, 7, 1]``
     - Days before expiry to warn
   * - ``expiration_check_interval_seconds``
     - integer
     - ``3600``
     - Expiration check interval
   * - ``retry_backoff_multiplier``
     - float
     - ``2.0``
     - Exponential backoff multiplier
   * - ``retry_max_delay_seconds``
     - integer
     - ``3600``
     - Maximum retry delay
   * - ``disabled_types``
     - string[]
     - ``[]``
     - Notification types to suppress. Valid values:
       ``delivery_succeeded``, ``delivery_failed``,
       ``revocation_succeeded``, ``revocation_failed``,
       ``registration_succeeded``, ``registration_failed``,
       ``admin_user_created``, ``admin_password_reset``,
       ``expiration_warning``, ``order_rejected``,
       ``challenge_failed``, ``csr_validation_failed``,
       ``order_stale_recovered``, ``account_deactivated``,
       ``key_rollover_succeeded``, ``order_quota_exceeded``,
       ``authorization_deactivated``

hooks
-----

Lifecycle hook configuration. See :ref:`hooks` in the Development guide for writing custom hooks.

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``timeout_seconds``
     - integer
     - ``30``
     - Default hook execution timeout
   * - ``max_workers``
     - integer
     - ``4``
     - Thread pool size for hook execution
   * - ``max_retries``
     - integer
     - ``0``
     - Default retry count on failure
   * - ``dead_letter_log``
     - string
     - ``null``
     - File path for failed hook payloads

hooks.registered[]
^^^^^^^^^^^^^^^^^^

See :doc:`extensibility` for the full list of hook events, configuration fields,
and a complete YAML example.

nonce
-----

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``expiry_seconds``
     - integer
     - ``3600``
     - Nonce expiry time
   * - ``gc_interval_seconds``
     - integer
     - ``300``
     - Garbage collection interval
   * - ``length``
     - integer
     - ``32``
     - Nonce byte length
   * - ``audit_consumed``
     - boolean
     - ``false``
     - Log consumed nonces in audit trail
   * - ``max_age_seconds``
     - integer
     - ``min(expiry_seconds, 300)``
     - Max age for nonce reuse. Defaults to the lesser of ``expiry_seconds`` and 300.

order
-----

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``expiry_seconds``
     - integer
     - ``604800``
     - Order expiry (7 days)
   * - ``authorization_expiry_seconds``
     - integer
     - ``2592000``
     - Authorization expiry (30 days)
   * - ``cleanup_interval_seconds``
     - integer
     - ``3600``
     - Expired order cleanup interval
   * - ``stale_processing_threshold_seconds``
     - integer
     - ``600``
     - Threshold for stale processing orders
   * - ``pre_authorization_lifetime_days``
     - integer
     - ``30``
     - Pre-authorization validity
   * - ``retry_after_seconds``
     - integer
     - ``3``
     - Retry-After for processing orders

quotas
------

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``false``
     - Enable per-account quotas
   * - ``max_certificates_per_account_per_day``
     - integer
     - ``0``
     - Daily cert limit (0 = unlimited)
   * - ``max_orders_per_account_per_day``
     - integer
     - ``0``
     - Daily order limit (0 = unlimited)

tos
---

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``url``
     - string
     - ``null``
     - Terms of Service URL
   * - ``require_agreement``
     - boolean
     - ``false``
     - Require TOS agreement for account creation

admin_api
---------

See :doc:`admin` for endpoint documentation.

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``false``
     - Enable admin REST API
   * - ``base_path``
     - string
     - ``/api``
     - Admin API base path
   * - ``token_secret``
     - string
     - ``""``
     - JWT signing secret
   * - ``token_expiry_seconds``
     - integer
     - ``3600``
     - Token validity period
   * - ``initial_admin_email``
     - string
     - ``""``
     - Email for auto-created initial admin
   * - ``password_length``
     - integer
     - ``20``
     - Generated password length
   * - ``default_page_size``
     - integer
     - ``50``
     - Default pagination size
   * - ``max_page_size``
     - integer
     - ``1000``
     - Maximum pagination size

crl
---

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``false``
     - Enable CRL distribution point
   * - ``path``
     - string
     - ``/crl``
     - CRL endpoint path
   * - ``rebuild_interval_seconds``
     - integer
     - ``3600``
     - Automatic rebuild interval
   * - ``next_update_seconds``
     - integer
     - ``86400``
     - Next Update field in CRL
   * - ``hash_algorithm``
     - string
     - ``sha256``
     - CRL signing hash algorithm

metrics
-------

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``false``
     - Enable Prometheus metrics endpoint
   * - ``path``
     - string
     - ``/metrics``
     - Metrics endpoint path
   * - ``auth_required``
     - boolean
     - ``false``
     - Require authentication for metrics

ct_logging
----------

Certificate Transparency log submission.

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``false``
     - Enable CT log submission
   * - ``submit_precert``
     - boolean
     - ``false``
     - Submit pre-certificates

ct_logging.logs[]
^^^^^^^^^^^^^^^^^^

Each entry in the ``logs`` array defines a Certificate Transparency log to submit to:

.. code-block:: yaml

   ct_logging:
     enabled: true
     logs:
       - url: https://ct.example.com/log
         public_key_path: /path/to/ct-log-key.pem
         timeout_seconds: 10

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``url``
     - string
     - **required**
     - CT log submission URL
   * - ``public_key_path``
     - string
     - ``null``
     - Path to the CT log's public key (PEM). Used for SCT verification.
   * - ``timeout_seconds``
     - integer
     - ``10``
     - HTTP request timeout for CT log submission

audit_retention
---------------

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``false``
     - Enable audit log cleanup
   * - ``max_age_days``
     - integer
     - ``90``
     - Maximum audit log age
   * - ``cleanup_interval_seconds``
     - integer
     - ``86400``
     - Cleanup interval

ari
---

ACME Renewal Information (draft-ietf-acme-ari).

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``false``
     - Enable ARI endpoint
   * - ``renewal_percentage``
     - float
     - ``0.6667``
     - Suggested renewal point (fraction of validity)
   * - ``path``
     - string
     - ``/renewalInfo``
     - ARI endpoint path

audit_export
------------

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``webhook_url``
     - string
     - ``null``
     - Webhook URL for audit event export
   * - ``syslog_host``
     - string
     - ``null``
     - Syslog server hostname
   * - ``syslog_port``
     - integer
     - ``514``
     - Syslog server port

retention
---------

Data retention policies for automatic cleanup of expired/invalid resources.

.. list-table::
   :header-rows: 1
   :widths: 20 10 15 55

   * - Field
     - Type
     - Default
     - Description
   * - ``enabled``
     - boolean
     - ``true``
     - Enable data retention cleanup
   * - ``invalid_order_max_age_days``
     - integer
     - ``30``
     - Max age for invalid orders
   * - ``expired_authz_max_age_days``
     - integer
     - ``30``
     - Max age for expired authorizations
   * - ``invalid_challenge_max_age_days``
     - integer
     - ``30``
     - Max age for invalid challenges
   * - ``expiration_notice_max_age_days``
     - integer
     - ``90``
     - Max age for expiration notices
   * - ``cleanup_interval_seconds``
     - integer
     - ``86400``
     - Cleanup worker interval
   * - ``cleanup_loop_interval_seconds``
     - integer
     - ``60``
     - Internal cleanup loop sleep interval

Cross-Field Validation Rules
----------------------------

ACMEEH performs cross-field validation during config loading. **Errors** prevent startup;
**warnings** are logged but non-fatal.

Errors (prevent startup)
^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Condition
     - Message
   * - ``server.external_url`` ends with ``/``
     - External URL must not end with a slash
   * - ``ca.backend=internal`` without ``root_cert_path`` or ``root_key_path``
     - Required paths for internal CA backend
   * - ``ca.backend=acme_proxy`` without ``directory_url``, ``email``, or ``challenge_handler``
     - Required fields for ACME proxy backend
   * - ``ca.backend=hsm`` without ``pkcs11_library``, token identifier, key identifier, or ``issuer_cert_path``
     - Required fields for HSM backend
   * - ``ca.backend=hsm`` with ``login_required=true`` but no ``pin``
     - PIN required when login is required
   * - ``ca.default_validity_days`` > ``ca.max_validity_days``
     - Default validity must not exceed maximum
   * - ``database.min_connections`` > ``database.max_connections``
     - Min connections must not exceed max
   * - ``challenges.backoff_base_seconds`` > ``challenges.backoff_max_seconds``
     - Backoff base must not exceed max
   * - ``smtp.enabled=true`` without ``host`` or ``from_address``
     - SMTP host and from_address required when enabled
   * - ``tos.require_agreement=true`` without ``tos.url``
     - TOS URL required when agreement is required
   * - ``proxy.enabled=true`` with empty ``trusted_proxies``
     - Trusted proxies must be specified when enabled
   * - ``admin_api.enabled=true`` without ``token_secret`` (min 16 chars) or ``initial_admin_email``
     - Token secret and initial admin email required
   * - ``admin_api.base_path`` collides with ``api.base_path``
     - Admin and ACME paths must not overlap
   * - ``ct_logging.enabled=true`` with empty ``logs`` array
     - At least one CT log required when enabled
   * - ``nonce.length`` < 16
     - Minimum 16 bytes for cryptographic safety
   * - ``security.min_rsa_key_size`` < 2048
     - Minimum RSA key size is 2048 bits
   * - Unknown hook event name in ``hooks.registered[].events``
     - Event must be a known lifecycle event
   * - Invalid hook class path format
     - Must be a valid dotted Python path (e.g., ``pkg.mod.Class``)

Warnings (logged, non-fatal)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Condition
     - Message
   * - ``notifications.enabled=true`` but ``smtp.enabled=false``
     - Notifications will be recorded but not sent via email
   * - ``admin_api.enabled=true`` but ``smtp.enabled=false``
     - Generated passwords will only be printed to stdout/log
   * - ``security.identifier_policy.enforce_account_allowlist=true`` but ``admin_api.enabled=false``
     - Cannot manage allowlists without admin API
   * - ``security.require_csr_profile=true`` but ``admin_api.enabled=false``
     - CSR profiles cannot be managed without admin API
   * - ``acme.eab_reusable=true`` but ``acme.eab_required=false``
     - EAB reusability has no effect when EAB is not required
   * - ``security.rate_limits.backend=memory`` with ``server.workers`` > 1
     - In-memory rate limits are per-process, not shared across workers
   * - ``database.max_connections`` < ``server.workers x 2 + 5``
     - Connection pool may be too small for configured workers
   * - ``email.validate_mx=true`` with empty ``dns.resolvers``
     - MX validation will use system DNS resolvers
   * - ``quotas.enabled=true`` with both limits set to 0
     - Quotas are enabled but have no effect
   * - 0 < ``security.hsts_max_age_seconds`` < 86400
     - HSTS max-age less than 1 day is not recommended
   * - ``crl.enabled=true`` with non-internal CA backend
     - CRL generation requires access to the CA signing key
   * - Hook ``timeout_seconds`` > ``server.timeout``
     - Hook execution may outlive the HTTP request

.. _csr-profile-enforcement:

CSR Profile Enforcement
-----------------------

When ``security.require_csr_profile`` is ``true``, every ACME account **must** have a
CSR profile assigned before it can finalize an order. If an account has no profile,
the finalize request is rejected with a ``badCSR`` error.

This pairs naturally with EAB-based enrollment: assign a CSR profile to each EAB
credential, and when a client registers using that credential, the profile is
automatically copied to the new account.

**Recommended setup:**

.. code-block:: yaml

   acme:
     eab_required: true

   security:
     require_csr_profile: true

   admin_api:
     enabled: true
     token_secret: ${ADMIN_TOKEN_SECRET}
     initial_admin_email: admin@example.com
     base_path: /admin

**Workflow:**

1. An admin creates a CSR profile via ``POST /admin/csr-profiles``
2. The admin assigns it to an EAB credential via ``PUT /admin/eab/{eab_id}/csr-profile/{profile_id}``
3. A client registers with the EAB credential --- the profile is copied to the new account
4. All certificate orders from that account are validated against the profile

Accounts without a profile receive a ``badCSR`` error at finalization with the detail
*"No CSR profile assigned to this account"*.

.. note::

   The ``admin_api.enabled`` option must be ``true`` for CSR profile management. If
   ``require_csr_profile`` is ``true`` but the admin API is disabled, a configuration
   warning is logged at startup and all finalization requests will fail.


Full Configuration Example
--------------------------

A comprehensive configuration file showing all commonly used sections:

.. code-block:: yaml

   # ACMEEH Configuration --- Full Example

   server:
     external_url: https://acme.example.com
     bind: 0.0.0.0
     port: 8443
     workers: 8
     timeout: 30
     max_requests: 1000
     max_requests_jitter: 50

   proxy:
     enabled: true
     trusted_proxies:
       - 10.0.0.0/8
       - 172.16.0.0/12

   database:
     host: ${DB_HOST:-localhost}
     port: 5432
     database: acmeeh
     user: acmeeh
     password: ${DB_PASSWORD}
     sslmode: require
     max_connections: 20
     auto_setup: true

   ca:
     backend: internal
     default_validity_days: 90
     max_validity_days: 397
     internal:
       root_cert_path: /etc/acmeeh/ca/root-ca.pem
       root_key_path: /etc/acmeeh/ca/root-ca-key.pem
     profiles:
       default:
         key_usages: [digital_signature, key_encipherment]
         extended_key_usages: [server_auth]
       client:
         key_usages: [digital_signature]
         extended_key_usages: [client_auth]
         validity_days: 365

   challenges:
     enabled:
       - http-01
       - dns-01
     dns01:
       resolvers:
         - 8.8.8.8
         - 8.8.4.4
       propagation_wait_seconds: 30

   security:
     allowed_algorithms: [ES256, RS256]
     rate_limits:
       enabled: true
     identifier_policy:
       allowed_domains:
         - .example.com
         - .internal.corp
       allow_wildcards: true

   acme:
     eab_required: true
     caa_enforce: true
     caa_identities:
       - acme.example.com

   tos:
     url: https://example.com/tos
     require_agreement: true

   admin_api:
     enabled: true
     token_secret: ${ADMIN_TOKEN_SECRET}
     initial_admin_email: admin@example.com

   smtp:
     enabled: true
     host: smtp.example.com
     port: 587
     username: ${SMTP_USER}
     password: ${SMTP_PASSWORD}
     from_address: acmeeh@example.com
     cc: []
     bcc: []

   notifications:
     enabled: true
     expiration_warning_days: [30, 14, 7, 1]

   logging:
     level: INFO
     format: json
     audit:
       enabled: true
       file: /var/log/acmeeh/audit.log

   crl:
     enabled: true

   metrics:
     enabled: true
