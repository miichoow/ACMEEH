======
Docker
======

*Building, configuring, and running ACMEEH in Docker*

ACMEEH ships with a production-ready Dockerfile (multi-stage build), a
``docker-compose.yaml`` that brings up ACMEEH and PostgreSQL together, and a
fully parameterized config at ``docker/config.yaml``.

Quick Start
-----------

.. code-block:: bash

   # 1. Create your .env (only POSTGRES_PASSWORD is required)
   cp docker/.env.example .env
   vi .env                            # set POSTGRES_PASSWORD

   # 2. Place your CA root cert + key
   mkdir -p certs
   cp /path/to/root.pem   certs/root.pem
   cp /path/to/root-key.pem certs/root-key.pem

   # 3. Build and start
   docker compose up -d

   # 4. Verify
   curl http://localhost:8443/livez
   curl http://localhost:8443/directory

.. tip::

   **No CA cert yet?** Generate a self-signed root CA for testing:

   .. code-block:: bash

      mkdir -p certs
      openssl ecparam -genkey -name prime256v1 -out certs/root-key.pem
      openssl req -new -x509 -key certs/root-key.pem -out certs/root.pem \
          -days 3650 -subj "/CN=ACMEEH Development CA"

Image Overview
--------------

.. list-table::
   :widths: 30 70

   * - **Base image**
     - ``python:3.12-slim-bookworm``
   * - **Build strategy**
     - Multi-stage (builder + runtime) for small final image
   * - **Init system**
     - ``tini`` — proper PID 1, signal forwarding, zombie reaping
   * - **User**
     - Non-root ``acmeeh`` (UID/GID configurable via build ARGs)
   * - **Port**
     - ``8443`` (HTTP — put behind a reverse proxy for TLS)
   * - **Healthcheck**
     - ``GET /healthz`` every 30 s
   * - **Entry point**
     - ``tini -- acmeeh -c /app/config.yaml``

Directory Layout Inside the Container
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: text

   /app/
   ├── config.yaml       Default config (override via bind mount)
   ├── certs/            CA certificates and keys (bind mount)
   └── data/             Persistent application data (named volume)
   /var/log/acmeeh/      Audit and application logs (named volume)

Build ARGs
----------

Customise the image at build time by setting these ARGs in your ``.env`` or
passing them to ``docker compose build --build-arg``:

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - ARG
     - Default
     - Description
   * - ``INSTALL_HSM``
     - ``0``
     - Set to ``1`` to install ``python-pkcs11`` and ``softhsm2`` for
       PKCS#11 / HSM CA backend support
   * - ``INSTALL_ACME_PROXY``
     - ``0``
     - Set to ``1`` to install ``acmeow`` for the ACME proxy CA backend
   * - ``INSTALL_GEVENT``
     - ``0``
     - Set to ``1`` to install ``gevent`` for async workers
       (use ``worker_class: gevent`` in config)
   * - ``EXTRA_PIP_PACKAGES``
     - *(empty)*
     - Space-separated list of additional pip packages to install
       (e.g. custom hook or CA backend plugins)
   * - ``ACMEEH_UID``
     - ``1000``
     - UID for the ``acmeeh`` runtime user
   * - ``ACMEEH_GID``
     - ``1000``
     - GID for the ``acmeeh`` runtime group

Examples — build with optional backends:

.. code-block:: bash

   # HSM support
   docker compose build --build-arg INSTALL_HSM=1

   # ACME proxy support
   docker compose build --build-arg INSTALL_ACME_PROXY=1

Or set them in your ``.env``:

.. code-block:: bash

   INSTALL_HSM=1
   INSTALL_ACME_PROXY=1

Docker Compose Services
-----------------------

The ``docker-compose.yaml`` at the project root defines two services:

acmeeh
^^^^^^

The application container.

- Builds from the project-root ``Dockerfile``
- Reads environment variables from ``.env``
- Mounts ``docker/config.yaml`` read-only at ``/app/config.yaml``
- Mounts the local ``certs/`` directory read-only at ``/app/certs``
- Uses named volumes for logs and data
- Waits for PostgreSQL to be healthy before starting
- Health check: ``GET /healthz`` every 30 s
- ``stop_grace_period: 35s`` allows gunicorn's graceful shutdown to complete

postgres
^^^^^^^^

PostgreSQL 16 (Alpine).

- Data persisted in the ``acmeeh-pgdata`` named volume
- Host port bound to ``127.0.0.1`` only (not exposed to network)
- Health check via ``pg_isready``

Named volumes:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Volume
     - Purpose
   * - ``acmeeh-pgdata``
     - PostgreSQL data directory
   * - ``acmeeh-logs``
     - ACMEEH audit and application logs
   * - ``acmeeh-data``
     - Application data (ACME proxy storage, etc.)

Configuration
-------------

The Docker config at ``docker/config.yaml`` covers every settings section.
It uses two mechanisms:

- **String fields** — ``${VAR:-default}`` environment variable substitution.
  These resolve at startup through ACMEEH's built-in env var processor.
- **Non-string fields** (integers, booleans, floats) — native YAML values.
  ACMEEH's env var resolver produces strings, which would fail JSON Schema
  validation for typed fields. Adjust these directly in the YAML or override
  the entire file via a bind mount.

To customise the config:

1. **Simple changes**: Set environment variables in ``.env`` (see table below).
2. **Structural changes**: Edit ``docker/config.yaml`` directly, or bind-mount
   your own config file.

Environment Variables
---------------------

All variables are documented in ``docker/.env.example``. Copy it to ``.env``
and uncomment the ones you need. Only ``POSTGRES_PASSWORD`` is required.

PostgreSQL
^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Variable
     - Default
     - Description
   * - ``POSTGRES_PASSWORD``
     - *(required)*
     - Database password (used by both ACMEEH and PostgreSQL container)
   * - ``POSTGRES_HOST``
     - ``postgres``
     - Database hostname (container name in Compose)
   * - ``POSTGRES_DB``
     - ``acmeeh``
     - Database name
   * - ``POSTGRES_USER``
     - ``acmeeh``
     - Database user
   * - ``POSTGRES_SSLMODE``
     - ``disable``
     - PostgreSQL SSL mode (``disable``, ``require``, ``verify-full``)
   * - ``POSTGRES_PORT``
     - ``5432``
     - Host port for PostgreSQL (Compose only — internal port is always 5432)

Server
^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Variable
     - Default
     - Description
   * - ``ACMEEH_EXTERNAL_URL``
     - ``https://acmeeh:8443``
     - The public URL clients use to reach ACMEEH
   * - ``ACMEEH_BIND``
     - ``0.0.0.0``
     - Bind address inside the container
   * - ``ACMEEH_PORT``
     - ``8443``
     - Host port mapping (Compose only)
   * - ``ACMEEH_BASE_PATH``
     - *(empty)*
     - URL path prefix for all endpoints (e.g. ``/acme``)
   * - ``ACMEEH_CERTS_DIR``
     - ``./certs``
     - Host path to CA certificates directory (Compose only)

Reverse Proxy
^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Variable
     - Default
     - Description
   * - ``ACMEEH_FORWARDED_FOR_HEADER``
     - ``X-Forwarded-For``
     - Header name for the client IP (set by reverse proxy)
   * - ``ACMEEH_FORWARDED_PROTO_HEADER``
     - ``X-Forwarded-Proto``
     - Header name for the original protocol (``http`` / ``https``)

CA Backend
^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Variable
     - Default
     - Description
   * - ``CA_BACKEND``
     - ``internal``
     - CA backend type (``internal``, ``external``, ``hsm``, ``acme_proxy``,
       ``ext:module.Class``)
   * - ``CA_ROOT_CERT_PATH``
     - ``/app/certs/root.pem``
     - Path to root CA certificate (internal backend)
   * - ``CA_ROOT_KEY_PATH``
     - ``/app/certs/root-key.pem``
     - Path to root CA private key (internal backend)
   * - ``CA_SERIAL_SOURCE``
     - ``database``
     - Serial number source (``database`` or ``random``)
   * - ``CA_HASH_ALGORITHM``
     - ``sha256``
     - Hash algorithm for signing (``sha256``, ``sha384``, ``sha512``)

External CA
^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Variable
     - Default
     - Description
   * - ``CA_EXT_SIGN_URL``
     - *(empty)*
     - External CA signing endpoint URL
   * - ``CA_EXT_REVOKE_URL``
     - *(empty)*
     - External CA revocation endpoint URL
   * - ``CA_EXT_AUTH_HEADER``
     - ``Authorization``
     - HTTP header name for authentication
   * - ``CA_EXT_AUTH_VALUE``
     - *(empty)*
     - Authentication header value (e.g. ``Bearer <token>``)

HSM / PKCS#11
^^^^^^^^^^^^^

Requires ``INSTALL_HSM=1`` at build time.

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Variable
     - Default
     - Description
   * - ``HSM_PKCS11_LIBRARY``
     - ``/usr/lib/softhsm/libsofthsm2.so``
     - Path to the PKCS#11 shared library
   * - ``HSM_TOKEN_LABEL``
     - ``acmeeh``
     - PKCS#11 token label
   * - ``HSM_PIN``
     - *(empty)*
     - Token PIN
   * - ``HSM_KEY_LABEL``
     - ``acmeeh-signing``
     - Signing key label on the token
   * - ``HSM_KEY_TYPE``
     - ``ec``
     - Key type (``ec`` or ``rsa``)
   * - ``HSM_HASH_ALGORITHM``
     - ``sha256``
     - Hash algorithm for HSM signing
   * - ``HSM_ISSUER_CERT_PATH``
     - ``/app/certs/issuer.pem``
     - Path to the issuer certificate
   * - ``HSM_SERIAL_SOURCE``
     - ``database``
     - Serial number source

ACME Proxy
^^^^^^^^^^

Requires ``INSTALL_ACME_PROXY=1`` at build time.

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Variable
     - Default
     - Description
   * - ``CA_PROXY_DIRECTORY_URL``
     - *(empty)*
     - Upstream ACME directory URL
   * - ``CA_PROXY_EMAIL``
     - *(empty)*
     - Email for upstream ACME account
   * - ``CA_PROXY_STORAGE_PATH``
     - ``/app/data/acme_proxy_storage``
     - Path for ACME proxy state (inside ``acmeeh-data`` volume)
   * - ``CA_PROXY_CHALLENGE_TYPE``
     - ``dns-01``
     - Challenge type to use with upstream CA
   * - ``CA_PROXY_CHALLENGE_HANDLER``
     - *(empty)*
     - Challenge handler class path
   * - ``CA_PROXY_EAB_KID``
     - *(empty)*
     - EAB Key Identifier for upstream CAs that require External Account
       Binding (e.g. ZeroSSL)
   * - ``CA_PROXY_EAB_HMAC_KEY``
     - *(empty)*
     - EAB HMAC key (Base64-encoded) for External Account Binding
   * - ``CA_PROXY_PROXY_URL``
     - *(empty)*
     - HTTP proxy URL for outbound connections to the upstream ACME server

Logging
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Variable
     - Default
     - Description
   * - ``LOG_LEVEL``
     - ``INFO``
     - Log level (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``)
   * - ``LOG_FORMAT``
     - ``human``
     - Log format (``human`` for ``docker logs``, ``json`` for log aggregation)
   * - ``AUDIT_LOG_FILE``
     - ``/var/log/acmeeh/audit.log``
     - Audit log file path (inside ``acmeeh-logs`` volume)

SMTP
^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Variable
     - Default
     - Description
   * - ``SMTP_HOST``
     - *(empty)*
     - SMTP server hostname (enable ``smtp.enabled: true`` in config)
   * - ``SMTP_USERNAME``
     - *(empty)*
     - SMTP authentication username
   * - ``SMTP_PASSWORD``
     - *(empty)*
     - SMTP authentication password
   * - ``SMTP_FROM``
     - *(empty)*
     - Sender email address

Admin API
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Variable
     - Default
     - Description
   * - ``ADMIN_TOKEN_SECRET``
     - *(empty)*
     - JWT signing secret (enable ``admin_api.enabled: true`` in config)
   * - ``ADMIN_INITIAL_EMAIL``
     - *(empty)*
     - Email for the initial admin user
   * - ``ADMIN_BASE_PATH``
     - ``/api``
     - Admin API URL prefix

Other
^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Variable
     - Default
     - Description
   * - ``RATE_LIMIT_BACKEND``
     - ``memory``
     - Rate limit storage (``memory`` or ``database``)
   * - ``TOS_URL``
     - *(empty)*
     - Terms of Service URL shown in the ACME directory
   * - ``CRL_PATH``
     - ``/crl``
     - CRL endpoint path
   * - ``ARI_PATH``
     - ``/renewalInfo``
     - ARI endpoint path
   * - ``METRICS_PATH``
     - ``/metrics``
     - Metrics endpoint path
   * - ``AUDIT_WEBHOOK_URL``
     - *(empty)*
     - Webhook URL for audit event export
   * - ``AUDIT_SYSLOG_HOST``
     - *(empty)*
     - Syslog host for audit event export

Common Operations
-----------------

Validate Config Without Starting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   docker compose run --rm --no-deps acmeeh \
       acmeeh -c /app/config.yaml --validate-only

The ``--no-deps`` flag skips starting PostgreSQL, which is not needed for
config validation.

View Logs
^^^^^^^^^

.. code-block:: bash

   # All services
   docker compose logs -f

   # ACMEEH only
   docker compose logs -f acmeeh

   # Audit log (inside the container volume)
   docker compose exec acmeeh cat /var/log/acmeeh/audit.log

Check Health
^^^^^^^^^^^^

.. code-block:: bash

   # Liveness (is the process alive?)
   curl http://localhost:8443/livez

   # Comprehensive health (database, CA, workers)
   curl http://localhost:8443/healthz

   # Readiness (ready for traffic?)
   curl http://localhost:8443/readyz

Test CA Signing
^^^^^^^^^^^^^^^

.. code-block:: bash

   docker compose exec acmeeh acmeeh -c /app/config.yaml ca test-sign

Database Operations
^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Check database connectivity
   docker compose exec acmeeh acmeeh -c /app/config.yaml db status

   # Connect to PostgreSQL directly
   docker compose exec postgres psql -U acmeeh -d acmeeh

Rebuild After Code Changes
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   docker compose build
   docker compose up -d

Restart ACMEEH Only
^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   docker compose restart acmeeh

Stop Everything
^^^^^^^^^^^^^^^

.. code-block:: bash

   # Stop containers (preserves volumes)
   docker compose down

   # Stop and delete volumes (destroys database!)
   docker compose down -v

Enabling Optional Subsystems
-----------------------------

Several subsystems are disabled by default. To enable them, edit
``docker/config.yaml`` and set the ``enabled`` flag to ``true``:

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Subsystem
     - Config key
     - Notes
   * - Admin API
     - ``admin_api.enabled``
     - Set ``ADMIN_TOKEN_SECRET`` to a strong random value
   * - CRL
     - ``crl.enabled``
     - Requires the internal or HSM CA backend
   * - ARI
     - ``ari.enabled``
     - ACME Renewal Information (draft-ietf-acme-ari)
   * - Metrics
     - ``metrics.enabled``
     - Prometheus-compatible ``/metrics`` endpoint
   * - SMTP
     - ``smtp.enabled``
     - Set ``SMTP_HOST``, ``SMTP_FROM``, and credentials
   * - Background worker
     - ``challenges.background_worker.enabled``
     - Retries stale challenges automatically

Reverse Proxy with Docker
--------------------------

In production, put ACMEEH behind a TLS-terminating reverse proxy. Enable
proxy header handling in ``docker/config.yaml``:

.. code-block:: yaml

   proxy:
     enabled: true
     trusted_proxies:
       - 172.16.0.0/12     # Docker default bridge network range
       - 10.0.0.0/8

Example Nginx service added to ``docker-compose.yaml``:

.. code-block:: yaml

   services:
     nginx:
       image: nginx:alpine
       ports:
         - "443:443"
       volumes:
         - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
         - ./tls:/etc/nginx/tls:ro
       depends_on:
         - acmeeh
       networks:
         - acmeeh-net

Production Hardening
--------------------

- Set ``ACMEEH_EXTERNAL_URL`` to the real public HTTPS URL
- Use a strong, random ``POSTGRES_PASSWORD`` (32+ characters)
- Set ``POSTGRES_SSLMODE=require`` if PostgreSQL is not on the same host
- Set ``LOG_FORMAT=json`` for structured log ingestion
- Set ``ADMIN_TOKEN_SECRET`` to 32+ random bytes if the admin API is enabled
- Restrict the ``certs/`` directory permissions — the CA private key should
  be readable only by the container user
- Bump ``server.workers`` in ``docker/config.yaml`` to match your CPU count
  (2--4x cores)
- Set ``server.max_requests: 1000`` to recycle workers periodically
- Use ``database`` rate limit backend for multi-instance deployments
- Enable CRL for revocation checking
- Back up the ``acmeeh-pgdata`` volume regularly

Scaling
-------

ACMEEH is stateless — all state lives in PostgreSQL. To run multiple
instances:

.. code-block:: bash

   docker compose up -d --scale acmeeh=3

All instances share the same database. Background workers use PostgreSQL
advisory locks for leader election, so only one instance runs each worker at
a time. Point a load balancer at the scaled instances and set the same
``ACMEEH_EXTERNAL_URL`` on all of them.

Troubleshooting
---------------

Container exits immediately
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check logs for configuration or CA errors:

.. code-block:: bash

   docker compose logs acmeeh

Common causes:

- Missing ``POSTGRES_PASSWORD`` in ``.env``
- CA certificate files not mounted (``certs/`` directory empty or missing)
- Config validation error (run ``--validate-only`` to diagnose)

Port already in use
^^^^^^^^^^^^^^^^^^^

If PostgreSQL port 5432 is already taken on your host:

.. code-block:: bash

   # In .env
   POSTGRES_PORT=5433

This only changes the host-side port mapping. The containers still
communicate on port 5432 internally.

Database connection refused
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ACMEEH container waits for PostgreSQL to be healthy before starting.
If it still fails, verify the ``POSTGRES_HOST`` matches the service name in
``docker-compose.yaml`` (default: ``postgres``).

Permission denied on certs
^^^^^^^^^^^^^^^^^^^^^^^^^^

The container runs as ``acmeeh`` (UID 1000 by default). Ensure your
certificate files are readable by this UID, or change ``ACMEEH_UID`` /
``ACMEEH_GID`` to match your host file ownership.
