==========
Deployment
==========

*Production setup, Docker, reverse proxy, monitoring, and HA considerations*

Production Checklist
--------------------

- Use gunicorn (not Flask dev server) --- omit ``--dev`` flag
- Set ``server.external_url`` to the public HTTPS URL
- Use a strong ``admin_api.token_secret`` (32+ random bytes)
- Store secrets in environment variables, not config files
- Set ``database.sslmode: require`` or ``verify-full``
- Enable ``database.auto_setup: true`` for first deploy, then disable
- Set appropriate ``server.workers`` (2-4 x CPU cores)
- Configure ``server.max_requests`` to restart workers periodically
- Enable rate limiting (``security.rate_limits.enabled: true``)
- Set ``logging.format: json`` for structured log ingestion
- Restrict CA private key file permissions to ``0400``
- Put ACMEEH behind a reverse proxy for TLS termination
- Enable CRL for revocation checking

CLI Reference
-------------

All operations are invoked through the ``acmeeh`` module:

.. code-block:: bash

   python -m acmeeh -c CONFIG [options] [command]

Global Flags
^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Flag
     - Description
   * - ``-c / --config PATH``
     - Configuration file path (required)
   * - ``--debug``
     - Enable debug output with full tracebacks
   * - ``--validate-only``
     - Validate config and exit
   * - ``--dev``
     - Use Flask development server
   * - ``-v / --version``
     - Show version

Subcommands
^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - ``serve [--dev]``
     - Start the server (default action when no subcommand is given)
   * - ``db status``
     - Check database connectivity and schema
   * - ``db migrate``
     - Run database schema migration
   * - ``ca test-sign``
     - Test CA backend with an ephemeral CSR
   * - ``crl rebuild``
     - Force CRL rebuild (requires ``crl.enabled: true``)
   * - ``admin create-user --username NAME --email ADDR [--role ROLE]``
     - Create an admin user
   * - ``inspect order <uuid>``
     - Inspect order with authorizations and challenges
   * - ``inspect certificate <uuid-or-serial>``
     - Inspect certificate details
   * - ``inspect account <uuid>``
     - Inspect account with contacts and order count

.. tip::

   **Quick Validation**

   Use ``--validate-only`` in CI/CD pipelines to verify configuration changes before deploying:

   .. code-block:: bash

      python -m acmeeh -c /etc/acmeeh/config.yaml --validate-only

Environment Variable Substitution
----------------------------------

ACMEEH config files support environment variable references that are resolved before JSON Schema validation. This allows you to keep secrets out of config files entirely.

.. code-block:: yaml

   database:
     password: ${DB_PASSWORD}
     host: ${DB_HOST:-localhost}
     port: ${DB_PORT:-5432}

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Syntax
     - Behavior
   * - ``${VAR}``
     - Required --- startup fails if the variable is not set
   * - ``${VAR:-default}``
     - Uses the default value if the variable is not set

Environment variables are resolved during ``additional_checks()`` in the config class, which runs after YAML parsing but before JSON Schema validation. This means the substituted values are still subject to full schema validation.

Gunicorn Configuration
----------------------

ACMEEH runs gunicorn in production mode. All gunicorn settings are configured via YAML:

.. code-block:: yaml

   server:
     external_url: https://acme.example.com
     bind: 0.0.0.0
     port: 8443
     workers: 8               # 2-4x CPU cores
     worker_class: sync
     timeout: 30
     graceful_timeout: 30
     keepalive: 2
     max_requests: 1000        # restart workers after 1000 requests
     max_requests_jitter: 50  # add randomness to prevent thundering herd

Start the production server:

.. code-block:: bash

   PYTHONPATH=src DB_PASSWORD=secret python -m acmeeh -c /etc/acmeeh/config.yaml

WSGI Entry Point
^^^^^^^^^^^^^^^^

For advanced deployments you can bypass the ``python -m acmeeh`` wrapper and use gunicorn (or any WSGI server) directly via the WSGI entry point:

.. code-block:: bash

   export ACMEEH_CONFIG=/etc/acmeeh/config.yaml
   gunicorn "acmeeh.server.wsgi:app"

This is useful when you need full control over gunicorn flags (e.g., ``--preload``, custom logging config, or ``--certfile`` / ``--keyfile`` for direct TLS). The ``ACMEEH_CONFIG`` environment variable tells the WSGI module where to find the configuration file.

Docker
------

ACMEEH ships with a production-ready ``Dockerfile``, ``docker-compose.yaml``,
and fully parameterized ``docker/config.yaml``. See the :doc:`docker` page
for the complete guide, including build ARGs, environment variables, and
common operations.

Quick start:

.. code-block:: bash

   cp docker/.env.example .env        # set POSTGRES_PASSWORD
   mkdir -p certs                     # place root.pem + root-key.pem
   docker compose up -d
   curl http://localhost:8443/livez

Reverse Proxy Setup
--------------------

ACMEEH should sit behind a reverse proxy that handles TLS termination. Enable proxy support in config:

.. code-block:: yaml

   proxy:
     enabled: true
     trusted_proxies:
       - 172.16.0.0/12
       - 10.0.0.0/8

Nginx Example
^^^^^^^^^^^^^

.. code-block:: nginx

   upstream acmeeh {
       server 127.0.0.1:8443;
   }

   server {
       listen 443 ssl http2;
       server_name acme.example.com;

       ssl_certificate     /etc/nginx/tls/cert.pem;
       ssl_certificate_key /etc/nginx/tls/key.pem;

       location / {
           proxy_pass http://acmeeh;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;

           # ACME clients may send large JWS payloads
           client_max_body_size 64k;
       }
   }

Caddy Example
^^^^^^^^^^^^^

.. code-block:: bash

   acme.example.com {
       reverse_proxy localhost:8443
   }

Health Check Endpoints
----------------------

ACMEEH exposes three health check endpoints designed for container orchestrators, load balancers, and monitoring systems.

GET /livez --- Liveness Probe
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Minimal liveness check. Returns ``200 OK`` if the process is running and able to serve HTTP. No backend checks are performed.

.. code-block:: json

   {
     "alive": true,
     "version": "1.0.0"
   }

Use this for Kubernetes liveness probes or basic load balancer health checks.

GET /healthz --- Comprehensive Health Check
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Deep health check that verifies all subsystems. Returns ``200 OK`` when all components are healthy, or ``503 Service Unavailable`` if the database, CA backend, or CRL subsystem is unhealthy.

.. code-block:: json

   {
     "status": "ok",
     "checks": {
       "database": {
         "status": "ok",
         "pool": {
           "size": 10,
           "available": 8,
           "waiting": 0
         }
       },
       "ca_backend": { "status": "ok" },
       "crl": { "status": "ok", "stale": false },
       "workers": {
         "challenge": true,
         "cleanup": true,
         "expiration": true
       },
       "smtp": { "status": "ok" },
       "dns_resolver": { "status": "ok" }
     },
     "shutting_down": false
   }

When the connection pool is exhausted (all connections in use), the database check is skipped to avoid blocking the health probe, and the response reports ``"database": "pool_exhausted"`` with ``"status": "degraded"``:

.. code-block:: json

   {
     "status": "degraded",
     "checks": {
       "database": "pool_exhausted",
       "ca_backend": { "status": "ok" },
       ...
     },
     "shutting_down": false
   }

.. note::

   **503 Triggers**

   The ``/healthz`` endpoint returns 503 if any of the following are unhealthy: ``database`` (including ``pool_exhausted``), ``ca_backend``, or ``crl`` (when CRL is enabled and stale). Non-critical subsystems like SMTP and DNS resolver are reported but do not affect the HTTP status code.

GET /readyz --- Readiness Probe
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Kubernetes readiness probe. Returns ``200 OK`` when the server is ready to accept traffic, or ``503 Service Unavailable`` with a reason when it is not.

Success response:

.. code-block:: json

   {
     "ready": true
   }

Failure responses:

.. code-block:: json

   {
     "ready": false,
     "reason": "database unavailable"
   }

When the connection pool is critically exhausted:

.. code-block:: json

   {
     "ready": false,
     "reason": "Connection pool exhausted",
     "pool": { "size": 20, "available": 0, "waiting": 5 }
   }

Use this for Kubernetes readiness probes so that traffic is only routed to instances that have completed startup and can serve requests.

Signal Handling & Graceful Shutdown
------------------------------------

ACMEEH handles Unix signals for clean lifecycle management.

SIGTERM / SIGINT --- Graceful Shutdown
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sending ``SIGTERM`` or ``SIGINT`` initiates a graceful shutdown sequence:

#. The server stops accepting new connections
#. In-flight requests are allowed to complete for up to ``server.graceful_timeout`` seconds
#. Challenges in ``PROCESSING`` state are drained back to ``PENDING`` so they will be retried on next startup
#. Background workers (challenge, cleanup, expiration) stop cleanly after their current cycle
#. Database connection pool is drained and closed

SIGHUP --- Config Hot-Reload (Unix only)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sending ``SIGHUP`` triggers a live configuration reload without restarting the process. Only a subset of settings can be safely reloaded at runtime:

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Safely Reloaded
     - Requires Restart
   * - ``logging.level``
     - CA backend settings
   * - ``security.rate_limits``
     - Database settings
   * - ``notifications`` (all settings)
     - Server bind/port/workers
   * - ``metrics.enabled``
     - Challenge types

.. warning::

   **Reload Limitations**

   CA backend, database, server, and challenge type settings are **not** reloaded by ``SIGHUP``. Changes to these settings require a full process restart.

Background Workers
------------------

ACMEEH runs three background workers that perform periodic maintenance tasks. Each worker operates independently and uses PostgreSQL advisory locks for leader election in multi-instance deployments.

Challenge Worker
^^^^^^^^^^^^^^^^

Reprocesses challenges that have been stuck in ``PROCESSING`` state beyond a configurable threshold. This handles cases where a validation attempt was interrupted (e.g., by a restart or crash).

.. code-block:: yaml

   challenges:
     background_worker:
       enabled: false         # default: false
       poll_seconds: 10       # how often to check for stale challenges
       stale_seconds: 300     # age threshold before a PROCESSING challenge is retried

Uses PostgreSQL advisory lock ID ``712003``.

Cleanup Worker
^^^^^^^^^^^^^^

Runs multiple independent maintenance tasks, each on its own interval:

- **Nonce garbage collection** --- ``nonce.gc_interval_seconds`` (default: 300)
- **Order expiry** --- ``order.cleanup_interval_seconds`` (default: 3600)
- **Stale processing recovery** --- ``order.stale_processing_threshold_seconds`` (default: 600)
- **Audit log retention** --- purges old audit records per configured retention period
- **Rate limit GC** --- cleans up expired rate limit entries
- **Authorization/challenge/order/notice retention** --- removes expired records per configured retention periods

Uses PostgreSQL advisory lock ID ``712001``.

Expiration Worker
^^^^^^^^^^^^^^^^^

Sends certificate expiration warning notifications to account contacts when certificates approach their expiry date.

.. code-block:: yaml

   notifications:
     expiration_warning_days: [30, 14, 7, 1]
     expiration_check_interval_seconds: 3600

Uses PostgreSQL advisory lock ID ``712002``. Deduplicates notifications via the ``certificate_expiration_notices`` database table so that each warning is sent only once per certificate per threshold.

.. note::

   **HA Leader Election**

   In multi-instance deployments, all three workers use PostgreSQL advisory locks for leader election. Only one instance runs each worker at a time. No additional coordination (e.g., Redis, ZooKeeper) is needed --- the database handles it.

Email Notifications
-------------------

ACMEEH can send email notifications for certificate expiration warnings and other events. Notifications are recorded in the database and optionally delivered via SMTP.

Notification Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: yaml

   notifications:
     enabled: true
     expiration_warning_days: [30, 14, 7, 1]
     expiration_check_interval_seconds: 3600
     max_retries: 3
     retry_delay_seconds: 60
     retry_backoff_multiplier: 2.0
     retry_max_delay_seconds: 3600
     batch_size: 50

SMTP Configuration
^^^^^^^^^^^^^^^^^^

.. code-block:: yaml

   smtp:
     enabled: true
     host: smtp.example.com
     port: 587
     use_tls: true
     username: acmeeh@example.com
     password: ${SMTP_PASSWORD}
     from_address: acmeeh@example.com
     cc: []                                  # addresses CC'd on every notification
     bcc: []                                  # addresses BCC'd (envelope only)
     timeout_seconds: 30
     templates_path: /etc/acmeeh/templates   # optional custom Jinja2 templates

Graceful Degradation
^^^^^^^^^^^^^^^^^^^^

The notification system degrades gracefully depending on configuration:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Scenario
     - Behavior
   * - ``notifications.enabled: false``
     - Complete no-op --- no notifications recorded, no emails sent
   * - ``smtp.enabled: false``
     - Notifications are recorded in the database (audit trail) but not emailed
   * - SMTP delivery failure
     - Notification marked as ``FAILED``, eligible for retry with exponential backoff up to ``retry_max_delay_seconds``

Maintenance Mode
----------------

ACMEEH supports a maintenance mode via the admin API that allows you to gracefully pause new certificate issuance during planned upgrades or CA maintenance windows.

Enabling Maintenance Mode
^^^^^^^^^^^^^^^^^^^^^^^^^

Enable via the admin API (requires admin authentication):

.. code-block:: bash

   # Enable maintenance mode
   curl -X POST https://acme.example.com/api/maintenance \
     -H "Authorization: Bearer <admin-token>" \
     -H "Content-Type: application/json" \
     -d '{"enabled": true}'

   # Check current status
   curl https://acme.example.com/api/maintenance \
     -H "Authorization: Bearer <admin-token>"

Behavior During Maintenance
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Operation
     - Behavior
   * - New order creation
     - Returns ``503`` with ``Retry-After: 60``
   * - Pre-authorization creation
     - Returns ``503`` with ``Retry-After: 60``
   * - Order finalization
     - Allowed (in-progress orders can complete)
   * - Challenge validation
     - Allowed (in-progress challenges can complete)
   * - Certificate downloads
     - Allowed
   * - Account operations
     - Allowed

.. tip::

   **Planned Upgrades**

   Enable maintenance mode before a planned upgrade, perform the upgrade, then disable maintenance mode. ACME clients that respect the ``Retry-After`` header will automatically retry after the maintenance window.

Database Sizing
---------------

.. list-table::
   :header-rows: 1
   :widths: 15 25 30 30

   * - Scale
     - Certificates
     - Connections
     - Disk
   * - Small
     - < 1,000
     - ``max_connections: 5``
     - 100 MB
   * - Medium
     - 1,000 - 50,000
     - ``max_connections: 20``
     - 1 GB
   * - Large
     - 50,000+
     - ``max_connections: 50``
     - 10+ GB

.. tip::

   **Connection Pool**

   Set ``database.max_connections`` to roughly ``server.workers x 2``. PostgreSQL's default ``max_connections`` is 100, which is usually sufficient.

Connection Pool Pressure Guard
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

ACMEEH automatically sheds load when the database connection pool is under pressure using a four-tier model that runs on every request before any database work:

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Tier
     - Retry-After
     - Condition
   * - **Growth headroom**
     - (allowed)
     - Pool has not reached ``max_connections`` --- new connections can be created on demand. No load shedding.
   * - **Exhausted**
     - ``5s``
     - All connections in use (``available=0``), requests are waiting, pool at max. Hard reject with a periodic recovery probe (one request every 2 seconds) to break deadlocks.
   * - **Critical**
     - ``3s``
     - Available connections at or below 30% of pool max (or 10% for pools > 20). Hard reject.
   * - **Pressure**
     - ``2s``
     - Available connections at or below 50% of pool max (or 20% for pools > 20) and requests are waiting. Soft reject.

Health check endpoints (``/livez``, ``/healthz``, ``/readyz``) are always exempt from this guard so that monitoring remains functional even during pool exhaustion.

This is transparent to ACME clients --- well-behaved clients will retry after the ``Retry-After`` delay. If you see frequent 503 responses in logs, increase ``database.max_connections`` or add more ACMEEH instances.

.. note::

   **Recovery Probes**

   When the pool is fully exhausted, the guard periodically allows a single request through (every 2 seconds) to prevent a deadlock where all connections are held by in-flight requests that cannot complete because the guard rejects every new request. This ensures the pool can eventually drain.

Monitoring
----------

Prometheus Metrics
^^^^^^^^^^^^^^^^^^

Enable the built-in metrics endpoint:

.. code-block:: yaml

   metrics:
     enabled: true
     path: /metrics
     auth_required: false

Scrape ``https://acme.example.com/metrics`` with Prometheus. The following metrics are exposed:

.. list-table::
   :header-rows: 1
   :widths: 40 15 45

   * - Metric
     - Type
     - Description
   * - ``acmeeh_uptime_seconds``
     - gauge
     - Server uptime in seconds
   * - ``acmeeh_accounts_created_total``
     - counter
     - Total accounts created
   * - ``acmeeh_accounts_deactivated_total``
     - counter
     - Total accounts deactivated
   * - ``acmeeh_certificates_issued_total``
     - counter
     - Total certificates issued
   * - ``acmeeh_certificates_revoked_total``
     - counter
     - Total certificates revoked
   * - ``acmeeh_orders_created_total``
     - counter
     - Total orders created
   * - ``acmeeh_challenges_validated_total{result=...}``
     - counter
     - Challenge validations (labeled: success, retry, failure)
   * - ``acmeeh_challenges_expired_total``
     - counter
     - Total challenges expired
   * - ``acmeeh_challenge_worker_polls_total``
     - counter
     - Challenge worker poll cycles
   * - ``acmeeh_challenge_worker_errors_total``
     - counter
     - Challenge worker errors
   * - ``acmeeh_cleanup_runs_total{task=...}``
     - counter
     - Cleanup task runs (labeled by task name)
   * - ``acmeeh_cleanup_errors_total{task=...}``
     - counter
     - Cleanup task errors (labeled by task name)
   * - ``acmeeh_expiration_warnings_sent_total``
     - counter
     - Expiration warnings sent
   * - ``acmeeh_expiration_worker_errors_total``
     - counter
     - Expiration worker errors
   * - ``acmeeh_ca_signing_errors_total``
     - counter
     - CA signing errors
   * - ``acmeeh_http_requests_total{method,status}``
     - counter
     - Total HTTP requests (labeled by method and status code)

Structured Logging
^^^^^^^^^^^^^^^^^^

Set ``logging.format: json`` to output structured JSON logs suitable for log aggregation systems (ELK, Loki, Splunk):

.. code-block:: yaml

   logging:
     level: INFO
     format: json
     audit:
       enabled: true
       file: /var/log/acmeeh/audit.log

High Availability
-----------------

ACMEEH is stateless at the application layer --- all state is in PostgreSQL. This means you can run multiple instances behind a load balancer.

Multi-Instance Setup
^^^^^^^^^^^^^^^^^^^^

#. Deploy 2+ ACMEEH instances with the same config (same ``external_url``)
#. Point all instances at the same PostgreSQL database
#. Load balance across instances (round-robin or least-connections)
#. Use PostgreSQL replication for database HA

.. note::

   **CRL Worker**

   The CRL rebuild worker, like all background workers, uses PostgreSQL advisory locks for leader election. Only one instance runs the CRL worker at a time, regardless of how many ACMEEH instances are deployed. No additional coordination is needed.

Backup & Recovery
-----------------

- **Database**: Regular ``pg_dump`` backups. The database contains all accounts, orders, certificates, and audit logs.
- **CA Keys**: Back up the root CA private key securely (encrypted, offline). Loss of the CA key means you cannot issue new certificates or rebuild CRLs.
- **Configuration**: Version-control your config YAML (excluding secrets which should be in env vars).

Systemd Service
---------------

.. code-block:: ini

   [Unit]
   Description=ACMEEH ACME Server
   After=network.target postgresql.service

   [Service]
   Type=simple
   User=acmeeh
   Group=acmeeh
   WorkingDirectory=/opt/acmeeh
   Environment=PYTHONPATH=src
   EnvironmentFile=/etc/acmeeh/env
   ExecStart=/opt/acmeeh/.venv/bin/python -m acmeeh -c /etc/acmeeh/config.yaml
   Restart=on-failure
   RestartSec=5
   LimitNOFILE=65536

   [Install]
   WantedBy=multi-user.target

Create ``/etc/acmeeh/env`` with your secrets:

.. code-block:: bash

   DB_PASSWORD=your-database-password
   ADMIN_TOKEN_SECRET=your-jwt-secret
