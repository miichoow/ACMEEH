ACMEEH Documentation
====================

Enterprise ACME (RFC 8555) server for internal PKI infrastructure

ACMEEH is a full-featured ACME server designed for organizations that need to issue and
manage TLS certificates on their internal network. It implements
`RFC 8555 <https://www.rfc-editor.org/rfc/rfc8555>`_ and works with any
standards-compliant ACME client (certbot, acme.sh, Caddy, Traefik, etc.).

Key Features
------------

- **4 CA Backends** — Internal file-based CA, external HTTP API, PKCS#11 HSM, or ACME proxy to an upstream CA. Or bring your own with ``ext:`` plugins.
- **3 Challenge Types** — HTTP-01, DNS-01, and TLS-ALPN-01 validation with configurable timeouts, retries, and background workers.
- **Admin API** — REST API for user management, audit logs, EAB credentials, allowed identifiers, CSR profiles, certificate search, and maintenance mode.
- **CRL, OCSP & ARI** — Built-in Certificate Revocation Lists, OCSP responder, and ACME Renewal Information (draft-ietf-acme-ari) support.
- **Hook System** — 10 lifecycle events with pluggable handlers for custom automation on account creation, certificate issuance, revocation, and more.
- **Security Controls** — Rate limiting, key size policies, identifier allowlists, EAB, CAA enforcement, CSR validation, and per-account quotas.
- **Prometheus Metrics** — Built-in ``/metrics`` endpoint exposing certificate counts, issuance rates, challenge success/failure, and CA backend health.
- **Email Notifications** — SMTP-based alerts for certificate expiration, with configurable warning days, retry logic, and Jinja2 templates.

Architecture
------------

::

                    ACME Clients (certbot, acme.sh, Caddy, ...)
                                    |
                            HTTPS / RFC 8555
                                    |
                    ┌───────────────────────────────┐
                    │         Flask API Layer        │
                    │  directory, nonce, account,    │
                    │  order, authz, challenge,      │
                    │  certificate, key-change       │
                    ├───────────────────────────────┤
                    │        Service Layer           │
                    │  AccountService, OrderService, │
                    │  ChallengeService, CertService │
                    ├──────────┬────────────────────┤
                    │Repository│    CA Backend       │
                    │  Layer   │  ┌──────────────┐  │
                    │(PyPGKit) │  │  internal     │  │
                    │          │  │  external     │  │
                    │          │  │  hsm          │  │
                    │          │  │  acme_proxy   │  │
                    │          │  │  ext:custom   │  │
                    │          │  └──────────────┘  │
                    ├──────────┴────────────────────┤
                    │     DI Container (context.py)  │
                    └───────────────┬───────────────┘
                                    │
                            PostgreSQL 14+

Quick Start
-----------

.. code-block:: bash

   # Clone and install
   git clone https://github.com/miichoow/ACMEEH.git
   cd acmeeh
   python -m venv .venv
   .venv/bin/pip install flask cryptography dnspython jinja2 psycopg[binary]
   .venv/bin/pip install pyConfigKit PyPGKit

   # Create minimal config (config.yaml)
   # See Configuration page for full reference

   # Validate config
   PYTHONPATH=src python -m acmeeh -c config.yaml --validate-only

   # Start development server
   PYTHONPATH=src DB_PASSWORD=secret python -m acmeeh -c config.yaml --dev

See the :doc:`installation` guide for detailed setup instructions.

.. toctree::
   :maxdepth: 2
   :caption: Contents

   installation
   configuration
   api-reference
   ca-backends
   extensibility
   admin
   docker
   deployment
   development
